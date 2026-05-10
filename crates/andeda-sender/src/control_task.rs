//! Control plane: poll /v1/policy, hand 200 results to the agent IPC.

use crate::transport::{classify_send_error, SendOutcome};
use crate::wire::SignedPolicyResponse;
use reqwest::Client;

#[derive(Debug)]
pub enum PollOutcome {
    /// Server returned a fresh policy. Caller hands this to apply_policy IPC.
    NewPolicy { etag: String, response: SignedPolicyResponse },
    /// Server returned 304 — no work to do.
    Unmodified,
    /// 404 → host is not in inventory; emit local event.
    HostUnknown,
    /// TLS handshake failure.
    TlsFailure(String),
    /// Network failure.
    Network(String),
    /// Other / parse failure.
    ProtocolViolation(String),
}

pub async fn poll_policy(
    client: &Client,
    server_base_url: &str,
    host_id: &str,
    cached_etag: Option<&str>,
) -> PollOutcome {
    let url = format!(
        "{}/v1/policy?host_id={}",
        server_base_url.trim_end_matches('/'),
        urlencoding::encode(host_id)
    );
    let mut req = client.get(&url);
    if let Some(etag) = cached_etag {
        req = req.header("if-none-match", etag);
    }
    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => match classify_send_error::<()>(e) {
            SendOutcome::TlsFailure(s) => return PollOutcome::TlsFailure(s),
            SendOutcome::Network(s) => return PollOutcome::Network(s),
            other => return PollOutcome::ProtocolViolation(format!("{other:?}")),
        },
    };
    let status = resp.status().as_u16();
    if status == 304 {
        return PollOutcome::Unmodified;
    }
    if status == 404 {
        return PollOutcome::HostUnknown;
    }
    if !(200..300).contains(&status) {
        let body = resp.text().await.unwrap_or_default();
        return PollOutcome::ProtocolViolation(format!("status {status}: {body}"));
    }
    let etag = resp
        .headers()
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_default();
    match resp.json::<SignedPolicyResponse>().await {
        Ok(response) => PollOutcome::NewPolicy { etag, response },
        Err(e) => PollOutcome::ProtocolViolation(format!("policy json: {e}")),
    }
}

use std::time::Duration;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

pub struct ControlLoopCtx {
    pub client: Client,
    pub server_base_url: String,
    pub host_id: String,
    pub poll_interval: Duration,
    pub shutdown: CancellationToken,
    pub outcomes: mpsc::Sender<PollOutcome>,
}

/// Runs `poll_policy` in a loop with the configured interval. Cached
/// ETag is held in-process (not persisted here — caller persists on
/// agent ACK).
pub async fn run(ctx: ControlLoopCtx) {
    let mut cached_etag: Option<String> = None;
    let mut interval = tokio::time::interval(ctx.poll_interval);
    interval.tick().await; // skip immediate fire
    loop {
        tokio::select! {
            biased;
            _ = ctx.shutdown.cancelled() => break,
            _ = interval.tick() => {
                let outcome = poll_policy(
                    &ctx.client,
                    &ctx.server_base_url,
                    &ctx.host_id,
                    cached_etag.as_deref(),
                ).await;
                if let PollOutcome::NewPolicy { etag, .. } = &outcome {
                    cached_etag = Some(etag.clone());
                }
                if ctx.outcomes.send(outcome).await.is_err() {
                    // Receiver dropped — exit loop.
                    break;
                }
            }
        }
    }
}
