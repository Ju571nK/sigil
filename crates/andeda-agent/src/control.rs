//! Control IPC: UDS on Unix, Named Pipe on Windows.
//!
//! Phase 1 supports a single command: `{"cmd":"stats"}` returning the current
//! Heartbeat-equivalent payload as JSON.

use andeda_core::policy::signed_envelope::SignedPolicyResponse;
use andeda_core::stats::{Stats, StatsSnapshot};
use andeda_core::PolicySignatureInvalidReason;
use serde::{Deserialize, Serialize};
#[cfg(unix)]
use std::path::Path;
use std::sync::Arc;

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    /// Existing Phase 1 command — unchanged on the wire.
    #[serde(rename = "stats")]
    Stats,
    /// Plan B `andeda-sender` hands a verified envelope here for application.
    ApplyPolicy {
        /// The full server response — agent re-verifies independently.
        response: SignedPolicyResponse,
    },
    /// Operator + sender introspection: returns the agent's current
    /// `last_applied_policy_version`, the active `valid_until`, and whether
    /// the active policy is currently expired.
    PolicyStatus,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Response {
    pub ok: bool,
    pub stats: Option<StatsSnapshot>,
    /// Present iff the request was `ApplyPolicy`.
    pub apply_policy: Option<ApplyPolicyResult>,
    /// Present iff the request was `PolicyStatus`.
    pub policy_status: Option<PolicyStatusPayload>,
    pub error: Option<String>,
}

/// Outcome of an `apply_policy` request.
#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ApplyPolicyResult {
    /// Verifier accepted; policy.yaml written; version advanced.
    Accepted {
        /// The new `last_applied_policy_version`.
        applied_policy_version: i64,
    },
    /// Verifier rejected. The wire-stable `reason` matches the
    /// `PolicySignatureInvalid` event variant emitted in parallel.
    Rejected {
        /// Which check failed.
        reason: PolicySignatureInvalidReason,
    },
}

/// Snapshot of the agent's current policy state.
#[derive(Serialize, Deserialize, Debug)]
pub struct PolicyStatusPayload {
    pub last_applied_policy_version: i64,
    /// RFC 3339; `None` if no envelope has ever been applied.
    pub active_envelope_valid_until: Option<String>,
    /// `true` iff `now >= active_envelope_valid_until`.
    pub policy_expired_active: bool,
}

#[cfg(unix)]
pub async fn serve(socket_path: &Path, stats: Arc<Stats>) -> std::io::Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixListener;

    if socket_path.exists() {
        let _ = std::fs::remove_file(socket_path);
    }
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let listener = UnixListener::bind(socket_path)?;
    tracing::info!(path = ?socket_path, "control IPC listening");
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = ?e, "control IPC accept failed");
                continue;
            }
        };
        let stats = stats.clone();
        tokio::spawn(async move {
            let (rd, mut wr) = stream.into_split();
            let mut reader = BufReader::new(rd);
            let mut line = String::new();
            if reader.read_line(&mut line).await.is_err() {
                return;
            }
            let resp = match serde_json::from_str::<Request>(line.trim()) {
                Ok(Request::Stats) => Response {
                    ok: true,
                    stats: Some(stats.snapshot()),
                    apply_policy: None,
                    policy_status: None,
                    error: None,
                },
                // ApplyPolicy and PolicyStatus arms are added in Task A6.3.
                // Until then, return a "not yet wired" error so the protocol
                // is well-formed but the handler is explicitly stubbed.
                Ok(Request::ApplyPolicy { .. }) | Ok(Request::PolicyStatus) => Response {
                    ok: false,
                    stats: None,
                    apply_policy: None,
                    policy_status: None,
                    error: Some("handler not yet wired (Task A6.3)".into()),
                },
                Err(e) => Response {
                    ok: false,
                    stats: None,
                    apply_policy: None,
                    policy_status: None,
                    error: Some(e.to_string()),
                },
            };
            if let Ok(json) = serde_json::to_string(&resp) {
                let _ = wr.write_all(json.as_bytes()).await;
                let _ = wr.write_all(b"\n").await;
            }
        });
    }
}

#[cfg(windows)]
pub async fn serve(pipe_name: &str, stats: Arc<Stats>) -> std::io::Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::windows::named_pipe::ServerOptions;

    loop {
        let server = ServerOptions::new()
            .first_pipe_instance(false)
            .access_inbound(true)
            .access_outbound(true)
            .create(pipe_name)?;
        server.connect().await?;
        let stats = stats.clone();
        tokio::spawn(async move {
            let (rd, mut wr) = tokio::io::split(server);
            let mut reader = BufReader::new(rd);
            let mut line = String::new();
            if reader.read_line(&mut line).await.is_err() {
                return;
            }
            let resp = match serde_json::from_str::<Request>(line.trim()) {
                Ok(Request::Stats) => Response {
                    ok: true,
                    stats: Some(stats.snapshot()),
                    apply_policy: None,
                    policy_status: None,
                    error: None,
                },
                // ApplyPolicy and PolicyStatus arms are added in Task A6.3.
                // Until then, return a "not yet wired" error so the protocol
                // is well-formed but the handler is explicitly stubbed.
                Ok(Request::ApplyPolicy { .. }) | Ok(Request::PolicyStatus) => Response {
                    ok: false,
                    stats: None,
                    apply_policy: None,
                    policy_status: None,
                    error: Some("handler not yet wired (Task A6.3)".into()),
                },
                Err(e) => Response {
                    ok: false,
                    stats: None,
                    apply_policy: None,
                    policy_status: None,
                    error: Some(e.to_string()),
                },
            };
            if let Ok(json) = serde_json::to_string(&resp) {
                let _ = wr.write_all(json.as_bytes()).await;
                let _ = wr.write_all(b"\n").await;
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use andeda_core::policy::signed_envelope::{SignedEnvelope, SignedPolicyResponse};
    use time::macros::datetime;

    fn sample_response() -> SignedPolicyResponse {
        SignedPolicyResponse {
            etag: "abc".into(),
            signed_envelope: SignedEnvelope {
                policy_version: 7,
                policy_bytes_b64: "AAA=".into(),
                valid_until: datetime!(2026-06-15 0:00 UTC),
                issued_at: datetime!(2026-05-15 8:00 UTC),
            },
            signature: "sig".into(),
            signing_pubkey_id: "k1".into(),
            applied_at: datetime!(2026-05-15 8:01 UTC),
        }
    }

    #[test]
    fn apply_policy_request_round_trips() {
        let req = Request::ApplyPolicy { response: sample_response() };
        let s = serde_json::to_string(&req).unwrap();
        // The cmd discriminator MUST be exactly "apply_policy" (snake_case is
        // wrong here — the existing Phase 1 control protocol uses lowercase).
        assert!(s.contains("\"cmd\":\"apply_policy\""));
        let back: Request = serde_json::from_str(&s).unwrap();
        match back {
            Request::ApplyPolicy { response } => {
                assert_eq!(response.signed_envelope.policy_version, 7);
            }
            _ => panic!("expected ApplyPolicy, got {back:?}"),
        }
    }

    #[test]
    fn policy_status_request_round_trips() {
        let req = Request::PolicyStatus;
        let s = serde_json::to_string(&req).unwrap();
        assert!(s.contains("\"cmd\":\"policy_status\""));
        let _: Request = serde_json::from_str(&s).unwrap();
    }

    #[test]
    fn response_includes_optional_apply_policy_payload() {
        let r = Response {
            ok: true,
            stats: None,
            apply_policy: Some(ApplyPolicyResult::Accepted {
                applied_policy_version: 9,
            }),
            policy_status: None,
            error: None,
        };
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains("\"apply_policy\""));
        assert!(s.contains("\"applied_policy_version\":9"));
    }

    #[test]
    fn response_apply_policy_rejected_carries_reason() {
        let r = Response {
            ok: false,
            stats: None,
            apply_policy: Some(ApplyPolicyResult::Rejected {
                reason: andeda_core::PolicySignatureInvalidReason::Expired,
            }),
            policy_status: None,
            error: None,
        };
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains("\"reason\":\"expired\""));
    }
}
