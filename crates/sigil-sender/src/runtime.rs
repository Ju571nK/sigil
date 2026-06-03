//! Top-level supervisor.
//!
//! Spawns three tasks:
//! - control_task: polls /v1/policy with cached ETag.
//! - reader: handles each PollOutcome — apply_policy IPC for fresh
//!   policies (then persists ETag on success), local-event emission for
//!   HostUnknown / TlsFailure / ProtocolViolation.
//! - data_task: read JSONL → POST /v1/events → apply_ack → state::store
//!   → dead-letter rejections → SharedStats updates.

use crate::agent_ipc::ApplyPolicyResult;
use crate::config::SenderConfig;
use crate::control_task::{ControlLoopCtx, PollOutcome};
use crate::data_task::{self, local_event, DataTaskCtx};
use crate::dead_letter;
use crate::heartbeat;
use crate::state;
use crate::transport::build_client;
use anyhow::Result;
use sigil_core::event::Evidence;
use std::path::PathBuf;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

pub struct RuntimeCtx {
    pub config: SenderConfig,
    pub host_id: String,
    pub agent_version: String,
    pub sender_version: String,
    pub shutdown: CancellationToken,
}

pub async fn run(ctx: RuntimeCtx) -> Result<()> {
    if ctx.config.client_cert_path.is_none() {
        tracing::warn!(
            "sigil-sender: no client_cert_path configured — running WITHOUT an mTLS \
             client identity. mTLS is the recommended production posture."
        );
    }
    let client = build_client(
        ctx.config.client_cert_path.as_deref(),
        ctx.config.client_key_path.as_deref(),
        ctx.config.server_ca_path.as_deref(),
    )?;
    let stats = heartbeat::shared();
    let etag_path = etag_path_for(&ctx.config.offset_path);
    let packs_etag_path = packs_etag_path_for(&ctx.config.offset_path);
    let initial_etag = state::load_etag(&etag_path).ok().flatten();

    let (poll_tx, mut poll_rx) = mpsc::channel::<PollOutcome>(8);

    let control = tokio::spawn({
        let client_c = client.clone();
        let cfg_c = ctx.config.clone();
        let host_id_c = ctx.host_id.clone();
        let cancel_c = ctx.shutdown.clone();
        async move {
            crate::control_task::run(ControlLoopCtx {
                client: client_c,
                server_base_url: cfg_c.server_base_url.clone(),
                host_id: host_id_c,
                poll_interval: cfg_c.policy_poll_interval,
                shutdown: cancel_c,
                outcomes: poll_tx,
            })
            .await;
        }
    });

    let reader = tokio::spawn({
        let agent_socket = ctx.config.agent_control.clone();
        let dead_letter_dir = ctx.config.dead_letter_dir.clone();
        let host_id = ctx.host_id.clone();
        let etag_path_c = etag_path.clone();
        let packs_etag_path_c = packs_etag_path.clone();
        let cancel_r = ctx.shutdown.clone();
        // Seed the in-process etag with whatever boot recovery loaded so the
        // first successful apply_policy doesn't re-store an unchanged value.
        let _ = initial_etag;
        async move {
            loop {
                tokio::select! {
                    biased;
                    _ = cancel_r.cancelled() => break,
                    maybe = poll_rx.recv() => {
                        match maybe {
                            Some(PollOutcome::NewPolicy { etag, response }) => {
                                match crate::agent_ipc::apply_policy(&agent_socket, &response).await {
                                    Ok(resp) if resp.ok
                                        && matches!(resp.apply_policy, Some(ApplyPolicyResult::Accepted { .. })) =>
                                    {
                                        if let Err(e) = state::store_etag(&etag_path_c, &etag) {
                                            tracing::warn!(error = ?e, "store_etag failed");
                                        }
                                    }
                                    Ok(resp) => {
                                        tracing::warn!(?resp, "agent did not accept policy; not caching etag");
                                    }
                                    Err(e) => {
                                        tracing::warn!(error = ?e, "apply_policy IPC failed");
                                    }
                                }
                            }
                            Some(PollOutcome::NewRulePacks { etag, response }) => {
                                match crate::agent_ipc::apply_rule_packs(&agent_socket, &response).await {
                                    Ok(resp) if resp.ok
                                        && matches!(resp.apply_policy, Some(ApplyPolicyResult::Accepted { .. })) =>
                                    {
                                        if let Err(e) = state::store_etag(&packs_etag_path_c, &etag) {
                                            tracing::warn!(error = ?e, "store rule-packs etag failed");
                                        }
                                    }
                                    Ok(resp) => {
                                        tracing::warn!(?resp, "agent did not accept rule packs; not caching etag");
                                    }
                                    Err(e) => {
                                        tracing::warn!(error = ?e, "apply_rule_packs IPC failed");
                                    }
                                }
                            }
                            Some(PollOutcome::Unmodified) => {}
                            Some(PollOutcome::HostUnknown) => {
                                let evt = local_event(&host_id, Evidence::HostIdConflict { observed_status: 404 });
                                let _ = dead_letter::append(&dead_letter_dir, &evt);
                            }
                            Some(PollOutcome::TlsFailure(reason)) => {
                                let evt = local_event(&host_id, Evidence::TlsFailure { reason });
                                let _ = dead_letter::append(&dead_letter_dir, &evt);
                            }
                            Some(PollOutcome::Network(reason)) => {
                                tracing::warn!(reason = %reason, "policy poll network failure");
                            }
                            Some(PollOutcome::ProtocolViolation(detail)) => {
                                let evt = local_event(&host_id, Evidence::ServerProtocolViolation { detail });
                                let _ = dead_letter::append(&dead_letter_dir, &evt);
                            }
                            None => break,
                        }
                    }
                }
            }
        }
    });

    let data = tokio::spawn({
        let stats_c = stats.clone();
        let cancel_d = ctx.shutdown.clone();
        let cfg_c = ctx.config.clone();
        let host_id = ctx.host_id.clone();
        let agent_version = ctx.agent_version.clone();
        let sender_version = ctx.sender_version.clone();
        async move {
            data_task::run(DataTaskCtx {
                client,
                config: cfg_c,
                host_id,
                agent_version,
                sender_version,
                stats: stats_c,
                shutdown: cancel_d,
            })
            .await;
        }
    });

    let _ = tokio::join!(control, reader, data);
    Ok(())
}

/// Convention: `policy-etag.txt` lives next to `sender-offset.json`
/// in the sender's persistent state dir.
fn etag_path_for(offset_path: &std::path::Path) -> PathBuf {
    let parent = offset_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    parent.join("policy-etag.txt")
}

/// Convention: `rule-packs-etag.txt` lives next to `sender-offset.json`,
/// alongside `policy-etag.txt`. Kept separate so rule packs and policy are
/// versioned independently.
fn packs_etag_path_for(offset_path: &std::path::Path) -> PathBuf {
    let parent = offset_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    parent.join("rule-packs-etag.txt")
}
