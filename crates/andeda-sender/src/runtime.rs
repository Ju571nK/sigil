//! Top-level supervisor.
//!
//! Currently spawns: control_task (policy poller) + a reader task that
//! hands `NewPolicy` outcomes to the agent via apply_policy IPC.
//!
//! NOT YET WIRED (Plan B follow-up):
//! - data_task loop (read JSONL → send_one_batch → apply_ack → state::store)
//! - dead_letter::append for EventsAccepted::rejected[]
//! - state::store_etag on agent ACK
//! - SharedStats updates for heartbeat backpressure fields
//! - Local event emission for HostUnknown/TlsFailure/Network/ProtocolViolation

use crate::config::SenderConfig;
use crate::control_task::{ControlLoopCtx, PollOutcome};
use crate::transport::build_client;
use anyhow::Result;
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
    let client = build_client(
        &ctx.config.client_cert_path,
        &ctx.config.client_key_path,
        &ctx.config.server_ca_path,
    )?;
    let (poll_tx, mut poll_rx) = mpsc::channel::<PollOutcome>(8);
    let cancel_c = ctx.shutdown.clone();
    let client_c = client.clone();
    let cfg_c = ctx.config.clone();
    let host_id_c = ctx.host_id.clone();
    let control = tokio::spawn(async move {
        crate::control_task::run(ControlLoopCtx {
            client: client_c,
            server_base_url: cfg_c.server_base_url.clone(),
            host_id: host_id_c,
            poll_interval: cfg_c.policy_poll_interval,
            shutdown: cancel_c,
            outcomes: poll_tx,
        })
        .await;
    });

    // Reader: handle each PollOutcome (apply_policy IPC handoff handled here).
    let agent_socket = ctx.config.agent_control.clone();
    let cancel_r = ctx.shutdown.clone();
    let reader = tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                _ = cancel_r.cancelled() => break,
                maybe = poll_rx.recv() => {
                    match maybe {
                        Some(PollOutcome::NewPolicy { response, .. }) => {
                            if let Err(e) = crate::agent_ipc::apply_policy(&agent_socket, &response).await {
                                tracing::warn!(error = ?e, "apply_policy IPC failed");
                            }
                        }
                        Some(_) => {}
                        None => break,
                    }
                }
            }
        }
    });

    let _ = tokio::join!(control, reader);
    Ok(())
}
