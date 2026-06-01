//! Hook IPC listener (`hook.sock`). One-way: the agent reads `HookEnvelope`
//! JSON lines from AI hook emitters (sigil-hook) and converts them to
//! `CommittableEvent` entries in the event sink. The emitter never reads a
//! response — `hook.sock` is write-only from the client's perspective.
//!
//! Security model (spec §9): DAC perms (0660) are the access gate.
//! `SO_PEERCRED` is read to stamp the kernel-verified peer uid onto the event
//! for attribution — it is NOT used to accept/reject connections.
//!
//! Concurrency: a `Semaphore` bounds inflight connections. When saturated the
//! connection is dropped BEFORE reading (never hold an fd open waiting on a
//! full sink). `try_send` is used so a full event channel never blocks the
//! listener loop.

use crate::state_task::CommittableEvent;
use sigil_core::event::{
    Evidence, HookInvocationEvidence, Severity, SourceKind, Subject, AGENT_VERSION, SCHEMA_VERSION,
};
use sigil_core::hook_proto::{HookAction, HookEnvelope};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::net::UnixListener;
use tokio::sync::{mpsc, Semaphore};

/// Maximum concurrent in-flight connections.
const MAX_INFLIGHT: usize = 32;

/// Maximum bytes read per connection before giving up (1 MiB).
const MAX_LINE: u64 = 1024 * 1024;

/// Bind `socket`, set 0o660 permissions, and start the accept loop.
///
/// Each accepted connection is handled in its own `tokio::spawn`ed task.
/// When `MAX_INFLIGHT` slots are all occupied the new connection is dropped
/// immediately without reading (a debug log records it). On parse success the
/// resulting `CommittableEvent` is sent with `try_send` — if the channel is
/// full the event is silently dropped rather than blocking.
///
/// This function runs until the tokio runtime shuts down (it does not return
/// under normal operation).
#[cfg(unix)]
pub async fn serve(
    socket: PathBuf,
    tx: mpsc::Sender<CommittableEvent>,
    host_id: String,
) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    // Remove a stale socket file from a previous run.
    if socket.exists() {
        let _ = std::fs::remove_file(&socket);
    }
    // Ensure parent directory exists.
    if let Some(p) = socket.parent() {
        std::fs::create_dir_all(p)?;
    }

    let listener = UnixListener::bind(&socket)?;
    // Set 0660 explicitly — do not rely on process umask.
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o660))?;

    let sem = Arc::new(Semaphore::new(MAX_INFLIGHT));
    tracing::info!(path = ?socket, "hook IPC listening");

    loop {
        let (stream, _) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = ?e, "hook accept failed");
                continue;
            }
        };

        // Overload check: try to acquire a permit BEFORE reading anything.
        // If the semaphore is exhausted, drop the connection without reading.
        let permit = match sem.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                tracing::debug!("hook overload: dropping connection (MAX_INFLIGHT reached)");
                drop(stream);
                continue;
            }
        };

        // Read SO_PEERCRED now, while we still own the stream. On failure
        // (e.g., abstract-namespace socket on old kernels) fall back to u32::MAX
        // so the event is still recorded with an obviously-sentinel uid.
        let peer_uid = stream.peer_cred().map(|c| c.uid()).unwrap_or(u32::MAX);

        let tx = tx.clone();
        let host_id = host_id.clone();

        tokio::spawn(async move {
            // Permit is held for the lifetime of this task.
            let _permit = permit;

            let mut line = String::new();
            // Limit bytes read to guard against a misbehaving / malicious sender
            // filling memory. `take` wraps the raw stream; BufReader sits on top.
            let mut rd = BufReader::new(stream.take(MAX_LINE));
            if rd.read_line(&mut line).await.is_err() {
                return;
            }

            let env: HookEnvelope = match serde_json::from_str(line.trim()) {
                Ok(e) => e,
                Err(e) => {
                    tracing::debug!(error = ?e, "hook: malformed envelope; dropping");
                    return;
                }
            };

            let ev = to_event(env, peer_uid, &host_id);
            let committable = CommittableEvent {
                event: ev,
                new_hash: None,
                path_for_db: PathBuf::new(),
                target_id: String::new(),
            };

            // try_send: if the channel is full (sink backpressure) we drop rather
            // than block. The listener must remain responsive to new connections.
            if tx.try_send(committable).is_err() {
                tracing::debug!("hook: event channel full; dropping hook event");
            }
        });
    }
}

/// Convert a decoded `HookEnvelope` + kernel-verified `peer_uid` into an
/// `Event` suitable for the sink pipeline.
fn to_event(env: HookEnvelope, peer_uid: u32, host_id: &str) -> sigil_core::event::Event {
    let inv = env.payload;

    // Decompose the action into normalized fields.
    let (kind, hash, preview) = match &inv.action {
        HookAction::Bash {
            command_hash,
            command_preview,
        } => ("bash", command_hash.clone(), command_preview.clone()),
        HookAction::FileEdit {
            path_hash,
            path_preview,
            ..
        } => ("file_edit", path_hash.clone(), path_preview.clone()),
        HookAction::McpCall {
            args_hash,
            args_preview,
            ..
        } => ("mcp_call", args_hash.clone(), args_preview.clone()),
        HookAction::Other {
            detail_hash,
            detail_preview,
            ..
        } => ("other", detail_hash.clone(), detail_preview.clone()),
    };

    sigil_core::event::Event {
        schema_version: SCHEMA_VERSION,
        event_id: uuid::Uuid::now_v7(),
        ts: time::OffsetDateTime::now_utc(),
        host_id: host_id.to_string(),
        agent_version: AGENT_VERSION.to_string(),
        severity: Severity::Info,
        source: SourceKind::AgentHook,
        subject: Subject::Self_,
        evidence: Evidence::HookInvocation(HookInvocationEvidence {
            agent: inv.agent,
            peer_uid,
            agent_session_id: inv.agent_session_id,
            tool_use_id: inv.tool_use_id,
            action_kind: kind.to_string(),
            action_hash: hash,
            action_preview: preview,
            capture_level: format!("{:?}", inv.capture_level).to_lowercase(),
            capture_status: format!("{:?}", inv.capture_status).to_lowercase(),
        }),
        target_id: None,
    }
}
