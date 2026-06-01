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
    // 4-tuple: (kind, hash, preview, other_label)
    // other_label is Some(tool_name) only for the Other arm, None for all others.
    let (kind, hash, preview, other_label) = match &inv.action {
        HookAction::Bash {
            command_hash,
            command_preview,
        } => ("bash", command_hash.clone(), command_preview.clone(), None),
        HookAction::FileEdit {
            path_hash,
            path_preview,
            ..
        } => ("file_edit", path_hash.clone(), path_preview.clone(), None),
        HookAction::McpCall {
            args_hash,
            args_preview,
            ..
        } => ("mcp_call", args_hash.clone(), args_preview.clone(), None),
        HookAction::Other {
            label,
            detail_hash,
            detail_preview,
        } => (
            "other",
            detail_hash.clone(),
            detail_preview.clone(),
            Some(label.clone()),
        ),
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
            other_label,
            action_hash: hash,
            action_preview: preview,
            capture_level: enum_str(&inv.capture_level),
            capture_status: enum_str(&inv.capture_status),
        }),
        target_id: None,
    }
}

/// Serialize a `rename_all = "snake_case"` enum to its wire string. The
/// persisted evidence schema must match the serde wire form exactly
/// (`"hash_only"`, `"unsupported_agent_schema"`, …), NOT the Rust Debug form.
/// Falls back to an empty string if the value somehow isn't a JSON string.
fn enum_str<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|j| j.as_str().map(String::from))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigil_core::hook_proto::{
        CaptureLevel, CaptureStatus, HookInvocation, HookMsgType, HOOK_PROTOCOL_VERSION,
    };

    fn envelope_with(level: CaptureLevel, status: CaptureStatus) -> HookEnvelope {
        HookEnvelope {
            protocol_version: HOOK_PROTOCOL_VERSION,
            msg_type: HookMsgType::HookInvocation,
            request_id: uuid::Uuid::now_v7(),
            sent_at_unix_ms: 1_700_000_000_000,
            payload: HookInvocation {
                agent: sigil_core::event::AiTool::ClaudeCode,
                agent_session_id: None,
                tool_use_id: None,
                action: HookAction::Bash {
                    command_hash: "ab".repeat(32),
                    command_preview: None,
                },
                capture_level: level,
                capture_status: status,
                cwd: None,
            },
        }
    }

    #[test]
    fn enum_str_yields_snake_case_wire_strings() {
        assert_eq!(enum_str(&CaptureLevel::HashOnly), "hash_only");
        assert_eq!(enum_str(&CaptureLevel::Redacted), "redacted");
        assert_eq!(enum_str(&CaptureLevel::Raw), "raw");
        assert_eq!(
            enum_str(&CaptureStatus::UnsupportedAgentSchema),
            "unsupported_agent_schema"
        );
        assert_eq!(enum_str(&CaptureStatus::Ok), "ok");
        assert_eq!(
            enum_str(&CaptureStatus::RedactionFailed),
            "redaction_failed"
        );
    }

    #[test]
    fn to_event_persists_snake_case_capture_fields() {
        let env = envelope_with(
            CaptureLevel::HashOnly,
            CaptureStatus::UnsupportedAgentSchema,
        );
        let ev = to_event(env, 1000, "host-x");
        match ev.evidence {
            Evidence::HookInvocation(h) => {
                assert_eq!(h.capture_level, "hash_only");
                assert_eq!(h.capture_status, "unsupported_agent_schema");
                assert_eq!(h.action_kind, "bash");
                assert_eq!(h.peer_uid, 1000);
                assert_eq!(h.other_label, None, "bash action must not set other_label");
            }
            other => panic!("expected HookInvocation, got {other:?}"),
        }
    }

    #[test]
    fn to_event_persists_other_label_for_other_action() {
        // I2: HookAction::Other carries the tool name; it must persist in
        // HookInvocationEvidence.other_label so operators can filter by tool.
        let env = HookEnvelope {
            protocol_version: HOOK_PROTOCOL_VERSION,
            msg_type: HookMsgType::HookInvocation,
            request_id: uuid::Uuid::now_v7(),
            sent_at_unix_ms: 1_700_000_000_000,
            payload: HookInvocation {
                agent: sigil_core::event::AiTool::ClaudeCode,
                agent_session_id: None,
                tool_use_id: None,
                action: HookAction::Other {
                    label: "WebFetch".into(),
                    detail_hash: "ab".repeat(32),
                    detail_preview: None,
                },
                capture_level: CaptureLevel::Redacted,
                capture_status: CaptureStatus::Ok,
                cwd: None,
            },
        };
        let ev = to_event(env, 501, "host-y");
        match ev.evidence {
            Evidence::HookInvocation(h) => {
                assert_eq!(h.action_kind, "other");
                assert_eq!(
                    h.other_label,
                    Some("WebFetch".into()),
                    "other_label must carry the tool name"
                );
            }
            other => panic!("expected HookInvocation, got {other:?}"),
        }
    }
}
