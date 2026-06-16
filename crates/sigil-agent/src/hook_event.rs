//! Cross-platform hook event-conversion helpers (#162). Shared by the one-way
//! `hook_listener` (Unix socket) and the two-way `hook_decide_listener` (Unix
//! socket on Unix, named pipe on Windows). Kept transport-agnostic and free of
//! Unix-only dependencies so the Windows decide path can build it without the
//! Unix-socket listener module.

use sigil_core::event::{
    Evidence, HookInvocationEvidence, Severity, SourceKind, Subject, AGENT_VERSION, SCHEMA_VERSION,
};
use sigil_core::hook_proto::{HookAction, HookEnvelope};

/// Convert a decoded one-way `HookEnvelope` + kernel-verified `peer_uid` into a
/// `HookInvocation` Event for the sink pipeline.
pub(crate) fn to_event(
    env: HookEnvelope,
    peer_uid: u32,
    host_id: &str,
) -> sigil_core::event::Event {
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
pub(crate) fn enum_str<T: serde::Serialize>(v: &T) -> String {
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
