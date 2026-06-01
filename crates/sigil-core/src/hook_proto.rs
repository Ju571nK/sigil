//! Wire protocol for the one-way hook IPC socket (`hook.sock`). Shared by
//! `sigil-hook` (emitter) and `sigil-agent` (listener). Types only — no I/O.
//! Distinct from `control_proto` (operator API) by design: a high-frequency,
//! multi-agent, latency-sensitive emit path must not share the operator socket.
use crate::event::AiTool;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Hook IPC protocol version. Bump on any breaking wire change.
pub const HOOK_PROTOCOL_VERSION: u16 = 1;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum HookMsgType {
    HookInvocation,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct HookEnvelope {
    pub protocol_version: u16,
    pub msg_type: HookMsgType,
    pub request_id: Uuid,
    pub sent_at_unix_ms: u64,
    pub payload: HookInvocation,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct HookInvocation {
    pub agent: AiTool,
    pub agent_session_id: Option<String>,
    pub tool_use_id: Option<String>,
    pub action: HookAction,
    pub capture_level: CaptureLevel,
    pub capture_status: CaptureStatus,
    pub cwd: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HookAction {
    Bash {
        command_hash: String,
        command_preview: Option<String>,
    },
    FileEdit {
        path_hash: String,
        path_preview: Option<String>,
        edit_hash: Option<String>,
    },
    McpCall {
        server: String,
        tool: String,
        args_hash: String,
        args_preview: Option<String>,
    },
    Other {
        label: String,
        detail_hash: String,
        detail_preview: Option<String>,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CaptureLevel {
    Redacted,
    Raw,
    HashOnly,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CaptureStatus {
    Ok,
    Malformed,
    Oversized,
    Timeout,
    UnsupportedAgentSchema,
    RedactionFailed,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::AiTool;

    #[test]
    fn envelope_round_trips_with_bash_action() {
        let env = HookEnvelope {
            protocol_version: HOOK_PROTOCOL_VERSION,
            msg_type: HookMsgType::HookInvocation,
            request_id: uuid::Uuid::nil(),
            sent_at_unix_ms: 1_700_000_000_000,
            payload: HookInvocation {
                agent: AiTool::ClaudeCode,
                agent_session_id: Some("sess-1".into()),
                tool_use_id: Some("tu-1".into()),
                action: HookAction::Bash {
                    command_hash: "ab".repeat(32),
                    command_preview: Some("git status".into()),
                },
                capture_level: CaptureLevel::Redacted,
                capture_status: CaptureStatus::Ok,
                cwd: None,
            },
        };
        let s = serde_json::to_string(&env).unwrap();
        assert!(s.contains("\"msg_type\":\"hook_invocation\""));
        assert!(s.contains("\"kind\":\"bash\""));
        let back: HookEnvelope = serde_json::from_str(&s).unwrap();
        assert_eq!(back.protocol_version, HOOK_PROTOCOL_VERSION);
        match back.payload.action {
            HookAction::Bash { command_hash, .. } => assert_eq!(command_hash.len(), 64),
            _ => panic!("expected bash"),
        }
    }
}
