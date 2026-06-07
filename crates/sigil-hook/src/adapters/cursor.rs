use super::{permission_deny, DenyOutput, HookAdapter};
use crate::redact::capture;
use sigil_core::event::AiTool;
use sigil_core::hook_proto::*;

/// Cursor hooks. Unlike the Claude-shaped agents, Cursor fires a *distinct
/// event per tool class* (`beforeShellExecution`, `beforeMCPExecution`) rather
/// than one `PreToolUse` with a `tool_name`, so this adapter dispatches on
/// `hook_event_name`. Shell puts the command at the top level (`command`); MCP
/// carries `tool_name` + `tool_input` + a server location (`url` or `command`).
/// Ids: `conversation_id` (session) and `generation_id` (per-call).
pub struct Cursor;

impl HookAdapter for Cursor {
    fn agent(&self) -> AiTool {
        AiTool::Cursor
    }

    fn normalize(
        &self,
        p: &serde_json::Value,
        level: CaptureLevel,
    ) -> Result<HookInvocation, CaptureStatus> {
        let event = p
            .get("hook_event_name")
            .and_then(|v| v.as_str())
            .ok_or(CaptureStatus::Malformed)?;

        let action = match event {
            "beforeShellExecution" => {
                let cmd = p.get("command").and_then(|v| v.as_str()).unwrap_or("");
                let c = capture(cmd, level);
                HookAction::Bash {
                    command_hash: c.hash,
                    command_preview: c.preview,
                }
            }
            "beforeMCPExecution" => {
                let tool = p
                    .get("tool_name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                // Server location is `url` (remote) or `command` (stdio).
                let server = p
                    .get("url")
                    .and_then(|v| v.as_str())
                    .or_else(|| p.get("command").and_then(|v| v.as_str()))
                    .unwrap_or("")
                    .to_string();
                let args = p
                    .get("tool_input")
                    .map(|v| v.to_string())
                    .unwrap_or_default();
                let c = capture(&args, level);
                HookAction::McpCall {
                    server,
                    tool,
                    args_hash: c.hash,
                    args_preview: c.preview,
                }
            }
            other => {
                let detail = p
                    .get("tool_input")
                    .map(|v| v.to_string())
                    .or_else(|| p.get("command").and_then(|v| v.as_str()).map(String::from))
                    .unwrap_or_default();
                let c = capture(&detail, level);
                HookAction::Other {
                    label: other.to_string(),
                    detail_hash: c.hash,
                    detail_preview: c.preview,
                }
            }
        };

        Ok(HookInvocation {
            agent: AiTool::Cursor,
            agent_session_id: p
                .get("conversation_id")
                .and_then(|v| v.as_str())
                .map(String::from),
            tool_use_id: p
                .get("generation_id")
                .and_then(|v| v.as_str())
                .map(String::from),
            action,
            capture_level: level,
            capture_status: CaptureStatus::Ok,
            cwd: p.get("cwd").and_then(|v| v.as_str()).map(String::from),
        })
    }

    /// Cursor blocks via a stdout `{"permission":"deny", …}` on exit 0 — not the
    /// default Claude PreToolUse JSON.
    fn deny_output(&self, rule_id: &str, reason: &str) -> DenyOutput {
        permission_deny(rule_id, reason)
    }

    /// Cursor blocks empty-stdout allows under `failClosed`, so emit an explicit
    /// allow. (See `allow_output` on the trait.)
    fn allow_output(&self) -> Option<String> {
        Some(serde_json::json!({ "permission": "allow" }).to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_execution_is_bash() {
        let p = serde_json::json!({
            "hook_event_name":"beforeShellExecution",
            "conversation_id":"c1","generation_id":"g1","cwd":"/repo",
            "command":"rm -rf build"
        });
        let inv = Cursor.normalize(&p, CaptureLevel::Redacted).unwrap();
        assert_eq!(inv.agent, AiTool::Cursor);
        assert_eq!(inv.agent_session_id.as_deref(), Some("c1"));
        assert_eq!(inv.tool_use_id.as_deref(), Some("g1"));
        match inv.action {
            HookAction::Bash {
                command_preview, ..
            } => assert_eq!(command_preview.unwrap(), "rm -rf build"),
            _ => panic!("expected Bash"),
        }
    }

    #[test]
    fn mcp_execution_is_mcp_call() {
        let p = serde_json::json!({
            "hook_event_name":"beforeMCPExecution",
            "conversation_id":"c1",
            "tool_name":"create_issue","tool_input":{"title":"x"},
            "url":"https://mcp.github.example"
        });
        match Cursor.normalize(&p, CaptureLevel::Redacted).unwrap().action {
            HookAction::McpCall { server, tool, .. } => {
                assert_eq!(tool, "create_issue");
                assert_eq!(server, "https://mcp.github.example");
            }
            _ => panic!("expected McpCall"),
        }
    }

    #[test]
    fn unknown_event_is_other() {
        let p = serde_json::json!({"hook_event_name":"afterFileEdit","tool_input":{"path":"x"}});
        match Cursor.normalize(&p, CaptureLevel::Redacted).unwrap().action {
            HookAction::Other { label, .. } => assert_eq!(label, "afterFileEdit"),
            _ => panic!("expected Other"),
        }
    }

    #[test]
    fn missing_event_name_is_malformed() {
        let p = serde_json::json!({"command":"ls"});
        assert_eq!(
            Cursor.normalize(&p, CaptureLevel::Redacted).unwrap_err(),
            CaptureStatus::Malformed
        );
    }

    #[test]
    fn deny_output_is_permission_deny() {
        let out = Cursor.deny_output("no-rm", "destructive");
        assert_eq!(out.exit_code, 0);
        let s = out.stdout.expect("deny prints stdout");
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["permission"], "deny");
        assert_eq!(
            v["agent_message"],
            "Blocked by Sigil rule no-rm: destructive"
        );
        // NOT the default Claude PreToolUse shape
        assert!(v.get("hookSpecificOutput").is_none());
    }

    #[test]
    fn allow_output_is_permission_allow() {
        let s = Cursor.allow_output().expect("cursor emits explicit allow");
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["permission"], "allow");
    }
}
