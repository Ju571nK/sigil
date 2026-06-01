use super::HookAdapter;
use crate::redact::capture;
use sigil_core::event::AiTool;
use sigil_core::hook_proto::*;

pub struct ClaudeCode;

impl HookAdapter for ClaudeCode {
    fn agent(&self) -> AiTool {
        AiTool::ClaudeCode
    }

    fn normalize(
        &self,
        p: &serde_json::Value,
        level: CaptureLevel,
    ) -> Result<HookInvocation, CaptureStatus> {
        let tool = p
            .get("tool_name")
            .and_then(|v| v.as_str())
            .ok_or(CaptureStatus::Malformed)?;
        let input = p
            .get("tool_input")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let action = if tool == "Bash" {
            let cmd = input.get("command").and_then(|v| v.as_str()).unwrap_or("");
            let c = capture(cmd, level);
            HookAction::Bash {
                command_hash: c.hash,
                command_preview: c.preview,
            }
        } else if let Some(rest) = tool.strip_prefix("mcp__") {
            let mut it = rest.splitn(2, "__");
            let server = it.next().unwrap_or("").to_string();
            let mcp_tool = it.next().unwrap_or("").to_string();
            let args = serde_json::to_string(&input).unwrap_or_default();
            let c = capture(&args, level);
            HookAction::McpCall {
                server,
                tool: mcp_tool,
                args_hash: c.hash,
                args_preview: c.preview,
            }
        } else if matches!(tool, "Edit" | "Write" | "MultiEdit") {
            let path = input
                .get("file_path")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let c = capture(path, level);
            HookAction::FileEdit {
                path_hash: c.hash,
                path_preview: c.preview,
                edit_hash: None,
            }
        } else {
            let detail = serde_json::to_string(&input).unwrap_or_default();
            let c = capture(&detail, level);
            HookAction::Other {
                label: tool.to_string(),
                detail_hash: c.hash,
                detail_preview: c.preview,
            }
        };
        Ok(HookInvocation {
            agent: AiTool::ClaudeCode,
            agent_session_id: p
                .get("session_id")
                .and_then(|v| v.as_str())
                .map(String::from),
            tool_use_id: p
                .get("tool_use_id")
                .and_then(|v| v.as_str())
                .map(String::from),
            action,
            capture_level: level,
            capture_status: CaptureStatus::Ok,
            cwd: p.get("cwd").and_then(|v| v.as_str()).map(String::from),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigil_core::hook_proto::{CaptureLevel, HookAction};

    fn bash_payload() -> serde_json::Value {
        serde_json::json!({
            "session_id":"s1","tool_use_id":"t1","cwd":"/repo",
            "tool_name":"Bash","tool_input":{"command":"rm -rf build"}
        })
    }

    #[test]
    fn normalizes_bash() {
        let inv = ClaudeCode
            .normalize(&bash_payload(), CaptureLevel::Redacted)
            .unwrap();
        assert_eq!(inv.agent_session_id.as_deref(), Some("s1"));
        match inv.action {
            HookAction::Bash {
                command_preview, ..
            } => assert_eq!(command_preview.unwrap(), "rm -rf build"),
            _ => panic!(),
        }
    }

    #[test]
    fn normalizes_mcp_tool_name() {
        let p =
            serde_json::json!({"tool_name":"mcp__github__create_issue","tool_input":{"title":"x"}});
        match ClaudeCode
            .normalize(&p, CaptureLevel::Redacted)
            .unwrap()
            .action
        {
            HookAction::McpCall { server, tool, .. } => {
                assert_eq!(server, "github");
                assert_eq!(tool, "create_issue");
            }
            _ => panic!(),
        }
    }

    #[test]
    fn unknown_tool_becomes_other() {
        let p = serde_json::json!({"tool_name":"WebFetch","tool_input":{"url":"x"}});
        assert!(matches!(
            ClaudeCode
                .normalize(&p, CaptureLevel::Redacted)
                .unwrap()
                .action,
            HookAction::Other { .. }
        ));
    }
}
