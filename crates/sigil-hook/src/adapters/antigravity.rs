use super::HookAdapter;
use crate::redact::capture;
use sigil_core::event::AiTool;
use sigil_core::hook_proto::*;

/// Antigravity (Google) — successor to Gemini CLI (sunset 2026-06-18). Its
/// `PreToolUse` hook adopts the Claude Code payload shape
/// (`session_id` / `cwd` / `tool_name` / `tool_input` / `tool_use_id`,
/// `hook_event_name: "PreToolUse"`), so this mirrors the Claude adapter — but we
/// also defensively handle Gemini-carryover tool names
/// (`run_shell_command` / `write_file` / `replace`) in case Antigravity still
/// emits any of them. Unknown tools degrade to `Other { label }`.
pub struct Antigravity;

impl HookAdapter for Antigravity {
    fn agent(&self) -> AiTool {
        AiTool::Antigravity
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

        let action = if let Some(rest) = tool.strip_prefix("mcp__") {
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
        } else if tool == "Bash" || tool == "run_shell_command" || input.get("command").is_some() {
            let cmd = input.get("command").and_then(|v| v.as_str()).unwrap_or("");
            let c = capture(cmd, level);
            HookAction::Bash {
                command_hash: c.hash,
                command_preview: c.preview,
            }
        } else if matches!(
            tool,
            "Edit" | "Write" | "MultiEdit" | "write_file" | "replace"
        ) || input.get("file_path").is_some()
        {
            let path = input
                .get("file_path")
                .and_then(|v| v.as_str())
                .unwrap_or(tool);
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
            agent: AiTool::Antigravity,
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

    #[test]
    fn claude_style_bash() {
        let p = serde_json::json!({
            "session_id":"s1","tool_use_id":"t1","cwd":"/repo",
            "hook_event_name":"PreToolUse",
            "tool_name":"Bash","tool_input":{"command":"npm test"}
        });
        let inv = Antigravity.normalize(&p, CaptureLevel::Redacted).unwrap();
        assert_eq!(inv.agent, AiTool::Antigravity);
        assert_eq!(inv.agent_session_id.as_deref(), Some("s1"));
        match inv.action {
            HookAction::Bash {
                command_preview, ..
            } => assert_eq!(command_preview.unwrap(), "npm test"),
            _ => panic!("expected Bash"),
        }
    }

    #[test]
    fn gemini_carryover_run_shell_command_is_bash() {
        let p = serde_json::json!({
            "tool_name":"run_shell_command","tool_input":{"command":"ls -la"}
        });
        assert!(matches!(
            Antigravity
                .normalize(&p, CaptureLevel::Redacted)
                .unwrap()
                .action,
            HookAction::Bash { .. }
        ));
    }

    #[test]
    fn edit_is_file_edit() {
        let p = serde_json::json!({
            "tool_name":"Edit","tool_input":{"file_path":"/repo/src/main.rs","old_string":"a","new_string":"b"}
        });
        match Antigravity
            .normalize(&p, CaptureLevel::Redacted)
            .unwrap()
            .action
        {
            HookAction::FileEdit { path_hash, .. } => assert_eq!(path_hash.len(), 64),
            _ => panic!("expected FileEdit"),
        }
    }

    #[test]
    fn gemini_carryover_write_file_is_file_edit() {
        let p = serde_json::json!({
            "tool_name":"write_file","tool_input":{"file_path":"/repo/x.txt","content":"y"}
        });
        assert!(matches!(
            Antigravity
                .normalize(&p, CaptureLevel::Redacted)
                .unwrap()
                .action,
            HookAction::FileEdit { .. }
        ));
    }

    #[test]
    fn mcp_tool() {
        let p = serde_json::json!({
            "tool_name":"mcp__github__create_issue","tool_input":{"title":"x"}
        });
        match Antigravity
            .normalize(&p, CaptureLevel::Redacted)
            .unwrap()
            .action
        {
            HookAction::McpCall { server, tool, .. } => {
                assert_eq!(server, "github");
                assert_eq!(tool, "create_issue");
            }
            _ => panic!("expected McpCall"),
        }
    }

    #[test]
    fn unknown_tool_is_other() {
        let p = serde_json::json!({"tool_name":"Glob","tool_input":{"pattern":"*.rs"}});
        match Antigravity
            .normalize(&p, CaptureLevel::Redacted)
            .unwrap()
            .action
        {
            HookAction::Other { label, .. } => assert_eq!(label, "Glob"),
            _ => panic!("expected Other"),
        }
    }
}
