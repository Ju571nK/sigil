use super::HookAdapter;
use crate::redact::capture;
use sigil_core::event::AiTool;
use sigil_core::hook_proto::*;

/// Codex CLI `PreToolUse` hook. Codex deliberately reuses the Claude Code hook
/// shape (`tool_name` / `tool_input` / `tool_use_id`, plus `turn_id` and a
/// Codex-only `permission_mode`), so this mirrors the Claude adapter but keys
/// shell detection on the `tool_input.command` field (Codex's shell tool is
/// `shell`/`local_shell`, not literally `Bash`) and treats `apply_patch` /
/// `file_path` inputs as file edits.
pub struct Codex;

impl HookAdapter for Codex {
    fn agent(&self) -> AiTool {
        AiTool::Codex
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
        } else if let Some(cmd) = input.get("command").and_then(|v| v.as_str()) {
            // Shell tool — keyed on the command field, not the exact tool_name.
            let c = capture(cmd, level);
            HookAction::Bash {
                command_hash: c.hash,
                command_preview: c.preview,
            }
        } else if matches!(tool, "Edit" | "Write" | "apply_patch")
            || input.get("file_path").is_some()
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
            agent: AiTool::Codex,
            // Codex provides `session_id`; fall back to `turn_id` for correlation.
            agent_session_id: p
                .get("session_id")
                .and_then(|v| v.as_str())
                .or_else(|| p.get("turn_id").and_then(|v| v.as_str()))
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
    fn normalizes_shell_command() {
        let p = serde_json::json!({
            "session_id":"s1","tool_use_id":"t1","turn_id":"turn1","cwd":"/repo",
            "tool_name":"shell","tool_input":{"command":"cargo test"}
        });
        let inv = Codex.normalize(&p, CaptureLevel::Redacted).unwrap();
        assert_eq!(inv.agent, AiTool::Codex);
        assert_eq!(inv.agent_session_id.as_deref(), Some("s1"));
        match inv.action {
            HookAction::Bash {
                command_preview, ..
            } => assert_eq!(command_preview.unwrap(), "cargo test"),
            _ => panic!("expected Bash"),
        }
    }

    #[test]
    fn falls_back_to_turn_id_for_session() {
        let p = serde_json::json!({
            "turn_id":"turn9","tool_name":"shell","tool_input":{"command":"ls"}
        });
        let inv = Codex.normalize(&p, CaptureLevel::Redacted).unwrap();
        assert_eq!(inv.agent_session_id.as_deref(), Some("turn9"));
    }

    #[test]
    fn normalizes_mcp_tool() {
        let p = serde_json::json!({
            "tool_name":"mcp__github__create_issue","tool_input":{"title":"x"}
        });
        match Codex.normalize(&p, CaptureLevel::Redacted).unwrap().action {
            HookAction::McpCall { server, tool, .. } => {
                assert_eq!(server, "github");
                assert_eq!(tool, "create_issue");
            }
            _ => panic!("expected McpCall"),
        }
    }

    #[test]
    fn apply_patch_is_file_edit() {
        let p = serde_json::json!({
            "tool_name":"apply_patch","tool_input":{"file_path":"/repo/src/lib.rs"}
        });
        assert!(matches!(
            Codex.normalize(&p, CaptureLevel::Redacted).unwrap().action,
            HookAction::FileEdit { .. }
        ));
    }

    #[test]
    fn unknown_tool_is_other() {
        let p = serde_json::json!({"tool_name":"update_plan","tool_input":{"plan":"x"}});
        match Codex.normalize(&p, CaptureLevel::Redacted).unwrap().action {
            HookAction::Other { label, .. } => assert_eq!(label, "update_plan"),
            _ => panic!("expected Other"),
        }
    }
}
