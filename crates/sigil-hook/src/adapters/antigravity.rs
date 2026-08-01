use super::{allow_tool_deny, DenyOutput, HookAdapter};
use crate::redact::capture;
use sigil_core::event::AiTool;
use sigil_core::hook_proto::*;

/// Antigravity (Google `agy`) `PreToolUse` hook.
///
/// Payload shape hardware-verified on agy 1.1.7 (#202) — it is NOT the Claude
/// shape this adapter previously assumed. The call is nested under `toolCall`
/// and its arguments use PascalCase keys:
///
/// ```json
/// {"conversationId":"…","modelName":"…","stepIdx":3,
///  "toolCall":{"name":"run_command","args":{"CommandLine":"echo hi","Cwd":"/x"}},
///  "transcriptPath":"…","workspacePaths":[]}
/// ```
///
/// There is no `hook_event_name`, no `session_id`, and no top-level `cwd`; the
/// session is `conversationId` and the working directory rides in the tool's
/// own arguments.
///
/// Deny is `{"allow_tool": false, "deny_reason": "…"}` with exit 0. agy is
/// **fail-open** — an empty stdout, an explicit allow, and a non-zero exit all
/// let the call through — so the deny must always be emitted explicitly and
/// never expressed through the exit code.
///
/// The legacy flat Claude-shaped keys are still accepted as a fallback. They
/// were this adapter's original assumption and cost little to keep, but no
/// agy version has been observed emitting them.
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
        // Verified 1.1.7 shape first; the flat Claude-shaped keys are the
        // legacy fallback.
        let call = p.get("toolCall");
        let tool = call
            .and_then(|c| c.get("name"))
            .or_else(|| p.get("tool_name"))
            .and_then(|v| v.as_str())
            .ok_or(CaptureStatus::Malformed)?;
        let input = call
            .and_then(|c| c.get("args"))
            .or_else(|| p.get("tool_input"))
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        // agy names the command `CommandLine`; the legacy shape used `command`.
        let command = input
            .get("CommandLine")
            .or_else(|| input.get("command"))
            .and_then(|v| v.as_str());
        let file_path = input
            .get("FilePath")
            .or_else(|| input.get("file_path"))
            .and_then(|v| v.as_str());

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
        } else if tool == "run_command"
            || tool == "Bash"
            || tool == "run_shell_command"
            || command.is_some()
        {
            let c = capture(command.unwrap_or(""), level);
            HookAction::Bash {
                command_hash: c.hash,
                command_preview: c.preview,
            }
        } else if matches!(
            tool,
            "Edit" | "Write" | "MultiEdit" | "write_file" | "replace"
        ) || file_path.is_some()
        {
            let path = file_path.unwrap_or(tool);
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
                .get("conversationId")
                .or_else(|| p.get("session_id"))
                .and_then(|v| v.as_str())
                .map(String::from),
            // agy carries no per-call id; `stepIdx` is the only ordinal in the
            // payload and is not stable across conversations, so it is not
            // presented as one.
            tool_use_id: p
                .get("tool_use_id")
                .and_then(|v| v.as_str())
                .map(String::from),
            action,
            capture_level: level,
            capture_status: CaptureStatus::Ok,
            // No top-level `cwd`; the working directory rides in the tool args.
            cwd: input
                .get("Cwd")
                .or_else(|| p.get("cwd"))
                .and_then(|v| v.as_str())
                .map(String::from),
        })
    }

    fn deny_output(&self, rule_id: &str, reason: &str) -> DenyOutput {
        allow_tool_deny(rule_id, reason)
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

    /// The exact payload agy 1.1.7 wrote to the hook's stdin (#202), captured
    /// from hardware. The adapter previously read `tool_name`/`tool_input` and
    /// would have returned `Malformed` for this.
    #[test]
    fn verified_agy_117_run_command_payload() {
        let p = serde_json::json!({
            "artifactDirectoryPath": "/h/.gemini/antigravity-cli/brain/bcc552c5",
            "conversationId": "bcc552c5-cac5-4512-97df-fbf89966a516",
            "modelName": "gemini-3.6-flash-high",
            "stepIdx": 3,
            "toolCall": {
                "name": "run_command",
                "args": {
                    "CommandLine": "echo SIGIL_PROBE_MARKER",
                    "Cwd": "/h/.gemini/antigravity-cli/scratch",
                    "WaitMsBeforeAsync": 1000
                }
            },
            "transcriptPath": "/h/.../transcript_full.jsonl",
            "workspacePaths": []
        });
        let inv = Antigravity.normalize(&p, CaptureLevel::Redacted).unwrap();
        assert_eq!(inv.agent, AiTool::Antigravity);
        assert_eq!(
            inv.agent_session_id.as_deref(),
            Some("bcc552c5-cac5-4512-97df-fbf89966a516")
        );
        assert_eq!(
            inv.cwd.as_deref(),
            Some("/h/.gemini/antigravity-cli/scratch"),
            "cwd rides in the tool args, not the top level"
        );
        match inv.action {
            HookAction::Bash {
                command_preview, ..
            } => assert_eq!(command_preview.unwrap(), "echo SIGIL_PROBE_MARKER"),
            other => panic!("expected Bash, got {other:?}"),
        }
    }

    #[test]
    fn nested_unknown_tool_is_other() {
        let p = serde_json::json!({
            "toolCall": {"name": "view_file", "args": {"AbsolutePath": "/x"}}
        });
        match Antigravity
            .normalize(&p, CaptureLevel::Redacted)
            .unwrap()
            .action
        {
            HookAction::Other { label, .. } => assert_eq!(label, "view_file"),
            other => panic!("expected Other, got {other:?}"),
        }
    }

    #[test]
    fn payload_without_a_tool_name_is_malformed() {
        let p = serde_json::json!({"conversationId": "c", "toolCall": {"args": {}}});
        assert!(matches!(
            Antigravity.normalize(&p, CaptureLevel::Redacted),
            Err(CaptureStatus::Malformed)
        ));
    }

    /// agy is fail-open, so the deny must be explicit and must not be
    /// expressed through the exit code.
    #[test]
    fn deny_is_allow_tool_false_with_exit_zero() {
        let out = Antigravity.deny_output("no-rm", "destructive");
        assert_eq!(out.exit_code, 0);
        let v: serde_json::Value =
            serde_json::from_str(&out.stdout.expect("deny prints stdout")).unwrap();
        assert_eq!(v["allow_tool"], false);
        assert_eq!(v["deny_reason"], "Blocked by Sigil rule no-rm: destructive");
        // Not any of the other agents' spellings.
        assert!(v["permission"].is_null(), "{v}");
        assert!(v["decision"].is_null(), "{v}");
        assert!(v["hookSpecificOutput"].is_null(), "{v}");
    }
}
