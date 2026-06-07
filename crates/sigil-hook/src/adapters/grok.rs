use super::{decision_deny, DenyOutput, HookAdapter};
use crate::redact::capture;
use sigil_core::event::AiTool;
use sigil_core::hook_proto::*;

/// Grok Build PreToolUse hook. camelCase JSON (`toolName`/`toolInput`,
/// `hookEventName:"pre_tool_use"`). Only the verified shell tool
/// (`toolName == "run_terminal_command"`; command read from `toolInput.command`)
/// maps to `Bash`; every other tool is `Other` until its payload is
/// hardware-verified. Deny is Grok-style `{"decision":"deny"}`.
pub struct Grok;

impl HookAdapter for Grok {
    fn agent(&self) -> AiTool {
        AiTool::Grok
    }

    fn normalize(
        &self,
        p: &serde_json::Value,
        level: CaptureLevel,
    ) -> Result<HookInvocation, CaptureStatus> {
        let tool = p
            .get("toolName")
            .and_then(|v| v.as_str())
            .ok_or(CaptureStatus::Malformed)?;
        let input = p
            .get("toolInput")
            .cloned()
            .unwrap_or(serde_json::Value::Null);

        let action = if tool == "run_terminal_command" {
            let cmd = input.get("command").and_then(|v| v.as_str()).unwrap_or("");
            let c = capture(cmd, level);
            HookAction::Bash {
                command_hash: c.hash,
                command_preview: c.preview,
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
            agent: AiTool::Grok,
            agent_session_id: p
                .get("sessionId")
                .and_then(|v| v.as_str())
                .map(String::from),
            tool_use_id: p
                .get("toolUseId")
                .and_then(|v| v.as_str())
                .map(String::from),
            action,
            capture_level: level,
            capture_status: CaptureStatus::Ok,
            cwd: p.get("cwd").and_then(|v| v.as_str()).map(String::from),
        })
    }

    fn deny_output(&self, rule_id: &str, reason: &str) -> DenyOutput {
        decision_deny(rule_id, reason)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigil_core::hook_proto::{CaptureLevel, HookAction};

    fn payload(tool: &str, input: serde_json::Value) -> serde_json::Value {
        serde_json::json!({ "hookEventName":"pre_tool_use", "toolName": tool,
            "toolInput": input, "sessionId":"s", "cwd":"/x" })
    }

    #[test]
    fn normalize_run_terminal_command_is_bash() {
        let p = payload(
            "run_terminal_command",
            serde_json::json!({"command":"echo hi"}),
        );
        let inv = Grok.normalize(&p, CaptureLevel::Redacted).unwrap();
        assert_eq!(inv.agent, AiTool::Grok);
        assert!(matches!(inv.action, HookAction::Bash { .. }));
    }

    #[test]
    fn normalize_read_file_is_other_not_fileedit() {
        let p = payload("read_file", serde_json::json!({"path":"/etc/hosts"}));
        let inv = Grok.normalize(&p, CaptureLevel::Redacted).unwrap();
        match inv.action {
            HookAction::Other { label, .. } => assert_eq!(label, "read_file"),
            other => panic!("expected Other, got {other:?}"),
        }
    }

    #[test]
    fn missing_tool_name_is_malformed() {
        let p = serde_json::json!({ "hookEventName":"pre_tool_use", "toolInput":{"command":"x"} });
        assert_eq!(
            Grok.normalize(&p, CaptureLevel::Redacted).unwrap_err(),
            CaptureStatus::Malformed
        );
    }

    #[test]
    fn grok_deny_output_is_decision_deny() {
        assert_eq!(
            Grok.deny_output("no-rm", "x").stdout,
            crate::adapters::decision_deny("no-rm", "x").stdout
        );
    }
}
