use sigil_core::event::AiTool;
use sigil_core::hook_proto::{CaptureLevel, CaptureStatus, HookInvocation};
pub mod antigravity;
pub mod claude_code;
pub mod codex;
pub mod cursor;
pub mod grok;

/// What a deny verdict renders to for a given agent: the text to print (the
/// deny response, if any) and the process exit code. claude-code/codex/
/// antigravity: the JSON rides stdout with exit 0; the exit_code field lets a
/// future agent whose deny path needs a non-zero exit express that.
pub struct DenyOutput {
    pub stdout: Option<String>,
    pub exit_code: i32,
}

/// Shared PreToolUse deny: `{"hookSpecificOutput":{"hookEventName":"PreToolUse",
/// "permissionDecision":"deny","permissionDecisionReason":"Blocked by Sigil rule
/// <id>: <reason>"}}` on stdout, exit 0. Used by every Claude-shaped agent.
pub(crate) fn pretooluse_deny(rule_id: &str, reason: &str) -> DenyOutput {
    let v = serde_json::json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": format!("Blocked by Sigil rule {rule_id}: {reason}")
        }
    });
    DenyOutput {
        stdout: Some(v.to_string()),
        exit_code: 0,
    }
}

/// Grok-shaped deny: `{"decision":"deny","reason":"…"}` on stdout, exit 0.
/// Grok honors the deny decision regardless of exit code. (Cursor uses a
/// different `permission`-keyed shape — see `permission_deny`.)
pub(crate) fn decision_deny(rule_id: &str, reason: &str) -> DenyOutput {
    let v = serde_json::json!({
        "decision": "deny",
        "reason": format!("Blocked by Sigil rule {rule_id}: {reason}"),
    });
    DenyOutput {
        stdout: Some(v.to_string()),
        exit_code: 0,
    }
}

/// Cursor-shaped deny: `{"permission":"deny","agent_message":"…","user_message":"…"}`
/// on stdout, exit 0. Cursor's `beforeShellExecution`/`beforeMCPExecution` honor a
/// stdout `permission` field on exit 0 (verified against its bundled hook skill).
/// Distinct from Grok's `decision_deny` — different field name.
pub(crate) fn permission_deny(rule_id: &str, reason: &str) -> DenyOutput {
    let msg = format!("Blocked by Sigil rule {rule_id}: {reason}");
    let v = serde_json::json!({
        "permission": "deny",
        "agent_message": msg,
        "user_message": msg,
    });
    DenyOutput {
        stdout: Some(v.to_string()),
        exit_code: 0,
    }
}

/// One impl per agent. Turns a vendor stdin payload into a normalized
/// HookInvocation. (Shape mirrors ai_guard/parser, but is a distinct trait —
/// that one assesses on-disk config, this one normalizes runtime stdin.)
pub trait HookAdapter {
    fn agent(&self) -> AiTool;
    fn normalize(
        &self,
        payload: &serde_json::Value,
        level: CaptureLevel,
    ) -> Result<HookInvocation, CaptureStatus>;
    /// Translate a Deny verdict into this agent's deny-UX wire output. Default =
    /// the shared PreToolUse permissionDecision JSON; override only when an
    /// agent's deny contract differs.
    fn deny_output(&self, rule_id: &str, reason: &str) -> DenyOutput {
        pretooluse_deny(rule_id, reason)
    }
}

pub fn for_agent(name: &str) -> Option<Box<dyn HookAdapter>> {
    match name {
        "claude-code" => Some(Box::new(claude_code::ClaudeCode)),
        "codex" => Some(Box::new(codex::Codex)),
        "cursor" => Some(Box::new(cursor::Cursor)),
        "antigravity" => Some(Box::new(antigravity::Antigravity)),
        "grok" => Some(Box::new(grok::Grok)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pretooluse_deny_exact_json_and_exit0() {
        let out = pretooluse_deny("no-rm", "destructive");
        assert_eq!(out.exit_code, 0);
        let s = out.stdout.expect("deny prints stdout");
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["hookSpecificOutput"]["hookEventName"], "PreToolUse");
        assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");
        assert_eq!(
            v["hookSpecificOutput"]["permissionDecisionReason"],
            "Blocked by Sigil rule no-rm: destructive"
        );
    }

    #[test]
    fn adapter_default_deny_output_is_pretooluse() {
        // ClaudeCode uses the default trait impl => identical to pretooluse_deny.
        let a = claude_code::ClaudeCode;
        assert_eq!(
            a.deny_output("no-rm", "destructive").stdout,
            pretooluse_deny("no-rm", "destructive").stdout
        );
    }

    #[test]
    fn decision_deny_exact_json_and_exit0() {
        let out = decision_deny("no-rm", "destructive");
        assert_eq!(out.exit_code, 0);
        let s = out.stdout.expect("deny prints stdout");
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["decision"], "deny");
        assert_eq!(v["reason"], "Blocked by Sigil rule no-rm: destructive");
    }

    #[test]
    fn permission_deny_exact_json_and_exit0() {
        let out = permission_deny("no-rm", "destructive");
        assert_eq!(out.exit_code, 0);
        let s = out.stdout.expect("deny prints stdout");
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["permission"], "deny");
        assert_eq!(
            v["agent_message"],
            "Blocked by Sigil rule no-rm: destructive"
        );
        assert_eq!(
            v["user_message"],
            "Blocked by Sigil rule no-rm: destructive"
        );
    }
}
