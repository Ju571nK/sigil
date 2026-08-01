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

/// Antigravity-shaped deny: `{"allow_tool":false,"deny_reason":"…"}` on stdout,
/// exit 0 (hardware-verified on agy 1.1.7, #202 — the reason is surfaced to the
/// model verbatim). A third distinct spelling: Grok keys on `decision`, Cursor
/// on `permission`, agy on `allow_tool`.
///
/// agy is fail-OPEN — empty stdout, an explicit allow, and a non-zero exit all
/// allow the call — so this must always be emitted and the exit code stays 0.
pub(crate) fn allow_tool_deny(rule_id: &str, reason: &str) -> DenyOutput {
    let v = serde_json::json!({
        "allow_tool": false,
        "deny_reason": format!("Blocked by Sigil rule {rule_id}: {reason}"),
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

    /// Explicit allow output for a deliberate allow, if the agent needs one.
    /// Default `None` = stay silent (claude-code/codex/grok: silence == allow).
    /// Cursor overrides: under `failClosed:true` Cursor treats empty stdout as a
    /// hook failure and BLOCKS, so a Cursor allow must be an explicit
    /// `{"permission":"allow"}` (hardware-verified). Keeping this `None` for the
    /// other agents means an empty-stdout exit there still means allow.
    fn allow_output(&self) -> Option<String> {
        None
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
    fn adapter_default_allow_output_is_none() {
        // claude-code uses the default trait impl => silent allow (None).
        assert!(claude_code::ClaudeCode.allow_output().is_none());
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
