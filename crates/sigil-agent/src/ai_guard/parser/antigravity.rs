//! Antigravity (Google) parser. Antigravity is the successor to Gemini CLI
//! (Gemini CLI sunset 2026-06-18) and reuses the `~/.gemini/` config tree, but
//! with Antigravity-specific keys/paths (official docs + macOS arm64 CLI 1.2.0
//! hardware verification, 2026-09-10):
//!   - settings (user-global): `~/.gemini/antigravity-cli/settings.json`
//!   - MCP servers: `~/.gemini/config/mcp_config.json` (`mcpServers`, a separate
//!     file — unlike Gemini, MCP is not inline in settings.json)
//!   - terminal sandbox: `enableTerminalSandbox` (boolean, default false). This
//!     is the ONLY sandbox knob the settings file carries — `sandbox_mode` /
//!     `sandbox_type` / `sandbox_allow_network` are internal sandbox-subsystem
//!     struct fields, NOT CLI settings keys (hardware-verified on agy 1.0.8:
//!     writing `sandbox_mode` into settings.json is silently ignored, exactly
//!     like an unknown key — the CLI settings validator never sees it).
//!   - tool permission: `toolPermission`. Documented values are `request-review`,
//!     `proceed-in-sandbox`, `strict`, and `always-proceed`. CLI 1.2.0 kept an
//!     unknown value byte-identical and treated it like review in the tested
//!     headless command; unknown values are ignored rather than assumed safe.
//!   - fine-grained permissions: global `permissions.deny`, `ask`, and `allow`
//!     arrays of `action(target)` rules, with Deny > Ask > Allow precedence.
//!
//! UserGlobal scope only for now; the per-repo (`<repo>/.antigravity/settings.json`)
//! parser needs an `antigravity_workspaces` policy field and is a follow-up.

use crate::ai_guard::parser::mcp_scan::emit_mcp_reasons;
use crate::ai_guard::parser::{AiGuardParser, AssessError};
use serde_json::Value;
use sigil_core::event::{AiGuardReason, AiGuardScope, AiTool};
use std::path::{Path, PathBuf};

fn settings_path(home: &Path) -> PathBuf {
    home.join(".gemini")
        .join("antigravity-cli")
        .join("settings.json")
}

fn mcp_config_path(home: &Path) -> PathBuf {
    home.join(".gemini").join("config").join("mcp_config.json")
}

fn assess_user(home: &Path) -> Result<Vec<AiGuardReason>, AssessError> {
    let mut out = Vec::new();
    if let Some(settings) = super::read_json_optional(&settings_path(home))? {
        emit_sandbox(&settings, &mut out);
        emit_approval(&settings, &mut out);
        emit_permission_lists(&settings, &mut out);
    }
    // MCP lives in a separate file (shared across Antigravity IDE/CLI).
    if let Some(mcp) = super::read_json_optional(&mcp_config_path(home))? {
        emit_mcp_reasons(&mcp, &mut out);
    }
    Ok(out)
}

/// `enableTerminalSandbox == false` (explicit) -> SandboxDisabled.
/// Antigravity defaults this to false, but we flag only the EXPLICIT `false`
/// to avoid flooding every install where the key is simply absent (consistent
/// with the Gemini parser's conservative "absent = ignore" stance).
pub(crate) fn emit_sandbox(v: &Value, out: &mut Vec<AiGuardReason>) {
    if v.get("enableTerminalSandbox").and_then(Value::as_bool) == Some(false) {
        out.push(AiGuardReason::SandboxDisabled);
    }
}

/// Flag the documented `toolPermission` modes that make the agent run tools
/// without per-action review (hardware-verified on `agy` 1.2.0):
///   - `always-proceed`     -> auto-execute, NOT sandboxed  (highest risk)
///   - `proceed-in-sandbox` -> auto-execute, confined to the terminal sandbox
///   - `request-review` / `strict` -> prompts; not flagged
///
/// Unknown values are deliberately not matched. CLI 1.2.0 left an unknown
/// value on disk and behaved like review for the tested command, but that is a
/// version-scoped observation rather than a validator guarantee.
///
/// A truthy `permissions.allowAll` is a separate explicit auto-approval signal.
pub(crate) fn emit_approval(v: &Value, out: &mut Vec<AiGuardReason>) {
    match v.get("toolPermission").and_then(Value::as_str) {
        Some(mode @ ("always-proceed" | "proceed-in-sandbox")) => {
            out.push(AiGuardReason::AutoApprovalEnabled { mode: mode.into() });
        }
        _ if v
            .get("permissions")
            .and_then(|p| p.get("allowAll"))
            .and_then(Value::as_bool)
            == Some(true) =>
        {
            out.push(AiGuardReason::AutoApprovalEnabled {
                mode: "allow_all".into(),
            });
        }
        _ => {}
    }
}

const PERMISSION_ACTIONS: &[&str] = &[
    "read_file",
    "write_file",
    "read_url",
    "execute_url",
    "command",
    "unsandboxed",
    "mcp",
];

fn parse_permission_rule(rule: &str) -> Option<(&str, &str)> {
    let rule = rule.trim();
    let (action, target) = rule.strip_suffix(')')?.split_once('(')?;
    let action = action.trim();
    let target = target.trim();
    if target.is_empty() || !PERMISSION_ACTIONS.contains(&action) {
        return None;
    }
    Some((action, target))
}

fn permission_rules<'a>(permissions: &'a Value, list: &str) -> impl Iterator<Item = &'a str> {
    permissions
        .get(list)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
}

fn is_risky_allow(rule: &str) -> bool {
    let Some((action, target)) = parse_permission_rule(rule) else {
        return false;
    };
    if target == "*" {
        return true;
    }
    matches!(action, "command" | "unsandboxed")
        && crate::ai_guard::rubric::is_destructive(target.strip_prefix("regex:").unwrap_or(target))
}

/// Whether a higher-priority rule fully covers an allow rule. Antigravity's
/// command rules match literal word prefixes, while `*` covers an entire action
/// namespace. Regex containment cannot be proven cheaply, so only identical
/// regex rules are treated as covering one another.
fn permission_rule_covers(higher: &str, allowed: &str) -> bool {
    let (Some((higher_action, higher_target)), Some((allow_action, allow_target))) = (
        parse_permission_rule(higher),
        parse_permission_rule(allowed),
    ) else {
        return false;
    };
    if higher_action != allow_action {
        return false;
    }
    if higher_target == "*" || higher_target == allow_target {
        return true;
    }
    if matches!(higher_action, "command" | "unsandboxed")
        && !higher_target.starts_with("regex:")
        && !allow_target.starts_with("regex:")
    {
        return allow_target
            .strip_prefix(higher_target)
            .is_some_and(|rest| rest.starts_with(char::is_whitespace));
    }
    false
}

/// Emit one finding per effective broad/destructive standing allow rule.
/// `deny` and `ask` are read first because either one overrides a matching
/// `allow`; a broad allow that is completely shadowed does not auto-approve.
pub(crate) fn emit_permission_lists(v: &Value, out: &mut Vec<AiGuardReason>) {
    let Some(permissions) = v.get("permissions") else {
        return;
    };
    let deny: Vec<&str> = permission_rules(permissions, "deny").collect();
    let ask: Vec<&str> = permission_rules(permissions, "ask").collect();
    for rule in permission_rules(permissions, "allow") {
        if !is_risky_allow(rule)
            || deny
                .iter()
                .any(|higher| permission_rule_covers(higher, rule))
            || ask
                .iter()
                .any(|higher| permission_rule_covers(higher, rule))
        {
            continue;
        }
        out.push(AiGuardReason::AutoApprovalEnabled {
            mode: format!("permissions.allow:{rule}"),
        });
    }
}

pub struct AntigravityParser;

impl AiGuardParser for AntigravityParser {
    fn tool(&self) -> AiTool {
        AiTool::Antigravity
    }
    fn scope(&self) -> AiGuardScope {
        AiGuardScope::UserGlobal
    }
    fn watched_paths(&self, home_dir: &Path) -> Vec<PathBuf> {
        vec![settings_path(home_dir), mcp_config_path(home_dir)]
    }
    fn assess(&self, home_dir: &Path) -> Result<Vec<AiGuardReason>, AssessError> {
        assess_user(home_dir)
    }
}

/// Per-repo parser: `<repo>/.antigravity/settings.json` (sandbox + approval).
/// Project-scope MCP config is not modeled (MCP lives in the shared user-global
/// `~/.gemini/config/mcp_config.json`).
pub struct AntigravityProjectParser {
    pub repo_root: PathBuf,
}

impl AntigravityProjectParser {
    fn settings(&self) -> PathBuf {
        self.repo_root.join(".antigravity").join("settings.json")
    }
}

// #145 — Option B is intentionally NOT applied to Antigravity in v1: its MCP
// servers live in a global file (`~/.gemini/config/mcp_config.json`), not in
// the per-repo `.antigravity/settings.json` this parser reads, so there is no
// project MCP payload to amplify. Revisit if Antigravity adds per-repo MCP.
impl AiGuardParser for AntigravityProjectParser {
    fn tool(&self) -> AiTool {
        AiTool::Antigravity
    }
    fn scope(&self) -> AiGuardScope {
        AiGuardScope::Project {
            path: self.repo_root.clone(),
        }
    }
    fn watched_paths(&self, _home: &Path) -> Vec<PathBuf> {
        vec![self.settings()]
    }
    fn assess(&self, _home: &Path) -> Result<Vec<AiGuardReason>, AssessError> {
        let mut out = Vec::new();
        if let Some(settings) = super::read_json_optional(&self.settings())? {
            emit_sandbox(&settings, &mut out);
            emit_approval(&settings, &mut out);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn write_settings(home: &Path, body: &str) {
        let d = home.join(".gemini").join("antigravity-cli");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("settings.json"), body).unwrap();
    }
    fn write_mcp(home: &Path, body: &str) {
        let d = home.join(".gemini").join("config");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("mcp_config.json"), body).unwrap();
    }
    fn assess(home: &Path) -> Vec<AiGuardReason> {
        AntigravityParser.assess(home).unwrap()
    }

    #[test]
    fn missing_returns_empty() {
        let d = tempdir().unwrap();
        assert!(assess(d.path()).is_empty());
    }
    #[test]
    fn corrupt_settings_returns_parse_error() {
        let d = tempdir().unwrap();
        write_settings(d.path(), "{ not json");
        assert!(matches!(
            AntigravityParser.assess(d.path()).unwrap_err(),
            AssessError::Parse { .. }
        ));
    }
    #[test]
    fn sandbox_false_emits_disabled() {
        let d = tempdir().unwrap();
        write_settings(d.path(), r#"{"enableTerminalSandbox":false}"#);
        assert!(assess(d.path())
            .iter()
            .any(|r| matches!(r, AiGuardReason::SandboxDisabled)));
    }
    #[test]
    fn sandbox_true_does_not_emit() {
        let d = tempdir().unwrap();
        write_settings(d.path(), r#"{"enableTerminalSandbox":true}"#);
        assert!(!assess(d.path())
            .iter()
            .any(|r| matches!(r, AiGuardReason::SandboxDisabled)));
    }
    #[test]
    fn absent_sandbox_does_not_emit() {
        let d = tempdir().unwrap();
        write_settings(d.path(), r#"{}"#);
        assert!(!assess(d.path())
            .iter()
            .any(|r| matches!(r, AiGuardReason::SandboxDisabled)));
    }
    #[test]
    fn sandbox_mode_key_is_ignored() {
        // `sandbox_mode` is NOT a CLI settings key (agy 1.0.8 silently ignores it,
        // like any unknown field — #158). Only `enableTerminalSandbox` counts, so a
        // file carrying solely `sandbox_mode` must not be read as a sandbox signal.
        let d = tempdir().unwrap();
        write_settings(d.path(), r#"{"sandbox_mode":"off"}"#);
        assert!(assess(d.path()).is_empty());
    }
    #[test]
    fn always_proceed_emits_auto_approval() {
        // agy 1.2.0: unsandboxed auto-execute — the highest-risk persisted mode.
        let d = tempdir().unwrap();
        write_settings(d.path(), r#"{"toolPermission":"always-proceed"}"#);
        assert!(assess(d.path()).iter().any(
            |r| matches!(r, AiGuardReason::AutoApprovalEnabled { mode } if mode == "always-proceed")
        ));
    }
    #[test]
    fn proceed_in_sandbox_emits_auto_approval() {
        // agy 1.2.0: auto-execute in the sandbox — still no per-action review.
        let d = tempdir().unwrap();
        write_settings(d.path(), r#"{"toolPermission":"proceed-in-sandbox"}"#);
        assert!(assess(d.path()).iter().any(
            |r| matches!(r, AiGuardReason::AutoApprovalEnabled { mode } if mode == "proceed-in-sandbox")
        ));
    }
    #[test]
    fn auto_approve_literal_is_not_flagged() {
        // agy 1.2.0 preserves unknown values. The tested headless command still
        // required review, but unknown values are not treated as a stable mode.
        let d = tempdir().unwrap();
        write_settings(d.path(), r#"{"toolPermission":"auto-approve"}"#);
        assert!(!assess(d.path())
            .iter()
            .any(|r| matches!(r, AiGuardReason::AutoApprovalEnabled { .. })));
    }
    #[test]
    fn broad_global_permission_allow_emits_auto_approval() {
        let d = tempdir().unwrap();
        write_settings(
            d.path(),
            r#"{"permissions":{"allow":["command(*)","read_url(*)","mcp(*)"]}}"#,
        );
        let reasons = assess(d.path());
        let modes: Vec<&str> = reasons
            .iter()
            .filter_map(|reason| match reason {
                AiGuardReason::AutoApprovalEnabled { mode } => Some(mode.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(
            modes,
            [
                "permissions.allow:command(*)",
                "permissions.allow:read_url(*)",
                "permissions.allow:mcp(*)",
            ]
        );
    }
    #[test]
    fn scoped_permission_allow_is_not_flagged() {
        let d = tempdir().unwrap();
        write_settings(
            d.path(),
            r#"{"permissions":{"allow":["command(echo)","read_url(example.com)","mcp(linter/*)"]}}"#,
        );
        assert!(!assess(d.path())
            .iter()
            .any(|r| matches!(r, AiGuardReason::AutoApprovalEnabled { .. })));
    }
    #[test]
    fn destructive_command_allow_emits_auto_approval() {
        let d = tempdir().unwrap();
        write_settings(
            d.path(),
            r#"{"permissions":{"allow":["command(rm -rf /)"]}}"#,
        );
        assert!(assess(d.path()).iter().any(
            |r| matches!(r, AiGuardReason::AutoApprovalEnabled { mode } if mode == "permissions.allow:command(rm -rf /)")
        ));
    }
    #[test]
    fn deny_or_ask_global_rule_shadows_command_allow() {
        for list in ["deny", "ask"] {
            let d = tempdir().unwrap();
            write_settings(
                d.path(),
                &format!(
                    r#"{{"permissions":{{"allow":["command(*)","command(rm -rf /)"],"{list}":["command(*)"]}}}}"#
                ),
            );
            assert!(!assess(d.path())
                .iter()
                .any(|r| matches!(r, AiGuardReason::AutoApprovalEnabled { .. })));
        }
    }
    #[test]
    fn higher_priority_command_prefix_shadows_destructive_allow() {
        let d = tempdir().unwrap();
        write_settings(
            d.path(),
            r#"{"permissions":{"allow":["command(rm -rf /)"],"ask":["command(rm)"]}}"#,
        );
        assert!(!assess(d.path())
            .iter()
            .any(|r| matches!(r, AiGuardReason::AutoApprovalEnabled { .. })));
    }
    #[test]
    fn unrelated_higher_priority_rule_does_not_shadow_broad_allow() {
        let d = tempdir().unwrap();
        write_settings(
            d.path(),
            r#"{"permissions":{"allow":["command(*)"],"deny":["read_url(*)"],"ask":["command(git)"]}}"#,
        );
        assert!(assess(d.path()).iter().any(
            |r| matches!(r, AiGuardReason::AutoApprovalEnabled { mode } if mode == "permissions.allow:command(*)")
        ));
    }
    #[test]
    fn malformed_permission_lists_and_rules_are_ignored() {
        let d = tempdir().unwrap();
        write_settings(
            d.path(),
            r#"{"permissions":{"allow":[null,7,"command()","unknown(*)"],"ask":"command(*)","deny":{}}}"#,
        );
        assert!(assess(d.path()).is_empty());
    }
    #[test]
    fn permissions_allow_all_emits_auto_approval() {
        let d = tempdir().unwrap();
        write_settings(d.path(), r#"{"permissions":{"allowAll":true}}"#);
        assert!(assess(d.path())
            .iter()
            .any(|r| matches!(r, AiGuardReason::AutoApprovalEnabled { .. })));
    }
    #[test]
    fn review_modes_are_safe() {
        for mode in ["request-review", "strict"] {
            let d = tempdir().unwrap();
            write_settings(d.path(), &format!(r#"{{"toolPermission":"{mode}"}}"#));
            assert!(!assess(d.path())
                .iter()
                .any(|r| matches!(r, AiGuardReason::AutoApprovalEnabled { .. })));
        }
    }
    #[test]
    fn gemini_approval_mode_no_longer_matches() {
        // The old Gemini key was dropped by Antigravity; must NOT false-fire.
        let d = tempdir().unwrap();
        write_settings(d.path(), r#"{"approval_mode":"yolo"}"#);
        assert!(!assess(d.path())
            .iter()
            .any(|r| matches!(r, AiGuardReason::AutoApprovalEnabled { .. })));
    }
    #[test]
    fn mcp_remote_from_separate_file_detected() {
        let d = tempdir().unwrap();
        write_mcp(
            d.path(),
            r#"{"mcpServers":{"a":{"httpUrl":"https://x/mcp"}}}"#,
        );
        assert!(assess(d.path())
            .iter()
            .any(|r| matches!(r, AiGuardReason::McpServerRemote { .. })));
    }
    #[test]
    fn corrupt_mcp_returns_parse_error() {
        let d = tempdir().unwrap();
        write_mcp(d.path(), "{ broken");
        assert!(matches!(
            AntigravityParser.assess(d.path()).unwrap_err(),
            AssessError::Parse { .. }
        ));
    }
    #[test]
    fn empty_config_is_clean() {
        let d = tempdir().unwrap();
        write_settings(d.path(), "");
        assert!(assess(d.path()).is_empty());
    }
    #[test]
    fn whitespace_config_is_clean() {
        let d = tempdir().unwrap();
        write_settings(d.path(), "  \n\t ");
        assert!(assess(d.path()).is_empty());
    }
    #[test]
    fn empty_mcp_config_is_clean() {
        let d = tempdir().unwrap();
        write_mcp(d.path(), "");
        assert!(assess(d.path()).is_empty());
    }
    #[test]
    fn whitespace_mcp_config_is_clean() {
        let d = tempdir().unwrap();
        write_mcp(d.path(), "  \n\t ");
        assert!(assess(d.path()).is_empty());
    }
    #[test]
    fn tool_and_scope() {
        assert_eq!(AntigravityParser.tool(), AiTool::Antigravity);
        assert_eq!(AntigravityParser.scope(), AiGuardScope::UserGlobal);
    }
    #[test]
    fn project_parser_scope_and_detect() {
        let d = tempdir().unwrap();
        let repo = d.path().join("repoX");
        std::fs::create_dir_all(repo.join(".antigravity")).unwrap();
        std::fs::write(
            repo.join(".antigravity").join("settings.json"),
            r#"{"enableTerminalSandbox":false,"toolPermission":"always-proceed"}"#,
        )
        .unwrap();
        let p = AntigravityProjectParser {
            repo_root: repo.clone(),
        };
        let reasons = p.assess(Path::new("/unused")).unwrap();
        assert!(reasons
            .iter()
            .any(|r| matches!(r, AiGuardReason::SandboxDisabled)));
        assert!(reasons
            .iter()
            .any(|r| matches!(r, AiGuardReason::AutoApprovalEnabled { .. })));
        assert_eq!(p.scope(), AiGuardScope::Project { path: repo });
    }
    #[test]
    fn project_permission_lists_are_not_scanned() {
        let d = tempdir().unwrap();
        let repo = d.path().join("repoX");
        std::fs::create_dir_all(repo.join(".antigravity")).unwrap();
        std::fs::write(
            repo.join(".antigravity").join("settings.json"),
            r#"{"permissions":{"allow":["command(*)"]}}"#,
        )
        .unwrap();
        let reasons = AntigravityProjectParser { repo_root: repo }
            .assess(Path::new("/unused"))
            .unwrap();
        assert!(reasons.is_empty());
    }
}
