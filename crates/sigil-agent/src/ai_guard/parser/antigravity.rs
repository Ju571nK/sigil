//! Antigravity (Google) parser. Antigravity is the successor to Gemini CLI
//! (Gemini CLI sunset 2026-06-18) and reuses the `~/.gemini/` config tree, but
//! with Antigravity-specific keys/paths (web-verified 2026-06):
//!   - settings (user-global): `~/.gemini/antigravity-cli/settings.json`
//!   - MCP servers: `~/.gemini/config/mcp_config.json` (`mcpServers`, a separate
//!     file — unlike Gemini, MCP is not inline in settings.json)
//!   - terminal sandbox: `enableTerminalSandbox` (boolean, default false). This
//!     is the ONLY sandbox knob the settings file carries — `sandbox_mode` /
//!     `sandbox_type` / `sandbox_allow_network` are internal sandbox-subsystem
//!     struct fields, NOT CLI settings keys (hardware-verified on agy 1.0.8:
//!     writing `sandbox_mode` into settings.json is silently ignored, exactly
//!     like an unknown key — the CLI settings validator never sees it).
//!   - tool permission: `toolPermission`. Accepted enum (hardware-verified on
//!     agy 1.0.8): `request-review` (default, safe — agent asks per action),
//!     `proceed-in-sandbox` (auto-executes inside the sandbox), `always-proceed`
//!     (auto-executes, NOT sandboxed). The old Gemini `approval_mode`
//!     (`yolo`/`auto_edit`) was dropped, and the literal `auto-approve` is now
//!     REJECTED by 1.0.8's settings validator (replaced with the `request-review`
//!     default at load) — see `emit_approval`.
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

/// Flag the `toolPermission` modes that make the agent run tools WITHOUT
/// per-action review. Hardware-verified against `agy` 1.0.8's settings
/// validator (`cli_setting_manager.go`, via `CLI settings initialized:
/// ... toolPermission=<value>` + `unrecognized value` rejections):
///   - `always-proceed`     -> auto-execute, NOT sandboxed  (highest risk)
///   - `proceed-in-sandbox` -> auto-execute, confined to the terminal sandbox
///   - `request-review`     -> the safe default (agent asks); not flagged
///
/// The old literal `auto-approve` is deliberately NOT matched: 1.0.8's validator
/// rejects it as an unrecognized value and falls back to `request-review`, so a
/// settings file carrying `auto-approve` is effectively safe at runtime — flagging
/// it would be a false positive. (Permissive auto-approval without a persisted
/// setting is reached via the session-scoped `--dangerously-skip-permissions`
/// CLI flag, which never touches settings.json and so is out of scope here.)
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
        // agy 1.0.8: unsandboxed auto-execute — the highest-risk persisted mode.
        let d = tempdir().unwrap();
        write_settings(d.path(), r#"{"toolPermission":"always-proceed"}"#);
        assert!(assess(d.path()).iter().any(
            |r| matches!(r, AiGuardReason::AutoApprovalEnabled { mode } if mode == "always-proceed")
        ));
    }
    #[test]
    fn proceed_in_sandbox_emits_auto_approval() {
        // agy 1.0.8: auto-execute confined to the sandbox — still no per-action review.
        let d = tempdir().unwrap();
        write_settings(d.path(), r#"{"toolPermission":"proceed-in-sandbox"}"#);
        assert!(assess(d.path()).iter().any(
            |r| matches!(r, AiGuardReason::AutoApprovalEnabled { mode } if mode == "proceed-in-sandbox")
        ));
    }
    #[test]
    fn auto_approve_literal_is_not_flagged() {
        // agy 1.0.8 rejects `auto-approve` as an unrecognized settings value and
        // falls back to `request-review`, so the file is safe at runtime —
        // flagging it would be a false positive. (Hardware-verified, #158.)
        let d = tempdir().unwrap();
        write_settings(d.path(), r#"{"toolPermission":"auto-approve"}"#);
        assert!(!assess(d.path())
            .iter()
            .any(|r| matches!(r, AiGuardReason::AutoApprovalEnabled { .. })));
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
    fn request_review_is_safe() {
        let d = tempdir().unwrap();
        write_settings(d.path(), r#"{"toolPermission":"request-review"}"#);
        assert!(!assess(d.path())
            .iter()
            .any(|r| matches!(r, AiGuardReason::AutoApprovalEnabled { .. })));
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
}
