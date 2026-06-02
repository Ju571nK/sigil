//! Antigravity (Google) parser. Antigravity is the successor to Gemini CLI
//! (Gemini CLI sunset 2026-06-18) and reuses the `~/.gemini/` config tree, but
//! with Antigravity-specific keys/paths (web-verified 2026-06):
//!   - settings (user-global): `~/.gemini/antigravity-cli/settings.json`
//!   - MCP servers: `~/.gemini/config/mcp_config.json` (`mcpServers`, a separate
//!     file — unlike Gemini, MCP is not inline in settings.json)
//!   - terminal sandbox: `enableTerminalSandbox` (boolean, default false)
//!   - tool permission: `toolPermission` (`request-review` default / `auto-approve`),
//!     verified against the real `agy` 1.0.4 binary + runtime log. (NOT Gemini's
//!     `approval_mode` — Antigravity dropped it.)
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

/// Read + parse a JSON file. Missing file -> `Ok(None)` (not an error); IO/parse
/// failures surface as `AssessError`.
fn read_json(path: &Path) -> Result<Option<Value>, AssessError> {
    let text = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(AssessError::Io {
                path: path.to_path_buf(),
                source,
            })
        }
    };
    serde_json::from_str(&text)
        .map(Some)
        .map_err(|e| AssessError::Parse {
            path: path.to_path_buf(),
            message: e.to_string(),
        })
}

fn assess_user(home: &Path) -> Result<Vec<AiGuardReason>, AssessError> {
    let mut out = Vec::new();
    if let Some(settings) = read_json(&settings_path(home))? {
        emit_sandbox(&settings, &mut out);
        emit_approval(&settings, &mut out);
    }
    // MCP lives in a separate file (shared across Antigravity IDE/CLI).
    if let Some(mcp) = read_json(&mcp_config_path(home))? {
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

/// `toolPermission == "auto-approve"` -> AutoApprovalEnabled (the agent runs
/// tools without confirmation). `request-review` (the default) is safe.
///
/// Verified against the real `agy` 1.0.4 binary + runtime log
/// (`CLI settings initialized: ... toolPermission=request-review`): the key is
/// `toolPermission`, NOT Gemini's `approval_mode` (`yolo`/`auto_edit`), which
/// Antigravity dropped. A truthy `permissions.allowAll` is also flagged.
pub(crate) fn emit_approval(v: &Value, out: &mut Vec<AiGuardReason>) {
    if v.get("toolPermission").and_then(Value::as_str) == Some("auto-approve") {
        out.push(AiGuardReason::AutoApprovalEnabled {
            mode: "auto-approve".into(),
        });
    } else if v
        .get("permissions")
        .and_then(|p| p.get("allowAll"))
        .and_then(Value::as_bool)
        == Some(true)
    {
        out.push(AiGuardReason::AutoApprovalEnabled {
            mode: "allow_all".into(),
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
        if let Some(settings) = read_json(&self.settings())? {
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
    fn auto_approve_emits_auto_approval() {
        let d = tempdir().unwrap();
        write_settings(d.path(), r#"{"toolPermission":"auto-approve"}"#);
        assert!(assess(d.path()).iter().any(
            |r| matches!(r, AiGuardReason::AutoApprovalEnabled { mode } if mode == "auto-approve")
        ));
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
            r#"{"enableTerminalSandbox":false,"toolPermission":"auto-approve"}"#,
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
