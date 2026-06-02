//! Antigravity (Google) parser. Antigravity is the successor to Gemini CLI
//! (Gemini CLI sunset 2026-06-18) and reuses the `~/.gemini/` config tree, but
//! with Antigravity-specific keys/paths (web-verified 2026-06):
//!   - settings (user-global): `~/.gemini/antigravity-cli/settings.json`
//!   - MCP servers: `~/.gemini/config/mcp_config.json` (`mcpServers`, a separate
//!     file — unlike Gemini, MCP is not inline in settings.json)
//!   - terminal sandbox: `enableTerminalSandbox` (boolean, default false)
//!   - approval mode: `approval_mode` (`default`/`auto_edit`/`yolo`/`plan`),
//!     where `yolo` skips ALL confirmation and `auto_edit` auto-approves edits.
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

/// `approval_mode` (top-level) or `general.defaultApprovalMode` (nested, Gemini
/// carry-over) in {`yolo`, `auto_edit`} -> AutoApprovalEnabled. `yolo` skips all
/// tool/command confirmation; `auto_edit` auto-approves edits. `default`/`plan`
/// are safe.
pub(crate) fn emit_approval(v: &Value, out: &mut Vec<AiGuardReason>) {
    let mode = v.get("approval_mode").and_then(Value::as_str).or_else(|| {
        v.get("general")
            .and_then(|g| g.get("defaultApprovalMode"))
            .and_then(Value::as_str)
    });
    if let Some(m @ ("yolo" | "auto_edit")) = mode {
        out.push(AiGuardReason::AutoApprovalEnabled { mode: m.into() });
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
    fn yolo_emits_auto_approval() {
        let d = tempdir().unwrap();
        write_settings(d.path(), r#"{"approval_mode":"yolo"}"#);
        assert!(assess(d.path())
            .iter()
            .any(|r| matches!(r, AiGuardReason::AutoApprovalEnabled { mode } if mode == "yolo")));
    }
    #[test]
    fn auto_edit_emits_auto_approval() {
        let d = tempdir().unwrap();
        write_settings(d.path(), r#"{"approval_mode":"auto_edit"}"#);
        assert!(assess(d.path()).iter().any(
            |r| matches!(r, AiGuardReason::AutoApprovalEnabled { mode } if mode == "auto_edit")
        ));
    }
    #[test]
    fn nested_gemini_carryover_approval_detected() {
        let d = tempdir().unwrap();
        write_settings(d.path(), r#"{"general":{"defaultApprovalMode":"yolo"}}"#);
        assert!(assess(d.path())
            .iter()
            .any(|r| matches!(r, AiGuardReason::AutoApprovalEnabled { .. })));
    }
    #[test]
    fn plan_mode_is_safe() {
        let d = tempdir().unwrap();
        write_settings(d.path(), r#"{"approval_mode":"plan"}"#);
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
}
