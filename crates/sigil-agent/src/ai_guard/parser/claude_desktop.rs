//! Phase 3b.6 — Claude Desktop (Anthropic.app) parser. Reads the
//! per-platform `claude_desktop_config.json` and maps MCP server entries
//! to `AiGuardReason`. Application-form companion to ClaudeCodeParser
//! (which covers the CLI form). Hooks / permissions don't exist in the
//! desktop config; only `mcpServers` is meaningful here.

use crate::ai_guard::parser::{AiGuardParser, AssessError};
use serde_json::Value;
use sigil_core::event::{AiGuardReason, AiGuardScope, AiTool};
use std::path::{Path, PathBuf};

pub struct ClaudeDesktopParser;

impl AiGuardParser for ClaudeDesktopParser {
    fn tool(&self) -> AiTool {
        AiTool::ClaudeDesktop
    }

    fn scope(&self) -> AiGuardScope {
        AiGuardScope::Application {
            app: "claude_desktop".into(),
        }
    }

    fn watched_paths(&self, home_dir: &Path) -> Vec<PathBuf> {
        // Per-platform config locations relative to HOME (= USERPROFILE on
        // Windows, where %APPDATA% resolves to USERPROFILE\AppData\Roaming).
        // We list all three so dispatch matches whichever file actually
        // exists; assess() short-circuits on the first one found.
        vec![
            // macOS
            home_dir
                .join("Library")
                .join("Application Support")
                .join("Claude")
                .join("claude_desktop_config.json"),
            // Linux
            home_dir
                .join(".config")
                .join("Claude")
                .join("claude_desktop_config.json"),
            // Windows: %APPDATA% = USERPROFILE\AppData\Roaming
            home_dir
                .join("AppData")
                .join("Roaming")
                .join("Claude")
                .join("claude_desktop_config.json"),
        ]
    }

    fn assess(&self, home_dir: &Path) -> Result<Vec<AiGuardReason>, AssessError> {
        let candidates = [
            home_dir
                .join("Library")
                .join("Application Support")
                .join("Claude")
                .join("claude_desktop_config.json"),
            home_dir
                .join(".config")
                .join("Claude")
                .join("claude_desktop_config.json"),
            home_dir
                .join("AppData")
                .join("Roaming")
                .join("Claude")
                .join("claude_desktop_config.json"),
        ];
        let mut text: Option<(PathBuf, String)> = None;
        for path in candidates {
            match std::fs::read_to_string(&path) {
                Ok(s) => {
                    text = Some((path, s));
                    break;
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(source) => return Err(AssessError::Io { path, source }),
            }
        }
        let Some((path, body)) = text else {
            return Ok(Vec::new());
        };
        let val: Value = serde_json::from_str(&body).map_err(|e| AssessError::Parse {
            path: path.clone(),
            message: e.to_string(),
        })?;
        let mut out = Vec::new();
        emit_mcp_reasons(&val, &mut out);
        Ok(out)
    }
}

/// Walk `mcpServers` object and delegate each entry to the shared
/// `mcp_scan::emit_one_server` assessor.
fn emit_mcp_reasons(settings: &Value, out: &mut Vec<AiGuardReason>) {
    let Some(servers) = settings.get("mcpServers").and_then(Value::as_object) else {
        return;
    };
    for (name, def) in servers {
        crate::ai_guard::parser::mcp_scan::emit_one_server(name, def, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    /// Write a claude_desktop_config.json in the macOS-style location
    /// under the given tempdir HOME. Returns the path written.
    fn write_config_macos(home: &Path, contents: &str) -> PathBuf {
        let dir = home
            .join("Library")
            .join("Application Support")
            .join("Claude");
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("claude_desktop_config.json");
        std::fs::write(&p, contents).unwrap();
        p
    }

    /// Same, Linux-style location.
    fn write_config_linux(home: &Path, contents: &str) -> PathBuf {
        let dir = home.join(".config").join("Claude");
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("claude_desktop_config.json");
        std::fs::write(&p, contents).unwrap();
        p
    }

    #[test]
    fn missing_config_returns_empty_vec() {
        let dir = tempdir().unwrap();
        let p = ClaudeDesktopParser;
        assert!(p.assess(dir.path()).unwrap().is_empty());
    }

    #[test]
    fn empty_mcp_servers_returns_empty_vec() {
        let dir = tempdir().unwrap();
        write_config_macos(dir.path(), r#"{"mcpServers": {}}"#);
        let p = ClaudeDesktopParser;
        assert!(p.assess(dir.path()).unwrap().is_empty());
    }

    #[test]
    fn local_command_mcp_emits_no_sandbox() {
        let dir = tempdir().unwrap();
        write_config_macos(
            dir.path(),
            r#"{"mcpServers": {"github": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"]}}}"#,
        );
        let p = ClaudeDesktopParser;
        let reasons = p.assess(dir.path()).unwrap();
        assert!(
            reasons.iter().any(|r| matches!(
                r,
                AiGuardReason::NoSandbox { executor } if executor == "mcp_command"
            )),
            "expected NoSandbox{{executor:\"mcp_command\"}} in {reasons:?}"
        );
        assert!(
            reasons
                .iter()
                .any(|r| matches!(r, AiGuardReason::McpServerLocalCommand { .. })),
            "#125: expected McpServerLocalCommand in {reasons:?}"
        );
    }

    #[test]
    fn remote_url_mcp_emits_remote() {
        let dir = tempdir().unwrap();
        write_config_macos(
            dir.path(),
            r#"{"mcpServers": {"remote-x": {"url": "https://mcp.example.com/sse"}}}"#,
        );
        let p = ClaudeDesktopParser;
        let reasons = p.assess(dir.path()).unwrap();
        assert!(reasons.iter().any(|r| matches!(
            r,
            AiGuardReason::McpServerRemote { server_name, url }
                if server_name == "remote-x" && url == "https://mcp.example.com/sse"
        )));
    }

    #[test]
    fn url_only_server_does_not_emit_no_sandbox() {
        let dir = tempdir().unwrap();
        write_config_macos(
            dir.path(),
            r#"{"mcpServers": {"remote": {"url": "https://x.example.com"}}}"#,
        );
        let p = ClaudeDesktopParser;
        let reasons = p.assess(dir.path()).unwrap();
        assert!(!reasons
            .iter()
            .any(|r| matches!(r, AiGuardReason::NoSandbox { .. })));
    }

    #[test]
    fn shell_with_destructive_arg_emits_destructive_and_no_sandbox() {
        let dir = tempdir().unwrap();
        write_config_macos(
            dir.path(),
            r#"{"mcpServers": {"risky": {"command": "bash", "args": ["-c", "rm -rf /tmp/sigil-test"]}}}"#,
        );
        let p = ClaudeDesktopParser;
        let reasons = p.assess(dir.path()).unwrap();
        assert!(reasons
            .iter()
            .any(|r| matches!(r, AiGuardReason::NoSandbox { .. })));
        assert!(reasons.iter().any(|r| matches!(
            r,
            AiGuardReason::DestructiveInInlineCommand { hook_event, .. }
                if hook_event == "mcp_command"
        )));
    }

    #[test]
    fn linux_path_is_also_read() {
        let dir = tempdir().unwrap();
        write_config_linux(
            dir.path(),
            r#"{"mcpServers": {"x": {"url": "https://y.example.com"}}}"#,
        );
        let p = ClaudeDesktopParser;
        let reasons = p.assess(dir.path()).unwrap();
        assert!(reasons
            .iter()
            .any(|r| matches!(r, AiGuardReason::McpServerRemote { .. })));
    }

    #[test]
    fn corrupt_json_returns_parse_error() {
        let dir = tempdir().unwrap();
        write_config_macos(dir.path(), "{ not json");
        let p = ClaudeDesktopParser;
        let err = p.assess(dir.path()).unwrap_err();
        assert!(matches!(err, AssessError::Parse { .. }), "got {err:?}");
    }

    #[test]
    fn scope_is_application_claude_desktop() {
        let p = ClaudeDesktopParser;
        assert_eq!(
            p.scope(),
            AiGuardScope::Application {
                app: "claude_desktop".into()
            }
        );
    }

    #[test]
    fn tool_is_claude_desktop() {
        let p = ClaudeDesktopParser;
        assert_eq!(p.tool(), AiTool::ClaudeDesktop);
    }

    #[test]
    fn local_command_mcp_emits_local_command_reason() {
        let dir = tempdir().unwrap();
        write_config_macos(
            dir.path(),
            r#"{"mcpServers": {"local": {"command": "/tmp/x", "args": ["a"]}}}"#,
        );
        let reasons = ClaudeDesktopParser.assess(dir.path()).unwrap();
        assert!(
            reasons.iter().any(|r| matches!(r,
            AiGuardReason::McpServerLocalCommand { server_name, .. } if server_name=="local")),
            "expected McpServerLocalCommand in {reasons:?}"
        );
    }

    #[test]
    fn server_with_both_url_and_command_emits_both() {
        let dir = tempdir().unwrap();
        write_config_macos(
            dir.path(),
            r#"{"mcpServers": {"both": {"url": "https://x", "command": "node"}}}"#,
        );
        let reasons = ClaudeDesktopParser.assess(dir.path()).unwrap();
        assert!(reasons
            .iter()
            .any(|r| matches!(r, AiGuardReason::McpServerRemote { .. })));
        assert!(reasons
            .iter()
            .any(|r| matches!(r, AiGuardReason::McpServerLocalCommand { .. })));
    }
}
