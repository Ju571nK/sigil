//! Phase 3b.8 — Cursor parser. Reads `~/.cursor/mcp.json` (user-global) and
//! `<repo>/.cursor/mcp.json` (per-repo) and maps MCP servers to reasons.
//! Cursor's only host-watchable guard surface is mcp.json; YOLO/auto-run is a
//! UI setting, out of scope.

use crate::ai_guard::parser::mcp_scan::emit_mcp_reasons;
use crate::ai_guard::parser::{AiGuardParser, AssessError};
use sigil_core::event::{AiGuardReason, AiGuardScope, AiTool};
use std::path::{Path, PathBuf};

fn assess_path(path: PathBuf) -> Result<Vec<AiGuardReason>, AssessError> {
    let Some(val) = super::read_json_optional(&path)? else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    emit_mcp_reasons(&val, &mut out);
    Ok(out)
}

pub struct CursorParser;

impl AiGuardParser for CursorParser {
    fn tool(&self) -> AiTool {
        AiTool::Cursor
    }
    fn scope(&self) -> AiGuardScope {
        AiGuardScope::Application {
            app: "cursor".into(),
        }
    }
    fn watched_paths(&self, home_dir: &Path) -> Vec<PathBuf> {
        vec![home_dir.join(".cursor").join("mcp.json")]
    }
    fn assess(&self, home_dir: &Path) -> Result<Vec<AiGuardReason>, AssessError> {
        assess_path(home_dir.join(".cursor").join("mcp.json"))
    }
}

pub struct CursorProjectParser {
    pub repo_root: PathBuf,
}

impl AiGuardParser for CursorProjectParser {
    fn tool(&self) -> AiTool {
        AiTool::Cursor
    }
    fn scope(&self) -> AiGuardScope {
        AiGuardScope::Project {
            path: self.repo_root.clone(),
        }
    }
    fn watched_paths(&self, _home: &Path) -> Vec<PathBuf> {
        vec![self.repo_root.join(".cursor").join("mcp.json")]
    }
    fn assess(&self, _home: &Path) -> Result<Vec<AiGuardReason>, AssessError> {
        assess_path(self.repo_root.join(".cursor").join("mcp.json"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn write(home: &Path, body: &str) {
        let d = home.join(".cursor");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("mcp.json"), body).unwrap();
    }

    #[test]
    fn empty_config_is_clean() {
        let d = tempdir().unwrap();
        write(d.path(), "");
        assert!(CursorParser.assess(d.path()).unwrap().is_empty());
    }
    #[test]
    fn whitespace_config_is_clean() {
        let d = tempdir().unwrap();
        write(d.path(), "  \n\t ");
        assert!(CursorParser.assess(d.path()).unwrap().is_empty());
    }
    #[test]
    fn missing_returns_empty() {
        let d = tempdir().unwrap();
        assert!(CursorParser.assess(d.path()).unwrap().is_empty());
    }
    #[test]
    fn corrupt_returns_parse_error() {
        let d = tempdir().unwrap();
        write(d.path(), "{ not json");
        assert!(matches!(
            CursorParser.assess(d.path()).unwrap_err(),
            AssessError::Parse { .. }
        ));
    }
    #[test]
    fn remote_detected() {
        let d = tempdir().unwrap();
        write(d.path(), r#"{"mcpServers":{"a":{"url":"https://x"}}}"#);
        let r = CursorParser.assess(d.path()).unwrap();
        assert!(r
            .iter()
            .any(|x| matches!(x, AiGuardReason::McpServerRemote { .. })));
    }
    #[test]
    fn scope_is_application_cursor() {
        assert_eq!(
            CursorParser.scope(),
            AiGuardScope::Application {
                app: "cursor".into()
            }
        );
    }
    #[test]
    fn tool_is_cursor() {
        assert_eq!(CursorParser.tool(), AiTool::Cursor);
    }
    #[test]
    fn project_parser_detects_repo_mcp() {
        let d = tempdir().unwrap();
        let repo = d.path().join("repoX");
        std::fs::create_dir_all(repo.join(".cursor")).unwrap();
        std::fs::write(
            repo.join(".cursor").join("mcp.json"),
            r#"{"mcpServers":{"a":{"command":"bash","args":["-c","rm -rf /tmp/sigil-c"]}}}"#,
        )
        .unwrap();
        let p = CursorProjectParser {
            repo_root: repo.clone(),
        };
        let r = p.assess(Path::new("/unused")).unwrap();
        assert!(r
            .iter()
            .any(|x| matches!(x, AiGuardReason::DestructiveInInlineCommand { .. })));
        assert_eq!(p.scope(), AiGuardScope::Project { path: repo });
    }
    #[test]
    fn project_parser_missing_empty() {
        let d = tempdir().unwrap();
        let p = CursorProjectParser {
            repo_root: d.path().to_path_buf(),
        };
        assert!(p.assess(Path::new("/unused")).unwrap().is_empty());
    }
}
