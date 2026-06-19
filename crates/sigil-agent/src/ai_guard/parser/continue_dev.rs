//! Phase 3b.6 — Continue.dev (VSCode/JetBrains 확장) parser. Reads the
//! user-global `~/.continue/config.json` and maps mcpServers /
//! slashCommands / customCommands to `AiGuardReason`.
//!
//! Schema notes: Continue's config.json has evolved across versions.
//! Top-level `mcpServers` is observed as both an object map ({"name": {...}})
//! and an array of {"name": "...", ...} objects in the wild. The parser
//! handles both shapes. Other surfaces (models, contextProviders, rules)
//! are deliberately out of scope for Phase 3b.6.

use crate::ai_guard::parser::{AiGuardParser, AssessError};
use crate::ai_guard::rubric;
use serde_json::Value;
use sigil_core::event::{AiGuardReason, AiGuardScope, AiTool};
use std::path::{Path, PathBuf};

pub struct ContinueDevParser;

impl AiGuardParser for ContinueDevParser {
    fn tool(&self) -> AiTool {
        AiTool::ContinueDev
    }

    fn scope(&self) -> AiGuardScope {
        AiGuardScope::Application {
            app: "continue".into(),
        }
    }

    fn watched_paths(&self, home_dir: &Path) -> Vec<PathBuf> {
        vec![home_dir.join(".continue").join("config.json")]
    }

    fn collect_external_script_paths(&self, home_dir: &Path) -> Vec<PathBuf> {
        let cd = home_dir.join(".continue");
        let config_path = cd.join("config.json");
        let Some(val) = super::read_json_optional(&config_path).ok().flatten() else {
            return Vec::new();
        };
        let hooks_dir = cd.join("hooks");
        collect_external_script_paths_from_settings(&val, &hooks_dir)
    }

    fn assess(&self, home_dir: &Path) -> Result<Vec<AiGuardReason>, AssessError> {
        let path = home_dir.join(".continue").join("config.json");
        let Some(val) = super::read_json_optional(&path)? else {
            return Ok(Vec::new());
        };
        let hooks_dir = home_dir.join(".continue").join("hooks");
        let mut out = Vec::new();
        emit_mcp_reasons(&val, &mut out);
        emit_slash_command_reasons(&val, &hooks_dir, &mut out);
        emit_custom_command_reasons(&val, &mut out);
        Ok(out)
    }
}

/// Continue mcpServers shape varies between v1 (object map keyed by name)
/// and v2 (array of objects with `name` field). Handle both.
pub(crate) fn emit_mcp_reasons(settings: &Value, out: &mut Vec<AiGuardReason>) {
    let Some(node) = settings.get("mcpServers") else {
        return;
    };
    if let Some(obj) = node.as_object() {
        for (name, def) in obj {
            emit_one_mcp(name, def, out);
        }
    } else if let Some(arr) = node.as_array() {
        for def in arr {
            let name = def
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("(unnamed)");
            emit_one_mcp(name, def, out);
        }
    }
}

fn emit_one_mcp(name: &str, def: &Value, out: &mut Vec<AiGuardReason>) {
    super::mcp_scan::emit_one_server(name, def, out);
}

/// slashCommands entries: {name, description, step?, run?, prompt?}.
/// - `step` 가 path-like 면: convention dir (~/.continue/hooks/) 안이면 read+scan,
///   외부면 ExternalScriptUnscanned.
/// - `run` / `prompt` 가 string 이면: destructive pattern scan.
pub(crate) fn emit_slash_command_reasons(
    settings: &Value,
    hooks_dir: &Path,
    out: &mut Vec<AiGuardReason>,
) {
    let Some(arr) = settings.get("slashCommands").and_then(Value::as_array) else {
        return;
    };
    for entry in arr {
        // step: path-like external/convention script
        if let Some(step) = entry.get("step").and_then(Value::as_str) {
            classify_script_path(step, "slash_command", hooks_dir, out);
        }
        // run: inline shell-like
        if let Some(run) = entry.get("run").and_then(Value::as_str) {
            scan_inline(run, "slash_command", out);
        }
        // prompt: model prompt that some configs piggyback shell commands into
        if let Some(prompt) = entry.get("prompt").and_then(Value::as_str) {
            scan_inline(prompt, "slash_command", out);
        }
    }
}

/// customCommands: {name, prompt, command?}. `command` is shell-exec; scan it.
pub(crate) fn emit_custom_command_reasons(settings: &Value, out: &mut Vec<AiGuardReason>) {
    let Some(arr) = settings.get("customCommands").and_then(Value::as_array) else {
        return;
    };
    for entry in arr {
        if let Some(cmd) = entry.get("command").and_then(Value::as_str) {
            scan_inline(cmd, "custom_command", out);
        }
        if let Some(prompt) = entry.get("prompt").and_then(Value::as_str) {
            scan_inline(prompt, "custom_command", out);
        }
    }
}

fn scan_inline(s: &str, hook_event: &str, out: &mut Vec<AiGuardReason>) {
    if let Some(pat) = rubric::first_destructive_pattern(s) {
        out.push(AiGuardReason::DestructiveInInlineCommand {
            pattern: pat.to_string(),
            hook_event: hook_event.to_string(),
            snippet: s.chars().take(80).collect(),
        });
    }
}

/// Mirrors ClaudeCodeParser::classify_command's path-detection logic at a smaller
/// scale: Unix-absolute / Windows-absolute / tilde / contains separator ⇒ path.
fn classify_script_path(s: &str, hook_event: &str, hooks_dir: &Path, out: &mut Vec<AiGuardReason>) {
    let first = s.split_whitespace().next().unwrap_or("");
    let has_shell_meta = first.contains('|') || first.contains('&');
    let looks_pathish = !has_shell_meta
        && (std::path::Path::new(first).is_absolute()
            || first.starts_with('~')
            || first.contains('/')
            || first.contains('\\'));
    if !looks_pathish {
        // Plain inline command — scan for destructive patterns.
        scan_inline(s, hook_event, out);
        return;
    }
    let candidate = PathBuf::from(first);
    if path_is_inside(&candidate, hooks_dir) {
        // 3b.3.1 — convention-dir script delegates to recursive walker
        // so sourced files inside the convention dir also get scanned.
        out.extend(crate::ai_guard::ext_script::scan_hook_script(
            &candidate, hook_event,
        ));
    } else {
        // 3b.3.1 — external path also uses recursive walker.
        out.extend(crate::ai_guard::ext_script::scan_hook_script(
            &candidate, hook_event,
        ));
    }
}

/// Phase 3b.3 — walk Continue.dev's slashCommands and return every `step`
/// path classified as external (outside the convention hooks_dir). Mirrors
/// the path-detection used inside `classify_script_path`. Caller is
/// responsible for canonicalizing the returned paths before registering.
pub(crate) fn collect_external_script_paths_from_settings(
    settings: &Value,
    hooks_dir: &Path,
) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Some(arr) = settings.get("slashCommands").and_then(Value::as_array) {
        for entry in arr {
            if let Some(step) = entry.get("step").and_then(Value::as_str) {
                if let Some(p) = external_path_from_command(step, hooks_dir) {
                    out.push(p);
                }
            }
        }
    }
    out
}

/// Returns Some(path) if `cmd`'s first token is a path that lies OUTSIDE
/// `hooks_dir`. Mirrors the path-detection logic of `classify_script_path`.
fn external_path_from_command(cmd: &str, hooks_dir: &Path) -> Option<PathBuf> {
    let first_token = cmd.split_whitespace().next().unwrap_or("");
    let has_shell_meta = first_token.contains('|') || first_token.contains('&');
    let looks_pathish = !has_shell_meta
        && (std::path::Path::new(first_token).is_absolute()
            || first_token.starts_with('~')
            || first_token.contains('/')
            || first_token.contains('\\'));
    if !looks_pathish {
        return None;
    }
    let candidate = PathBuf::from(first_token);
    if path_is_inside(&candidate, hooks_dir) {
        None
    } else {
        Some(candidate)
    }
}

fn path_is_inside(candidate: &Path, root: &Path) -> bool {
    let c = dunce::canonicalize(candidate).unwrap_or_else(|_| candidate.to_path_buf());
    let r = dunce::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    c.starts_with(&r)
}

/// Phase 3b.6.1 — per-repo Continue.dev parser. Spawned by runtime /
/// policy_reload after discovery; each instance carries its own repo
/// root and emits AiGuardRiskAssessed with scope=Project{path:repo_root}.
pub struct ContinueDevProjectParser {
    pub repo_root: PathBuf,
}

impl AiGuardParser for ContinueDevProjectParser {
    fn tool(&self) -> AiTool {
        AiTool::ContinueDev
    }

    fn scope(&self) -> AiGuardScope {
        AiGuardScope::Project {
            path: self.repo_root.clone(),
        }
    }

    fn watched_paths(&self, _home_dir: &Path) -> Vec<PathBuf> {
        vec![self.repo_root.join(".continue").join("config.json")]
    }

    fn collect_external_script_paths(&self, _home_dir: &Path) -> Vec<PathBuf> {
        let cd = self.repo_root.join(".continue");
        let config_path = cd.join("config.json");
        let Some(val) = super::read_json_optional(&config_path).ok().flatten() else {
            return Vec::new();
        };
        let hooks_dir = cd.join("hooks");
        collect_external_script_paths_from_settings(&val, &hooks_dir)
    }

    fn assess(&self, _home_dir: &Path) -> Result<Vec<AiGuardReason>, AssessError> {
        let path = self.repo_root.join(".continue").join("config.json");
        let Some(val) = super::read_json_optional(&path)? else {
            return Ok(Vec::new());
        };
        let hooks_dir = self.repo_root.join(".continue").join("hooks");
        let mut out = Vec::new();
        emit_mcp_reasons(&val, &mut out);
        // #154 Option B — Continue auto-loads repo-local `.continue/` config and
        // spawns its mcpServers (StdioClientTransport) on workspace config load
        // with NO per-server approval (source-verified: MCPManagerSingleton marks
        // new servers refresh=true -> refreshConnections -> connectClient). The
        // only gate is VS Code Workspace Trust (absent in JetBrains) — the same
        // one-keypress folder-trust trigger TrustFall describes. Amplify off the
        // MCP-only reasons here, BEFORE the slash/custom-command reasons (which
        // can also emit DestructiveInInlineCommand) join `out`.
        if super::mcp_scan::has_local_or_risky_mcp(&out) {
            out.push(AiGuardReason::ProjectMcpAutoEnabled {
                mechanism: "folder-trust autorun (default)".to_string(),
            });
        }
        emit_slash_command_reasons(&val, &hooks_dir, &mut out);
        emit_custom_command_reasons(&val, &mut out);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn write_config(home: &Path, contents: &str) -> PathBuf {
        let dir = home.join(".continue");
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("config.json");
        std::fs::write(&p, contents).unwrap();
        p
    }

    #[test]
    fn empty_config_is_clean() {
        let dir = tempdir().unwrap();
        write_config(dir.path(), "");
        let p = ContinueDevParser;
        assert!(p.assess(dir.path()).unwrap().is_empty());
    }

    #[test]
    fn whitespace_config_is_clean() {
        let dir = tempdir().unwrap();
        write_config(dir.path(), "  \n\t ");
        let p = ContinueDevParser;
        assert!(p.assess(dir.path()).unwrap().is_empty());
    }

    #[test]
    fn missing_config_returns_empty_vec() {
        let dir = tempdir().unwrap();
        let p = ContinueDevParser;
        assert!(p.assess(dir.path()).unwrap().is_empty());
    }

    #[test]
    fn empty_object_returns_empty_vec() {
        let dir = tempdir().unwrap();
        write_config(dir.path(), "{}");
        let p = ContinueDevParser;
        assert!(p.assess(dir.path()).unwrap().is_empty());
    }

    #[test]
    fn corrupt_json_returns_parse_error() {
        let dir = tempdir().unwrap();
        write_config(dir.path(), "{ not json");
        let p = ContinueDevParser;
        let err = p.assess(dir.path()).unwrap_err();
        assert!(matches!(err, AssessError::Parse { .. }), "got {err:?}");
    }

    #[test]
    fn mcp_object_form_local_command_emits_no_sandbox() {
        let dir = tempdir().unwrap();
        write_config(
            dir.path(),
            r#"{"mcpServers": {"fs": {"command": "node", "args": ["mcp.js"]}}}"#,
        );
        let p = ContinueDevParser;
        let reasons = p.assess(dir.path()).unwrap();
        assert!(reasons.iter().any(|r| matches!(
            r,
            AiGuardReason::NoSandbox { executor } if executor == "mcp_command"
        )));
        assert!(
            reasons
                .iter()
                .any(|r| matches!(r, AiGuardReason::McpServerLocalCommand { .. })),
            "#125: expected McpServerLocalCommand in {reasons:?}"
        );
    }

    #[test]
    fn mcp_array_form_local_command_emits_no_sandbox() {
        let dir = tempdir().unwrap();
        write_config(
            dir.path(),
            r#"{"mcpServers": [{"name": "fs", "command": "node", "args": ["mcp.js"]}]}"#,
        );
        let p = ContinueDevParser;
        let reasons = p.assess(dir.path()).unwrap();
        assert!(reasons.iter().any(|r| matches!(
            r,
            AiGuardReason::NoSandbox { executor } if executor == "mcp_command"
        )));
        assert!(
            reasons
                .iter()
                .any(|r| matches!(r, AiGuardReason::McpServerLocalCommand { .. })),
            "#125: expected McpServerLocalCommand in {reasons:?}"
        );
    }

    #[test]
    fn mcp_remote_url_emits_remote() {
        let dir = tempdir().unwrap();
        write_config(
            dir.path(),
            r#"{"mcpServers": [{"name": "remote", "url": "https://mcp.example.com"}]}"#,
        );
        let p = ContinueDevParser;
        let reasons = p.assess(dir.path()).unwrap();
        assert!(reasons.iter().any(|r| matches!(
            r,
            AiGuardReason::McpServerRemote { server_name, url }
                if server_name == "remote" && url == "https://mcp.example.com"
        )));
    }

    #[test]
    fn mcp_uppercase_scheme_emits_remote() {
        let dir = tempdir().unwrap();
        write_config(
            dir.path(),
            r#"{"mcpServers": [{"name": "remote", "url": "HtTpS://mcp.example.com"}]}"#,
        );
        let p = ContinueDevParser;
        let reasons = p.assess(dir.path()).unwrap();
        assert!(
            reasons.iter().any(|r| matches!(
                r,
                AiGuardReason::McpServerRemote { server_name, .. }
                    if server_name == "remote"
            )),
            "expected McpServerRemote for HtTpS:// (mixed-case) url, got {reasons:?}"
        );
    }

    #[test]
    fn slash_command_run_with_destructive_pattern_emits_destructive() {
        let dir = tempdir().unwrap();
        write_config(
            dir.path(),
            r#"{"slashCommands": [{"name": "danger", "run": "rm -rf /tmp/sigil-test"}]}"#,
        );
        let p = ContinueDevParser;
        let reasons = p.assess(dir.path()).unwrap();
        assert!(reasons.iter().any(|r| matches!(
            r,
            AiGuardReason::DestructiveInInlineCommand { hook_event, .. }
                if hook_event == "slash_command"
        )));
    }

    #[test]
    fn slash_command_external_script_emits_external_script_unscanned() {
        let dir = tempdir().unwrap();
        write_config(
            dir.path(),
            r#"{"slashCommands": [{"name": "ext", "step": "/usr/local/bin/foo.sh"}]}"#,
        );
        let p = ContinueDevParser;
        let reasons = p.assess(dir.path()).unwrap();
        assert!(reasons.iter().any(|r| matches!(
            r,
            AiGuardReason::ExternalScriptUnscanned { hook_event, script_path }
                if hook_event == "slash_command"
                    && script_path.to_string_lossy() == "/usr/local/bin/foo.sh"
        )));
    }

    #[test]
    fn custom_command_with_destructive_emits_destructive() {
        let dir = tempdir().unwrap();
        write_config(
            dir.path(),
            r#"{"customCommands": [{"name": "x", "command": "bash -c 'rm -rf /tmp/sigil-test'"}]}"#,
        );
        let p = ContinueDevParser;
        let reasons = p.assess(dir.path()).unwrap();
        assert!(reasons.iter().any(|r| matches!(
            r,
            AiGuardReason::DestructiveInInlineCommand { hook_event, .. }
                if hook_event == "custom_command"
        )));
    }

    #[test]
    fn safe_slash_command_emits_nothing() {
        let dir = tempdir().unwrap();
        write_config(
            dir.path(),
            r#"{"slashCommands": [{"name": "ok", "run": "echo hello"}]}"#,
        );
        let p = ContinueDevParser;
        let reasons = p.assess(dir.path()).unwrap();
        assert!(reasons.is_empty(), "got {reasons:?}");
    }

    #[test]
    fn scope_is_application_continue() {
        let p = ContinueDevParser;
        assert_eq!(
            p.scope(),
            AiGuardScope::Application {
                app: "continue".into()
            }
        );
    }

    #[test]
    fn tool_is_continue_dev() {
        let p = ContinueDevParser;
        assert_eq!(p.tool(), AiTool::ContinueDev);
    }

    #[test]
    fn project_parser_missing_config_returns_empty() {
        let dir = tempdir().unwrap();
        let p = ContinueDevProjectParser {
            repo_root: dir.path().to_path_buf(),
        };
        assert!(p
            .assess(std::path::Path::new("/unused"))
            .unwrap()
            .is_empty());
    }

    #[test]
    fn project_parser_destructive_slash_command_is_detected() {
        let dir = tempdir().unwrap();
        let repo = dir.path().join("repoX");
        let cdir = repo.join(".continue");
        std::fs::create_dir_all(&cdir).unwrap();
        std::fs::write(
            cdir.join("config.json"),
            r#"{"slashCommands": [{"name": "danger", "run": "rm -rf /tmp/sigil-3b6.1"}]}"#,
        )
        .unwrap();
        let p = ContinueDevProjectParser {
            repo_root: repo.clone(),
        };
        let reasons = p.assess(std::path::Path::new("/unused")).unwrap();
        assert!(reasons.iter().any(|r| matches!(
            r,
            AiGuardReason::DestructiveInInlineCommand { hook_event, .. }
                if hook_event == "slash_command"
        )));
    }

    #[test]
    fn project_parser_scope_is_project_with_repo_root_path() {
        let dir = tempdir().unwrap();
        let repo = dir.path().to_path_buf();
        let p = ContinueDevProjectParser {
            repo_root: repo.clone(),
        };
        assert_eq!(p.scope(), AiGuardScope::Project { path: repo });
    }

    #[test]
    fn project_parser_tool_is_continue_dev_same_as_user_global() {
        let p = ContinueDevProjectParser {
            repo_root: std::path::PathBuf::from("/x"),
        };
        assert_eq!(p.tool(), AiTool::ContinueDev);
    }

    #[test]
    fn external_slash_command_destructive_emits_destructive_in_hook_script() {
        use std::io::Write;
        let mut ext = tempfile::NamedTempFile::new().unwrap();
        ext.write_all(b"#!/bin/bash\nrm -rf /tmp/sigil-3b3-cd\n")
            .unwrap();
        ext.flush().unwrap();
        let ext_path = ext.path().to_str().unwrap().to_string();

        let hooks_dir = std::path::PathBuf::from("/nonexistent/.continue/hooks");
        let settings = serde_json::json!({
            "slashCommands": [{
                "name": "lint",
                "step": ext_path
            }]
        });
        let mut out = Vec::new();
        emit_slash_command_reasons(&settings, &hooks_dir, &mut out);
        assert!(
            out.iter()
                .any(|r| matches!(r, AiGuardReason::DestructiveInHookScript { .. })),
            "expected DestructiveInHookScript for external slash command, got {out:?}"
        );
    }

    #[test]
    fn external_slash_command_safe_emits_nothing() {
        use std::io::Write;
        let mut ext = tempfile::NamedTempFile::new().unwrap();
        ext.write_all(b"#!/bin/bash\necho hi\n").unwrap();
        ext.flush().unwrap();
        let ext_path = ext.path().to_str().unwrap().to_string();

        let hooks_dir = std::path::PathBuf::from("/nonexistent/.continue/hooks");
        let settings = serde_json::json!({
            "slashCommands": [{
                "name": "lint",
                "step": ext_path
            }]
        });
        let mut out = Vec::new();
        emit_slash_command_reasons(&settings, &hooks_dir, &mut out);
        assert!(
            !out.iter().any(|r| matches!(
                r,
                AiGuardReason::DestructiveInHookScript { .. }
                    | AiGuardReason::ExternalScriptUnscanned { .. }
            )),
            "expected no hook-script reason for safe external slash command, got {out:?}"
        );
    }

    #[test]
    fn collect_external_script_paths_continue() {
        let hooks_dir = std::path::PathBuf::from("/nonexistent/.continue/hooks");
        let settings = serde_json::json!({
            "slashCommands": [
                {"name": "lint", "step": "/opt/sigil-tools/lint.sh"},
                {"name": "inline", "run": "echo hi"},
                {"name": "internal", "step": "/nonexistent/.continue/hooks/foo.sh"}
            ]
        });
        let mut paths = collect_external_script_paths_from_settings(&settings, &hooks_dir);
        paths.sort();
        let expected = vec![std::path::PathBuf::from("/opt/sigil-tools/lint.sh")];
        assert_eq!(paths, expected);
    }

    #[test]
    fn mcp_object_form_emits_local_command_reason() {
        let dir = tempdir().unwrap();
        write_config(
            dir.path(),
            r#"{"mcpServers": {"fs": {"command": "/tmp/x", "args": ["m.js"]}}}"#,
        );
        let reasons = ContinueDevParser.assess(dir.path()).unwrap();
        assert!(
            reasons.iter().any(|r| matches!(r,
            AiGuardReason::McpServerLocalCommand { server_name, .. } if server_name=="fs")),
            "expected McpServerLocalCommand in {reasons:?}"
        );
    }

    #[test]
    fn mcp_array_form_emits_local_command_reason() {
        let dir = tempdir().unwrap();
        write_config(
            dir.path(),
            r#"{"mcpServers": [{"name": "fs", "command": "/tmp/x", "args": ["m.js"]}]}"#,
        );
        let reasons = ContinueDevParser.assess(dir.path()).unwrap();
        assert!(reasons.iter().any(|r| matches!(r,
            AiGuardReason::McpServerLocalCommand { server_name, .. } if server_name=="fs")));
    }

    #[test]
    fn project_parser_corrupt_json_returns_parse_error() {
        let dir = tempdir().unwrap();
        let repo = dir.path();
        std::fs::create_dir_all(repo.join(".continue")).unwrap();
        std::fs::write(repo.join(".continue").join("config.json"), "{ not json").unwrap();
        let p = ContinueDevProjectParser {
            repo_root: repo.to_path_buf(),
        };
        let err = p.assess(std::path::Path::new("/unused")).unwrap_err();
        assert!(matches!(err, AssessError::Parse { .. }), "got {err:?}");
    }

    fn write_project_config(repo: &Path, body: &str) {
        let cd = repo.join(".continue");
        std::fs::create_dir_all(&cd).unwrap();
        std::fs::write(cd.join("config.json"), body).unwrap();
    }

    #[test]
    fn project_local_mcp_emits_auto_enabled() {
        // #154: a repo-committed local-command MCP server -> ProjectMcpAutoEnabled
        // (Continue auto-spawns it on workspace config load, no per-server prompt).
        let dir = tempdir().unwrap();
        write_project_config(
            dir.path(),
            r#"{"mcpServers": {"fs": {"command": "/tmp/x", "args": ["m.js"]}}}"#,
        );
        let out = ContinueDevProjectParser {
            repo_root: dir.path().to_path_buf(),
        }
        .assess(std::path::Path::new("/unused"))
        .unwrap();
        assert!(
            out.iter().any(|r| matches!(
                r, AiGuardReason::ProjectMcpAutoEnabled { mechanism }
                    if mechanism == "folder-trust autorun (default)"
            )),
            "got {out:?}"
        );
    }

    #[test]
    fn project_benign_remote_mcp_no_auto_enabled() {
        // #154: remote-only project MCP launches no local code -> no amplify.
        let dir = tempdir().unwrap();
        write_project_config(
            dir.path(),
            r#"{"mcpServers": {"r": {"url": "https://api.example/mcp"}}}"#,
        );
        let out = ContinueDevProjectParser {
            repo_root: dir.path().to_path_buf(),
        }
        .assess(std::path::Path::new("/unused"))
        .unwrap();
        assert!(
            !out.iter()
                .any(|r| matches!(r, AiGuardReason::ProjectMcpAutoEnabled { .. })),
            "benign remote must not amplify; got {out:?}"
        );
    }

    #[test]
    fn project_amplifier_ignores_non_mcp_destructive_reasons() {
        // #154: the amplifier keys only on MCP-derived reasons. A destructive
        // slash command alongside a benign remote-only MCP must NOT auto-enable.
        let dir = tempdir().unwrap();
        write_project_config(
            dir.path(),
            r#"{"mcpServers": {"r": {"url": "https://api.example/mcp"}},
                "slashCommands": [{"name": "danger", "run": "rm -rf /tmp/sigil-test"}]}"#,
        );
        let out = ContinueDevProjectParser {
            repo_root: dir.path().to_path_buf(),
        }
        .assess(std::path::Path::new("/unused"))
        .unwrap();
        // Sanity: the destructive slash-command reason IS present (test is real)…
        assert!(
            out.iter().any(|r| matches!(
                r, AiGuardReason::DestructiveInInlineCommand { hook_event, .. }
                    if hook_event == "slash_command"
            )),
            "fixture should produce a destructive slash-command reason; got {out:?}"
        );
        // …but it must NOT be mistaken for an auto-launching project MCP.
        assert!(
            !out.iter()
                .any(|r| matches!(r, AiGuardReason::ProjectMcpAutoEnabled { .. })),
            "destructive slash command (not MCP) must not trigger the amplifier; got {out:?}"
        );
    }
}
