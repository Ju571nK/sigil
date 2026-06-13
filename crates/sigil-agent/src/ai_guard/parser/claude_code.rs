//! Phase 3b.1 — Claude Code parser. Reads `~/.claude/settings.json` (and
//! `settings.local.json` overlay if present), enumerates hooks + permissions
//! + mcp servers, and maps findings to `AiGuardReason`.

use crate::ai_guard::parser::{AiGuardParser, AssessError};
use crate::ai_guard::rubric;
use serde_json::Value;
use sigil_core::event::{AiGuardReason, AiGuardScope, AiTool};
use std::path::{Path, PathBuf};

pub struct ClaudeCodeParser;

impl AiGuardParser for ClaudeCodeParser {
    fn tool(&self) -> AiTool {
        AiTool::ClaudeCode
    }

    fn scope(&self) -> AiGuardScope {
        AiGuardScope::UserGlobal
    }

    fn watched_paths(&self, home_dir: &Path) -> Vec<PathBuf> {
        vec![
            home_dir.join(".claude").join("settings.json"),
            home_dir.join(".claude").join("settings.local.json"),
            home_dir.join(".claude").join("hooks"),
        ]
    }

    fn collect_external_script_paths(&self, home_dir: &Path) -> Vec<PathBuf> {
        let claude = home_dir.join(".claude");
        let base = super::read_json_optional(&claude.join("settings.json"))
            .ok()
            .flatten();
        let local = super::read_json_optional(&claude.join("settings.local.json"))
            .ok()
            .flatten();
        if base.is_none() && local.is_none() {
            return Vec::new();
        }
        let merged = merge_overlay(
            base.unwrap_or(serde_json::Value::Object(Default::default())),
            local,
        );
        let hooks_dir = claude.join("hooks");
        collect_external_script_paths_from_settings(&merged, &hooks_dir)
    }

    fn assess(&self, home_dir: &Path) -> Result<Vec<AiGuardReason>, AssessError> {
        let claude = home_dir.join(".claude");
        let base_path = claude.join("settings.json");
        let local_path = claude.join("settings.local.json");

        let base = super::read_json_optional(&base_path)?;
        let local = super::read_json_optional(&local_path)?;

        // Missing primary file with no overlay → operator hasn't enabled tool.
        if base.is_none() && local.is_none() {
            return Ok(Vec::new());
        }

        let merged = merge_overlay(base.unwrap_or(Value::Object(Default::default())), local);

        let hooks_dir = claude.join("hooks");
        let mut out = Vec::new();
        emit_hook_reasons(&merged, &hooks_dir, &mut out)?;
        emit_permission_reasons(&merged, &mut out);
        emit_mcp_reasons(&merged, &mut out);
        // #145 (codex C8) — a user-global `enableAllProjectMcpServers: true`
        // blanket-approves project MCP servers across EVERY repo. No single
        // repo context here, so emit on the key alone.
        if merged
            .get("enableAllProjectMcpServers")
            .and_then(Value::as_bool)
            == Some(true)
        {
            out.push(AiGuardReason::ProjectMcpAutoEnabled {
                mechanism: "user-global blanket: enableAllProjectMcpServers".to_string(),
            });
        }
        Ok(out)
    }
}

/// Shallow merge: top-level keys from `overlay` win over `base`. Adequate for
/// Claude's settings.json structure (permissions, hooks, mcpServers are each
/// either fully overridden or absent in the overlay).
pub(crate) fn merge_overlay(mut base: Value, overlay: Option<Value>) -> Value {
    let Some(overlay) = overlay else {
        return base;
    };
    if let (Value::Object(base_obj), Value::Object(over_obj)) = (&mut base, overlay) {
        for (k, v) in over_obj {
            base_obj.insert(k, v);
        }
    }
    base
}

pub(crate) fn emit_hook_reasons(
    settings: &Value,
    hooks_dir: &Path,
    out: &mut Vec<AiGuardReason>,
) -> Result<(), AssessError> {
    let Some(hooks) = settings.get("hooks").and_then(Value::as_object) else {
        return Ok(());
    };
    if hooks.is_empty() {
        // Empty `"hooks": {}` — no actual hook configured. Treat as "tool
        // present but no host-shell exposure"; not a NoSandbox finding.
        return Ok(());
    }
    // At least one hook event configured → host shell w/o sandbox.
    out.push(AiGuardReason::NoSandbox {
        executor: "host_shell".into(),
    });
    for (event_name, entries) in hooks {
        let Some(arr) = entries.as_array() else {
            continue;
        };
        for entry in arr {
            // matcher
            if let Some(matcher) = entry.get("matcher").and_then(Value::as_str) {
                if matcher.is_empty() || matcher == "*" || matcher == ".*" {
                    out.push(AiGuardReason::BroadMatcher {
                        hook_event: event_name.clone(),
                        matcher: matcher.to_string(),
                    });
                }
            }
            // commands
            let Some(inner) = entry.get("hooks").and_then(Value::as_array) else {
                continue;
            };
            for h in inner {
                let Some(cmd) = h.get("command").and_then(Value::as_str) else {
                    continue;
                };
                classify_command(cmd, event_name, hooks_dir, out)?;
            }
        }
    }
    Ok(())
}

/// Decide whether `cmd` is inline shell, a convention-dir script (we read it),
/// or an external script (we mark unscanned).
fn classify_command(
    cmd: &str,
    event_name: &str,
    hooks_dir: &Path,
    out: &mut Vec<AiGuardReason>,
) -> Result<(), AssessError> {
    // First token whitespace-separated. Treat as path candidate iff it looks
    // path-like cross-platform (Unix absolute / tilde / any separator, OR a
    // Windows absolute path like `C:\...` which `Path::is_absolute()` catches,
    // OR contains a backslash). Exclude shell metacharacters so things like
    // `./foo | bash` stay classified as inline. Issue #15 — Windows hook
    // commands like `C:\Users\alice\.claude\hooks\pre.sh` were previously
    // misclassified as inline because the original check only looked for `/`.
    let first_token = cmd.split_whitespace().next().unwrap_or("");
    let has_shell_meta = first_token.contains('|') || first_token.contains('&');
    let looks_pathish = !has_shell_meta
        && (std::path::Path::new(first_token).is_absolute()
            || first_token.starts_with('~')
            || first_token.contains('/')
            || first_token.contains('\\'));

    if looks_pathish {
        let candidate = std::path::PathBuf::from(first_token);
        if path_is_inside(&candidate, hooks_dir) {
            // 3b.3.1 — convention-dir script delegates to recursive walker
            // so sourced files inside the convention dir also get scanned.
            out.extend(crate::ai_guard::ext_script::scan_hook_script(
                &candidate, event_name,
            ));
        } else {
            // 3b.3.1 — external path also uses recursive walker.
            out.extend(crate::ai_guard::ext_script::scan_hook_script(
                &candidate, event_name,
            ));
        }
        return Ok(());
    }

    // Inline command — scan directly.
    if let Some(pat) = rubric::first_destructive_pattern(cmd) {
        out.push(AiGuardReason::DestructiveInInlineCommand {
            pattern: pat.to_string(),
            hook_event: event_name.to_string(),
            snippet: truncate_for_snippet(cmd),
        });
    }
    Ok(())
}

fn path_is_inside(candidate: &Path, root: &Path) -> bool {
    let c = dunce::canonicalize(candidate).unwrap_or_else(|_| candidate.to_path_buf());
    let r = dunce::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    c.starts_with(&r)
}

/// Phase 3b.3 — walk the `hooks` table of a Claude Code settings.json (or
/// merged settings+local overlay) and return every command path that's
/// classified as external (outside the convention hooks_dir). Caller is
/// responsible for canonicalizing the returned paths before registering.
pub(crate) fn collect_external_script_paths_from_settings(
    settings: &serde_json::Value,
    hooks_dir: &std::path::Path,
) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let Some(hooks) = settings.get("hooks").and_then(serde_json::Value::as_object) else {
        return out;
    };
    for (_event_name, entries) in hooks {
        let Some(entries_arr) = entries.as_array() else {
            continue;
        };
        for entry in entries_arr {
            let Some(inner) = entry.get("hooks").and_then(serde_json::Value::as_array) else {
                continue;
            };
            for h in inner {
                let Some(cmd) = h.get("command").and_then(serde_json::Value::as_str) else {
                    continue;
                };
                if let Some(p) = external_path_from_command(cmd, hooks_dir) {
                    out.push(p);
                }
            }
        }
    }
    out
}

/// Returns Some(path) if `cmd`'s first token is a path that lies OUTSIDE
/// `hooks_dir` (i.e., would be classified as external by `classify_command`).
/// Mirrors the path-detection logic of `classify_command` exactly.
fn external_path_from_command(
    cmd: &str,
    hooks_dir: &std::path::Path,
) -> Option<std::path::PathBuf> {
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
    let candidate = std::path::PathBuf::from(first_token);
    if path_is_inside(&candidate, hooks_dir) {
        None
    } else {
        Some(candidate)
    }
}

/// Truncate command for inclusion in evidence (max 80 chars, sanitize NULs).
fn truncate_for_snippet(s: &str) -> String {
    let cleaned: String = s.chars().filter(|c| *c != '\0').collect();
    cleaned.chars().take(80).collect()
}

pub(crate) fn emit_permission_reasons(settings: &Value, out: &mut Vec<AiGuardReason>) {
    let perms = match settings.get("permissions") {
        Some(p) => p,
        None => {
            // No `permissions` section at all. Only flag this as a finding if
            // the operator is actively using hooks (NON-empty hooks object) —
            // an empty `{}` settings file means "tool not really configured"
            // rather than "configured insecurely".
            let has_active_hooks = settings
                .get("hooks")
                .and_then(Value::as_object)
                .map(|m| !m.is_empty())
                .unwrap_or(false);
            if has_active_hooks {
                out.push(AiGuardReason::PermissionsDenyEmpty);
            }
            return;
        }
    };
    let deny_empty = match perms.get("deny") {
        None => true,
        Some(Value::Array(a)) => a.is_empty(),
        Some(_) => false,
    };
    if deny_empty {
        out.push(AiGuardReason::PermissionsDenyEmpty);
    }
    if let Some(allow) = perms.get("allow").and_then(Value::as_array) {
        for v in allow {
            if let Some(rule) = v.as_str() {
                if is_broad_allow(rule) {
                    out.push(AiGuardReason::PermissionsAllowBroad {
                        rule: rule.to_string(),
                    });
                }
            }
        }
    }
}

/// Claude Code permission rules are `Tool:matcher` (colon-delimited), so
/// breadth lives in the matcher position: bare `*`, `*:*`, or any rule whose
/// matcher is a wildcard (`:*` / `:.*`). This heuristic is intentionally
/// distinct from Gemini's `emit_tools_allowed` (issue #30): Gemini uses a
/// `tool(restriction)` paren format, not colon format, so a shared predicate
/// would not fit. Over-flagging is acceptable — Sigil measures, doesn't block.
fn is_broad_allow(rule: &str) -> bool {
    rule == "*" || rule == "*:*" || rule.ends_with(":*") || rule.ends_with(":.*")
}

pub(crate) fn emit_mcp_reasons(settings: &Value, out: &mut Vec<AiGuardReason>) {
    let Some(servers) = settings.get("mcpServers").and_then(Value::as_object) else {
        return;
    };
    for (name, def) in servers {
        super::mcp_scan::emit_one_server(name, def, out);
    }
}

/// #145 — emit MCP reasons from BOTH the merged settings `mcpServers` and the
/// committed project `<repo>/.mcp.json`, deduplicated by server name. A given
/// name connects once in Claude Code, so it must be scored once; settings
/// definitions take precedence (a `.mcp.json` server whose name already
/// appears in settings is skipped).
pub(crate) fn emit_project_mcp_reasons(
    settings: &Value,
    mcp_json: Option<&Value>,
    out: &mut Vec<AiGuardReason>,
) {
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    if let Some(servers) = settings.get("mcpServers").and_then(Value::as_object) {
        for (name, def) in servers {
            seen.insert(name.clone());
            super::mcp_scan::emit_one_server(name, def, out);
        }
    }
    if let Some(servers) = mcp_json
        .and_then(|v| v.get("mcpServers"))
        .and_then(Value::as_object)
    {
        for (name, def) in servers {
            if seen.insert(name.clone()) {
                super::mcp_scan::emit_one_server(name, def, out);
            }
        }
    }
}

/// #145 — does `<repo>/.mcp.json` define at least one project MCP server?
/// The auto-enable keys only matter when there is a payload for them to launch.
fn has_project_mcp_servers(mcp_json: Option<&Value>) -> bool {
    mcp_json
        .and_then(|v| v.get("mcpServers"))
        .and_then(Value::as_object)
        .map(|m| !m.is_empty())
        .unwrap_or(false)
}

/// #145 — the server-enable signal in committed settings that auto-launches
/// project `.mcp.json` servers on folder-trust, if any. `enableAllProjectMcpServers`
/// takes priority over `enabledMcpjsonServers`. NOTE: `permissions.allow:["mcp__*"]`
/// is NOT a trigger — that grants tool-call permission, not server pre-approval
/// (codex C4); a separate auto-approval signal is future work.
fn project_auto_enable_mechanism(settings: &Value) -> Option<&'static str> {
    if settings
        .get("enableAllProjectMcpServers")
        .and_then(Value::as_bool)
        == Some(true)
    {
        return Some("enableAllProjectMcpServers");
    }
    if settings
        .get("enabledMcpjsonServers")
        .and_then(Value::as_array)
        .map(|a| !a.is_empty())
        .unwrap_or(false)
    {
        return Some("enabledMcpjsonServers");
    }
    None
}

/// Phase 3b.6.2 — per-repo Claude Code parser. Spawned by runtime /
/// policy_reload after discovery; each instance carries its own repo
/// root and emits AiGuardRiskAssessed with scope=Project{path:repo_root}.
/// Reuses the user-global ClaudeCodeParser's overlay + emit helpers via
/// pub(crate) visibility — identical assessment logic, different root.
pub struct ClaudeCodeProjectParser {
    pub repo_root: PathBuf,
}

impl AiGuardParser for ClaudeCodeProjectParser {
    fn tool(&self) -> AiTool {
        AiTool::ClaudeCode
    }

    fn scope(&self) -> AiGuardScope {
        AiGuardScope::Project {
            path: self.repo_root.clone(),
        }
    }

    fn watched_paths(&self, _home_dir: &Path) -> Vec<PathBuf> {
        let cd = self.repo_root.join(".claude");
        vec![
            cd.join("settings.json"),
            cd.join("settings.local.json"),
            cd.join("hooks"),
            self.repo_root.join(".mcp.json"),
        ]
    }

    fn collect_external_script_paths(&self, _home_dir: &Path) -> Vec<PathBuf> {
        let claude = self.repo_root.join(".claude");
        let base = super::read_json_optional(&claude.join("settings.json"))
            .ok()
            .flatten();
        let local = super::read_json_optional(&claude.join("settings.local.json"))
            .ok()
            .flatten();
        if base.is_none() && local.is_none() {
            return Vec::new();
        }
        let merged = merge_overlay(
            base.unwrap_or(serde_json::Value::Object(Default::default())),
            local,
        );
        let hooks_dir = claude.join("hooks");
        collect_external_script_paths_from_settings(&merged, &hooks_dir)
    }

    fn assess(&self, _home_dir: &Path) -> Result<Vec<AiGuardReason>, AssessError> {
        let cd = self.repo_root.join(".claude");
        let base = super::read_json_optional(&cd.join("settings.json"))?;
        let local = super::read_json_optional(&cd.join("settings.local.json"))?;
        let mcp_json = super::read_json_optional(&self.repo_root.join(".mcp.json"))?;
        if base.is_none() && local.is_none() && mcp_json.is_none() {
            return Ok(Vec::new());
        }
        let merged = merge_overlay(base.unwrap_or(Value::Object(Default::default())), local);
        let hooks_dir = cd.join("hooks");
        let mut out = Vec::new();
        emit_hook_reasons(&merged, &hooks_dir, &mut out)?;
        emit_permission_reasons(&merged, &mut out);
        emit_project_mcp_reasons(&merged, mcp_json.as_ref(), &mut out);
        // #145 — auto-enable posture: emit ONLY when a server-enable key is
        // present AND the project actually ships `.mcp.json` servers for it
        // to launch (key-only with no payload -> no emit).
        if has_project_mcp_servers(mcp_json.as_ref()) {
            if let Some(mechanism) = project_auto_enable_mechanism(&merged) {
                out.push(AiGuardReason::ProjectMcpAutoEnabled {
                    mechanism: mechanism.to_string(),
                });
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigil_core::event::AiGuardReason;
    use tempfile::tempdir;

    fn write_settings(home: &Path, contents: &str) {
        let claude = home.join(".claude");
        std::fs::create_dir_all(&claude).unwrap();
        std::fs::write(claude.join("settings.json"), contents).unwrap();
    }

    fn write_file(dir: &Path, rel: &str, contents: &str) {
        let p = dir.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, contents).unwrap();
    }

    #[test]
    fn project_mcp_json_payload_scored() {
        let repo = tempdir().unwrap();
        write_file(
            repo.path(),
            ".mcp.json",
            r#"{ "mcpServers": { "x": { "command": "bash", "args": ["-c", "echo hi"] } } }"#,
        );
        let parser = ClaudeCodeProjectParser {
            repo_root: repo.path().to_path_buf(),
        };
        let out = parser.assess(repo.path()).unwrap();
        assert!(
            out.iter()
                .any(|r| matches!(r, AiGuardReason::McpServerSuspiciousLauncher { .. })),
            "expected #127 launcher reason from .mcp.json payload, got {out:?}"
        );
    }

    #[test]
    fn empty_config_is_clean() {
        let dir = tempdir().unwrap();
        write_settings(dir.path(), "");
        let p = ClaudeCodeParser;
        assert!(p.assess(dir.path()).unwrap().is_empty());
    }

    #[test]
    fn whitespace_config_is_clean() {
        let dir = tempdir().unwrap();
        write_settings(dir.path(), "  \n\t ");
        let p = ClaudeCodeParser;
        assert!(p.assess(dir.path()).unwrap().is_empty());
    }

    #[test]
    fn missing_settings_file_returns_empty_vec() {
        let dir = tempdir().unwrap();
        let p = ClaudeCodeParser;
        let reasons = p.assess(dir.path()).unwrap();
        assert!(reasons.is_empty(), "expected empty, got {reasons:?}");
    }

    #[test]
    fn empty_settings_object_returns_empty_vec() {
        let dir = tempdir().unwrap();
        write_settings(dir.path(), "{}");
        let p = ClaudeCodeParser;
        let reasons = p.assess(dir.path()).unwrap();
        assert!(reasons.is_empty(), "expected empty, got {reasons:?}");
    }

    #[test]
    fn hooks_with_destructive_inline_command_emits_destructive_and_no_sandbox() {
        let dir = tempdir().unwrap();
        write_settings(
            dir.path(),
            r#"{
              "hooks": {
                "PreToolUse": [
                  {"matcher": "Bash", "hooks": [
                    {"type": "command", "command": "rm -rf /tmp/sigil-test/*"}
                  ]}
                ]
              }
            }"#,
        );
        let p = ClaudeCodeParser;
        let reasons = p.assess(dir.path()).unwrap();
        assert!(
            reasons
                .iter()
                .any(|r| matches!(r, AiGuardReason::DestructiveInInlineCommand { .. })),
            "expected DestructiveInInlineCommand in {reasons:?}"
        );
        assert!(
            reasons
                .iter()
                .any(|r| matches!(r, AiGuardReason::NoSandbox { .. })),
            "expected NoSandbox in {reasons:?}"
        );
    }

    #[test]
    fn broad_matcher_dot_star_emits_broad_matcher() {
        let dir = tempdir().unwrap();
        write_settings(
            dir.path(),
            r#"{
              "hooks": {
                "PreToolUse": [
                  {"matcher": ".*", "hooks": [
                    {"type": "command", "command": "echo hi"}
                  ]}
                ]
              }
            }"#,
        );
        let p = ClaudeCodeParser;
        let reasons = p.assess(dir.path()).unwrap();
        assert!(
            reasons.iter().any(|r| matches!(
                r,
                AiGuardReason::BroadMatcher { matcher, .. } if matcher == ".*"
            )),
            "expected BroadMatcher in {reasons:?}"
        );
    }

    #[test]
    fn empty_matcher_string_also_treated_as_broad() {
        let dir = tempdir().unwrap();
        write_settings(
            dir.path(),
            r#"{
              "hooks": {
                "PreToolUse": [
                  {"matcher": "", "hooks": [
                    {"type": "command", "command": "echo hi"}
                  ]}
                ]
              }
            }"#,
        );
        let p = ClaudeCodeParser;
        let reasons = p.assess(dir.path()).unwrap();
        assert!(reasons.iter().any(|r| matches!(
            r,
            AiGuardReason::BroadMatcher { matcher, .. } if matcher.is_empty()
        )));
    }

    #[test]
    fn empty_deny_emits_permissions_deny_empty() {
        let dir = tempdir().unwrap();
        write_settings(dir.path(), r#"{"permissions": {"allow": [], "deny": []}}"#);
        let p = ClaudeCodeParser;
        let reasons = p.assess(dir.path()).unwrap();
        assert!(reasons
            .iter()
            .any(|r| matches!(r, AiGuardReason::PermissionsDenyEmpty)));
    }

    #[test]
    fn missing_deny_field_also_emits_permissions_deny_empty() {
        let dir = tempdir().unwrap();
        write_settings(dir.path(), r#"{"permissions": {"allow": ["Read"]}}"#);
        let p = ClaudeCodeParser;
        let reasons = p.assess(dir.path()).unwrap();
        assert!(reasons
            .iter()
            .any(|r| matches!(r, AiGuardReason::PermissionsDenyEmpty)));
    }

    #[test]
    fn wildcard_allow_emits_permissions_allow_broad() {
        let dir = tempdir().unwrap();
        write_settings(
            dir.path(),
            r#"{"permissions": {"allow": ["Bash:.*"], "deny": ["Foo"]}}"#,
        );
        let p = ClaudeCodeParser;
        let reasons = p.assess(dir.path()).unwrap();
        assert!(reasons.iter().any(|r| matches!(
            r,
            AiGuardReason::PermissionsAllowBroad { rule } if rule == "Bash:.*"
        )));
    }

    #[test]
    fn mcp_server_with_http_url_emits_remote() {
        let dir = tempdir().unwrap();
        write_settings(
            dir.path(),
            r#"{"mcpServers": {"acme": {"url": "https://mcp.example.com"}}}"#,
        );
        let p = ClaudeCodeParser;
        let reasons = p.assess(dir.path()).unwrap();
        assert!(reasons.iter().any(|r| matches!(
            r,
            AiGuardReason::McpServerRemote { server_name, url }
                if server_name == "acme" && url == "https://mcp.example.com"
        )));
    }

    #[test]
    fn mcp_server_with_command_only_does_not_emit_remote() {
        let dir = tempdir().unwrap();
        write_settings(
            dir.path(),
            r#"{"mcpServers": {"local": {"command": "/usr/local/bin/x"}}}"#,
        );
        let p = ClaudeCodeParser;
        let reasons = p.assess(dir.path()).unwrap();
        assert!(!reasons
            .iter()
            .any(|r| matches!(r, AiGuardReason::McpServerRemote { .. })));
        // #125: it must ALSO now emit the local-command baseline.
        assert!(
            reasons
                .iter()
                .any(|r| matches!(r, AiGuardReason::McpServerLocalCommand { .. })),
            "expected McpServerLocalCommand in {reasons:?}"
        );
    }

    #[test]
    fn external_script_path_emits_external_script_unscanned() {
        let dir = tempdir().unwrap();
        write_settings(
            dir.path(),
            r#"{
              "hooks": {
                "PreToolUse": [
                  {"matcher": "Bash", "hooks": [
                    {"type": "command", "command": "/usr/local/bin/foo.sh"}
                  ]}
                ]
              }
            }"#,
        );
        let p = ClaudeCodeParser;
        let reasons = p.assess(dir.path()).unwrap();
        assert!(reasons.iter().any(|r| matches!(
            r,
            AiGuardReason::ExternalScriptUnscanned { script_path, .. }
                if script_path.to_string_lossy() == "/usr/local/bin/foo.sh"
        )));
    }

    #[test]
    fn convention_hooks_dir_script_with_destructive_pattern_emits_in_hook_script() {
        let dir = tempdir().unwrap();
        let hooks_dir = dir.path().join(".claude").join("hooks");
        std::fs::create_dir_all(&hooks_dir).unwrap();
        let script = hooks_dir.join("pre.sh");
        std::fs::write(&script, "#!/bin/sh\nrm -rf /\n").unwrap();
        let cmd = format!("{} arg", script.display());
        write_settings(
            dir.path(),
            &format!(
                r#"{{
                  "hooks": {{
                    "PreToolUse": [
                      {{"matcher": "Bash", "hooks": [
                        {{"type": "command", "command": "{}"}}
                      ]}}
                    ]
                  }}
                }}"#,
                cmd.replace('\\', "\\\\")
            ),
        );
        let p = ClaudeCodeParser;
        let reasons = p.assess(dir.path()).unwrap();
        // 3b.3.1: scan_hook_script canonicalizes paths via dunce, so compare
        // with the canonical form of script (on macOS /tmp → /private/var/...).
        let script_canon = dunce::canonicalize(&script).unwrap_or(script.clone());
        assert!(
            reasons.iter().any(|r| matches!(
                r,
                AiGuardReason::DestructiveInHookScript { script_path, .. }
                    if script_path == &script_canon
            )),
            "expected DestructiveInHookScript in {reasons:?}"
        );
        // External-script reason should NOT fire for convention paths.
        assert!(
            !reasons
                .iter()
                .any(|r| matches!(r, AiGuardReason::ExternalScriptUnscanned { .. })),
            "convention path should not be marked external"
        );
    }

    #[test]
    fn broad_matcher_plain_star_emits_broad_matcher() {
        let dir = tempdir().unwrap();
        write_settings(
            dir.path(),
            r#"{
              "hooks": {
                "PreToolUse": [
                  {"matcher": "*", "hooks": [
                    {"type": "command", "command": "echo hi"}
                  ]}
                ]
              }
            }"#,
        );
        let p = ClaudeCodeParser;
        let reasons = p.assess(dir.path()).unwrap();
        assert!(
            reasons.iter().any(|r| matches!(
                r,
                AiGuardReason::BroadMatcher { matcher, .. } if matcher == "*"
            )),
            "expected BroadMatcher with matcher=\"*\" in {reasons:?}"
        );
    }

    #[test]
    fn empty_hooks_object_emits_no_findings() {
        let dir = tempdir().unwrap();
        write_settings(dir.path(), r#"{"hooks": {}}"#);
        let p = ClaudeCodeParser;
        let reasons = p.assess(dir.path()).unwrap();
        assert!(
            reasons.is_empty(),
            "empty hooks object should produce no findings, got {reasons:?}"
        );
    }

    #[test]
    fn corrupt_json_returns_parse_error() {
        let dir = tempdir().unwrap();
        write_settings(dir.path(), "{ not json");
        let p = ClaudeCodeParser;
        let err = p.assess(dir.path()).unwrap_err();
        assert!(matches!(err, AssessError::Parse { .. }), "got {err:?}");
    }

    #[test]
    fn settings_local_overlay_overrides_base() {
        let dir = tempdir().unwrap();
        let claude = dir.path().join(".claude");
        std::fs::create_dir_all(&claude).unwrap();
        // Base: clean.
        std::fs::write(
            claude.join("settings.json"),
            r#"{"permissions": {"allow": ["Read"], "deny": ["Bash"]}}"#,
        )
        .unwrap();
        // Local overlay: empty deny → should win.
        std::fs::write(
            claude.join("settings.local.json"),
            r#"{"permissions": {"deny": []}}"#,
        )
        .unwrap();
        let p = ClaudeCodeParser;
        let reasons = p.assess(dir.path()).unwrap();
        assert!(
            reasons
                .iter()
                .any(|r| matches!(r, AiGuardReason::PermissionsDenyEmpty)),
            "overlay's empty deny should produce PermissionsDenyEmpty in {reasons:?}"
        );
    }

    #[test]
    fn windows_style_backslash_path_is_classified_as_path_like() {
        // Regression test for issue #15: hook commands whose first token is a
        // Windows-style backslash path (e.g., `C:\Users\alice\.claude\hooks\pre.sh`)
        // must be classified as path-like so they go through the external-
        // script or convention-dir branch — NOT scanned as an inline command.
        //
        // Previously `looks_pathish` only checked for `/` and missed Windows
        // separators, so Windows hook scripts were silently never read.
        //
        // On a Unix test box, the backslash path doesn't exist as a real file
        // and won't canonicalize inside the tempdir's `hooks` dir. The
        // post-fix behavior is that it gets classified as an external script
        // (ExternalScriptUnscanned), proving the path-detection branch fired
        // rather than the inline branch.
        let dir = tempdir().unwrap();
        write_settings(
            dir.path(),
            r#"{
              "hooks": {
                "PreToolUse": [
                  {"matcher": "Bash", "hooks": [
                    {"type": "command", "command": "C:\\Users\\alice\\.claude\\hooks\\pre.sh"}
                  ]}
                ]
              }
            }"#,
        );
        let p = ClaudeCodeParser;
        let reasons = p.assess(dir.path()).unwrap();
        assert!(
            reasons.iter().any(|r| matches!(
                r,
                AiGuardReason::ExternalScriptUnscanned { script_path, .. }
                    if script_path.to_string_lossy().contains("Users")
                        && script_path.to_string_lossy().contains("pre.sh")
            )),
            "Windows-style backslash path must be classified as path-like \
             (and emit ExternalScriptUnscanned when outside the convention dir). \
             Got: {reasons:?}"
        );
        // Conversely, the path must NOT have been treated as inline shell —
        // a Windows path string contains no destructive regex matches, but if
        // the inline branch fired we'd be silently dropping the scan instead
        // of emitting the marker.
        assert!(
            !reasons
                .iter()
                .any(|r| matches!(r, AiGuardReason::DestructiveInInlineCommand { .. })),
            "Windows-style path must not be inline-scanned: {reasons:?}"
        );
    }

    #[test]
    fn project_parser_missing_settings_returns_empty() {
        let dir = tempdir().unwrap();
        let p = ClaudeCodeProjectParser {
            repo_root: dir.path().to_path_buf(),
        };
        assert!(p
            .assess(std::path::Path::new("/unused"))
            .unwrap()
            .is_empty());
    }

    #[test]
    fn project_parser_destructive_hook_in_repo_is_detected() {
        let dir = tempdir().unwrap();
        let repo = dir.path().join("repoX");
        let cd = repo.join(".claude");
        std::fs::create_dir_all(&cd).unwrap();
        std::fs::write(
            cd.join("settings.json"),
            r#"{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"rm -rf /tmp/sigil-3b6.2"}]}]}}"#,
        )
        .unwrap();
        let p = ClaudeCodeProjectParser { repo_root: repo };
        let reasons = p.assess(std::path::Path::new("/unused")).unwrap();
        assert!(reasons.iter().any(|r| matches!(
            r,
            AiGuardReason::DestructiveInInlineCommand { hook_event, .. }
                if hook_event == "PreToolUse"
        )));
    }

    #[test]
    fn project_parser_scope_is_project_with_repo_root_path() {
        let dir = tempdir().unwrap();
        let repo = dir.path().to_path_buf();
        let p = ClaudeCodeProjectParser {
            repo_root: repo.clone(),
        };
        assert_eq!(p.scope(), AiGuardScope::Project { path: repo });
    }

    #[test]
    fn project_parser_tool_is_claude_code() {
        let p = ClaudeCodeProjectParser {
            repo_root: std::path::PathBuf::from("/x"),
        };
        assert_eq!(p.tool(), AiTool::ClaudeCode);
    }

    #[test]
    fn project_parser_corrupt_settings_returns_parse_error() {
        let dir = tempdir().unwrap();
        let repo = dir.path();
        std::fs::create_dir_all(repo.join(".claude")).unwrap();
        std::fs::write(repo.join(".claude").join("settings.json"), "{ not json").unwrap();
        let p = ClaudeCodeProjectParser {
            repo_root: repo.to_path_buf(),
        };
        let err = p.assess(std::path::Path::new("/unused")).unwrap_err();
        assert!(matches!(err, AssessError::Parse { .. }), "got {err:?}");
    }

    #[test]
    fn external_script_destructive_emits_destructive_in_hook_script() {
        use std::io::Write;

        let mut ext = tempfile::NamedTempFile::new().unwrap();
        ext.write_all(b"#!/bin/bash\nrm -rf /tmp/sigil-3b3\n")
            .unwrap();
        ext.flush().unwrap();
        let ext_path = ext.path().to_path_buf();

        let hooks_dir = std::path::PathBuf::from("/nonexistent/.claude/hooks");
        let settings = serde_json::json!({
            "hooks": {
                "PreToolUse": [{
                    "hooks": [{
                        "type": "command",
                        "command": ext_path.to_str().unwrap()
                    }]
                }]
            }
        });
        let mut out = Vec::new();
        emit_hook_reasons(&settings, &hooks_dir, &mut out).unwrap();
        assert!(
            out.iter()
                .any(|r| matches!(r, AiGuardReason::DestructiveInHookScript { .. })),
            "expected DestructiveInHookScript for external script, got {out:?}"
        );
    }

    #[test]
    fn external_script_safe_emits_nothing() {
        use std::io::Write;
        let mut ext = tempfile::NamedTempFile::new().unwrap();
        ext.write_all(b"#!/bin/bash\necho hello\n").unwrap();
        ext.flush().unwrap();
        let ext_path = ext.path().to_path_buf();

        let hooks_dir = std::path::PathBuf::from("/nonexistent/.claude/hooks");
        let settings = serde_json::json!({
            "hooks": {
                "PreToolUse": [{
                    "hooks": [{
                        "type": "command",
                        "command": ext_path.to_str().unwrap()
                    }]
                }]
            }
        });
        let mut out = Vec::new();
        emit_hook_reasons(&settings, &hooks_dir, &mut out).unwrap();
        assert!(
            !out.iter().any(|r| matches!(
                r,
                AiGuardReason::DestructiveInHookScript { .. }
                    | AiGuardReason::ExternalScriptUnscanned { .. }
            )),
            "expected no hook-script reason for safe external script, got {out:?}"
        );
    }

    #[test]
    fn external_script_missing_emits_unscanned_fallback() {
        let hooks_dir = std::path::PathBuf::from("/nonexistent/.claude/hooks");
        let settings = serde_json::json!({
            "hooks": {
                "PreToolUse": [{
                    "hooks": [{
                        "type": "command",
                        "command": "/tmp/sigil-3b3-missing-script-abc123"
                    }]
                }]
            }
        });
        let mut out = Vec::new();
        emit_hook_reasons(&settings, &hooks_dir, &mut out).unwrap();
        assert!(
            out.iter()
                .any(|r| matches!(r, AiGuardReason::ExternalScriptUnscanned { .. })),
            "expected ExternalScriptUnscanned for missing external script, got {out:?}"
        );
    }

    #[test]
    fn mcp_local_command_emits_local_and_nosandbox() {
        let dir = tempdir().unwrap();
        write_settings(
            dir.path(),
            r#"{"mcpServers": {"local": {"command": "/tmp/payload", "args": ["x"]}}}"#,
        );
        let reasons = ClaudeCodeParser.assess(dir.path()).unwrap();
        assert!(
            reasons.iter().any(|r| matches!(r,
            AiGuardReason::McpServerLocalCommand { server_name, command }
                if server_name=="local" && command=="/tmp/payload")),
            "expected McpServerLocalCommand in {reasons:?}"
        );
        assert!(reasons.iter().any(|r| matches!(r,
            AiGuardReason::NoSandbox { executor } if executor=="mcp_command")));
    }

    #[test]
    fn mcp_url_normalization_uppercase_and_leading_space() {
        let dir = tempdir().unwrap();
        write_settings(
            dir.path(),
            r#"{"mcpServers": {"a": {"url": "HTTP://x"}, "b": {"url": "  https://y"}}}"#,
        );
        let reasons = ClaudeCodeParser.assess(dir.path()).unwrap();
        assert!(
            reasons.iter().any(|r| matches!(r,
                AiGuardReason::McpServerRemote { server_name, .. } if server_name == "a")),
            "uppercase-scheme server \"a\" should emit remote: {reasons:?}"
        );
        assert!(
            reasons.iter().any(|r| matches!(r,
                AiGuardReason::McpServerRemote { server_name, .. } if server_name == "b")),
            "leading-space server \"b\" should emit remote: {reasons:?}"
        );
    }

    #[test]
    fn user_scope_blanket_enable_emits_on_key_alone() {
        let home = tempdir().unwrap();
        write_settings(home.path(), r#"{ "enableAllProjectMcpServers": true }"#);
        let out = ClaudeCodeParser.assess(home.path()).unwrap();
        assert!(
            out.iter().any(|r| matches!(
                r, AiGuardReason::ProjectMcpAutoEnabled { mechanism }
                    if mechanism.starts_with("user-global blanket")
            )),
            "got {out:?}"
        );
    }

    #[test]
    fn auto_enable_key_with_servers_emits_high() {
        let repo = tempdir().unwrap();
        write_file(
            repo.path(),
            ".claude/settings.json",
            r#"{ "enableAllProjectMcpServers": true }"#,
        );
        write_file(
            repo.path(),
            ".mcp.json",
            r#"{ "mcpServers": { "x": { "command": "node", "args": ["/tmp/.x/p.js"] } } }"#,
        );
        let parser = ClaudeCodeProjectParser {
            repo_root: repo.path().to_path_buf(),
        };
        let out = parser.assess(repo.path()).unwrap();
        assert!(out.iter().any(|r| matches!(
            r, AiGuardReason::ProjectMcpAutoEnabled { mechanism } if mechanism == "enableAllProjectMcpServers"
        )), "got {out:?}");
    }

    #[test]
    fn auto_enable_key_without_servers_no_emit() {
        let repo = tempdir().unwrap();
        write_file(
            repo.path(),
            ".claude/settings.json",
            r#"{ "enableAllProjectMcpServers": true }"#,
        );
        let parser = ClaudeCodeProjectParser {
            repo_root: repo.path().to_path_buf(),
        };
        let out = parser.assess(repo.path()).unwrap();
        assert!(
            !out.iter()
                .any(|r| matches!(r, AiGuardReason::ProjectMcpAutoEnabled { .. })),
            "key with no .mcp.json payload must not emit; got {out:?}"
        );
    }

    #[test]
    fn enabled_mcpjson_servers_array_emits() {
        let repo = tempdir().unwrap();
        write_file(
            repo.path(),
            ".claude/settings.json",
            r#"{ "enabledMcpjsonServers": ["x"] }"#,
        );
        write_file(
            repo.path(),
            ".mcp.json",
            r#"{ "mcpServers": { "x": { "command": "node" } } }"#,
        );
        let parser = ClaudeCodeProjectParser {
            repo_root: repo.path().to_path_buf(),
        };
        let out = parser.assess(repo.path()).unwrap();
        assert!(out.iter().any(|r| matches!(
            r, AiGuardReason::ProjectMcpAutoEnabled { mechanism } if mechanism == "enabledMcpjsonServers"
        )), "got {out:?}");
    }

    #[test]
    fn permissions_allow_mcp_does_not_emit_auto_enabled() {
        // codex C4 regression guard: mcp__* tool-call permission is NOT a
        // server auto-enable signal.
        let repo = tempdir().unwrap();
        write_file(
            repo.path(),
            ".claude/settings.json",
            r#"{ "permissions": { "allow": ["mcp__x"] } }"#,
        );
        write_file(
            repo.path(),
            ".mcp.json",
            r#"{ "mcpServers": { "x": { "command": "node" } } }"#,
        );
        let parser = ClaudeCodeProjectParser {
            repo_root: repo.path().to_path_buf(),
        };
        let out = parser.assess(repo.path()).unwrap();
        assert!(
            !out.iter()
                .any(|r| matches!(r, AiGuardReason::ProjectMcpAutoEnabled { .. })),
            "got {out:?}"
        );
    }

    #[test]
    fn mcp_json_and_settings_dedup_by_name() {
        // codex C9: same server name in both settings and .mcp.json scores once.
        let repo = tempdir().unwrap();
        write_file(
            repo.path(),
            ".claude/settings.json",
            r#"{ "mcpServers": { "x": { "command": "node" } } }"#,
        );
        write_file(
            repo.path(),
            ".mcp.json",
            r#"{ "mcpServers": { "x": { "command": "node" } } }"#,
        );
        let parser = ClaudeCodeProjectParser {
            repo_root: repo.path().to_path_buf(),
        };
        let out = parser.assess(repo.path()).unwrap();
        let n = out.iter().filter(|r| matches!(
            r, AiGuardReason::McpServerLocalCommand { server_name, .. } if server_name == "x"
        )).count();
        assert_eq!(n, 1, "name dedup failed; got {out:?}");
    }

    #[test]
    fn collect_external_script_paths_helper_returns_path() {
        let settings = serde_json::json!({
            "hooks": {
                "PreToolUse": [{
                    "hooks": [{
                        "type": "command",
                        "command": "/opt/sigil-tools/pre.sh"
                    }]
                }]
            }
        });
        let hooks_dir = std::path::PathBuf::from("/nonexistent/.claude/hooks");
        let paths = collect_external_script_paths_from_settings(&settings, &hooks_dir);
        assert_eq!(
            paths,
            vec![std::path::PathBuf::from("/opt/sigil-tools/pre.sh")]
        );
    }

    #[test]
    fn project_parser_watches_mcp_json() {
        let repo = tempdir().unwrap();
        let parser = ClaudeCodeProjectParser {
            repo_root: repo.path().to_path_buf(),
        };
        let watched = parser.watched_paths(repo.path());
        assert!(
            watched.contains(&repo.path().join(".mcp.json")),
            "got {watched:?}"
        );
    }
}
