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

    fn assess(&self, home_dir: &Path) -> Result<Vec<AiGuardReason>, AssessError> {
        let claude = home_dir.join(".claude");
        let base_path = claude.join("settings.json");
        let local_path = claude.join("settings.local.json");

        let base = read_json_optional(&base_path)?;
        let local = read_json_optional(&local_path)?;

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
        Ok(out)
    }
}

/// Read + parse a JSON file, treating `NotFound` as `Ok(None)`.
fn read_json_optional(path: &Path) -> Result<Option<Value>, AssessError> {
    match std::fs::read_to_string(path) {
        Ok(s) => serde_json::from_str(&s)
            .map(Some)
            .map_err(|e| AssessError::Parse {
                path: path.to_path_buf(),
                message: e.to_string(),
            }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(AssessError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

/// Shallow merge: top-level keys from `overlay` win over `base`. Adequate for
/// Claude's settings.json structure (permissions, hooks, mcpServers are each
/// either fully overridden or absent in the overlay).
fn merge_overlay(mut base: Value, overlay: Option<Value>) -> Value {
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

fn emit_hook_reasons(
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
            // Convention dir → read script, scan for destructive patterns.
            match std::fs::read_to_string(&candidate) {
                Ok(contents) => {
                    if let Some(pat) = rubric::first_destructive_pattern(&contents) {
                        out.push(AiGuardReason::DestructiveInHookScript {
                            pattern: pat.to_string(),
                            hook_event: event_name.to_string(),
                            script_path: candidate.clone(),
                            snippet: snippet_around_match(&contents, pat),
                        });
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    // Script referenced but not present — quietly skip; the
                    // tool will fail to invoke at runtime, not our concern.
                }
                Err(source) => {
                    return Err(AssessError::Io {
                        path: candidate,
                        source,
                    });
                }
            }
        } else {
            out.push(AiGuardReason::ExternalScriptUnscanned {
                hook_event: event_name.to_string(),
                script_path: candidate,
            });
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

/// Truncate command for inclusion in evidence (max 80 chars, sanitize NULs).
fn truncate_for_snippet(s: &str) -> String {
    let cleaned: String = s.chars().filter(|c| *c != '\0').collect();
    cleaned.chars().take(80).collect()
}

/// Find the matching pattern in `contents` and return up to 80 chars of context
/// centered on the first match.
fn snippet_around_match(contents: &str, pattern: &str) -> String {
    if let Ok(re) = regex::Regex::new(pattern) {
        if let Some(m) = re.find(contents) {
            let start = m.start().saturating_sub(20);
            let end = (m.end() + 20).min(contents.len());
            return truncate_for_snippet(&contents[start..end]);
        }
    }
    truncate_for_snippet(contents)
}

fn emit_permission_reasons(settings: &Value, out: &mut Vec<AiGuardReason>) {
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

fn is_broad_allow(rule: &str) -> bool {
    rule == "*" || rule == "*:*" || rule.ends_with(":*") || rule.ends_with(":.*")
}

fn emit_mcp_reasons(settings: &Value, out: &mut Vec<AiGuardReason>) {
    let Some(servers) = settings.get("mcpServers").and_then(Value::as_object) else {
        return;
    };
    for (name, def) in servers {
        let Some(url) = def.get("url").and_then(Value::as_str) else {
            continue;
        };
        if url.starts_with("http://") || url.starts_with("https://") {
            out.push(AiGuardReason::McpServerRemote {
                server_name: name.clone(),
                url: url.to_string(),
            });
        }
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
        assert!(
            reasons.iter().any(|r| matches!(
                r,
                AiGuardReason::DestructiveInHookScript { script_path, .. }
                    if script_path == &script
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
}
