// Consumed by install/uninstall subcommands. Registers/deregisters the
// sigil-hook entry in each agent's config WITHOUT clobbering unrelated hooks.
//
// Agents differ in config path AND format (web-verified 2026-06):
//   - Claude Code / Codex: nested `hooks.PreToolUse[]` with
//     `{matcher, hooks:[{type:"command", command}]}`.
//       Claude Code: ~/.claude/settings.json
//       Codex:       ~/.codex/hooks.json   (also needs hooks enabled in
//                    ~/.codex/config.toml — surfaced as a note)
//   - Antigravity: TOP-LEVEL `PreToolUse[]` (same entry shape, no `hooks`
//     wrapper) in ~/.gemini/antigravity-cli/settings.json.
//   - Cursor: ~/.cursor/hooks.json with `version:1` + per-event arrays
//     (`beforeShellExecution`, `beforeMCPExecution`) of `{command}`.

use serde_json::{json, Value};
use std::io;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, PartialEq)]
enum HookFormat {
    /// `root.hooks.PreToolUse[]` — Claude Code, Codex.
    NestedPreToolUse,
    /// `root.PreToolUse[]` — Antigravity settings.json (top-level).
    TopLevelPreToolUse,
    /// `root.version` + `root.hooks.{beforeShellExecution,beforeMCPExecution}[]`.
    Cursor,
}

fn agent_format(agent: &str) -> Option<HookFormat> {
    match agent {
        "claude-code" | "codex" => Some(HookFormat::NestedPreToolUse),
        "antigravity" => Some(HookFormat::TopLevelPreToolUse),
        "cursor" => Some(HookFormat::Cursor),
        _ => None,
    }
}

const CURSOR_EVENTS: [&str; 2] = ["beforeShellExecution", "beforeMCPExecution"];

fn command_string(exe: &str, agent: &str, capture: &str) -> String {
    format!("{exe} {agent} --capture {capture}")
}

/// First whitespace token of a command string (= the binary path).
fn first_token(cmd: &str) -> &str {
    cmd.split_whitespace().next().unwrap_or("")
}

// --- Claude-style entry helpers (Nested + TopLevel share the entry shape) ---

fn claude_entry(cmd: &str) -> Value {
    json!({ "matcher": "*", "hooks": [{ "type": "command", "command": cmd }] })
}

/// The command of a Claude-style entry's first inner hook, if any.
fn claude_entry_cmd(entry: &Value) -> Option<&str> {
    entry
        .get("hooks")
        .and_then(|h| h.as_array())
        .and_then(|hooks| hooks.first())
        .and_then(|h| h.get("command"))
        .and_then(|c| c.as_str())
}

fn claude_entry_is_ours(entry: &Value, exe: &str) -> bool {
    entry
        .get("hooks")
        .and_then(|h| h.as_array())
        .map(|hooks| {
            hooks.iter().any(|h| {
                h.get("command")
                    .and_then(|c| c.as_str())
                    .map(|c| first_token(c) == exe)
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false)
}

/// Get-or-create the Claude-style PreToolUse array for the given location.
fn pretooluse_array_mut(root: &mut Value, nested: bool) -> &mut Vec<Value> {
    if !root.is_object() {
        *root = json!({});
    }
    if nested {
        if !root["hooks"].is_object() {
            root["hooks"] = json!({});
        }
        let h = &mut root["hooks"];
        if !h["PreToolUse"].is_array() {
            h["PreToolUse"] = json!([]);
        }
        h["PreToolUse"].as_array_mut().unwrap()
    } else {
        if !root["PreToolUse"].is_array() {
            root["PreToolUse"] = json!([]);
        }
        root["PreToolUse"].as_array_mut().unwrap()
    }
}

fn merge_claude(arr: &mut Vec<Value>, exe: &str, cmd: &str) -> bool {
    match arr.iter().position(|e| claude_entry_is_ours(e, exe)) {
        Some(i) => {
            if claude_entry_cmd(&arr[i]) == Some(cmd) {
                false
            } else {
                arr[i] = claude_entry(cmd);
                true
            }
        }
        None => {
            arr.push(claude_entry(cmd));
            true
        }
    }
}

// --- Cursor helpers ---

fn cursor_entry_is_ours(entry: &Value, exe: &str) -> bool {
    entry
        .get("command")
        .and_then(|c| c.as_str())
        .map(|c| first_token(c) == exe)
        .unwrap_or(false)
}

fn merge_cursor(root: &mut Value, exe: &str, cmd: &str) -> bool {
    if !root.is_object() {
        *root = json!({});
    }
    let mut changed = false;
    if root["version"].is_null() {
        root["version"] = json!(1);
        changed = true;
    }
    if !root["hooks"].is_object() {
        root["hooks"] = json!({});
    }
    for ev in CURSOR_EVENTS {
        let arr = {
            let h = &mut root["hooks"];
            if !h[ev].is_array() {
                h[ev] = json!([]);
            }
            h[ev].as_array_mut().unwrap()
        };
        match arr.iter().position(|e| cursor_entry_is_ours(e, exe)) {
            Some(i) => {
                if arr[i].get("command").and_then(|c| c.as_str()) != Some(cmd) {
                    arr[i] = json!({ "command": cmd });
                    changed = true;
                }
            }
            None => {
                arr.push(json!({ "command": cmd }));
                changed = true;
            }
        }
    }
    changed
}

// ---------------------------------------------------------------------------
// Public API (dispatched by agent format)
// ---------------------------------------------------------------------------

/// Human-pasteable block showing the settings fragment + undo hint.
pub fn render_block(exe: &str, agent: &str, capture: &str) -> String {
    let cmd = command_string(exe, agent, capture);
    let Some(fmt) = agent_format(agent) else {
        return format!("// unsupported agent '{agent}'\n");
    };
    let path = settings_path(agent)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| "<settings>".into());
    let fragment = match fmt {
        HookFormat::NestedPreToolUse => json!({ "hooks": { "PreToolUse": [claude_entry(&cmd)] } }),
        HookFormat::TopLevelPreToolUse => json!({ "PreToolUse": [claude_entry(&cmd)] }),
        HookFormat::Cursor => json!({
            "version": 1,
            "hooks": {
                "beforeShellExecution": [{ "command": cmd }],
                "beforeMCPExecution": [{ "command": cmd }],
            }
        }),
    };
    let pretty = serde_json::to_string_pretty(&fragment).unwrap_or_default();
    let note = if agent == "codex" {
        "// note: Codex also requires hooks enabled in ~/.codex/config.toml.\n"
    } else {
        ""
    };
    format!(
        "// Merge this into {path}:\n\
         {pretty}\n\
         {note}// remove with: sigil-hook uninstall --agent {agent} --write\n"
    )
}

/// Idempotently ensure the sigil-hook entry is present. Returns `true` if the
/// document was modified.
pub fn merge_into(root: &mut Value, exe: &str, agent: &str, capture: &str) -> bool {
    let cmd = command_string(exe, agent, capture);
    match agent_format(agent) {
        Some(HookFormat::NestedPreToolUse) => {
            merge_claude(pretooluse_array_mut(root, true), exe, &cmd)
        }
        Some(HookFormat::TopLevelPreToolUse) => {
            merge_claude(pretooluse_array_mut(root, false), exe, &cmd)
        }
        Some(HookFormat::Cursor) => merge_cursor(root, exe, &cmd),
        None => false,
    }
}

/// Remove every sigil-hook entry for `exe`. Returns `true` if anything was
/// removed. Leaves unrelated hooks untouched.
pub fn remove_from(root: &mut Value, exe: &str, agent: &str) -> bool {
    match agent_format(agent) {
        Some(HookFormat::NestedPreToolUse) | Some(HookFormat::TopLevelPreToolUse) => {
            let nested = agent_format(agent) == Some(HookFormat::NestedPreToolUse);
            let arr = if nested {
                root["hooks"]["PreToolUse"].as_array_mut()
            } else {
                root["PreToolUse"].as_array_mut()
            };
            match arr {
                Some(a) => {
                    let before = a.len();
                    a.retain(|e| !claude_entry_is_ours(e, exe));
                    a.len() < before
                }
                None => false,
            }
        }
        Some(HookFormat::Cursor) => {
            let mut removed = false;
            for ev in CURSOR_EVENTS {
                if let Some(a) = root["hooks"][ev].as_array_mut() {
                    let before = a.len();
                    a.retain(|e| !cursor_entry_is_ours(e, exe));
                    removed |= a.len() < before;
                }
            }
            removed
        }
        None => false,
    }
}

/// Count sigil-hook entries for `exe` (across all relevant arrays).
pub fn count_sigil_entries(root: &Value, exe: &str, agent: &str) -> usize {
    match agent_format(agent) {
        Some(HookFormat::NestedPreToolUse) => root["hooks"]["PreToolUse"]
            .as_array()
            .map(|a| a.iter().filter(|e| claude_entry_is_ours(e, exe)).count())
            .unwrap_or(0),
        Some(HookFormat::TopLevelPreToolUse) => root["PreToolUse"]
            .as_array()
            .map(|a| a.iter().filter(|e| claude_entry_is_ours(e, exe)).count())
            .unwrap_or(0),
        Some(HookFormat::Cursor) => CURSOR_EVENTS
            .iter()
            .map(|ev| {
                root["hooks"][*ev]
                    .as_array()
                    .map(|a| a.iter().filter(|e| cursor_entry_is_ours(e, exe)).count())
                    .unwrap_or(0)
            })
            .sum(),
        None => 0,
    }
}

/// `$XDG_STATE_HOME/sigil` or `$HOME/.local/state/sigil`.
pub fn state_dir() -> PathBuf {
    if let Ok(base) = std::env::var("XDG_STATE_HOME") {
        PathBuf::from(base).join("sigil")
    } else {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        PathBuf::from(home).join(".local/state/sigil")
    }
}

/// Map agent name → absolute path to its hook config file.
pub fn settings_path(agent: &str) -> Option<PathBuf> {
    let home = PathBuf::from(std::env::var("HOME").ok()?);
    let p = match agent {
        "claude-code" => home.join(".claude/settings.json"),
        "codex" => home.join(".codex/hooks.json"),
        "cursor" => home.join(".cursor/hooks.json"),
        "antigravity" => home.join(".gemini/antigravity-cli/settings.json"),
        _ => return None,
    };
    Some(p)
}

/// Write `state_dir()/hook-registration.json` + append to the discovery index.
pub fn write_baseline(
    agent: &str,
    settings_path: &std::path::Path,
    exe: &str,
    agent_arg: &str,
    capture: &str,
    matcher: &str,
) -> io::Result<()> {
    let dir = state_dir();
    std::fs::create_dir_all(&dir)?;

    let cmd = command_string(exe, agent_arg, capture);
    let block_hash = blake3::hash(cmd.as_bytes()).to_hex().to_string();
    let written_at_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let settings_path_str = settings_path.to_string_lossy().to_string();

    let baseline = json!({
        "agent": agent,
        "settings_path": settings_path_str,
        "command": cmd,
        "capture": capture,
        "matcher": matcher,
        "block_hash": block_hash,
        "written_at_unix": written_at_unix,
    });

    let reg_path = dir.join("hook-registration.json");
    let pretty = serde_json::to_string_pretty(&baseline).map_err(io::Error::other)?;
    std::fs::write(&reg_path, pretty.as_bytes())?;

    let index_path = dir.join("hook-index.json");
    let mut entries: Vec<String> = if index_path.exists() {
        let raw = std::fs::read(&index_path)?;
        serde_json::from_slice::<Vec<String>>(&raw).unwrap_or_default()
    } else {
        Vec::new()
    };
    if !entries.contains(&settings_path_str) {
        entries.push(settings_path_str);
        let json = serde_json::to_string_pretty(&entries).map_err(io::Error::other)?;
        std::fs::write(&index_path, json.as_bytes())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Claude Code (nested) ---
    #[test]
    fn render_block_has_abs_path_and_capture() {
        let s = render_block("/abs/sigil-hook", "claude-code", "redacted");
        assert!(s.contains("/abs/sigil-hook claude-code --capture redacted"));
        assert!(s.contains("PreToolUse"));
    }
    #[test]
    fn nested_merge_empty_idempotent_update() {
        let mut v = json!({});
        assert!(merge_into(
            &mut v,
            "/abs/sigil-hook",
            "claude-code",
            "redacted"
        ));
        assert!(!merge_into(
            &mut v,
            "/abs/sigil-hook",
            "claude-code",
            "redacted"
        ));
        assert_eq!(count_sigil_entries(&v, "/abs/sigil-hook", "claude-code"), 1);
        // capture change updates in place
        assert!(merge_into(&mut v, "/abs/sigil-hook", "claude-code", "raw"));
        assert_eq!(count_sigil_entries(&v, "/abs/sigil-hook", "claude-code"), 1);
        let s = serde_json::to_string(&v).unwrap();
        assert!(s.contains("--capture raw") && !s.contains("--capture redacted"));
    }
    #[test]
    fn nested_remove_preserves_foreign() {
        let mut v = json!({"hooks":{"PreToolUse":[
            {"matcher":"*","hooks":[{"type":"command","command":"/other/tool run"}]}
        ]}});
        merge_into(&mut v, "/abs/sigil-hook", "claude-code", "redacted");
        assert!(remove_from(&mut v, "/abs/sigil-hook", "claude-code"));
        assert_eq!(count_sigil_entries(&v, "/abs/sigil-hook", "claude-code"), 0);
        assert!(serde_json::to_string(&v)
            .unwrap()
            .contains("/other/tool run"));
    }

    // --- Codex (nested, ~/.codex/hooks.json) ---
    #[test]
    fn codex_uses_nested_and_notes_config_toml() {
        let s = render_block("/abs/sigil-hook", "codex", "redacted");
        assert!(s.contains("/abs/sigil-hook codex --capture redacted"));
        // Path-separator-agnostic: PathBuf renders `\` on Windows.
        assert!(s.contains("codex") && s.contains("hooks.json"));
        assert!(s.contains("config.toml"));
        let mut v = json!({});
        assert!(merge_into(&mut v, "/abs/sigil-hook", "codex", "redacted"));
        assert_eq!(count_sigil_entries(&v, "/abs/sigil-hook", "codex"), 1);
        assert!(v["hooks"]["PreToolUse"].is_array());
    }

    // --- Antigravity (top-level PreToolUse) ---
    #[test]
    fn antigravity_uses_top_level_pretooluse() {
        let mut v = json!({});
        assert!(merge_into(
            &mut v,
            "/abs/sigil-hook",
            "antigravity",
            "redacted"
        ));
        // top-level, NOT under hooks
        assert!(v["PreToolUse"].is_array());
        assert!(v["hooks"].is_null());
        assert_eq!(count_sigil_entries(&v, "/abs/sigil-hook", "antigravity"), 1);
        assert!(!merge_into(
            &mut v,
            "/abs/sigil-hook",
            "antigravity",
            "redacted"
        ));
        assert!(remove_from(&mut v, "/abs/sigil-hook", "antigravity"));
        assert_eq!(count_sigil_entries(&v, "/abs/sigil-hook", "antigravity"), 0);
    }

    // --- Cursor (version + two event arrays) ---
    #[test]
    fn cursor_registers_both_events_with_version() {
        let mut v = json!({});
        assert!(merge_into(&mut v, "/abs/sigil-hook", "cursor", "redacted"));
        assert_eq!(v["version"], json!(1));
        assert!(v["hooks"]["beforeShellExecution"].is_array());
        assert!(v["hooks"]["beforeMCPExecution"].is_array());
        // one entry per event = 2 total
        assert_eq!(count_sigil_entries(&v, "/abs/sigil-hook", "cursor"), 2);
        assert!(!merge_into(&mut v, "/abs/sigil-hook", "cursor", "redacted"));
        let s = render_block("/abs/sigil-hook", "cursor", "redacted");
        assert!(s.contains("beforeShellExecution") && s.contains("beforeMCPExecution"));
    }
    #[test]
    fn cursor_remove_preserves_foreign() {
        let mut v = json!({"version":1,"hooks":{"beforeShellExecution":[
            {"command":"/other/guard.sh"}
        ]}});
        merge_into(&mut v, "/abs/sigil-hook", "cursor", "redacted");
        assert!(remove_from(&mut v, "/abs/sigil-hook", "cursor"));
        assert_eq!(count_sigil_entries(&v, "/abs/sigil-hook", "cursor"), 0);
        assert!(serde_json::to_string(&v)
            .unwrap()
            .contains("/other/guard.sh"));
    }

    #[test]
    fn unsupported_agent_paths() {
        assert!(settings_path("nope").is_none());
        assert_eq!(count_sigil_entries(&json!({}), "/x", "nope"), 0);
    }
}
