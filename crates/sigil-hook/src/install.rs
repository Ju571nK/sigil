// Consumed by install/uninstall subcommands. Writes and reads Claude Code's
// ~/.claude/settings.json to register/deregister the sigil-hook PreToolUse
// entry without clobbering unrelated hooks.

use serde_json::Value;
use std::io;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// Helper: build the command string
// ---------------------------------------------------------------------------

fn command_string(exe: &str, agent: &str, capture: &str) -> String {
    format!("{exe} {agent} --capture {capture}")
}

// ---------------------------------------------------------------------------
// Helper: first whitespace token of a command string (= the binary path)
// ---------------------------------------------------------------------------

fn first_token(cmd: &str) -> &str {
    cmd.split_whitespace().next().unwrap_or("")
}

// ---------------------------------------------------------------------------
// Public: render a human-pasteable block showing the settings fragment
// ---------------------------------------------------------------------------

/// Returns a comment + pretty-printed JSON fragment that the operator can
/// paste into ~/.claude/settings.json, plus an undo hint.
pub fn render_block(exe: &str, agent: &str, capture: &str) -> String {
    let cmd = command_string(exe, agent, capture);
    let entry = serde_json::json!({
        "matcher": "*",
        "hooks": [{ "type": "command", "command": cmd }]
    });
    let fragment = serde_json::json!({
        "hooks": {
            "PreToolUse": [entry]
        }
    });
    let pretty = serde_json::to_string_pretty(&fragment).unwrap_or_default();
    format!(
        "// Merge this into ~/.claude/settings.json under \"hooks\":\n\
         {pretty}\n\
         // remove with: sigil-hook uninstall --agent {agent} --write\n"
    )
}

// ---------------------------------------------------------------------------
// Public: merge our entry into a settings Value (idempotent)
// ---------------------------------------------------------------------------

/// Ensure `root["hooks"]["PreToolUse"]` contains exactly one sigil-hook entry
/// for `exe`. Returns `true` if the document was modified, `false` if it was
/// already up-to-date (idempotent no-op).
pub fn merge_into(root: &mut Value, exe: &str, agent: &str, capture: &str) -> bool {
    let cmd = command_string(exe, agent, capture);

    // Ensure root is an object.
    if !root.is_object() {
        *root = serde_json::json!({});
    }

    // Ensure root["hooks"] is an object.
    if root["hooks"].is_null() || !root["hooks"].is_object() {
        root["hooks"] = serde_json::json!({});
    }

    // Ensure root["hooks"]["PreToolUse"] is an array.
    if root["hooks"]["PreToolUse"].is_null() || !root["hooks"]["PreToolUse"].is_array() {
        root["hooks"]["PreToolUse"] = serde_json::json!([]);
    }

    let arr = root["hooks"]["PreToolUse"]
        .as_array_mut()
        .expect("just ensured it's an array");

    // Search for an existing entry whose command first-token == exe.
    let existing_idx = arr.iter().position(|entry| {
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
    });

    let new_entry = serde_json::json!({
        "matcher": "*",
        "hooks": [{ "type": "command", "command": cmd }]
    });

    if let Some(idx) = existing_idx {
        // Check if the existing entry's command already matches exactly.
        let existing_cmd = arr[idx]
            .get("hooks")
            .and_then(|h| h.as_array())
            .and_then(|hooks| hooks.first())
            .and_then(|h| h.get("command"))
            .and_then(|c| c.as_str())
            .unwrap_or("");

        if existing_cmd == cmd {
            // Already up-to-date — idempotent no-op.
            return false;
        }
        // Update in-place.
        arr[idx] = new_entry;
        true
    } else {
        // Not found — push.
        arr.push(new_entry);
        true
    }
}

// ---------------------------------------------------------------------------
// Public: remove sigil-hook entries from PreToolUse
// ---------------------------------------------------------------------------

/// Remove every PreToolUse entry whose command first-token == `exe`. Returns
/// `true` if anything was removed. Leaves unrelated hooks untouched.
pub fn remove_from(root: &mut Value, exe: &str) -> bool {
    let arr = match root["hooks"]["PreToolUse"].as_array_mut() {
        Some(a) => a,
        None => return false,
    };

    let before = arr.len();
    arr.retain(|entry| {
        !entry
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
    });
    arr.len() < before
}

// ---------------------------------------------------------------------------
// Public: paths
// ---------------------------------------------------------------------------

/// Returns `$XDG_STATE_HOME/sigil` or `$HOME/.local/state/sigil`.
pub fn state_dir() -> PathBuf {
    if let Ok(base) = std::env::var("XDG_STATE_HOME") {
        PathBuf::from(base).join("sigil")
    } else {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        PathBuf::from(home).join(".local/state/sigil")
    }
}

/// Map agent name → absolute path to its settings file.
/// Currently only `claude-code` is supported; returns None for unknown agents.
pub fn settings_path(agent: &str) -> Option<PathBuf> {
    match agent {
        "claude-code" => {
            let home = std::env::var("HOME").ok()?;
            Some(PathBuf::from(home).join(".claude/settings.json"))
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Public: write baseline + update discovery index
// ---------------------------------------------------------------------------

/// Write `state_dir()/hook-registration.json` with metadata about the
/// installed hook, and append the absolute `settings_path` to the discovery
/// index at `state_dir()/hook-index.json` (deduplicated).
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

    let baseline = serde_json::json!({
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

    // Read-modify-write the index (deduped).
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

// ---------------------------------------------------------------------------
// Count helper — used by tests AND by callers
// ---------------------------------------------------------------------------

/// Count entries in `root["hooks"]["PreToolUse"]` whose command first-token == `exe`.
pub fn count_sigil_entries(root: &Value, exe: &str) -> usize {
    root["hooks"]["PreToolUse"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter(|entry| {
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
                })
                .count()
        })
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Tests (Step 1 — written first, before implementation is wired in)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn render_block_has_abs_path_and_capture() {
        let s = render_block("/abs/sigil-hook", "claude-code", "redacted");
        assert!(s.contains("/abs/sigil-hook claude-code --capture redacted"));
        assert!(s.contains("PreToolUse"));
    }
    #[test]
    fn merge_into_empty_adds_entry() {
        let mut v = json!({});
        assert!(merge_into(
            &mut v,
            "/abs/sigil-hook",
            "claude-code",
            "redacted"
        ));
        assert_eq!(count_sigil_entries(&v, "/abs/sigil-hook"), 1);
    }
    #[test]
    fn merge_into_is_idempotent() {
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
        )); // no change
        assert_eq!(count_sigil_entries(&v, "/abs/sigil-hook"), 1);
    }
    #[test]
    fn merge_into_updates_capture_in_place() {
        let mut v = json!({});
        merge_into(&mut v, "/abs/sigil-hook", "claude-code", "redacted");
        assert!(merge_into(&mut v, "/abs/sigil-hook", "claude-code", "raw")); // changed
        assert_eq!(count_sigil_entries(&v, "/abs/sigil-hook"), 1);
        // the command now says --capture raw
        let s = serde_json::to_string(&v).unwrap();
        assert!(s.contains("--capture raw"));
        assert!(!s.contains("--capture redacted"));
    }
    #[test]
    fn remove_from_removes_only_sigil_and_preserves_foreign() {
        let mut v = json!({"hooks":{"PreToolUse":[
            {"matcher":"*","hooks":[{"type":"command","command":"/other/tool run"}]}
        ]}});
        merge_into(&mut v, "/abs/sigil-hook", "claude-code", "redacted");
        assert_eq!(count_sigil_entries(&v, "/abs/sigil-hook"), 1);
        assert!(remove_from(&mut v, "/abs/sigil-hook"));
        assert_eq!(count_sigil_entries(&v, "/abs/sigil-hook"), 0);
        // foreign hook still present:
        let s = serde_json::to_string(&v).unwrap();
        assert!(s.contains("/other/tool run"));
    }
}
