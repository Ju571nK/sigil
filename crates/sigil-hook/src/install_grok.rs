// Grok install. Unlike the JSON-settings agents in install.rs, Grok loads hooks
// from a dedicated JSON file at ~/.grok/hooks/sigil-hook.json — Grok's
// always-trusted native hook dir. This is a dedicated-file agent (like
// Antigravity), so it must NOT enter the shared-settings merge path.
//
// Canonical format (based on Grok's native hook dir):
//   ~/.grok/hooks/sigil-hook.json
//   { "hooks": { "PreToolUse": [ { "matcher": "", "hooks": [ { "type": "command", "command": "..." } ] } ] } }
//
// The matcher "" means match-all (equivalent to "*" in other agents).

use serde_json::{json, Value};
use std::io;
use std::path::{Path, PathBuf};

fn command_string(exe: &str, capture: &str, enforce: bool, on_failure: &str) -> String {
    if enforce {
        format!("{exe} grok --enforce --on-failure {on_failure} --capture {capture}")
    } else {
        format!("{exe} grok --capture {capture}")
    }
}

/// The full hook JSON written to ~/.grok/hooks/sigil-hook.json.
pub fn hook_json(exe: &str, capture: &str, enforce: bool, on_failure: &str) -> Value {
    json!({
        "hooks": {
            "PreToolUse": [{
                "matcher": "",
                "hooks": [{ "type": "command", "command": command_string(exe, capture, enforce, on_failure) }]
            }]
        }
    })
}

/// ~/.grok/hooks/sigil-hook.json (Grok's always-trusted global hook dir).
pub fn hook_file() -> Option<PathBuf> {
    crate::install::home_dir().map(|h| h.join(".grok").join("hooks").join("sigil-hook.json"))
}

/// Write `v` (pretty-printed JSON) to `path`, creating parent dirs as needed.
/// Idempotent: if the file already has identical content, no write occurs.
pub fn write_file_at(path: &Path, v: &Value) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let content = serde_json::to_string_pretty(v).map_err(io::Error::other)?;
    // Idempotent: skip the write if existing content is identical.
    if let Ok(existing) = std::fs::read_to_string(path) {
        if existing == content {
            return Ok(());
        }
    }
    std::fs::write(path, content.as_bytes())
}

/// Remove the sigil-hook.json file. If already absent, returns Ok (no error).
pub fn remove_file_at(path: &Path) -> io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hook_json_observe_renders_matcher_all_and_command() {
        let s = serde_json::to_string(&hook_json("/usr/bin/sigil-hook", "redacted", false, "open"))
            .unwrap();
        assert!(s.contains("\"PreToolUse\""));
        assert!(s.contains("\"matcher\":\"\""));
        assert!(s.contains("sigil-hook grok"));
        assert!(s.contains("--capture redacted"));
        assert!(!s.contains("--enforce"));
    }

    #[test]
    fn hook_json_enforce_includes_flags() {
        let s = serde_json::to_string(&hook_json("/usr/bin/sigil-hook", "redacted", true, "open"))
            .unwrap();
        assert!(s.contains("--enforce"));
        assert!(s.contains("--on-failure open"));
    }

    #[test]
    fn write_is_idempotent_and_uninstall_removes_only_our_file() {
        let tmp = tempfile::tempdir().unwrap();
        let f = tmp.path().join("sigil-hook.json");
        write_file_at(&f, &hook_json("x", "redacted", false, "open")).unwrap();
        let a = std::fs::read(&f).unwrap();
        write_file_at(&f, &hook_json("x", "redacted", false, "open")).unwrap();
        assert_eq!(a, std::fs::read(&f).unwrap()); // idempotent
        remove_file_at(&f).unwrap();
        assert!(!f.exists());
        remove_file_at(&f).unwrap(); // removing again = Ok (no error)
    }
}
