//! Phase 3b.1 — per-tool parser trait. Each implementation reads a single
//! tool's user-global config and returns the assessed reasons.

pub mod antigravity;
pub mod claude_code;
pub mod claude_desktop;
pub mod codex;
pub mod continue_dev;
pub mod cursor;
pub mod gemini;
pub(crate) mod instruction_scan;
pub mod mcp_scan;

use serde_json::Value;
use sigil_core::event::{AiGuardReason, AiGuardScope, AiTool};
use std::io;
use std::path::{Path, PathBuf};

/// Per-tool guard-surface reader.
pub trait AiGuardParser: Send + Sync {
    /// Returns the tool identity this parser covers. Used by `ai_guard_task`
    /// to dispatch file_change events to the right parser and to tag the
    /// emitted `AiGuardRiskAssessed` events.
    fn tool(&self) -> AiTool;

    /// Returns the scope to tag emitted events with. CLI parsers (claude_code,
    /// codex) return `UserGlobal`; application-form parsers return
    /// `Application{app:"..."}`. Phase 3b.6.
    fn scope(&self) -> AiGuardScope;

    /// Path globs (canonical/expanded) the parser cares about. Used by
    /// `ai_guard_task` to decide whether an incoming file_change belongs to
    /// this parser.
    fn watched_paths(&self, home_dir: &Path) -> Vec<PathBuf>;

    /// Read current state from disk and return reasons. Empty Vec = clean.
    /// Missing primary config file = empty Vec (operator hasn't enabled the
    /// tool — not a finding). I/O / parse errors bubble up.
    fn assess(&self, home_dir: &Path) -> Result<Vec<AiGuardReason>, AssessError>;

    /// Phase 3b.7 — downcast hook for hot-reload reconciliation. Default
    /// returns a static unit reference; only RulePackParser overrides to
    /// return `self` so policy_reload_task can identify rule pack parsers
    /// and reconcile them by id. Existing hardcoded parsers don't need
    /// downcasting (they're identified structurally by tool+scope).
    fn as_any(&self) -> &dyn std::any::Any {
        &()
    }

    /// Phase 3b.3 — return the external (non-convention-dir) hook script paths
    /// referenced by this parser's config. Default: empty. Implementations
    /// re-read their config and extract path strings (caller will canonicalize).
    ///
    /// Called by runtime boot + policy_reload_task to populate
    /// `ExtScriptRegistry`. Paths are also pushed to `effective.targets` as
    /// synthetic WatchTarget entries so the OS watcher subscribes.
    fn collect_external_script_paths(
        &self,
        _home_dir: &std::path::Path,
    ) -> Vec<std::path::PathBuf> {
        Vec::new()
    }

    /// Phase 3b.7.2 — identity discriminator. None for built-in (structural)
    /// parsers; rule-pack parsers override to Some(pack id) so the assessment
    /// StateMap key and emitted event distinguish overlapping (tool, scope).
    fn rule_pack_id(&self) -> Option<&str> {
        None
    }

    /// Phase 3b.7.5 — human label for an `AiTool::Other` parser; None for built-ins
    /// and for Other parsers without a label. Stamped onto the emitted event.
    fn tool_label(&self) -> Option<&str> {
        None
    }
}

/// Read + parse a JSON config file with the AI Guard's "absent = clean"
/// convention. A missing file AND an empty / whitespace-only file both map to
/// `Ok(None)` — the operator hasn't configured anything, which is not a
/// finding. Non-empty malformed JSON is a real `Parse` error; I/O failures are
/// `Io`. Single source of truth so every JSON parser treats a 0-byte config
/// alike (#131).
pub(crate) fn read_json_optional(path: &Path) -> Result<Option<Value>, AssessError> {
    let text = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(AssessError::Io {
                path: path.to_path_buf(),
                source,
            })
        }
    };
    if text.trim().is_empty() {
        return Ok(None);
    }
    serde_json::from_str(&text)
        .map(Some)
        .map_err(|e| AssessError::Parse {
            path: path.to_path_buf(),
            message: e.to_string(),
        })
}

/// #146 — scan-size cap for instruction files. Regex scanning is linear, so we
/// keep a generous cap purely as a memory/DoS guard; real instruction files are
/// KB-sized. A larger file is itself anomalous and only its head is scanned.
const INSTRUCTION_FILE_SCAN_CAP: usize = 4 * 1024 * 1024;

/// Read a UTF-8 text file for content scanning. Symmetric with
/// `read_json_optional`: NotFound or empty/whitespace-only → `Ok(None)`; other
/// IO errors → `Err`. The returned string is capped at `INSTRUCTION_FILE_SCAN_CAP`
/// (truncated at a char boundary, with a warning).
pub(crate) fn read_text_optional(path: &Path) -> Result<Option<String>, AssessError> {
    let mut text = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(AssessError::Io {
                path: path.to_path_buf(),
                source,
            })
        }
    };
    if text.trim().is_empty() {
        return Ok(None);
    }
    if text.len() > INSTRUCTION_FILE_SCAN_CAP {
        let mut end = INSTRUCTION_FILE_SCAN_CAP;
        while end > 0 && !text.is_char_boundary(end) {
            end -= 1;
        }
        tracing::warn!(path = %path.display(), bytes = text.len(),
            "instruction file exceeds scan cap; scanning head only");
        text.truncate(end);
    }
    Ok(Some(text))
}

#[derive(Debug, thiserror::Error)]
pub enum AssessError {
    #[error("read {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("parse {path}: {message}")]
    Parse { path: PathBuf, message: String },
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn read_json_optional_missing_file_returns_none() {
        let d = tempdir().unwrap();
        let result = read_json_optional(&d.path().join("nonexistent.json"));
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn read_json_optional_empty_file_returns_none() {
        let d = tempdir().unwrap();
        let p = d.path().join("empty.json");
        std::fs::write(&p, "").unwrap();
        assert!(read_json_optional(&p).unwrap().is_none());
    }

    #[test]
    fn read_json_optional_whitespace_only_returns_none() {
        let d = tempdir().unwrap();
        let p = d.path().join("ws.json");
        std::fs::write(&p, "  \n\t ").unwrap();
        assert!(read_json_optional(&p).unwrap().is_none());
    }

    #[test]
    fn read_json_optional_valid_json_returns_some() {
        let d = tempdir().unwrap();
        let p = d.path().join("valid.json");
        std::fs::write(&p, r#"{"key": "value"}"#).unwrap();
        let val = read_json_optional(&p).unwrap().unwrap();
        assert_eq!(val.get("key").and_then(Value::as_str), Some("value"));
    }

    #[test]
    fn read_json_optional_nonempty_malformed_returns_parse_error() {
        let d = tempdir().unwrap();
        let p = d.path().join("bad.json");
        std::fs::write(&p, "{bad").unwrap();
        assert!(matches!(
            read_json_optional(&p).unwrap_err(),
            AssessError::Parse { .. }
        ));
    }

    #[test]
    fn read_text_optional_missing_returns_none() {
        let d = tempdir().unwrap();
        assert!(read_text_optional(&d.path().join("nope.md"))
            .unwrap()
            .is_none());
    }
    #[test]
    fn read_text_optional_empty_returns_none() {
        let d = tempdir().unwrap();
        let p = d.path().join("e.md");
        std::fs::write(&p, "   \n\t").unwrap();
        assert!(read_text_optional(&p).unwrap().is_none());
    }
    #[test]
    fn read_text_optional_reads_content() {
        let d = tempdir().unwrap();
        let p = d.path().join("c.md");
        std::fs::write(&p, "hello").unwrap();
        assert_eq!(read_text_optional(&p).unwrap().as_deref(), Some("hello"));
    }
}
