//! Phase 3b.3 — external hook-script content scanning.
//!
//! Reads a script at an arbitrary filesystem path (caller pre-canonicalizes),
//! enforces 256 KB read cap + binary detection, and runs the existing
//! destructive-pattern rubric over the contents. Returns
//! `DestructiveInHookScript` when a pattern matches, or
//! `ExternalScriptUnscanned` as fallback when content can't be safely scanned.
//!
//! Pure-fn, parser-independent. Used by claude_code, codex, continue_dev
//! parsers wherever they detect an external-path hook command.

use std::path::Path;

use sigil_core::event::AiGuardReason;

use crate::ai_guard::rubric;

/// Max bytes read from any external hook script. Chosen to comfortably cover
/// real-world hook scripts (most <10 KB) while preventing DoS via attacker
/// placing a multi-GB file at a configured hook path.
pub const MAX_READ_BYTES: usize = 256 * 1024;

/// Sample size for binary detection — first chunk of the file.
pub const BINARY_DETECT_PREFIX_BYTES: usize = 1024;

/// Heuristic binary detection. Returns true if the prefix contains a NUL byte
/// OR more than 30% of bytes fall outside the printable ASCII range
/// (0x09-0x0d tab/LF/CR, 0x20-0x7e printable).
pub fn looks_binary(prefix: &[u8]) -> bool {
    if prefix.contains(&0u8) {
        return true;
    }
    if prefix.is_empty() {
        return false;
    }
    let non_printable = prefix
        .iter()
        .filter(|b| !matches!(**b, 0x09..=0x0d | 0x20..=0x7e))
        .count();
    (non_printable * 100) > (prefix.len() * 30)
}

/// Read at most `MAX_READ_BYTES` from `path`, detect binary, and run the
/// destructive-pattern rubric. Caller must have already canonicalized `path`.
/// `hook_event` is forwarded into the emitted reason.
///
/// Returns:
/// - `Some(DestructiveInHookScript { .. })` — content read, pattern matched
/// - `Some(ExternalScriptUnscanned { .. })` — fallback (unreadable, too big,
///    binary, or I/O error)
/// - `None` — content read and clean (no destructive pattern; no emission)
pub fn scan_external_script(path: &Path, hook_event: &str) -> Option<AiGuardReason> {
    use std::io::Read;

    let mut file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => {
            return Some(AiGuardReason::ExternalScriptUnscanned {
                hook_event: hook_event.to_string(),
                script_path: path.to_path_buf(),
            });
        }
    };

    // Read up to MAX_READ_BYTES + 1 so we can detect "exceeds cap" precisely.
    let mut buf = Vec::with_capacity(MAX_READ_BYTES.min(8192));
    if file
        .by_ref()
        .take((MAX_READ_BYTES as u64) + 1)
        .read_to_end(&mut buf)
        .is_err()
    {
        return Some(AiGuardReason::ExternalScriptUnscanned {
            hook_event: hook_event.to_string(),
            script_path: path.to_path_buf(),
        });
    }

    if buf.len() > MAX_READ_BYTES {
        return Some(AiGuardReason::ExternalScriptUnscanned {
            hook_event: hook_event.to_string(),
            script_path: path.to_path_buf(),
        });
    }

    let prefix_len = buf.len().min(BINARY_DETECT_PREFIX_BYTES);
    if looks_binary(&buf[..prefix_len]) {
        return Some(AiGuardReason::ExternalScriptUnscanned {
            hook_event: hook_event.to_string(),
            script_path: path.to_path_buf(),
        });
    }

    let contents = String::from_utf8_lossy(&buf);
    if let Some(pat) = rubric::first_destructive_pattern(&contents) {
        return Some(AiGuardReason::DestructiveInHookScript {
            pattern: pat.to_string(),
            hook_event: hook_event.to_string(),
            script_path: path.to_path_buf(),
            snippet: snippet_around_match(&contents, pat),
        });
    }

    None
}

fn snippet_around_match(contents: &str, pattern: &str) -> String {
    if let Ok(re) = regex::Regex::new(pattern) {
        if let Some(m) = re.find(contents) {
            let start = m.start().saturating_sub(20);
            let end = (m.end() + 20).min(contents.len());
            // Snap to UTF-8 char boundaries (rare with byte arithmetic but cheap).
            let start = (start..=m.start())
                .rev()
                .find(|i| contents.is_char_boundary(*i))
                .unwrap_or(0);
            let end = (end..=contents.len())
                .find(|i| contents.is_char_boundary(*i))
                .unwrap_or(contents.len());
            return truncate_for_snippet(&contents[start..end]);
        }
    }
    truncate_for_snippet(contents)
}

/// UTF-8 char-boundary-safe truncate to ~80 chars. Mirrors the helper used by
/// the claude_code parser.
fn truncate_for_snippet(s: &str) -> String {
    s.chars().take(80).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn tempfile_with(contents: &[u8]) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(contents).unwrap();
        f.flush().unwrap();
        f
    }

    #[test]
    fn happy_path_destructive() {
        let f = tempfile_with(b"#!/bin/bash\nrm -rf /tmp/foo\n");
        let r = scan_external_script(f.path(), "PreToolUse");
        match r {
            Some(AiGuardReason::DestructiveInHookScript {
                pattern,
                hook_event,
                snippet,
                ..
            }) => {
                // `first_destructive_pattern` returns the regex source string,
                // not a literal — match the existing rubric contract.
                assert!(
                    pattern.contains("rm") && pattern.contains("[rR][fF]"),
                    "expected rm-rf regex pattern, got {pattern:?}"
                );
                assert_eq!(hook_event, "PreToolUse");
                // Snippet must actually contain the matched destructive content,
                // proving the regex-based span lookup works (not naive substring).
                assert!(
                    snippet.contains("rm -rf"),
                    "snippet should contain matched destructive text, got: {snippet:?}"
                );
            }
            other => panic!("expected DestructiveInHookScript, got {other:?}"),
        }
    }

    #[test]
    fn happy_path_safe_returns_none() {
        let f = tempfile_with(b"#!/bin/bash\necho hi\n");
        assert!(scan_external_script(f.path(), "PreToolUse").is_none());
    }

    #[test]
    fn size_cap_triggers_unscanned_fallback() {
        let big = vec![b'a'; MAX_READ_BYTES + 100];
        let f = tempfile_with(&big);
        match scan_external_script(f.path(), "PreToolUse") {
            Some(AiGuardReason::ExternalScriptUnscanned { .. }) => {}
            other => panic!("expected ExternalScriptUnscanned, got {other:?}"),
        }
    }

    #[test]
    fn binary_detection_triggers_unscanned_fallback() {
        let mut bin = Vec::new();
        for _ in 0..256 {
            bin.extend_from_slice(b"\x00\xff\x01\xfe");
        }
        let f = tempfile_with(&bin);
        match scan_external_script(f.path(), "PreToolUse") {
            Some(AiGuardReason::ExternalScriptUnscanned { .. }) => {}
            other => panic!("expected ExternalScriptUnscanned, got {other:?}"),
        }
    }

    #[test]
    fn nonexistent_path_returns_unscanned_fallback() {
        let path = std::path::PathBuf::from("/tmp/sigil-3b3-does-not-exist-9f8e7d6c");
        match scan_external_script(&path, "PreToolUse") {
            Some(AiGuardReason::ExternalScriptUnscanned { script_path, .. }) => {
                assert_eq!(script_path, path);
            }
            other => panic!("expected ExternalScriptUnscanned, got {other:?}"),
        }
    }

    #[test]
    fn utf8_boundary_at_cap_does_not_panic() {
        let mut bytes = Vec::with_capacity(MAX_READ_BYTES + 4);
        let glyph = "🎉".as_bytes();
        while bytes.len() < MAX_READ_BYTES + 4 {
            bytes.extend_from_slice(glyph);
        }
        let f = tempfile_with(&bytes);
        let _ = scan_external_script(f.path(), "PreToolUse");
    }

    #[test]
    fn looks_binary_detects_nul() {
        assert!(looks_binary(b"hello\x00world"));
    }

    #[test]
    fn looks_binary_passes_ascii_shell() {
        assert!(!looks_binary(b"#!/bin/bash\nrm -rf /tmp/foo\n"));
    }

    #[test]
    fn looks_binary_passes_empty() {
        assert!(!looks_binary(b""));
    }
}
