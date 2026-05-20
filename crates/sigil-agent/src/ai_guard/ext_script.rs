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

use std::path::{Path, PathBuf};

use sigil_core::event::AiGuardReason;

use crate::ai_guard::rubric;

/// Max bytes read from any external hook script. Chosen to comfortably cover
/// real-world hook scripts (most <10 KB) while preventing DoS via attacker
/// placing a multi-GB file at a configured hook path.
pub const MAX_READ_BYTES: usize = 256 * 1024;

/// Sample size for binary detection — first chunk of the file.
pub const BINARY_DETECT_PREFIX_BYTES: usize = 1024;

/// Max depth of `source` chain to follow. Real-world hook scripts rarely
/// nest beyond 3; 5 gives slack while bounding DoS.
pub const MAX_SOURCE_DEPTH: usize = 5;

/// Max unique scripts visited per entry-point walk (entry counts as 1).
pub const MAX_FILES_PER_WALK: usize = 32;

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

/// Outcome of attempting to read a script for scanning.
enum ReadOutcome {
    Ok(String),
    Unscannable,
}

fn read_with_guards(path: &Path) -> ReadOutcome {
    use std::io::Read;

    let mut file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return ReadOutcome::Unscannable,
    };
    let mut buf = Vec::with_capacity(MAX_READ_BYTES.min(8192));
    if file
        .by_ref()
        .take((MAX_READ_BYTES as u64) + 1)
        .read_to_end(&mut buf)
        .is_err()
    {
        return ReadOutcome::Unscannable;
    }
    if buf.len() > MAX_READ_BYTES {
        return ReadOutcome::Unscannable;
    }
    let prefix_len = buf.len().min(BINARY_DETECT_PREFIX_BYTES);
    if looks_binary(&buf[..prefix_len]) {
        return ReadOutcome::Unscannable;
    }
    ReadOutcome::Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Recursive hook-script scanner. Walks `source X` / `. X` directives DFS,
/// bounded by [`MAX_SOURCE_DEPTH`] and [`MAX_FILES_PER_WALK`]. Returns:
/// - At most one `DestructiveInHookScript` (first match in DFS order). Its
///   `script_path` is the entry path; its `source_chain` is
///   `[entry, ..., matched_file]` (empty if match was in entry itself).
/// - Zero or more `ExternalScriptUnscanned` for unresolved/oversized/binary
///   references encountered anywhere in the walk.
pub fn scan_hook_script(entry: &Path, hook_event: &str) -> Vec<AiGuardReason> {
    let entry_canon = dunce::canonicalize(entry).unwrap_or_else(|_| entry.to_path_buf());
    let mut visited: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
    let mut emissions: Vec<AiGuardReason> = Vec::new();
    let mut file_budget = MAX_FILES_PER_WALK;
    let mut chain: Vec<PathBuf> = vec![entry_canon.clone()];
    walk(
        &entry_canon,
        hook_event,
        &mut chain,
        &mut visited,
        &mut emissions,
        &mut file_budget,
        0,
    );
    emissions
}

fn walk(
    path: &Path,
    hook_event: &str,
    chain: &mut Vec<PathBuf>,
    visited: &mut std::collections::HashSet<PathBuf>,
    emissions: &mut Vec<AiGuardReason>,
    file_budget: &mut usize,
    depth: usize,
) {
    if depth > MAX_SOURCE_DEPTH {
        return;
    }
    if *file_budget == 0 {
        return;
    }
    if !visited.insert(path.to_path_buf()) {
        return; // cycle / already walked
    }
    *file_budget -= 1;

    let contents = match read_with_guards(path) {
        ReadOutcome::Ok(s) => s,
        ReadOutcome::Unscannable => {
            emissions.push(AiGuardReason::ExternalScriptUnscanned {
                hook_event: hook_event.to_string(),
                script_path: path.to_path_buf(),
            });
            return;
        }
    };

    // First-match-wins for destructive patterns across the entire walk.
    let already_matched = emissions
        .iter()
        .any(|e| matches!(e, AiGuardReason::DestructiveInHookScript { .. }));
    if !already_matched {
        if let Some(pat) = rubric::first_destructive_pattern(&contents) {
            let chain_out: Vec<PathBuf> = if chain.len() == 1 {
                Vec::new()
            } else {
                chain.clone()
            };
            let entry_path = chain[0].clone();
            emissions.push(AiGuardReason::DestructiveInHookScript {
                pattern: pat.to_string(),
                hook_event: hook_event.to_string(),
                script_path: entry_path,
                snippet: snippet_around_match(&contents, pat),
                source_chain: chain_out,
            });
            // Continue walking — we still want to surface unscanned siblings.
        }
    }

    for source_ref in parse_source_directives(&contents) {
        match source_ref {
            SourceRef::Unresolvable(literal) => {
                emissions.push(AiGuardReason::ExternalScriptUnscanned {
                    hook_event: hook_event.to_string(),
                    script_path: PathBuf::from(literal),
                });
            }
            SourceRef::Resolvable(literal) => {
                match resolve_path(&literal, path) {
                    Ok(target) => {
                        chain.push(target.clone());
                        walk(
                            &target,
                            hook_event,
                            chain,
                            visited,
                            emissions,
                            file_budget,
                            depth + 1,
                        );
                        chain.pop();
                    }
                    Err(unresolved_path) => {
                        emissions.push(AiGuardReason::ExternalScriptUnscanned {
                            hook_event: hook_event.to_string(),
                            script_path: unresolved_path,
                        });
                    }
                }
            }
        }
    }
}

/// Backwards-compat shim around [`scan_hook_script`]. Returns the first
/// emitted reason (matching pre-3b.3.1 single-emission semantics).
pub fn scan_external_script(path: &Path, hook_event: &str) -> Option<AiGuardReason> {
    scan_hook_script(path, hook_event).into_iter().next()
}

/// One reference extracted from a `source X` / `. X` directive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SourceRef {
    /// Literal that we can attempt to resolve to a filesystem path.
    Resolvable(String),
    /// Literal that contains shell variables, command substitution, tilde,
    /// or other dynamic constructs. Reported as ExternalScriptUnscanned but
    /// not recursed into.
    Unresolvable(String),
}

fn line_contains_dynamic(literal: &str) -> bool {
    literal.contains('$')
        || literal.contains('`')
        || literal.starts_with('~')
        || literal.contains('*')
        || literal.contains('?')
        || literal.contains('[')
}

/// Strip surrounding balanced single or double quotes. No-op otherwise.
fn unquote(s: &str) -> &str {
    let bytes = s.as_bytes();
    if bytes.len() >= 2 {
        let first = bytes[0];
        let last = bytes[bytes.len() - 1];
        if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
            return &s[1..s.len() - 1];
        }
    }
    s
}

/// Parse `source X` and `. X` directives from shell script content.
/// Line-based, comment-stripping. Heredocs and multi-line strings are NOT
/// handled (accepted false-positives per spec §4).
pub(crate) fn parse_source_directives(contents: &str) -> Vec<SourceRef> {
    let mut out = Vec::new();
    for raw_line in contents.lines() {
        let line = raw_line.trim_start();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Strip trailing inline comment (naive — ignores # inside strings).
        let line = match line.find('#') {
            Some(idx) => &line[..idx],
            None => line,
        };
        let line = line.trim();
        let mut toks = line.split_whitespace();
        let cmd = match toks.next() {
            Some(t) => t,
            None => continue,
        };
        if cmd != "source" && cmd != "." {
            continue;
        }
        let arg = match toks.next() {
            Some(t) => t,
            None => continue,
        };
        let literal = unquote(arg);
        if line_contains_dynamic(literal) {
            out.push(SourceRef::Unresolvable(literal.to_string()));
        } else {
            out.push(SourceRef::Resolvable(literal.to_string()));
        }
    }
    out
}

/// Resolve a literal path string (from a `source` directive) against the
/// parent script's path. Absolute paths used as-is; relative joined with
/// parent dir. Returns canonicalized PathBuf on success, or the constructed
/// (non-canonical) path as an error if the file does not exist.
pub(crate) fn resolve_path(literal: &str, parent_script: &Path) -> Result<std::path::PathBuf, std::path::PathBuf> {
    let candidate = if Path::new(literal).is_absolute() {
        std::path::PathBuf::from(literal)
    } else {
        let parent_dir = parent_script
            .parent()
            .unwrap_or_else(|| Path::new("."));
        parent_dir.join(literal)
    };

    match dunce::canonicalize(&candidate) {
        Ok(canon) => Ok(canon),
        Err(_) => Err(candidate),
    }
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

    #[test]
    fn parser_finds_source_directive() {
        let s = "#!/bin/bash\nsource ./helper.sh\necho hi\n";
        let refs = parse_source_directives(s);
        assert_eq!(refs, vec![SourceRef::Resolvable("./helper.sh".into())]);
    }

    #[test]
    fn parser_finds_dot_directive() {
        let s = ". /etc/profile.d/x.sh\n";
        let refs = parse_source_directives(s);
        assert_eq!(refs, vec![SourceRef::Resolvable("/etc/profile.d/x.sh".into())]);
    }

    #[test]
    fn parser_skips_comment_lines() {
        let s = "# source ./evil.sh\nsource ./real.sh\n";
        let refs = parse_source_directives(s);
        assert_eq!(refs, vec![SourceRef::Resolvable("./real.sh".into())]);
    }

    #[test]
    fn parser_unwraps_quoted_paths() {
        let s = "source \"./helper.sh\"\nsource './other.sh'\n";
        let refs = parse_source_directives(s);
        assert_eq!(refs, vec![
            SourceRef::Resolvable("./helper.sh".into()),
            SourceRef::Resolvable("./other.sh".into()),
        ]);
    }

    #[test]
    fn parser_marks_var_expansion_unresolvable() {
        let s = "source $HOME/x.sh\n";
        let refs = parse_source_directives(s);
        assert_eq!(refs, vec![SourceRef::Unresolvable("$HOME/x.sh".into())]);
    }

    #[test]
    fn parser_marks_tilde_unresolvable() {
        let s = "source ~/x.sh\n";
        let refs = parse_source_directives(s);
        assert_eq!(refs, vec![SourceRef::Unresolvable("~/x.sh".into())]);
    }

    #[test]
    fn parser_marks_command_subst_unresolvable() {
        let s = "source $(which lint)\n";
        let refs = parse_source_directives(s);
        assert_eq!(refs, vec![SourceRef::Unresolvable("$(which".into())]);
    }

    #[test]
    fn parser_ignores_non_source_lines() {
        let s = "echo foo\nrm bar\nls /etc\n";
        assert!(parse_source_directives(s).is_empty());
    }

    #[test]
    fn parser_does_not_match_word_prefix_source() {
        let s = "sourceless command here\n";
        assert!(parse_source_directives(s).is_empty());
    }

    #[test]
    fn parser_strips_inline_comment() {
        let s = "source ./helper.sh  # local helper\n";
        let refs = parse_source_directives(s);
        assert_eq!(refs, vec![SourceRef::Resolvable("./helper.sh".into())]);
    }

    #[test]
    fn resolve_absolute_path_succeeds_when_file_exists() {
        let f = tempfile_with(b"#!/bin/bash\n");
        let parent = f.path().parent().unwrap();
        let result = resolve_path(
            &f.path().to_string_lossy(),
            &parent.join("dummy.sh"),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn resolve_relative_path_joins_with_parent() {
        let dir = tempfile::tempdir().unwrap();
        let parent_script = dir.path().join("entry.sh");
        std::fs::write(&parent_script, b"#!/bin/bash\n").unwrap();
        let helper = dir.path().join("helper.sh");
        std::fs::write(&helper, b"#!/bin/bash\n").unwrap();

        let result = resolve_path("./helper.sh", &parent_script);
        assert!(result.is_ok());
        let canon = result.unwrap();
        assert!(canon.ends_with("helper.sh"));
    }

    #[test]
    fn resolve_missing_relative_path_errors_with_literal() {
        let dir = tempfile::tempdir().unwrap();
        let parent_script = dir.path().join("entry.sh");
        std::fs::write(&parent_script, b"#!/bin/bash\n").unwrap();

        let result = resolve_path("./missing.sh", &parent_script);
        let err = result.unwrap_err();
        assert!(err.to_string_lossy().contains("missing.sh"));
    }

    // ── walker tests ──────────────────────────────────────────────────────────

    fn write_script(dir: &Path, name: &str, contents: &[u8]) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, contents).unwrap();
        p
    }

    #[test]
    fn walker_direct_match_empty_source_chain() {
        let dir = tempfile::tempdir().unwrap();
        let entry = write_script(dir.path(), "entry.sh", b"#!/bin/bash\nrm -rf /tmp/foo\n");
        let out = scan_hook_script(&entry, "PreToolUse");
        let chain = out
            .iter()
            .find_map(|r| match r {
                AiGuardReason::DestructiveInHookScript { source_chain, .. } => Some(source_chain),
                _ => None,
            })
            .expect("expected DestructiveInHookScript");
        assert!(chain.is_empty(), "match in entry should yield empty chain");
    }

    #[test]
    fn walker_one_hop_source_populates_chain() {
        let dir = tempfile::tempdir().unwrap();
        write_script(dir.path(), "helper.sh", b"#!/bin/bash\nrm -rf /tmp/foo\n");
        let entry = write_script(dir.path(), "entry.sh", b"#!/bin/bash\nsource ./helper.sh\n");
        let out = scan_hook_script(&entry, "PreToolUse");
        let (script_path, chain) = out
            .iter()
            .find_map(|r| match r {
                AiGuardReason::DestructiveInHookScript { script_path, source_chain, .. } =>
                    Some((script_path, source_chain)),
                _ => None,
            })
            .expect("expected DestructiveInHookScript");
        assert!(script_path.ends_with("entry.sh"));
        assert_eq!(chain.len(), 2, "chain = [entry, helper]");
        assert!(chain[0].ends_with("entry.sh"));
        assert!(chain[1].ends_with("helper.sh"));
    }

    #[test]
    fn walker_two_hop_dot_directive() {
        let dir = tempfile::tempdir().unwrap();
        write_script(dir.path(), "deep.sh", b"#!/bin/bash\nrm -rf /tmp/foo\n");
        write_script(dir.path(), "mid.sh", b"#!/bin/bash\n. ./deep.sh\n");
        let entry = write_script(dir.path(), "entry.sh", b"#!/bin/bash\n. ./mid.sh\n");
        let out = scan_hook_script(&entry, "PreToolUse");
        let chain = out
            .iter()
            .find_map(|r| match r {
                AiGuardReason::DestructiveInHookScript { source_chain, .. } => Some(source_chain),
                _ => None,
            })
            .expect("expected DestructiveInHookScript");
        assert_eq!(chain.len(), 3);
        assert!(chain[0].ends_with("entry.sh"));
        assert!(chain[1].ends_with("mid.sh"));
        assert!(chain[2].ends_with("deep.sh"));
    }

    #[test]
    fn walker_cycle_terminates() {
        let dir = tempfile::tempdir().unwrap();
        write_script(dir.path(), "b.sh", b"#!/bin/bash\nsource ./a.sh\n");
        let entry = write_script(dir.path(), "a.sh", b"#!/bin/bash\nsource ./b.sh\n");
        let out = scan_hook_script(&entry, "PreToolUse");
        assert!(
            !out.iter().any(|r| matches!(r, AiGuardReason::DestructiveInHookScript { .. })),
            "no destructive pattern in either file; cycle must not produce false positive"
        );
    }

    #[test]
    fn walker_depth_limit_enforced() {
        let dir = tempfile::tempdir().unwrap();
        // Build chain: lvl6.sh has rm -rf; lvl0 -> lvl1 -> ... -> lvl6 (depth 6).
        write_script(dir.path(), "lvl6.sh", b"#!/bin/bash\nrm -rf /tmp/foo\n");
        for i in (0..6).rev() {
            let next = format!("lvl{}.sh", i + 1);
            let body = format!("#!/bin/bash\nsource ./{}\n", next);
            write_script(dir.path(), &format!("lvl{i}.sh"), body.as_bytes());
        }
        let entry = dir.path().join("lvl0.sh");
        let out = scan_hook_script(&entry, "PreToolUse");
        assert!(
            !out.iter().any(|r| matches!(r, AiGuardReason::DestructiveInHookScript { .. })),
            "depth 6 must NOT be reached when MAX_SOURCE_DEPTH=5; got {out:?}"
        );
    }

    #[test]
    fn walker_file_count_cap_enforced() {
        let dir = tempfile::tempdir().unwrap();
        let mut body = String::from("#!/bin/bash\n");
        for i in 0..50 {
            write_script(dir.path(), &format!("h{i}.sh"), b"#!/bin/bash\necho ok\n");
            body.push_str(&format!("source ./h{i}.sh\n"));
        }
        let entry = write_script(dir.path(), "entry.sh", body.as_bytes());
        let out = scan_hook_script(&entry, "PreToolUse");
        assert!(
            !out.iter().any(|r| matches!(r, AiGuardReason::DestructiveInHookScript { .. })),
            "no destructive pattern present"
        );
    }

    #[test]
    fn walker_var_expansion_emits_unscanned() {
        let dir = tempfile::tempdir().unwrap();
        let entry = write_script(dir.path(), "entry.sh", b"#!/bin/bash\nsource $HOME/x.sh\n");
        let out = scan_hook_script(&entry, "PreToolUse");
        let unscanned: Vec<_> = out
            .iter()
            .filter(|r| matches!(r, AiGuardReason::ExternalScriptUnscanned { .. }))
            .collect();
        assert_eq!(unscanned.len(), 1, "got: {out:?}");
    }

    #[test]
    fn walker_missing_relative_target_emits_unscanned() {
        let dir = tempfile::tempdir().unwrap();
        let entry = write_script(dir.path(), "entry.sh", b"#!/bin/bash\nsource ./missing.sh\n");
        let out = scan_hook_script(&entry, "PreToolUse");
        assert!(
            out.iter().any(|r| matches!(r, AiGuardReason::ExternalScriptUnscanned { .. })),
            "got: {out:?}"
        );
    }

    #[test]
    fn walker_multi_emission_destructive_plus_unscanned() {
        let dir = tempfile::tempdir().unwrap();
        write_script(dir.path(), "danger.sh", b"#!/bin/bash\nrm -rf /tmp/foo\n");
        let entry = write_script(
            dir.path(),
            "entry.sh",
            b"#!/bin/bash\nsource $UNRESOLVED/x.sh\nsource ./danger.sh\n",
        );
        let out = scan_hook_script(&entry, "PreToolUse");
        assert!(out.iter().any(|r| matches!(r, AiGuardReason::DestructiveInHookScript { .. })));
        assert!(out.iter().any(|r| matches!(r, AiGuardReason::ExternalScriptUnscanned { .. })));
    }

    #[test]
    fn walker_first_match_wins_no_double_destructive() {
        let dir = tempfile::tempdir().unwrap();
        write_script(dir.path(), "b.sh", b"#!/bin/bash\nrm -rf /tmp/zzz\n");
        write_script(dir.path(), "a.sh", b"#!/bin/bash\nrm -rf /tmp/aaa\nsource ./b.sh\n");
        let entry = write_script(dir.path(), "entry.sh", b"#!/bin/bash\nsource ./a.sh\n");
        let out = scan_hook_script(&entry, "PreToolUse");
        let destructive: Vec<_> = out
            .iter()
            .filter(|r| matches!(r, AiGuardReason::DestructiveInHookScript { .. }))
            .collect();
        assert_eq!(destructive.len(), 1, "first-match-wins; got: {out:?}");
    }
}
