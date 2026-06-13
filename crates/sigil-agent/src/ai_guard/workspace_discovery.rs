//! Phase 3b.6.2 — generic per-repo discovery shared by Continue.dev,
//! Claude Code, and Codex per-repo parsers. Extracted from the
//! per-tool `continue_discovery` module shipped in 3b.6.1.

use std::path::PathBuf;

const DISCOVERY_WARN_THRESHOLD: usize = 50;

/// Scan each operator-supplied workspace root 1-level deep and return
/// canonical paths of direct subdirs that contain `marker_subpath`
/// as an existing file.
///
/// - `roots`: raw policy.yaml strings (one root per element). Each is
///   ~/$VAR-expanded via `sigil_core::policy::expand::expand` then
///   canonicalized via `dunce::canonicalize`.
/// - `marker_subpath`: relative path under each candidate repo that
///   must exist as a file for the repo to count
///   (e.g. `".continue/config.json"`, `".claude/settings.json"`,
///   `".codex/config.toml"`).
///
/// Errors / edge cases are tolerated:
/// - Roots that fail to expand / canonicalize → warn-log, skip.
/// - Non-dir entries → silent skip.
/// - Output deduplicated via BTreeSet.
/// - Info-log once when total > `DISCOVERY_WARN_THRESHOLD`.
pub fn discover_per_repo(roots: &[String], marker_subpath: &str) -> Vec<PathBuf> {
    let mut out = std::collections::BTreeSet::new();
    for raw in roots {
        let Some(root) = expand_and_canonicalize(raw) else {
            continue;
        };
        let entries = match std::fs::read_dir(&root) {
            Ok(it) => it,
            Err(e) => {
                tracing::warn!(root = %root.display(), error = %e,
                    "workspace_discovery: read_dir failed; skipping root");
                continue;
            }
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let marker = path.join(marker_subpath);
            if marker.is_file() {
                match dunce::canonicalize(&path) {
                    Ok(canonical) => {
                        out.insert(canonical);
                    }
                    Err(e) => {
                        tracing::warn!(path = %path.display(), error = %e,
                            "workspace_discovery: canonicalize failed; skipping repo");
                    }
                }
            }
        }
    }
    if out.len() > DISCOVERY_WARN_THRESHOLD {
        tracing::info!(count = out.len(), marker = %marker_subpath,
            "workspace_discovery: many repos discovered (operator may want narrower roots)");
    }
    out.into_iter().collect()
}

/// #145 — Claude Code repos are discovered by EITHER marker: the per-tool
/// settings file (`.claude/settings.json`) OR a committed project MCP payload
/// at the repo root (`.mcp.json`). A repo with only `.mcp.json` is still a
/// TrustFall surface, so it must be discovered (and watched) too. Union,
/// deduplicated by canonical path.
pub fn discover_claude_repos(roots: &[String]) -> Vec<PathBuf> {
    let mut set: std::collections::BTreeSet<PathBuf> =
        discover_per_repo(roots, ".claude/settings.json")
            .into_iter()
            .collect();
    set.extend(discover_per_repo(roots, ".mcp.json"));
    set.extend(discover_per_repo(roots, "CLAUDE.md"));
    set.extend(discover_per_repo(roots, "AGENTS.md"));
    set.into_iter().collect()
}

/// #146 — Codex repos by EITHER `.codex/config.toml` OR a committed `AGENTS.md`
/// (Codex's first-class instruction file). Union, deduped by canonical path.
pub fn discover_codex_repos(roots: &[String]) -> Vec<PathBuf> {
    let mut set: std::collections::BTreeSet<PathBuf> =
        discover_per_repo(roots, ".codex/config.toml")
            .into_iter()
            .collect();
    set.extend(discover_per_repo(roots, "AGENTS.md"));
    set.into_iter().collect()
}

/// #146 — Cursor repos by `.cursor/mcp.json` OR `.cursorrules` (files) OR a
/// `.cursor/rules` directory. Union, deduped by canonical path.
pub fn discover_cursor_repos(roots: &[String]) -> Vec<PathBuf> {
    let mut set: std::collections::BTreeSet<PathBuf> = discover_per_repo(roots, ".cursor/mcp.json")
        .into_iter()
        .collect();
    set.extend(discover_per_repo(roots, ".cursorrules"));
    // `.cursor/rules` is a DIRECTORY marker — discover_per_repo only matches files.
    for raw in roots {
        let Some(root) = expand_and_canonicalize(raw) else {
            continue;
        };
        let Ok(entries) = std::fs::read_dir(&root) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() && path.join(".cursor").join("rules").is_dir() {
                if let Ok(c) = dunce::canonicalize(&path) {
                    set.insert(c);
                }
            }
        }
    }
    set.into_iter().collect()
}

fn expand_and_canonicalize(raw: &str) -> Option<PathBuf> {
    let expanded =
        match sigil_core::policy::expand::expand(raw, &sigil_core::policy::expand::EnvLookup) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(raw, error = ?e, "workspace_discovery: expand failed; skipping");
                return None;
            }
        };
    match dunce::canonicalize(&expanded) {
        Ok(p) => Some(p),
        Err(e) => {
            tracing::warn!(raw, expanded = %expanded.display(), error = %e,
                "workspace_discovery: canonicalize failed; skipping");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    const CONTINUE_MARKER: &str = ".continue/config.json";
    const CLAUDE_MARKER: &str = ".claude/settings.json";
    const CODEX_MARKER: &str = ".codex/config.toml";

    fn make_repo_with(dir: &std::path::Path, name: &str, marker: &str) {
        let repo = dir.join(name);
        let (sub, file) = marker.split_once('/').unwrap();
        std::fs::create_dir_all(repo.join(sub)).unwrap();
        std::fs::write(repo.join(sub).join(file), "{}").unwrap();
    }

    #[test]
    fn discover_empty_roots() {
        let out = discover_per_repo(&[], CONTINUE_MARKER);
        assert!(out.is_empty());
    }

    #[test]
    fn discover_skips_nonexistent_root() {
        let out = discover_per_repo(
            &["/this/path/does/not/exist/sigil-3b6.2".to_string()],
            CONTINUE_MARKER,
        );
        assert!(out.is_empty());
    }

    #[test]
    fn discover_finds_one_level_subdir_with_marker_continue() {
        let dir = tempdir().unwrap();
        make_repo_with(dir.path(), "repoA", CONTINUE_MARKER);
        let out = discover_per_repo(&[dir.path().to_string_lossy().into()], CONTINUE_MARKER);
        let canonical = dunce::canonicalize(dir.path().join("repoA")).unwrap();
        assert_eq!(out, vec![canonical]);
    }

    #[test]
    fn discover_finds_one_level_subdir_with_marker_claude() {
        let dir = tempdir().unwrap();
        make_repo_with(dir.path(), "repoA", CLAUDE_MARKER);
        let out = discover_per_repo(&[dir.path().to_string_lossy().into()], CLAUDE_MARKER);
        let canonical = dunce::canonicalize(dir.path().join("repoA")).unwrap();
        assert_eq!(out, vec![canonical]);
    }

    #[test]
    fn discover_finds_one_level_subdir_with_marker_codex() {
        let dir = tempdir().unwrap();
        make_repo_with(dir.path(), "repoA", CODEX_MARKER);
        let out = discover_per_repo(&[dir.path().to_string_lossy().into()], CODEX_MARKER);
        let canonical = dunce::canonicalize(dir.path().join("repoA")).unwrap();
        assert_eq!(out, vec![canonical]);
    }

    #[test]
    fn discover_ignores_subdir_without_marker() {
        let dir = tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("emptyRepo")).unwrap();
        let out = discover_per_repo(&[dir.path().to_string_lossy().into()], CONTINUE_MARKER);
        assert!(out.is_empty());
    }

    #[test]
    fn discover_does_not_recurse_two_levels() {
        let dir = tempdir().unwrap();
        let workspace = dir.path().join("ws");
        let group = workspace.join("group");
        std::fs::create_dir_all(&group).unwrap();
        make_repo_with(&group, "repoC", CONTINUE_MARKER);
        let out = discover_per_repo(&[workspace.to_string_lossy().into()], CONTINUE_MARKER);
        assert!(
            out.is_empty(),
            "1-level scan must not match group/repoC; got {out:?}"
        );
    }

    #[test]
    fn discover_multiple_repos_under_one_root() {
        let dir = tempdir().unwrap();
        make_repo_with(dir.path(), "repoA", CONTINUE_MARKER);
        make_repo_with(dir.path(), "repoB", CONTINUE_MARKER);
        let out = discover_per_repo(&[dir.path().to_string_lossy().into()], CONTINUE_MARKER);
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn discover_dedups_across_roots() {
        let dir = tempdir().unwrap();
        make_repo_with(dir.path(), "repoA", CONTINUE_MARKER);
        let root = dir.path().to_string_lossy().to_string();
        let out = discover_per_repo(&[root.clone(), root], CONTINUE_MARKER);
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn discover_claude_repos_finds_mcp_json_only_repo() {
        let root = tempdir().unwrap();
        let repo = root.path().join("only-mcp");
        std::fs::create_dir_all(&repo).unwrap();
        std::fs::write(repo.join(".mcp.json"), "{}").unwrap();
        let roots = vec![root.path().to_string_lossy().to_string()];
        let found = discover_claude_repos(&roots);
        let canon = dunce::canonicalize(&repo).unwrap();
        assert!(found.contains(&canon), "got {found:?}");
    }

    #[test]
    fn discover_claude_repos_finds_agents_md_only() {
        let root = tempdir().unwrap();
        let repo = root.path().join("only-agents");
        std::fs::create_dir_all(&repo).unwrap();
        std::fs::write(repo.join("AGENTS.md"), "x").unwrap();
        let roots = vec![root.path().to_string_lossy().to_string()];
        assert!(discover_claude_repos(&roots).contains(&dunce::canonicalize(&repo).unwrap()));
    }
    #[test]
    fn discover_codex_repos_finds_agents_md_only() {
        let root = tempdir().unwrap();
        let repo = root.path().join("only-agents");
        std::fs::create_dir_all(&repo).unwrap();
        std::fs::write(repo.join("AGENTS.md"), "x").unwrap();
        let roots = vec![root.path().to_string_lossy().to_string()];
        assert!(discover_codex_repos(&roots).contains(&dunce::canonicalize(&repo).unwrap()));
    }
    #[test]
    fn discover_cursor_repos_finds_cursorrules_and_rules_dir() {
        let root = tempdir().unwrap();
        let r1 = root.path().join("a");
        std::fs::create_dir_all(&r1).unwrap();
        std::fs::write(r1.join(".cursorrules"), "x").unwrap();
        let r2 = root.path().join("b");
        std::fs::create_dir_all(r2.join(".cursor").join("rules")).unwrap();
        let roots = vec![root.path().to_string_lossy().to_string()];
        let found = discover_cursor_repos(&roots);
        assert!(found.contains(&dunce::canonicalize(&r1).unwrap()));
        assert!(found.contains(&dunce::canonicalize(&r2).unwrap()));
    }

    #[test]
    fn discover_skips_when_marker_is_dir_not_file() {
        let dir = tempdir().unwrap();
        let repo = dir.path().join("badRepo");
        // Create `.continue/config.json` as a DIRECTORY, not a file
        std::fs::create_dir_all(repo.join(".continue").join("config.json")).unwrap();
        let out = discover_per_repo(&[dir.path().to_string_lossy().into()], CONTINUE_MARKER);
        assert!(out.is_empty(), "marker must be a file, not a dir");
    }
}
