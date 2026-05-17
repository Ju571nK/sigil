//! Phase 3b.6.1 — given workspace root paths, find the direct
//! subdirectories that contain `.continue/config.json` and return their
//! canonical absolute paths. Used by runtime / policy_reload to spawn
//! ContinueDevProjectParser instances.

use std::path::PathBuf;

/// Walk each workspace_root 1-level deep. For each direct subdirectory D,
/// check if D/.continue/config.json exists and is a regular file. Collect
/// canonical absolute paths to the matching D (the "repo root", not the
/// config file). Dedup. Sort for deterministic ordering. Logs (warn) when
/// the discovered count exceeds 50 as a runaway indicator.
///
/// Input strings may contain `~` or `$VAR`; both are expanded via the
/// shared sigil-core helper before scanning.
pub fn discover_continue_projects(workspace_roots: &[String]) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    for raw in workspace_roots {
        let root = match expand_and_canonicalize(raw) {
            Some(r) => r,
            None => continue,
        };
        let entries = match std::fs::read_dir(&root) {
            Ok(it) => it,
            Err(e) => {
                tracing::warn!(
                    root = %root.display(),
                    error = %e,
                    "continue_discovery: read_dir failed; skipping"
                );
                continue;
            }
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let cfg = path.join(".continue").join("config.json");
            if cfg.is_file() {
                if let Ok(canonical) = dunce::canonicalize(&path) {
                    out.push(canonical);
                }
            }
        }
    }
    out.sort();
    out.dedup();
    if out.len() >= 50 {
        tracing::warn!(
            count = out.len(),
            "continue_discovery: large discovered repo count (operator config may be too wide)"
        );
    }
    out
}

fn expand_and_canonicalize(raw: &str) -> Option<PathBuf> {
    // sigil-core's policy::expand handles `~` and `$VAR`. We reuse it so
    // discovery behaves the same as the rest of policy path resolution.
    let expanded =
        match sigil_core::policy::expand::expand(raw, &sigil_core::policy::expand::EnvLookup) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(raw, error = ?e, "continue_discovery: expand failed; skipping");
                return None;
            }
        };
    match dunce::canonicalize(&expanded) {
        Ok(p) => Some(p),
        Err(e) => {
            tracing::warn!(
                raw,
                expanded = %expanded.display(),
                error = %e,
                "continue_discovery: canonicalize failed (root may not exist); skipping"
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn make_repo_with_continue(workspace: &std::path::Path, name: &str) -> PathBuf {
        let repo = workspace.join(name);
        fs::create_dir_all(repo.join(".continue")).unwrap();
        fs::write(repo.join(".continue").join("config.json"), "{}").unwrap();
        repo
    }

    fn make_dir_only(workspace: &std::path::Path, name: &str) -> PathBuf {
        let p = workspace.join(name);
        fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn empty_workspace_roots_returns_empty_vec() {
        let out = discover_continue_projects(&[]);
        assert!(out.is_empty());
    }

    #[test]
    fn nonexistent_root_is_skipped_silently() {
        let out = discover_continue_projects(&["/nonexistent/path/xyz".into()]);
        assert!(out.is_empty());
    }

    #[test]
    fn one_level_subdir_with_continue_config_is_discovered() {
        let dir = tempdir().unwrap();
        let workspace = dir.path();
        let repo = make_repo_with_continue(workspace, "repoA");
        let canonical_repo = dunce::canonicalize(&repo).unwrap();

        let out = discover_continue_projects(&[workspace.to_string_lossy().into()]);
        assert_eq!(out, vec![canonical_repo]);
    }

    #[test]
    fn subdir_without_continue_is_ignored() {
        let dir = tempdir().unwrap();
        let workspace = dir.path();
        make_dir_only(workspace, "repoB");
        let out = discover_continue_projects(&[workspace.to_string_lossy().into()]);
        assert!(out.is_empty());
    }

    #[test]
    fn two_level_deep_continue_is_not_discovered() {
        // workspace/group/repo/.continue/config.json — 1-level scan must NOT match.
        let dir = tempdir().unwrap();
        let workspace = dir.path();
        let group = workspace.join("group");
        fs::create_dir_all(&group).unwrap();
        make_repo_with_continue(&group, "repoC");

        let out = discover_continue_projects(&[workspace.to_string_lossy().into()]);
        assert!(
            out.is_empty(),
            "1-level scan must not match group/repoC; got {out:?}"
        );
    }

    #[test]
    fn multiple_repos_in_one_workspace_all_discovered() {
        let dir = tempdir().unwrap();
        let workspace = dir.path();
        let a = make_repo_with_continue(workspace, "repoA");
        let b = make_repo_with_continue(workspace, "repoB");
        let ca = dunce::canonicalize(&a).unwrap();
        let cb = dunce::canonicalize(&b).unwrap();

        let out = discover_continue_projects(&[workspace.to_string_lossy().into()]);
        assert_eq!(out.len(), 2);
        assert!(out.contains(&ca));
        assert!(out.contains(&cb));
    }

    #[test]
    fn duplicate_workspace_roots_are_deduped() {
        let dir = tempdir().unwrap();
        let workspace = dir.path();
        make_repo_with_continue(workspace, "repoA");
        let ws_str: String = workspace.to_string_lossy().into();

        let out = discover_continue_projects(&[ws_str.clone(), ws_str]);
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn config_json_must_be_regular_file_not_dir() {
        let dir = tempdir().unwrap();
        let workspace = dir.path();
        let repo = workspace.join("repoFake");
        fs::create_dir_all(repo.join(".continue").join("config.json")).unwrap();

        let out = discover_continue_projects(&[workspace.to_string_lossy().into()]);
        assert!(out.is_empty(), "directory named config.json must not match");
    }
}
