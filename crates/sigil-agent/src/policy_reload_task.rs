//! Live policy reload: rebuilds the watcher subgraph's targets/roots when
//! `apply_policy` commits a new version — no agent restart needed.
//!
//! `apply_policy` already writes `policy.yaml`, bumps `state.db`, sends the new
//! version on `policy_version_tx`, and emits `PolicyReloaded`. This task
//! subscribes to that channel; on a bump it re-reads `policy.yaml`, re-merges
//! with the built-in defaults, re-expands per-user paths, re-runs critical-tier
//! warmup, reconciles the live notify watcher's roots, and publishes the new
//! `Arc<Vec<CompiledTarget>>` on `targets_tx` (which the normalizer and the
//! hasher's lookup read per event).

use crate::normalizer::{self, CompiledTarget};
use crate::platform::ActivePlatform;
use crate::watcher::WatcherHandle;
use parking_lot::Mutex;
use sigil_core::state::HashCache;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

/// Inputs for the reload task. The `WatcherHandle` lives here for the task's
/// lifetime (so the OS watcher stays alive); `watched_roots` is the diff base
/// for the next reconcile (start it equal to the roots `run` registered).
pub struct ReloadCtx {
    pub policy_yaml_path: PathBuf,
    pub policy_version_rx: watch::Receiver<i64>,
    pub targets_tx: watch::Sender<Arc<Vec<CompiledTarget>>>,
    pub watcher: WatcherHandle,
    pub watched_roots: Vec<(PathBuf, bool)>,
    pub cache: Arc<Mutex<HashCache>>,
    pub shutdown: CancellationToken,
    /// Phase 3b.6.1 — shared with `ai_guard::task` so reload can add/remove
    /// per-repo `ContinueDevProjectParser` instances when `continue_workspaces`
    /// changes.
    pub parsers: Arc<parking_lot::RwLock<Vec<Arc<dyn crate::ai_guard::parser::AiGuardParser>>>>,
    /// Phase 3b.6.1 — shared with `ai_guard::task` so reload can clean up
    /// stale `(continue_dev, Project{path})` state entries for repos that
    /// were dropped from `continue_workspaces`.
    pub ai_guard_state: Arc<parking_lot::RwLock<crate::ai_guard::task::StateMap>>,
}

pub async fn run(mut ctx: ReloadCtx) {
    let plat = ActivePlatform::new();
    loop {
        tokio::select! {
            biased;
            _ = ctx.shutdown.cancelled() => break,
            changed = ctx.policy_version_rx.changed() => {
                if changed.is_err() {
                    // Sender (apply_ctx) dropped — agent is shutting down.
                    break;
                }
                reload(&mut ctx, &plat);
            }
        }
    }
}

/// Re-derive targets/roots from `policy.yaml` on disk and apply them to the
/// live pipeline + watcher. On any parse/merge failure, log and keep the
/// previous state untouched (can't happen via `apply_policy` — `sigil-sign`
/// parses before it signs — but a hand-edited file shouldn't kill the agent).
pub(crate) fn reload(ctx: &mut ReloadCtx, plat: &ActivePlatform) {
    let version = *ctx.policy_version_rx.borrow();

    let yaml = match std::fs::read_to_string(&ctx.policy_yaml_path) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(path = %ctx.policy_yaml_path.display(), error = %e,
                "policy reload: re-read failed; keeping previous targets");
            return;
        }
    };
    let doc = match sigil_core::policy::parse(&yaml) {
        Ok(d) => d,
        Err(e) => {
            tracing::error!(error = %e, "policy reload: re-parse failed; keeping previous targets");
            return;
        }
    };
    let defaults = match sigil_core::policy::defaults() {
        Ok(d) => d,
        Err(e) => {
            tracing::error!(error = %e, "policy reload: defaults() failed; keeping previous targets");
            return;
        }
    };
    let mut effective = match sigil_core::policy::merge(
        defaults,
        Some(doc),
        sigil_core::policy::current_platform(),
    ) {
        Ok(e) => e,
        Err(e) => {
            tracing::error!(error = %e, "policy reload: merge failed; keeping previous targets");
            return;
        }
    };

    // Phase 3b.6.1 — re-discover Continue per-repo parsers and reconcile.
    // Diff the newly-discovered set against the currently-installed parsers
    // (filtered to ContinueDev + Project{path}), then add the deltas and drop
    // the removed. Returns (added_repos, removed_repos) for state cleanup +
    // logging. The synthetic WatchTarget block below picks up the same
    // `new_repos` set so the watcher subgraph sees the new config.json files.
    let new_repos: std::collections::BTreeSet<PathBuf> =
        crate::ai_guard::continue_discovery::discover_continue_projects(
            &effective.continue_workspaces,
        )
        .into_iter()
        .collect();

    let (added_repos, removed_repos): (Vec<PathBuf>, Vec<PathBuf>) = {
        let mut guard = ctx.parsers.write();
        let mut old_repos: std::collections::BTreeSet<PathBuf> = std::collections::BTreeSet::new();
        guard.retain(|p| {
            if p.tool() == sigil_core::event::AiTool::ContinueDev {
                if let sigil_core::event::AiGuardScope::Project { path } = p.scope() {
                    old_repos.insert(path.clone());
                    return new_repos.contains(&path);
                }
            }
            true
        });
        let added: Vec<PathBuf> = new_repos.difference(&old_repos).cloned().collect();
        let removed: Vec<PathBuf> = old_repos.difference(&new_repos).cloned().collect();
        for repo_root in &added {
            guard.push(Arc::new(crate::ai_guard::ContinueDevProjectParser {
                repo_root: repo_root.clone(),
            }));
        }
        (added, removed)
    };

    // State map cleanup so stale (continue_dev, Project{path}) entries don't
    // accumulate across reloads.
    if !removed_repos.is_empty() {
        let mut state = ctx.ai_guard_state.write();
        for repo_root in &removed_repos {
            let key = (
                sigil_core::event::AiTool::ContinueDev,
                sigil_core::event::AiGuardScope::Project {
                    path: repo_root.clone(),
                },
            );
            state.remove(&key);
        }
    }

    // Synthetic WatchTarget entries — in-memory only; never persisted to the
    // signed policy envelope on disk. The watcher subgraph picks up changes
    // to these config.json files and re-evaluates the corresponding parser.
    for repo_root in &new_repos {
        let config = repo_root.join(".continue").join("config.json");
        let id_suffix = {
            let hex = blake3::hash(repo_root.to_string_lossy().as_bytes()).to_hex();
            hex.as_str()[..8].to_string()
        };
        effective.targets.push(sigil_core::policy::WatchTarget {
            id: format!("continue-project-{id_suffix}"),
            description: format!("Phase 3b.6.1 synthetic: {}", repo_root.display()),
            tier: sigil_core::policy::Tier::Critical,
            platform: sigil_core::policy::Platform::Any,
            paths: vec![config.to_string_lossy().to_string()],
            recursive: false,
            follow_symlinks: false,
            disabled: false,
        });
    }

    tracing::info!(
        continue_added = added_repos.len(),
        continue_removed = removed_repos.len(),
        "policy reload: per-repo Continue parsers reconciled"
    );

    let (expanded_paths, new_roots) = crate::runtime::expand_targets(&effective, plat);

    // Re-seed the critical-tier warmup cache (idempotent — overwrites).
    let _ = crate::runtime::perform_warmup(&effective, &expanded_paths, &ctx.cache);

    // Reconcile watch roots on the live watcher. `watch`/`unwatch` failures are
    // logged and tolerated, same as the startup `watch_all`.
    let mut added = 0usize;
    let mut removed = 0usize;
    for old in &ctx.watched_roots {
        if !new_roots.contains(old) {
            match ctx.watcher.unwatch(&old.0) {
                Ok(()) => removed += 1,
                Err(e) => tracing::warn!(root = %old.0.display(), error = %e,
                    "policy reload: unwatch failed"),
            }
        }
    }
    for new in &new_roots {
        if !ctx.watched_roots.contains(new) {
            match ctx.watcher.watch(&new.0, new.1) {
                Ok(()) => added += 1,
                Err(e) => tracing::warn!(root = %new.0.display(), recursive = new.1, error = %e,
                    "policy reload: watch failed"),
            }
        }
    }
    ctx.watched_roots = new_roots;

    let target_count = effective.targets.len();
    let _ = ctx.targets_tx.send(Arc::new(normalizer::compile_targets(
        &effective,
        &expanded_paths,
    )));

    tracing::info!(
        version,
        roots_added = added,
        roots_removed = removed,
        targets = target_count,
        "policy reload: applied to live watcher"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::expand_targets;
    use std::time::Duration;

    fn policy_yaml(target_id: &str, watch_path: &str, tier: &str) -> String {
        format!(
            "version: 1\ntargets:\n  - id: {target_id}\n    description: reload-test\n    tier: {tier}\n    platform: any\n    paths:\n      - '{watch_path}'\n    recursive: false\n    follow_symlinks: false\n"
        )
    }

    fn effective_from(yaml: &str) -> sigil_core::policy::EffectivePolicy {
        sigil_core::policy::merge(
            sigil_core::policy::defaults().unwrap(),
            Some(sigil_core::policy::parse(yaml).unwrap()),
            sigil_core::policy::current_platform(),
        )
        .unwrap()
    }

    #[allow(clippy::type_complexity)]
    fn build_ctx(
        dir: &std::path::Path,
        initial_yaml: &str,
    ) -> (
        ReloadCtx,
        ActivePlatform,
        watch::Receiver<Arc<Vec<CompiledTarget>>>,
    ) {
        let plat = ActivePlatform::new();
        let policy_yaml_path = dir.join("policy.yaml");
        std::fs::write(&policy_yaml_path, initial_yaml).unwrap();

        let eff = effective_from(initial_yaml);
        let (expanded, roots) = expand_targets(&eff, &plat);
        let initial_targets = Arc::new(normalizer::compile_targets(&eff, &expanded));
        let (targets_tx, targets_rx) = watch::channel(initial_targets);

        // A live PollWatcher-backed handle so reload()'s watch/unwatch are real
        // syscalls. Start it watching nothing — reload() will register the new
        // policy's roots. (Passing the full `roots` list would make the poll
        // watcher recursively scan the platform-default targets' big dirs.)
        let rt_handle = tokio::runtime::Handle::current();
        let (_rx, watcher) =
            crate::watcher::spawn_watcher(vec![], rt_handle, 16, Some(Duration::from_millis(200)))
                .unwrap();

        let (_vtx, policy_version_rx) = watch::channel(1i64);
        // Keep _vtx and the watcher's event receiver alive for the test's
        // duration (we drive `reload` directly, never `run`).
        std::mem::forget(_vtx);
        std::mem::forget(_rx);

        let cache = Arc::new(Mutex::new(HashCache::open(&dir.join("state.db")).unwrap()));

        (
            ReloadCtx {
                policy_yaml_path,
                policy_version_rx,
                targets_tx,
                watcher,
                watched_roots: roots,
                cache,
                shutdown: CancellationToken::new(),
                parsers: Arc::new(parking_lot::RwLock::new(Vec::new())),
                ai_guard_state: Arc::new(
                    parking_lot::RwLock::new(std::collections::HashMap::new()),
                ),
            },
            plat,
            targets_rx,
        )
    }

    #[allow(clippy::type_complexity)]
    fn build_ctx_with_parsers(
        dir: &std::path::Path,
        initial_yaml: &str,
    ) -> (
        ReloadCtx,
        ActivePlatform,
        watch::Receiver<Arc<Vec<CompiledTarget>>>,
        Arc<parking_lot::RwLock<Vec<Arc<dyn crate::ai_guard::parser::AiGuardParser>>>>,
        Arc<parking_lot::RwLock<crate::ai_guard::task::StateMap>>,
    ) {
        let plat = ActivePlatform::new();
        let policy_yaml_path = dir.join("policy.yaml");
        std::fs::write(&policy_yaml_path, initial_yaml).unwrap();

        let eff = effective_from(initial_yaml);
        let (expanded, roots) = expand_targets(&eff, &plat);
        let initial_targets = Arc::new(normalizer::compile_targets(&eff, &expanded));
        let (targets_tx, targets_rx) = watch::channel(initial_targets);

        let rt_handle = tokio::runtime::Handle::current();
        let (_rx, watcher) =
            crate::watcher::spawn_watcher(vec![], rt_handle, 16, Some(Duration::from_millis(200)))
                .unwrap();

        let (_vtx, policy_version_rx) = watch::channel(1i64);
        std::mem::forget(_vtx);
        std::mem::forget(_rx);

        let cache = Arc::new(Mutex::new(HashCache::open(&dir.join("state.db")).unwrap()));

        let parsers: Arc<
            parking_lot::RwLock<Vec<Arc<dyn crate::ai_guard::parser::AiGuardParser>>>,
        > = Arc::new(parking_lot::RwLock::new(Vec::new()));
        let state: Arc<parking_lot::RwLock<crate::ai_guard::task::StateMap>> =
            Arc::new(parking_lot::RwLock::new(std::collections::HashMap::new()));

        (
            ReloadCtx {
                policy_yaml_path,
                policy_version_rx,
                targets_tx,
                watcher,
                watched_roots: roots,
                cache,
                shutdown: CancellationToken::new(),
                parsers: parsers.clone(),
                ai_guard_state: state.clone(),
            },
            plat,
            targets_rx,
            parsers,
            state,
        )
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reload_swaps_targets_and_watch_roots_and_warms_new_critical() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("dirA")).unwrap();
        std::fs::create_dir(dir.path().join("dirB")).unwrap();
        let path_a = format!("{}/dirA/a.json", dir.path().display());
        let path_b = format!("{}/dirB/b.json", dir.path().display());

        let (mut ctx, plat, targets_rx) =
            build_ctx(dir.path(), &policy_yaml("target-a", &path_a, "standard"));

        // Switch to policy B (different id, different dir, critical tier) and
        // create B's file so the warmup hashes it.
        std::fs::write(dir.path().join("dirB").join("b.json"), b"hello").unwrap();
        std::fs::write(
            &ctx.policy_yaml_path,
            policy_yaml("target-b", &path_b, "critical"),
        )
        .unwrap();

        reload(&mut ctx, &plat);

        // Targets channel now reflects policy B.
        {
            let t = targets_rx.borrow();
            assert!(
                t.iter().any(|c| c.id == "target-b"),
                "expected target-b in {:?}",
                t.iter().map(|c| &c.id).collect::<Vec<_>>()
            );
            assert!(
                !t.iter().any(|c| c.id == "target-a"),
                "target-a should be gone"
            );
        }

        // Watch-root bookkeeping reflects policy B's roots.
        let eff_b = effective_from(&policy_yaml("target-b", &path_b, "critical"));
        let (_exp_b, roots_b) = expand_targets(&eff_b, &plat);
        assert_eq!(ctx.watched_roots, roots_b);

        // Warmup re-seeded the cache for B's critical file. The cache key is the
        // canonicalized path (same canonicalization expand_targets applies).
        let b_file = normalizer::canonicalize_glob_prefix(std::path::Path::new(&path_b));
        assert!(
            ctx.cache.lock().get(&b_file).unwrap().is_some(),
            "expected a cache entry for {}",
            b_file.display()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reload_keeps_previous_state_on_unparseable_policy() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("dirA")).unwrap();
        let path_a = format!("{}/dirA/a.json", dir.path().display());
        let (mut ctx, plat, targets_rx) =
            build_ctx(dir.path(), &policy_yaml("target-a", &path_a, "standard"));
        let roots_before = ctx.watched_roots.clone();

        std::fs::write(&ctx.policy_yaml_path, b": this is not : valid : yaml :::\n").unwrap();
        reload(&mut ctx, &plat); // must not panic

        assert!(
            targets_rx.borrow().iter().any(|c| c.id == "target-a"),
            "targets unchanged"
        );
        assert_eq!(ctx.watched_roots, roots_before, "watch roots unchanged");
    }

    // Phase 3b.6.1 — per-repo Continue parser hot-reload reconciliation.

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reload_adds_continue_per_repo_parser_when_workspace_root_added() {
        let dir = tempfile::tempdir().unwrap();
        let workspace = dir.path().join("ws");
        let repo_a = workspace.join("repoA");
        std::fs::create_dir_all(repo_a.join(".continue")).unwrap();
        std::fs::write(repo_a.join(".continue").join("config.json"), "{}").unwrap();
        let canonical_a = dunce::canonicalize(&repo_a).unwrap();

        let initial = "version: 1\nhost_id_strategy: machine_id\ntargets: []\n";
        let (mut ctx, plat, _trx, parsers, _state) = build_ctx_with_parsers(dir.path(), initial);
        reload(&mut ctx, &plat);
        {
            let guard = parsers.read();
            assert!(
                guard.iter().all(|p| !matches!(
                    (p.tool(), p.scope()),
                    (
                        sigil_core::event::AiTool::ContinueDev,
                        sigil_core::event::AiGuardScope::Project { .. }
                    )
                )),
                "no per-repo Continue parser should exist before continue_workspaces is set"
            );
        }

        let updated = format!(
            "version: 1\nhost_id_strategy: machine_id\ncontinue_workspaces:\n  - '{}'\ntargets: []\n",
            workspace.display()
        );
        std::fs::write(&ctx.policy_yaml_path, &updated).unwrap();
        reload(&mut ctx, &plat);
        {
            let guard = parsers.read();
            let has_repo_a = guard.iter().any(|p| {
                p.tool() == sigil_core::event::AiTool::ContinueDev
                    && matches!(p.scope(),
                        sigil_core::event::AiGuardScope::Project { ref path } if path == &canonical_a)
            });
            assert!(
                has_repo_a,
                "expected ContinueDevProjectParser for repoA after reload"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reload_removes_continue_per_repo_parser_when_workspace_root_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let workspace = dir.path().join("ws");
        let repo_a = workspace.join("repoA");
        std::fs::create_dir_all(repo_a.join(".continue")).unwrap();
        std::fs::write(repo_a.join(".continue").join("config.json"), "{}").unwrap();
        let canonical_a = dunce::canonicalize(&repo_a).unwrap();

        let initial = format!(
            "version: 1\nhost_id_strategy: machine_id\ncontinue_workspaces:\n  - '{}'\ntargets: []\n",
            workspace.display()
        );
        let (mut ctx, plat, _trx, parsers, state) = build_ctx_with_parsers(dir.path(), &initial);
        reload(&mut ctx, &plat);

        // Plant a fake state entry to verify cleanup on removal.
        {
            let mut s = state.write();
            s.insert(
                (
                    sigil_core::event::AiTool::ContinueDev,
                    sigil_core::event::AiGuardScope::Project {
                        path: canonical_a.clone(),
                    },
                ),
                crate::ai_guard::task::CachedAssessment {
                    score: 5.0,
                    bucket: sigil_core::event::AiGuardBucket::High,
                    reasons_blake3: [0u8; 32],
                    reasons_count: 1,
                    last_assessed_ts: time::OffsetDateTime::now_utc(),
                },
            );
        }

        let updated = "version: 1\nhost_id_strategy: machine_id\ntargets: []\n";
        std::fs::write(&ctx.policy_yaml_path, updated).unwrap();
        reload(&mut ctx, &plat);

        {
            let guard = parsers.read();
            let still_present = guard.iter().any(|p| {
                p.tool() == sigil_core::event::AiTool::ContinueDev
                    && matches!(p.scope(),
                        sigil_core::event::AiGuardScope::Project { ref path } if path == &canonical_a)
            });
            assert!(
                !still_present,
                "ContinueDevProjectParser for repoA should be removed"
            );
        }
        {
            let s = state.read();
            let key = (
                sigil_core::event::AiTool::ContinueDev,
                sigil_core::event::AiGuardScope::Project {
                    path: canonical_a.clone(),
                },
            );
            assert!(
                !s.contains_key(&key),
                "state map entry for removed repo should be cleaned"
            );
        }
    }
}
