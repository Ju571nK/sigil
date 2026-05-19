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

/// Phase 3b.6.2 — generic reconcile applied per-tool during hot-reload.
/// Drops parsers whose repo was removed, adds parsers for new repos,
/// and returns (added, removed) for tracing + state-map cleanup.
///
/// `guard`: a write guard already held on `ctx.parsers`.
/// `state`: the ai_guard StateMap Arc — entries for removed repos get evicted.
/// `tool`: the AiTool variant this reconcile operates on (filters which
/// existing parsers we examine).
/// `new_repos`: the freshly-discovered repo set from `discover_per_repo`.
/// `make_parser`: closure that builds the per-tool parser from a repo root.
fn reconcile_per_repo<P, F>(
    guard: &mut parking_lot::RwLockWriteGuard<Vec<Arc<dyn crate::ai_guard::parser::AiGuardParser>>>,
    state: &Arc<parking_lot::RwLock<crate::ai_guard::task::StateMap>>,
    tool: sigil_core::event::AiTool,
    new_repos: &std::collections::BTreeSet<PathBuf>,
    make_parser: F,
) -> (Vec<PathBuf>, Vec<PathBuf>)
where
    P: crate::ai_guard::parser::AiGuardParser + 'static,
    F: Fn(PathBuf) -> P,
{
    let mut old_repos: std::collections::BTreeSet<PathBuf> = std::collections::BTreeSet::new();
    guard.retain(|p| {
        if p.tool() == tool {
            if let sigil_core::event::AiGuardScope::Project { path } = p.scope() {
                old_repos.insert(path.clone());
                return new_repos.contains(&path);
            }
        }
        true
    });
    let added: Vec<PathBuf> = new_repos.difference(&old_repos).cloned().collect();
    let removed: Vec<PathBuf> = old_repos.difference(new_repos).cloned().collect();
    for repo_root in &added {
        guard.push(Arc::new(make_parser(repo_root.clone())));
    }
    if !removed.is_empty() {
        let mut s = state.write();
        for repo_root in &removed {
            s.remove(&(
                tool,
                sigil_core::event::AiGuardScope::Project {
                    path: repo_root.clone(),
                },
            ));
        }
    }
    (added, removed)
}

/// Phase 3b.7 — reconcile rule pack parsers during hot-reload. Downcasts
/// existing parsers via `as_any()` to identify rule pack parsers by id, diffs
/// the old id set against the new (loadable) one, drops removed packs (and
/// cleans up their (tool, scope) entries from the ai_guard state map), and
/// pushes freshly-compiled parsers for newly-added packs. Returns
/// (added_ids, removed_ids) for tracing + observability.
fn reconcile_rule_packs(
    guard: &mut parking_lot::RwLockWriteGuard<Vec<Arc<dyn crate::ai_guard::parser::AiGuardParser>>>,
    state: &Arc<parking_lot::RwLock<crate::ai_guard::task::StateMap>>,
    new_packs: &[sigil_core::policy::RulePack],
) -> (Vec<String>, Vec<String>) {
    use std::collections::HashSet;

    let new_ids: HashSet<String> = new_packs
        .iter()
        .filter(|p| crate::ai_guard::rule_pack::pack_is_loadable(p))
        .map(|p| p.id.clone())
        .collect();

    let mut old_ids: HashSet<String> = HashSet::new();
    let mut removed_scopes: Vec<(sigil_core::event::AiTool, sigil_core::event::AiGuardScope)> =
        Vec::new();

    guard.retain(|p| {
        if let Some(rpp) = p
            .as_any()
            .downcast_ref::<crate::ai_guard::rule_pack::parser::RulePackParser>()
        {
            let id = rpp.pack.id.clone();
            old_ids.insert(id.clone());
            if new_ids.contains(&id) {
                true
            } else {
                removed_scopes.push((rpp.pack.tool, rpp.pack.scope.clone()));
                false
            }
        } else {
            true
        }
    });

    let added: Vec<String> = new_ids.difference(&old_ids).cloned().collect();
    let removed: Vec<String> = old_ids.difference(&new_ids).cloned().collect();

    for pack in new_packs.iter().filter(|p| added.contains(&p.id)) {
        if !crate::ai_guard::rule_pack::pack_is_loadable(pack) {
            continue;
        }
        match crate::ai_guard::rule_pack::parser::RulePackParser::new(pack.clone()) {
            Ok(p) => guard.push(Arc::new(p)),
            Err(e) => tracing::warn!(
                id = %pack.id, error = ?e,
                "rule_pack: reload load failed; skipping"
            ),
        }
    }

    if !removed_scopes.is_empty() {
        let mut s = state.write();
        for (tool, scope) in &removed_scopes {
            s.remove(&(*tool, scope.clone()));
        }
    }

    (added, removed)
}

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

    // Phase 3b.6.2 — re-discover all 3 tools and reconcile each via the
    // generic reconcile_per_repo helper. State map entries for removed
    // repos are evicted to prevent stale memory across reloads.
    let new_continue: std::collections::BTreeSet<PathBuf> =
        crate::ai_guard::workspace_discovery::discover_per_repo(
            &effective.continue_workspaces,
            ".continue/config.json",
        )
        .into_iter()
        .collect();
    let new_claude: std::collections::BTreeSet<PathBuf> =
        crate::ai_guard::workspace_discovery::discover_per_repo(
            &effective.claude_code_workspaces,
            ".claude/settings.json",
        )
        .into_iter()
        .collect();
    let new_codex: std::collections::BTreeSet<PathBuf> =
        crate::ai_guard::workspace_discovery::discover_per_repo(
            &effective.codex_workspaces,
            ".codex/config.toml",
        )
        .into_iter()
        .collect();

    let (
        continue_added,
        continue_removed,
        claude_added,
        claude_removed,
        codex_added,
        codex_removed,
        rule_packs_added,
        rule_packs_removed,
    ) = {
        let mut guard = ctx.parsers.write();
        let (a1, r1) = reconcile_per_repo(
            &mut guard,
            &ctx.ai_guard_state,
            sigil_core::event::AiTool::ContinueDev,
            &new_continue,
            |p| crate::ai_guard::ContinueDevProjectParser { repo_root: p },
        );
        let (a2, r2) = reconcile_per_repo(
            &mut guard,
            &ctx.ai_guard_state,
            sigil_core::event::AiTool::ClaudeCode,
            &new_claude,
            |p| crate::ai_guard::ClaudeCodeProjectParser { repo_root: p },
        );
        let (a3, r3) = reconcile_per_repo(
            &mut guard,
            &ctx.ai_guard_state,
            sigil_core::event::AiTool::Codex,
            &new_codex,
            |p| crate::ai_guard::CodexProjectParser { repo_root: p },
        );
        let (rp_added, rp_removed) =
            reconcile_rule_packs(&mut guard, &ctx.ai_guard_state, &effective.rule_packs);
        (a1, r1, a2, r2, a3, r3, rp_added, rp_removed)
    };

    // Synthetic WatchTargets — in-memory only; never persisted.
    for repo_root in &new_continue {
        crate::runtime::push_continue_synthetic_target(&mut effective, repo_root);
    }
    for repo_root in &new_claude {
        crate::runtime::push_claude_code_synthetic_targets(&mut effective, repo_root);
    }
    for repo_root in &new_codex {
        crate::runtime::push_codex_synthetic_target(&mut effective, repo_root);
    }

    tracing::info!(
        continue_added = continue_added.len(),
        continue_removed = continue_removed.len(),
        claude_code_added = claude_added.len(),
        claude_code_removed = claude_removed.len(),
        codex_added = codex_added.len(),
        codex_removed = codex_removed.len(),
        rule_packs_added = rule_packs_added.len(),
        rule_packs_removed = rule_packs_removed.len(),
        "policy reload: per-repo parsers + rule packs reconciled"
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

    // Phase 3b.6.2 — per-repo Claude Code + Codex parser hot-reload reconciliation.

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reload_adds_claude_code_per_repo_parser_when_workspace_root_added() {
        let dir = tempfile::tempdir().unwrap();
        let workspace = dir.path().join("ws");
        let repo_a = workspace.join("repoA");
        std::fs::create_dir_all(repo_a.join(".claude")).unwrap();
        std::fs::write(repo_a.join(".claude").join("settings.json"), r#"{}"#).unwrap();
        let canonical_a = dunce::canonicalize(&repo_a).unwrap();

        let initial = "version: 1\nhost_id_strategy: machine_id\ntargets: []\n";
        let (mut ctx, plat, _trx, parsers, _state) = build_ctx_with_parsers(dir.path(), initial);
        reload(&mut ctx, &plat);
        assert!(parsers.read().iter().all(|p| !matches!(
            (p.tool(), p.scope()),
            (
                sigil_core::event::AiTool::ClaudeCode,
                sigil_core::event::AiGuardScope::Project { .. }
            )
        )));

        let updated = format!(
            "version: 1\nhost_id_strategy: machine_id\nclaude_code_workspaces:\n  - '{}'\ntargets: []\n",
            workspace.display()
        );
        std::fs::write(&ctx.policy_yaml_path, &updated).unwrap();
        reload(&mut ctx, &plat);
        let has = parsers.read().iter().any(|p| {
            p.tool() == sigil_core::event::AiTool::ClaudeCode
                && matches!(
                    p.scope(),
                    sigil_core::event::AiGuardScope::Project { ref path } if path == &canonical_a
                )
        });
        assert!(
            has,
            "expected ClaudeCodeProjectParser for repoA after reload"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reload_adds_codex_per_repo_parser_when_workspace_root_added() {
        let dir = tempfile::tempdir().unwrap();
        let workspace = dir.path().join("ws");
        let repo_a = workspace.join("repoA");
        std::fs::create_dir_all(repo_a.join(".codex")).unwrap();
        std::fs::write(repo_a.join(".codex").join("config.toml"), "").unwrap();
        let canonical_a = dunce::canonicalize(&repo_a).unwrap();

        let initial = "version: 1\nhost_id_strategy: machine_id\ntargets: []\n";
        let (mut ctx, plat, _trx, parsers, _state) = build_ctx_with_parsers(dir.path(), initial);
        reload(&mut ctx, &plat);
        assert!(parsers.read().iter().all(|p| !matches!(
            (p.tool(), p.scope()),
            (
                sigil_core::event::AiTool::Codex,
                sigil_core::event::AiGuardScope::Project { .. }
            )
        )));

        let updated = format!(
            "version: 1\nhost_id_strategy: machine_id\ncodex_workspaces:\n  - '{}'\ntargets: []\n",
            workspace.display()
        );
        std::fs::write(&ctx.policy_yaml_path, &updated).unwrap();
        reload(&mut ctx, &plat);
        let has = parsers.read().iter().any(|p| {
            p.tool() == sigil_core::event::AiTool::Codex
                && matches!(
                    p.scope(),
                    sigil_core::event::AiGuardScope::Project { ref path } if path == &canonical_a
                )
        });
        assert!(has, "expected CodexProjectParser for repoA after reload");
    }

    // Phase 3b.7 — rule pack parser hot-reload reconciliation.

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reload_adds_rule_pack_when_user_adds_one() {
        let dir = tempfile::tempdir().unwrap();
        let initial = "version: 1\nhost_id_strategy: machine_id\ntargets:\n  - id: t1\n    description: x\n    tier: standard\n    platform: any\n    paths: [\"/tmp/x\"]\n";
        let (mut ctx, plat, _trx, parsers, _state) = build_ctx_with_parsers(dir.path(), initial);
        reload(&mut ctx, &plat);

        // Defaults loaded — 2 packs (gemini-default, cursor-default).
        let default_count = parsers
            .read()
            .iter()
            .filter(|p| {
                p.as_any()
                    .downcast_ref::<crate::ai_guard::rule_pack::parser::RulePackParser>()
                    .is_some()
            })
            .count();
        assert_eq!(default_count, 2);

        // Add a custom user rule pack.
        let updated = "version: 1\nhost_id_strategy: machine_id\ntargets:\n  - id: t1\n    description: x\n    tier: standard\n    platform: any\n    paths: [\"/tmp/x\"]\nrule_packs:\n  - id: my-extra\n    pack_version: 1\n    tool: gemini\n    scope:\n      kind: user_global\n    watched_paths: []\n    rules: []\n";
        std::fs::write(&ctx.policy_yaml_path, updated).unwrap();
        reload(&mut ctx, &plat);

        let has_extra = parsers.read().iter().any(|p| {
            p.as_any()
                .downcast_ref::<crate::ai_guard::rule_pack::parser::RulePackParser>()
                .map(|rpp| rpp.pack.id == "my-extra")
                .unwrap_or(false)
        });
        assert!(has_extra, "expected my-extra rule pack after reload");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reload_removes_user_rule_pack_when_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let initial = "version: 1\nhost_id_strategy: machine_id\ntargets:\n  - id: t1\n    description: x\n    tier: standard\n    platform: any\n    paths: [\"/tmp/x\"]\nrule_packs:\n  - id: my-extra\n    pack_version: 1\n    tool: gemini\n    scope:\n      kind: user_global\n    watched_paths: []\n    rules: []\n";
        let (mut ctx, plat, _trx, parsers, _state) = build_ctx_with_parsers(dir.path(), initial);
        reload(&mut ctx, &plat);

        // Confirm my-extra loaded.
        assert!(parsers.read().iter().any(|p| {
            p.as_any()
                .downcast_ref::<crate::ai_guard::rule_pack::parser::RulePackParser>()
                .map(|rpp| rpp.pack.id == "my-extra")
                .unwrap_or(false)
        }));

        // Drop the user pack — should leave just the 2 defaults.
        let updated = "version: 1\nhost_id_strategy: machine_id\ntargets:\n  - id: t1\n    description: x\n    tier: standard\n    platform: any\n    paths: [\"/tmp/x\"]\n";
        std::fs::write(&ctx.policy_yaml_path, updated).unwrap();
        reload(&mut ctx, &plat);

        let still_present = parsers.read().iter().any(|p| {
            p.as_any()
                .downcast_ref::<crate::ai_guard::rule_pack::parser::RulePackParser>()
                .map(|rpp| rpp.pack.id == "my-extra")
                .unwrap_or(false)
        });
        assert!(!still_present, "my-extra should be removed after reload");

        // Defaults still there.
        let default_count = parsers
            .read()
            .iter()
            .filter(|p| {
                p.as_any()
                    .downcast_ref::<crate::ai_guard::rule_pack::parser::RulePackParser>()
                    .is_some()
            })
            .count();
        assert_eq!(default_count, 2);
    }
}
