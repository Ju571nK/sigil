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
    let effective = match sigil_core::policy::merge(
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
            },
            plat,
            targets_rx,
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
}
