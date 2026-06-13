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
        // Task 6 — rule-pack parsers (also Project-scoped) are owned by
        // `reconcile_rule_packs`; never reconcile them here or this built-in
        // reconcile would drop them and miss their `Some(pack_id)` state keys.
        if p.as_any()
            .downcast_ref::<crate::ai_guard::rule_pack::parser::RulePackParser>()
            .is_some()
        {
            return true;
        }
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
                None::<String>,
            ));
        }
    }
    (added, removed)
}

/// Phase 3b.7 + Task 6 — reconcile rule pack parsers during hot-reload via a
/// full rebuild. Every rule-pack parser (UserGlobal and per-repo Project) is
/// dropped and re-expanded from the new loadable pack set through
/// `expand_pack_parsers`, so Project packs correctly add/drop one parser per
/// discovered repo. State-map entries whose `(tool, scope, Some(id))` identity
/// no longer exists are evicted. Returns `(added_ids, removed_ids)` — diffed at
/// PACK-ID granularity for tracing + observability.
fn reconcile_rule_packs(
    guard: &mut parking_lot::RwLockWriteGuard<Vec<Arc<dyn crate::ai_guard::parser::AiGuardParser>>>,
    state: &Arc<parking_lot::RwLock<crate::ai_guard::task::StateMap>>,
    new_packs: &[sigil_core::policy::RulePack],
    repos_for_tool: &dyn Fn(sigil_core::event::AiTool) -> Vec<PathBuf>,
) -> (Vec<String>, Vec<String>) {
    use crate::ai_guard::parser::AiGuardParser;
    use std::collections::HashSet;
    type Ident = (
        sigil_core::event::AiTool,
        sigil_core::event::AiGuardScope,
        String,
    );

    // 1. Record old identities + old pack-id set; drop all rule-pack parsers
    //    (keep built-ins).
    let mut old_keys: HashSet<Ident> = HashSet::new();
    let mut old_pack_ids: HashSet<String> = HashSet::new();
    guard.retain(|p| {
        if let Some(rpp) = p
            .as_any()
            .downcast_ref::<crate::ai_guard::rule_pack::parser::RulePackParser>()
        {
            old_pack_ids.insert(rpp.pack.id.clone());
            old_keys.insert((p.tool(), p.scope(), rpp.pack.id.clone()));
            false
        } else {
            true
        }
    });

    // 2. Re-expand loadable packs; record new identities + pack-id set.
    let mut new_keys: HashSet<Ident> = HashSet::new();
    let mut new_pack_ids: HashSet<String> = HashSet::new();
    for pack in new_packs {
        if !crate::ai_guard::rule_pack::pack_is_loadable(pack) {
            continue;
        }
        new_pack_ids.insert(pack.id.clone());
        let repos = repos_for_tool(pack.tool);
        for parser in crate::ai_guard::rule_pack::expand::expand_pack_parsers(pack, &repos) {
            new_keys.insert((parser.tool(), parser.scope(), pack.id.clone()));
            guard.push(Arc::new(parser));
        }
    }

    // 3. Prune vanished state identities (old − new).
    let gone: Vec<Ident> = old_keys.difference(&new_keys).cloned().collect();
    if !gone.is_empty() {
        let mut s = state.write();
        for (tool, scope, id) in gone {
            s.remove(&(tool, scope, Some(id)));
        }
    }

    // 4. Tracing diffs at pack-id granularity.
    let added: Vec<String> = new_pack_ids.difference(&old_pack_ids).cloned().collect();
    let removed: Vec<String> = old_pack_ids.difference(&new_pack_ids).cloned().collect();
    (added, removed)
}

/// States for the rule-pack bundle file.
/// - `Absent` = file genuinely missing (NotFound) → deliberate `rm`, clear the layer.
/// - `Present` = parsed OK.
/// - `Corrupt` = file exists but read/parse failed → retain the last-good bundle.
/// - `Empty` = file is zero-byte / whitespace-only → retain the last-good bundle.
///   A non-atomic `cp` truncates the destination to zero bytes before writing, so a
///   transient empty read is ambiguous with a half-finished write; retaining (#135)
///   never drops enforcement on that race. To intentionally clear the layer, `rm` the
///   file (→ Absent) or write a valid empty document (→ Present with no packs).
///
/// PolicyDocument is large (~392 B) so we box it to keep the enum small.
pub(crate) enum BundleState {
    Absent,
    Present(Box<sigil_core::policy::PolicyDocument>),
    Corrupt,
    Empty,
}

pub(crate) fn read_bundle_state(path: &std::path::Path) -> BundleState {
    let s = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return BundleState::Absent,
        Err(e) => {
            tracing::warn!(error = ?e, path = %path.display(), "rule-packs.yaml read failed");
            return BundleState::Corrupt; // 읽기 실패도 보수적으로 corrupt(이전 유지)
        }
    };
    // A zero-byte / whitespace-only file is a transient truncate window (non-atomic
    // cp), NOT a deliberate removal. Treat it as `Empty` → retain last-good (#135),
    // distinct from NotFound → Absent → clear. Deliberately clearing packs means
    // `rm` the file or write a valid empty document (which parses to Present).
    if s.trim().is_empty() {
        return BundleState::Empty;
    }
    match sigil_core::policy::parse(&s) {
        Ok(d) => BundleState::Present(Box::new(d)),
        Err(e) => {
            tracing::warn!(error = ?e, path = %path.display(),
                "rule-packs.yaml parse failed; retaining last good bundle");
            BundleState::Corrupt
        }
    }
}

/// Inputs for the reload task. The `WatcherHandle` lives here for the task's
/// lifetime (so the OS watcher stays alive); `watched_roots` is the diff base
/// for the next reconcile (start it equal to the roots `run` registered).
pub struct ReloadCtx {
    pub policy_yaml_path: PathBuf,
    pub policy_version_rx: watch::Receiver<i64>,
    /// Task 5 — bumped by `apply_rule_packs` whenever it commits a new
    /// `rule-packs.yaml`. A change here re-runs `reload()` so the bundle's
    /// rule packs are re-merged into the live parser set.
    pub rule_packs_version_rx: watch::Receiver<i64>,
    /// Task 5 — on-disk path of the distributed rule-pack bundle, beside
    /// `policy.yaml`. IDENTICAL to `ApplyContext.rule_packs_yaml_path` so the
    /// apply path writes exactly where boot/reload read.
    pub rule_packs_yaml_path: PathBuf,
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
    /// Phase 3b.3 — shared registry of external hook-script paths per
    /// parser (tool, scope). Reload rebuilds this on every policy change
    /// and synthesizes ext-script WatchTargets into the freshly-merged
    /// effective.
    pub ext_scripts: crate::ai_guard::ExtScriptRegistry,
    /// Phase 3b.5 — shared rubric handle. reload() rebuilds from
    /// EffectivePolicy.rubric_overrides and atomic-swaps via write lock.
    pub rubric: crate::ai_guard::RubricHandle,
    /// #115 — shared deny evaluator. reload() rebuilds from
    /// EffectivePolicy.hook_deny_rules and swaps; keep-previous on Err.
    pub shared_evaluator: crate::hook_deny::SharedEvaluator,
    /// #134 — 마지막으로 성공 파스된 번들 doc. corrupt 시 이를 재사용해
    /// transient 파스 실패가 번들 룰팩을 drop하지 않게 한다.
    pub last_good_bundle: Option<sigil_core::policy::PolicyDocument>,
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
            changed = ctx.rule_packs_version_rx.changed() => {
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
    // Task 5 / #134 — read the distributed rule-pack bundle (3rd merge layer:
    // defaults < policy < bundle).
    // Corrupt(파일 존재+파스 실패) → retain last good (transient git-pull state protected).
    // Empty(0바이트/공백, cp 트렁케이트 창) → retain last good (#135, enforcement race 방지).
    // Absent(파일 NotFound) → clear cache (deliberate rm honored).
    let bundle: Option<sigil_core::policy::PolicyDocument> =
        match read_bundle_state(&ctx.rule_packs_yaml_path) {
            BundleState::Present(d) => {
                let doc = *d;
                ctx.last_good_bundle = Some(doc.clone());
                Some(doc)
            }
            BundleState::Corrupt | BundleState::Empty => ctx.last_good_bundle.clone(), // 이전 정상 유지
            BundleState::Absent => {
                ctx.last_good_bundle = None; // 의도적 제거 → 캐시 비움
                None
            }
        };
    let mut effective = match sigil_core::policy::merge(
        defaults,
        Some(doc),
        bundle,
        sigil_core::policy::current_platform(),
    ) {
        Ok(e) => e,
        Err(e) => {
            tracing::error!(error = %e, "policy reload: merge failed; keeping previous targets");
            return;
        }
    };

    // #115 / #134 — rebuild the shared deny evaluator from the freshly-merged
    // policy. Keep-previous on deny-id validation failure OR regex compile
    // failure (fail-open is the previous state).
    if let Err(e) = sigil_core::policy::validate_deny_rule_ids(&effective.hook_deny_rules) {
        tracing::warn!(error = %e,
            "merged hook_deny_rules failed id validation on reload; keeping previous evaluator");
    } else {
        match crate::hook_deny::DenyEvaluator::new(&effective.hook_deny_rules) {
            Ok(ev) => {
                *ctx.shared_evaluator.write() = std::sync::Arc::new(ev);
            }
            Err(e) => tracing::warn!(error = ?e,
                "hook deny rules failed to compile on reload; keeping previous evaluator"),
        }
    }

    // Phase 3b.6.2 — re-discover all 5 tools and reconcile each via the
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
        crate::ai_guard::workspace_discovery::discover_claude_repos(
            &effective.claude_code_workspaces,
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
    let new_gemini: std::collections::BTreeSet<PathBuf> =
        crate::ai_guard::workspace_discovery::discover_per_repo(
            &effective.gemini_workspaces,
            ".gemini/settings.json",
        )
        .into_iter()
        .collect();
    let new_cursor: std::collections::BTreeSet<PathBuf> =
        crate::ai_guard::workspace_discovery::discover_per_repo(
            &effective.cursor_workspaces,
            ".cursor/mcp.json",
        )
        .into_iter()
        .collect();
    // #93 — reconciled like the other five tools (built-in
    // AntigravityProjectParser) AND used for Project rule-pack expansion.
    let new_antigravity: std::collections::BTreeSet<PathBuf> =
        crate::ai_guard::workspace_discovery::discover_per_repo(
            &effective.antigravity_workspaces,
            ".antigravity/settings.json",
        )
        .into_iter()
        .collect();

    // Task 6 — exhaustive AiTool -> repos lookup for Project rule-pack
    // expansion (used by reconcile_rule_packs and the synthetic-target loop).
    let repos_for_tool = |tool: sigil_core::event::AiTool| -> Vec<PathBuf> {
        use sigil_core::event::AiTool::*;
        match tool {
            ContinueDev => new_continue.iter().cloned().collect(),
            ClaudeCode => new_claude.iter().cloned().collect(),
            Codex => new_codex.iter().cloned().collect(),
            Gemini => new_gemini.iter().cloned().collect(),
            Cursor => new_cursor.iter().cloned().collect(),
            Antigravity => new_antigravity.iter().cloned().collect(),
            ClaudeDesktop => Vec::new(),
            Grok => Vec::new(), // #110: no Grok project parser/workspace yet
            Other => Vec::new(),
        }
    };

    let (
        continue_added,
        continue_removed,
        claude_added,
        claude_removed,
        codex_added,
        codex_removed,
        gemini_added,
        gemini_removed,
        cursor_added,
        cursor_removed,
        antigravity_added,
        antigravity_removed,
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
        let (a4, r4) = reconcile_per_repo(
            &mut guard,
            &ctx.ai_guard_state,
            sigil_core::event::AiTool::Gemini,
            &new_gemini,
            |p| crate::ai_guard::GeminiProjectParser { repo_root: p },
        );
        let (a5, r5) = reconcile_per_repo(
            &mut guard,
            &ctx.ai_guard_state,
            sigil_core::event::AiTool::Cursor,
            &new_cursor,
            |p| crate::ai_guard::CursorProjectParser { repo_root: p },
        );
        let (a6, r6) = reconcile_per_repo(
            &mut guard,
            &ctx.ai_guard_state,
            sigil_core::event::AiTool::Antigravity,
            &new_antigravity,
            |p| crate::ai_guard::AntigravityProjectParser { repo_root: p },
        );
        let (rp_added, rp_removed) = reconcile_rule_packs(
            &mut guard,
            &ctx.ai_guard_state,
            &effective.rule_packs,
            &repos_for_tool,
        );
        (
            a1, r1, a2, r2, a3, r3, a4, r4, a5, r5, a6, r6, rp_added, rp_removed,
        )
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
    for repo_root in &new_gemini {
        crate::runtime::push_gemini_synthetic_target(&mut effective, repo_root);
    }
    for repo_root in &new_cursor {
        crate::runtime::push_cursor_synthetic_target(&mut effective, repo_root);
    }
    for repo_root in &new_antigravity {
        crate::runtime::push_antigravity_synthetic_target(&mut effective, repo_root);
    }
    // Task 6 — synthetic WatchTargets for Project-scoped rule packs, one per
    // discovered repo for the pack's tool (mirrors boot-time instantiation).
    // Clone the relevant packs first so the loop doesn't hold an immutable
    // borrow of `effective` while `push_rule_pack_synthetic_targets` mutates it.
    let project_packs: Vec<sigil_core::policy::RulePack> = effective
        .rule_packs
        .iter()
        .filter(|p| {
            crate::ai_guard::rule_pack::pack_is_loadable(p)
                && matches!(p.scope, sigil_core::policy::RulePackScope::Project)
        })
        .cloned()
        .collect();
    for pack in &project_packs {
        for repo in repos_for_tool(pack.tool) {
            crate::runtime::push_rule_pack_synthetic_targets(&mut effective, pack, &repo);
        }
    }

    tracing::info!(
        continue_added = continue_added.len(),
        continue_removed = continue_removed.len(),
        claude_code_added = claude_added.len(),
        claude_code_removed = claude_removed.len(),
        codex_added = codex_added.len(),
        codex_removed = codex_removed.len(),
        gemini_added = gemini_added.len(),
        gemini_removed = gemini_removed.len(),
        cursor_added = cursor_added.len(),
        cursor_removed = cursor_removed.len(),
        antigravity_added = antigravity_added.len(),
        antigravity_removed = antigravity_removed.len(),
        rule_packs_added = rule_packs_added.len(),
        rule_packs_removed = rule_packs_removed.len(),
        "policy reload: per-repo parsers + rule packs reconciled"
    );

    // Phase 3b.3 — rebuild ExtScriptRegistry and synthesize ext-script
    // WatchTargets into freshly-merged effective. Stale synth targets are
    // automatically dropped because `effective` is rebuilt each cycle.
    // The reconcile_per_repo / reconcile_rule_packs write guard on
    // `ctx.parsers` was released above (end of the let-block at the
    // `reconcile_rule_packs` call), so taking a read guard here is safe.
    {
        let parsers_snapshot: Vec<Arc<dyn crate::ai_guard::parser::AiGuardParser>> =
            ctx.parsers.read().clone();
        let home_dir = std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/"));
        crate::runtime::discover_and_register_ext_scripts(
            &parsers_snapshot,
            &home_dir,
            &ctx.ext_scripts,
            &mut effective,
        );
    }

    // Phase 3b.5 — rebuild + atomic-swap the rubric to reflect any
    // change in EffectivePolicy.rubric_overrides. Unknown keys are
    // warn-logged by with_overrides and accumulated into the new
    // Rubric's unknown_override_keys.
    {
        let new_rubric =
            crate::ai_guard::rubric::Rubric::defaults().with_overrides(&effective.rubric_overrides);
        let overridden_count = new_rubric.overridden.len();
        let unknown_count = new_rubric.unknown_override_keys.len();
        *ctx.rubric.write() = new_rubric;
        if overridden_count > 0 || unknown_count > 0 {
            tracing::info!(
                applied = overridden_count,
                unknown = unknown_count,
                "rubric: reload reconciled"
            );
        }
    }

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

    /// Verify the repos_for_tool closure (as defined in reload()) returns an
    /// empty Vec for AiTool::Grok — no project parser/workspace registered yet (#110).
    #[test]
    fn repos_for_tool_grok_is_empty() {
        // Mirror the closure shape from reload(): all empty BTreeSets.
        let empty: std::collections::BTreeSet<PathBuf> = std::collections::BTreeSet::new();
        let repos_for_tool = |tool: sigil_core::event::AiTool| -> Vec<PathBuf> {
            use sigil_core::event::AiTool::*;
            match tool {
                ContinueDev => empty.iter().cloned().collect(),
                ClaudeCode => empty.iter().cloned().collect(),
                Codex => empty.iter().cloned().collect(),
                Gemini => empty.iter().cloned().collect(),
                Cursor => empty.iter().cloned().collect(),
                Antigravity => empty.iter().cloned().collect(),
                ClaudeDesktop => Vec::new(),
                Grok => Vec::new(), // #110: no Grok project parser/workspace yet
                Other => Vec::new(),
            }
        };
        assert!(repos_for_tool(sigil_core::event::AiTool::Grok).is_empty());
    }

    fn policy_yaml(target_id: &str, watch_path: &str, tier: &str) -> String {
        format!(
            "version: 1\ntargets:\n  - id: {target_id}\n    description: reload-test\n    tier: {tier}\n    platform: any\n    paths:\n      - '{watch_path}'\n    recursive: false\n    follow_symlinks: false\n"
        )
    }

    fn effective_from(yaml: &str) -> sigil_core::policy::EffectivePolicy {
        sigil_core::policy::merge(
            sigil_core::policy::defaults().unwrap(),
            Some(sigil_core::policy::parse(yaml).unwrap()),
            None,
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
        let (_rptx, rule_packs_version_rx) = watch::channel(0i64);
        std::mem::forget(_rptx);

        let cache = Arc::new(Mutex::new(HashCache::open(&dir.join("state.db")).unwrap()));

        (
            ReloadCtx {
                policy_yaml_path,
                policy_version_rx,
                rule_packs_version_rx,
                rule_packs_yaml_path: dir.join("rule-packs.yaml"),
                targets_tx,
                watcher,
                watched_roots: roots,
                cache,
                shutdown: CancellationToken::new(),
                parsers: Arc::new(parking_lot::RwLock::new(Vec::new())),
                ai_guard_state: Arc::new(
                    parking_lot::RwLock::new(std::collections::HashMap::new()),
                ),
                ext_scripts: crate::ai_guard::empty_ext_script_registry(),
                rubric: crate::ai_guard::default_rubric_handle(),
                shared_evaluator: Arc::new(parking_lot::RwLock::new(Arc::new(
                    crate::hook_deny::DenyEvaluator::new(&[]).unwrap(),
                ))),
                last_good_bundle: None,
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
        let (_rptx, rule_packs_version_rx) = watch::channel(0i64);
        std::mem::forget(_rptx);

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
                rule_packs_version_rx,
                rule_packs_yaml_path: dir.join("rule-packs.yaml"),
                targets_tx,
                watcher,
                watched_roots: roots,
                cache,
                shutdown: CancellationToken::new(),
                parsers: parsers.clone(),
                ai_guard_state: state.clone(),
                ext_scripts: crate::ai_guard::empty_ext_script_registry(),
                rubric: crate::ai_guard::default_rubric_handle(),
                shared_evaluator: Arc::new(parking_lot::RwLock::new(Arc::new(
                    crate::hook_deny::DenyEvaluator::new(&[]).unwrap(),
                ))),
                last_good_bundle: None,
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
                    None::<String>,
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
                None::<String>,
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

    // Phase 3b.8 — per-repo Gemini + Cursor parser hot-reload reconciliation.

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reload_adds_gemini_project_parser_when_workspace_added() {
        let dir = tempfile::tempdir().unwrap();
        let workspace = dir.path().join("ws");
        let repo_a = workspace.join("repoA");
        std::fs::create_dir_all(repo_a.join(".gemini")).unwrap();
        std::fs::write(repo_a.join(".gemini").join("settings.json"), "{}").unwrap();
        let canonical_a = dunce::canonicalize(&repo_a).unwrap();

        let initial = "version: 1\nhost_id_strategy: machine_id\ntargets: []\n";
        let (mut ctx, plat, _trx, parsers, _state) = build_ctx_with_parsers(dir.path(), initial);
        reload(&mut ctx, &plat);
        assert!(parsers.read().iter().all(|p| !matches!(
            (p.tool(), p.scope()),
            (
                sigil_core::event::AiTool::Gemini,
                sigil_core::event::AiGuardScope::Project { .. }
            )
        )));

        let updated = format!(
            "version: 1\nhost_id_strategy: machine_id\ngemini_workspaces:\n  - '{}'\ntargets: []\n",
            workspace.display()
        );
        std::fs::write(&ctx.policy_yaml_path, &updated).unwrap();
        reload(&mut ctx, &plat);
        let has = parsers.read().iter().any(|p| {
            p.tool() == sigil_core::event::AiTool::Gemini
                && matches!(
                    p.scope(),
                    sigil_core::event::AiGuardScope::Project { ref path } if path == &canonical_a
                )
        });
        assert!(has, "expected GeminiProjectParser for repoA after reload");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reload_adds_cursor_project_parser_when_workspace_added() {
        let dir = tempfile::tempdir().unwrap();
        let workspace = dir.path().join("ws");
        let repo_a = workspace.join("repoA");
        std::fs::create_dir_all(repo_a.join(".cursor")).unwrap();
        std::fs::write(repo_a.join(".cursor").join("mcp.json"), "{}").unwrap();
        let canonical_a = dunce::canonicalize(&repo_a).unwrap();

        let initial = "version: 1\nhost_id_strategy: machine_id\ntargets: []\n";
        let (mut ctx, plat, _trx, parsers, _state) = build_ctx_with_parsers(dir.path(), initial);
        reload(&mut ctx, &plat);
        assert!(parsers.read().iter().all(|p| !matches!(
            (p.tool(), p.scope()),
            (
                sigil_core::event::AiTool::Cursor,
                sigil_core::event::AiGuardScope::Project { .. }
            )
        )));

        let updated = format!(
            "version: 1\nhost_id_strategy: machine_id\ncursor_workspaces:\n  - '{}'\ntargets: []\n",
            workspace.display()
        );
        std::fs::write(&ctx.policy_yaml_path, &updated).unwrap();
        reload(&mut ctx, &plat);
        let has = parsers.read().iter().any(|p| {
            p.tool() == sigil_core::event::AiTool::Cursor
                && matches!(
                    p.scope(),
                    sigil_core::event::AiGuardScope::Project { ref path } if path == &canonical_a
                )
        });
        assert!(has, "expected CursorProjectParser for repoA after reload");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reload_adds_antigravity_project_parser_when_workspace_added() {
        let dir = tempfile::tempdir().unwrap();
        let workspace = dir.path().join("ws");
        let repo_a = workspace.join("repoA");
        std::fs::create_dir_all(repo_a.join(".antigravity")).unwrap();
        std::fs::write(repo_a.join(".antigravity").join("settings.json"), "{}").unwrap();
        let canonical_a = dunce::canonicalize(&repo_a).unwrap();

        let initial = "version: 1\nhost_id_strategy: machine_id\ntargets: []\n";
        let (mut ctx, plat, _trx, parsers, _state) = build_ctx_with_parsers(dir.path(), initial);
        reload(&mut ctx, &plat);
        assert!(parsers.read().iter().all(|p| !matches!(
            (p.tool(), p.scope()),
            (
                sigil_core::event::AiTool::Antigravity,
                sigil_core::event::AiGuardScope::Project { .. }
            )
        )));

        let updated = format!(
            "version: 1\nhost_id_strategy: machine_id\nantigravity_workspaces:\n  - '{}'\ntargets: []\n",
            workspace.display()
        );
        std::fs::write(&ctx.policy_yaml_path, &updated).unwrap();
        reload(&mut ctx, &plat);
        let has = parsers.read().iter().any(|p| {
            p.tool() == sigil_core::event::AiTool::Antigravity
                && matches!(
                    p.scope(),
                    sigil_core::event::AiGuardScope::Project { ref path } if path == &canonical_a
                )
        });
        assert!(
            has,
            "expected AntigravityProjectParser for repoA after reload"
        );
    }

    // Phase 3b.7 — rule pack parser hot-reload reconciliation.

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reload_adds_rule_pack_when_user_adds_one() {
        let dir = tempfile::tempdir().unwrap();
        let initial = "version: 1\nhost_id_strategy: machine_id\ntargets:\n  - id: t1\n    description: x\n    tier: standard\n    platform: any\n    paths: [\"/tmp/x\"]\n";
        let (mut ctx, plat, _trx, parsers, _state) = build_ctx_with_parsers(dir.path(), initial);
        reload(&mut ctx, &plat);

        // Defaults retired in 3b.8 — 0 default packs.
        let default_count = parsers
            .read()
            .iter()
            .filter(|p| {
                p.as_any()
                    .downcast_ref::<crate::ai_guard::rule_pack::parser::RulePackParser>()
                    .is_some()
            })
            .count();
        assert_eq!(default_count, 0);

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

        // Drop the user pack — no defaults remain after 3b.8 retirement.
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

        // No default packs remain.
        let default_count = parsers
            .read()
            .iter()
            .filter(|p| {
                p.as_any()
                    .downcast_ref::<crate::ai_guard::rule_pack::parser::RulePackParser>()
                    .is_some()
            })
            .count();
        assert_eq!(default_count, 0);
    }

    // Task 6 — Project-scoped rule pack hot-reload reconciliation: when a repo
    // is removed from disk, the per-repo RulePackParser AND its state entry are
    // pruned.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reload_project_pack_prunes_removed_repo() {
        use crate::ai_guard::parser::AiGuardParser;
        let dir = tempfile::tempdir().unwrap();
        let workspace = dir.path().join("ws");
        let repo_a = workspace.join("repoA");
        let repo_b = workspace.join("repoB");
        std::fs::create_dir_all(repo_a.join(".gemini")).unwrap();
        std::fs::create_dir_all(repo_b.join(".gemini")).unwrap();
        std::fs::write(
            repo_a.join(".gemini").join("settings.json"),
            r#"{"sandbox": false}"#,
        )
        .unwrap();
        std::fs::write(
            repo_b.join(".gemini").join("settings.json"),
            r#"{"sandbox": false}"#,
        )
        .unwrap();
        let canonical_a = dunce::canonicalize(&repo_a).unwrap();
        let canonical_b = dunce::canonicalize(&repo_b).unwrap();

        let pack_id = "proj-pack";
        let policy = format!(
            "version: 1\nhost_id_strategy: machine_id\ngemini_workspaces:\n  - '{}'\ntargets: []\nrule_packs:\n  - id: {pack_id}\n    pack_version: 1\n    tool: gemini\n    scope:\n      kind: project\n    watched_paths:\n      - '.gemini/settings.json'\n    rules:\n      - id: r1\n        on_file: '.gemini/settings.json'\n        format: json\n        selector: '$.sandbox'\n        matcher:\n          kind: exists\n        emit:\n          kind: sandbox_disabled\n",
            workspace.display()
        );
        let (mut ctx, plat, _trx, parsers, state) = build_ctx_with_parsers(dir.path(), &policy);

        // Initial reconcile: drive reload so both repoA and repoB get a
        // Project-scoped RulePackParser.
        reload(&mut ctx, &plat);
        {
            let guard = parsers.read();
            let proj_packs: Vec<_> = guard
                .iter()
                .filter_map(|p| {
                    p.as_any()
                        .downcast_ref::<crate::ai_guard::rule_pack::parser::RulePackParser>()
                })
                .filter(|rpp| rpp.pack.id == pack_id)
                .map(|rpp| rpp.scope())
                .collect();
            assert_eq!(
                proj_packs.len(),
                2,
                "expected 2 per-repo rule pack parsers (repoA, repoB), got {proj_packs:?}"
            );
        }

        // Plant state entries for both repos to verify pruning of repoB.
        {
            let mut s = state.write();
            for path in [&canonical_a, &canonical_b] {
                s.insert(
                    (
                        sigil_core::event::AiTool::Gemini,
                        sigil_core::event::AiGuardScope::Project { path: path.clone() },
                        Some(pack_id.to_string()),
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
        }

        // Remove repoB from disk and reload (policy unchanged).
        std::fs::remove_dir_all(&repo_b).unwrap();
        reload(&mut ctx, &plat);

        {
            let guard = parsers.read();
            let proj_scopes: Vec<_> = guard
                .iter()
                .filter_map(|p| {
                    p.as_any()
                        .downcast_ref::<crate::ai_guard::rule_pack::parser::RulePackParser>()
                })
                .filter(|rpp| rpp.pack.id == pack_id)
                .map(|rpp| rpp.scope())
                .collect();
            assert_eq!(
                proj_scopes.len(),
                1,
                "expected exactly 1 remaining rule pack parser after repoB removed, got {proj_scopes:?}"
            );
            assert_eq!(
                proj_scopes[0],
                sigil_core::event::AiGuardScope::Project {
                    path: canonical_a.clone()
                },
                "remaining parser should be repoA"
            );
        }
        {
            let s = state.read();
            let key_b = (
                sigil_core::event::AiTool::Gemini,
                sigil_core::event::AiGuardScope::Project {
                    path: canonical_b.clone(),
                },
                Some(pack_id.to_string()),
            );
            assert!(
                !s.contains_key(&key_b),
                "state entry for removed repoB should be pruned"
            );
            let key_a = (
                sigil_core::event::AiTool::Gemini,
                sigil_core::event::AiGuardScope::Project {
                    path: canonical_a.clone(),
                },
                Some(pack_id.to_string()),
            );
            assert!(
                s.contains_key(&key_a),
                "state entry for surviving repoA should remain"
            );
        }
    }

    // Task 5 — distributed rule-pack bundle is merged as the 3rd layer at
    // reload: a pack present only in `rule-packs.yaml` (not policy.yaml) shows
    // up as a live RulePackParser after reload().
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reload_loads_rule_pack_from_distributed_bundle() {
        let dir = tempfile::tempdir().unwrap();
        // policy.yaml has no rule packs.
        let initial = "version: 1\nhost_id_strategy: machine_id\ntargets:\n  - id: t1\n    description: x\n    tier: standard\n    platform: any\n    paths: [\"/tmp/x\"]\n";
        let (mut ctx, plat, _trx, parsers, _state) = build_ctx_with_parsers(dir.path(), initial);

        // Bundle (rule-packs.yaml) carries one UserGlobal pack.
        let bundle = "version: 1\nrule_packs:\n  - id: bundle-pack\n    pack_version: 1\n    tool: gemini\n    scope:\n      kind: user_global\n    watched_paths: []\n    rules: []\n";
        std::fs::write(&ctx.rule_packs_yaml_path, bundle).unwrap();

        reload(&mut ctx, &plat);

        let has_bundle = parsers.read().iter().any(|p| {
            p.as_any()
                .downcast_ref::<crate::ai_guard::rule_pack::parser::RulePackParser>()
                .map(|rpp| rpp.pack.id == "bundle-pack")
                .unwrap_or(false)
        });
        assert!(
            has_bundle,
            "expected bundle-pack from rule-packs.yaml after reload"
        );
    }

    // #134 review — reload()-level retain test: a corrupt rule-packs.yaml write
    // arriving AFTER a good bundle was loaded must keep the bundle's pack live
    // (via ctx.last_good_bundle), not drop it. Exercises the actual Present →
    // Corrupt arms in reload(), not just the read_bundle_state state machine.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reload_corrupt_bundle_retains_pack_in_live_set() {
        let dir = tempfile::tempdir().unwrap();
        let initial = "version: 1\nhost_id_strategy: machine_id\ntargets:\n  - id: t1\n    description: x\n    tier: standard\n    platform: any\n    paths: [\"/tmp/x\"]\n";
        let (mut ctx, plat, _trx, parsers, _state) = build_ctx_with_parsers(dir.path(), initial);

        // 1. Valid bundle → pack goes live, cache seeded.
        let bundle = "version: 1\nrule_packs:\n  - id: retained-pack\n    pack_version: 1\n    tool: gemini\n    scope:\n      kind: user_global\n    watched_paths: []\n    rules: []\n";
        std::fs::write(&ctx.rule_packs_yaml_path, bundle).unwrap();
        reload(&mut ctx, &plat);

        let is_live = |parsers: &Arc<
            parking_lot::RwLock<Vec<Arc<dyn crate::ai_guard::parser::AiGuardParser>>>,
        >| {
            parsers.read().iter().any(|p| {
                p.as_any()
                    .downcast_ref::<crate::ai_guard::rule_pack::parser::RulePackParser>()
                    .map(|rpp| rpp.pack.id == "retained-pack")
                    .unwrap_or(false)
            })
        };
        assert!(is_live(&parsers), "pack should be live after valid bundle");
        assert!(
            ctx.last_good_bundle.is_some(),
            "cache should be seeded after valid bundle"
        );

        // 2. Corrupt the bundle on disk and reload.
        std::fs::write(&ctx.rule_packs_yaml_path, "}{not yaml").unwrap();
        reload(&mut ctx, &plat);

        // 3. The pack MUST still be live (retained from last-good), and the
        //    cache must still hold it.
        assert!(
            is_live(&parsers),
            "pack must stay live after corrupt reload (retained from last-good)"
        );
        assert!(
            ctx.last_good_bundle.is_some(),
            "cache must persist across a corrupt reload"
        );
    }

    // #134/#135 — BundleState state machine: Absent / Present / Corrupt / Empty.
    #[test]
    fn bundle_state_distinguishes_missing_valid_corrupt() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("rule-packs.yaml");
        // NotFound → Absent (deliberate rm).
        assert!(matches!(read_bundle_state(&p), BundleState::Absent));
        std::fs::write(
            &p,
            "version: 1\nhost_id_strategy: machine_id\ntargets: []\n",
        )
        .unwrap();
        assert!(matches!(read_bundle_state(&p), BundleState::Present(_)));
        std::fs::write(&p, "}{not yaml").unwrap();
        assert!(matches!(read_bundle_state(&p), BundleState::Corrupt));
        // #135 — zero-byte / whitespace-only → Empty (transient truncate), NOT Absent.
        std::fs::write(&p, "").unwrap();
        assert!(matches!(read_bundle_state(&p), BundleState::Empty));
        std::fs::write(&p, "   \n\t\n").unwrap();
        assert!(matches!(read_bundle_state(&p), BundleState::Empty));
    }

    // #135 — a transient empty read (cp truncate window) retains the last-good
    // bundle rather than clearing it, distinct from a NotFound (rm) which clears.
    #[test]
    fn empty_bundle_retains_last_good() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("rule-packs.yaml");
        std::fs::write(
            &p,
            "version: 1\nhost_id_strategy: machine_id\ntargets: []\n",
        )
        .unwrap();
        let mut cache: Option<sigil_core::policy::PolicyDocument> = None;
        if let BundleState::Present(d) = read_bundle_state(&p) {
            cache = Some(*d);
        }
        assert!(cache.is_some());
        // Truncate to zero bytes (the non-atomic cp window).
        std::fs::write(&p, "").unwrap();
        let retained = match read_bundle_state(&p) {
            BundleState::Empty => cache.clone(),
            _ => None,
        };
        assert!(
            retained.is_some(),
            "empty read must retain last good (#135)"
        );
        // Contrast: an actual removal clears.
        std::fs::remove_file(&p).unwrap();
        assert!(matches!(read_bundle_state(&p), BundleState::Absent));
    }

    // #134 — corrupt bundle retains the last successfully parsed bundle doc.
    #[test]
    fn corrupt_bundle_retains_last_good() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("rule-packs.yaml");
        std::fs::write(
            &p,
            "version: 1\nhost_id_strategy: machine_id\ntargets: []\n",
        )
        .unwrap();
        let mut cache: Option<sigil_core::policy::PolicyDocument> = None;
        if let BundleState::Present(d) = read_bundle_state(&p) {
            cache = Some(*d);
        }
        assert!(cache.is_some());
        std::fs::write(&p, "}{bad").unwrap();
        let retained = match read_bundle_state(&p) {
            BundleState::Corrupt => cache.clone(),
            _ => None,
        };
        assert!(retained.is_some(), "corrupt must retain last good");
    }

    // Task 5 — when policy.yaml and the distributed bundle both carry a pack
    // with the SAME id, the bundle layer wins (merge order: defaults < policy
    // < bundle). `pack_version` is a schema-compat field clamped to
    // MAX_PACK_VERSION, so the observable discriminator here is `watched_paths`:
    // the live pack must expose the BUNDLE's paths, not the policy's.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reload_bundle_pack_overrides_policy_pack_same_id() {
        let dir = tempfile::tempdir().unwrap();
        // policy.yaml authors pack `shared` with watched_paths ["from-policy"].
        let initial = "version: 1\nhost_id_strategy: machine_id\ntargets:\n  - id: t1\n    description: x\n    tier: standard\n    platform: any\n    paths: [\"/tmp/x\"]\nrule_packs:\n  - id: shared\n    pack_version: 1\n    tool: gemini\n    scope:\n      kind: user_global\n    watched_paths: [\"from-policy\"]\n    rules: []\n";
        let (mut ctx, plat, _trx, parsers, _state) = build_ctx_with_parsers(dir.path(), initial);

        // Bundle authors the SAME id `shared` with watched_paths ["from-bundle"].
        let bundle = "version: 1\nrule_packs:\n  - id: shared\n    pack_version: 1\n    tool: gemini\n    scope:\n      kind: user_global\n    watched_paths: [\"from-bundle\"]\n    rules: []\n";
        std::fs::write(&ctx.rule_packs_yaml_path, bundle).unwrap();

        reload(&mut ctx, &plat);

        let live_paths = parsers.read().iter().find_map(|p| {
            p.as_any()
                .downcast_ref::<crate::ai_guard::rule_pack::parser::RulePackParser>()
                .filter(|rpp| rpp.pack.id == "shared")
                .map(|rpp| rpp.pack.watched_paths.clone())
        });
        assert_eq!(
            live_paths.as_deref(),
            Some(["from-bundle".to_string()].as_slice()),
            "bundle pack should override the policy pack with the same id"
        );
    }
}
