//! Pipeline assembly. Owns channel topology and task spawning.

use crate::{
    debouncer,
    hasher::{HashedEvent, TargetLookup},
    heartbeat,
    normalizer::{self, NormalizedEvent},
    platform::{ActivePlatform, FdaState, Platform},
    sink_task,
    state_task::{self, CommittableEvent},
    supervisor::Supervisor,
    watcher,
};
use parking_lot::Mutex;
use sigil_core::policy::expand::{expand_per_user, EnvLookup, UserEnumerator};
use sigil_core::policy::pubkeys::Keystore;
use sigil_core::policy::{current_platform, defaults, merge, Tier};
use sigil_core::sink::jsonl::JsonlSink;
use sigil_core::state::HashCache;
use sigil_core::stats::Stats;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use time::OffsetDateTime;
use tokio::sync::{mpsc, watch};

pub struct RuntimeConfig {
    pub policy_path: Option<PathBuf>,
    pub state_db_path: PathBuf,
    pub events_dir: PathBuf,
    pub control_socket: PathBuf,
    pub control_pipe_name: String,
    /// Force a polling watcher instead of the OS-native backend (`--poll`).
    pub poll_watcher: bool,
    /// Override the policy-signing keystore path (tests). `None` → `keystore_path()`.
    pub keystore_path: Option<PathBuf>,
}

pub async fn run(cfg: RuntimeConfig) -> anyhow::Result<i32> {
    // `try_init` instead of `init` so integration tests can spawn multiple
    // agents in the same process without the second one panicking on the
    // already-set global subscriber. In production main.rs only calls
    // `run` once, so the duplicate-registration branch is test-only.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("SIGIL_LOG")
                .unwrap_or_else(|_| "info".into()),
        )
        .with_writer(std::io::stderr)
        .try_init();

    let plat = ActivePlatform::new();
    let started = Instant::now();

    // Open state.db FIRST — host_id resolution depends on it.
    if let Some(dir) = cfg.state_db_path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let cache = Arc::new(Mutex::new(HashCache::open(&cfg.state_db_path)?));

    // Resolve persisted host_id (UUIDv4, generated on first run).
    let host_id = {
        let c = cache.lock();
        crate::host_meta_task::ensure_host_id(&c)
            .map_err(|e| anyhow::anyhow!("failed to initialize host_id: {e}"))?
    };
    tracing::info!(host_id = %host_id, "agent host_id resolved");

    // Phase 2: load the policy-signing keystore. Optional — if missing, the
    // agent runs in Phase 1 mode (no inbound apply_policy can succeed).
    let keystore =
        match Keystore::load_from_file(cfg.keystore_path.clone().unwrap_or_else(keystore_path)) {
            Ok(k) => Arc::new(k),
            Err(e) => {
                tracing::warn!(
                    error = ?e,
                    "policy-signing keystore unavailable; apply_policy will reject all envelopes"
                );
                Arc::new(Keystore { pubkeys: vec![] })
            }
        };

    // Phase 2: shared state for IPC + expiry monitor + heartbeat.
    let policy_expired_active = Arc::new(parking_lot::RwLock::new(false));
    let jsonl_above_soft_floor = Arc::new(parking_lot::RwLock::new(false));
    let current_segment_filename = Arc::new(parking_lot::RwLock::new(String::new()));
    let active_valid_until: Arc<parking_lot::RwLock<Option<OffsetDateTime>>> =
        Arc::new(parking_lot::RwLock::new(None));
    let (policy_version_tx, _policy_version_rx_init) = watch::channel::<i64>(0);

    // Phase 2: boot reconciliation — disk may be ahead of state.db after a
    // crash between atomic-rename and state.db version-bump. If so, advance
    // state.db and remember the version so we can emit a synthetic
    // PolicyReloaded event once `tx_sink` is bound below.
    let policy_path_for_apply = cfg
        .policy_path
        .clone()
        .unwrap_or_else(default_policy_yaml_path);
    let pending_reconcile: Option<i64> = {
        let c = cache.lock();
        match reconcile_policy_on_boot(&c, &policy_path_for_apply) {
            Ok(Some(v)) => {
                tracing::info!(
                    version = v,
                    "policy reconciliation: state.db advanced to match disk"
                );
                Some(v)
            }
            Ok(None) => None,
            Err(e) => {
                tracing::warn!(error = ?e, "policy reconciliation failed; skipping");
                None
            }
        }
    };

    // 1. Load + merge policy.
    let user_doc = match cfg.policy_path.as_ref() {
        Some(p) if p.exists() => Some(sigil_core::policy::parse(&std::fs::read_to_string(p)?)?),
        _ => None,
    };
    let mut effective = merge(defaults()?, user_doc, current_platform())?;
    // (host_id resolution moved up above; effective.host_id_strategy is no longer consulted)

    // Phase 3b.6.2 — per-repo discovery for Continue / Claude Code / Codex.
    // Operator opts in via {continue,claude_code,codex}_workspaces in
    // policy.yaml. For each tool's roots we scan 1-level deep, spawn a
    // per-repo parser (Task 3+4), and synthesize in-memory WatchTarget
    // entries so the existing watcher subgraph picks up file_change events.
    // Synthetic targets are in-memory only; never written back to the
    // signed policy envelope on disk.
    let continue_repos = crate::ai_guard::workspace_discovery::discover_per_repo(
        &effective.continue_workspaces,
        ".continue/config.json",
    );
    let claude_code_repos = crate::ai_guard::workspace_discovery::discover_per_repo(
        &effective.claude_code_workspaces,
        ".claude/settings.json",
    );
    let codex_repos = crate::ai_guard::workspace_discovery::discover_per_repo(
        &effective.codex_workspaces,
        ".codex/config.toml",
    );

    for repo_root in &continue_repos {
        push_continue_synthetic_target(&mut effective, repo_root);
    }
    for repo_root in &claude_code_repos {
        push_claude_code_synthetic_targets(&mut effective, repo_root);
    }
    for repo_root in &codex_repos {
        push_codex_synthetic_target(&mut effective, repo_root);
    }

    // Phase 3b.6.1 — build the shared parsers list BEFORE the policy_reload
    // task and ai_guard task so both can share an `Arc<RwLock<..>>` and reload
    // can mutate the live parser set on hot-reload.
    //
    // Phase 3b.3 Task 7 — this block (parsers vec, ai_guard_parsers Arc,
    // ext_scripts_registry + discover_and_register_ext_scripts) is hoisted
    // ABOVE expand_targets so that the synthetic WatchTargets pushed into
    // `effective.targets` by ext-script discovery are visible to
    // `expand_targets` → `watch_roots` → `spawn_watcher` at boot. Otherwise
    // the OS watcher never subscribes to ext-script paths until the first
    // hot-reload. Per-repo synth above follows the same ordering rule.
    let mut parsers_vec: Vec<Arc<dyn crate::ai_guard::parser::AiGuardParser>> = vec![
        Arc::new(crate::ai_guard::ClaudeCodeParser),
        Arc::new(crate::ai_guard::CodexParser),
        Arc::new(crate::ai_guard::ClaudeDesktopParser),
        Arc::new(crate::ai_guard::ContinueDevParser),
    ];
    for repo_root in continue_repos {
        parsers_vec.push(Arc::new(crate::ai_guard::ContinueDevProjectParser {
            repo_root,
        }));
    }
    for repo_root in claude_code_repos {
        parsers_vec.push(Arc::new(crate::ai_guard::ClaudeCodeProjectParser {
            repo_root,
        }));
    }
    for repo_root in codex_repos {
        parsers_vec.push(Arc::new(crate::ai_guard::CodexProjectParser { repo_root }));
    }
    // Phase 3b.7 — declarative rule packs (sigil-rules-basic defaults +
    // operator overlay from signed envelope, already merged into
    // effective.rule_packs by sigil_core::policy::merge).
    for pack in &effective.rule_packs {
        if !crate::ai_guard::rule_pack::pack_is_loadable(pack) {
            continue;
        }
        match crate::ai_guard::rule_pack::parser::RulePackParser::new(pack.clone()) {
            Ok(p) => parsers_vec.push(Arc::new(p)),
            Err(e) => tracing::warn!(
                id = %pack.id, error = ?e,
                "rule_pack: load failed; skipping"
            ),
        }
    }
    let ai_guard_parsers: Arc<
        parking_lot::RwLock<Vec<Arc<dyn crate::ai_guard::parser::AiGuardParser>>>,
    > = Arc::new(parking_lot::RwLock::new(parsers_vec));

    // Phase 3b.3 Task 6 — resolve `home_dir` once (shared by ext-script
    // discovery + ai_guard TaskCtx below) and discover external hook-script
    // paths for every parser. Synthesizes one in-memory WatchTarget per
    // unique canonical path so the OS watcher subscribes, and populates an
    // `ExtScriptRegistry` keyed by (AiTool, AiGuardScope) so the dispatcher
    // can route fsnotify events on script paths to the right parser.
    // Synthetic targets are in-memory only — never written back to disk.
    let home_dir = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("/"));
    let ext_scripts_registry = crate::ai_guard::empty_ext_script_registry();
    {
        let parsers_snapshot: Vec<Arc<dyn crate::ai_guard::parser::AiGuardParser>> =
            ai_guard_parsers.read().clone();
        discover_and_register_ext_scripts(
            &parsers_snapshot,
            &home_dir,
            &ext_scripts_registry,
            &mut effective,
        );
    }

    // 2. Expand paths per user → watch paths + watch roots.
    let (expanded_paths, watch_roots) = expand_targets(&effective, &plat);

    // 3. Perform critical-tier warmup (state.db already opened above).
    perform_warmup(&effective, &expanded_paths, &cache)?;

    // 4. Open sink.
    let sink = JsonlSink::open(&cfg.events_dir, OffsetDateTime::now_utc())?;

    // 5. Bootstrap channels and tasks.
    let (tx_norm, rx_norm) = mpsc::channel::<NormalizedEvent>(512);
    let (tx_pending, rx_pending) = mpsc::channel::<sigil_core::debounce::PendingEvent>(512);
    let (tx_hashed, rx_hashed) = mpsc::channel::<HashedEvent>(512);
    let (tx_sink, rx_sink) = mpsc::channel::<CommittableEvent>(256);
    let (tx_dropped, mut rx_dropped) = mpsc::channel::<sigil_core::ratelimit::DropReport>(64);

    let stats = Stats::shared();

    // Phase 2: hardware fingerprint reconciliation. Drift produces a
    // HostIdFingerprintDrift event (Severity::Warn) for operator triage.
    {
        let outcome = {
            let c = cache.lock();
            crate::host_meta_task::ensure_fingerprint(&c, &plat)
                .map_err(|e| anyhow::anyhow!("hw_fingerprint init failed: {e}"))?
        };
        match outcome {
            crate::host_meta_task::FingerprintOutcome::FreshlyPersisted => {
                tracing::info!("hw_fingerprint freshly persisted (first run)");
            }
            crate::host_meta_task::FingerprintOutcome::Unchanged => {
                tracing::debug!("hw_fingerprint unchanged");
            }
            crate::host_meta_task::FingerprintOutcome::Drift { prev, new } => {
                use sigil_core::event::{
                    Event, Evidence, Severity, SourceKind, Subject, AGENT_VERSION, SCHEMA_VERSION,
                };
                let event = Event {
                    schema_version: SCHEMA_VERSION,
                    event_id: uuid::Uuid::now_v7(),
                    ts: OffsetDateTime::now_utc(),
                    host_id: host_id.clone(),
                    agent_version: AGENT_VERSION.to_string(),
                    severity: Severity::Warn,
                    source: SourceKind::Agent,
                    subject: Subject::Self_,
                    evidence: Evidence::HostIdFingerprintDrift {
                        prev_fingerprint: prev,
                        new_fingerprint: new,
                    },
                    target_id: None,
                };
                let committable = CommittableEvent {
                    event,
                    new_hash: None,
                    path_for_db: std::path::PathBuf::new(),
                    target_id: String::new(),
                };
                if tx_sink.try_send(committable).is_err() {
                    tracing::warn!("event channel full; HostIdFingerprintDrift dropped");
                }
                tracing::warn!("hw_fingerprint drift detected; event emitted");
            }
        }
    }

    // Phase 2: emit the deferred PolicyReloaded event from boot reconciliation
    // (held above until tx_sink existed). Best-effort: if the channel is full,
    // the heartbeat's `last_applied_policy_version` will still surface it.
    if let Some(version) = pending_reconcile {
        use sigil_core::event::{
            Event, Evidence, Severity, SourceKind, Subject, AGENT_VERSION, SCHEMA_VERSION,
        };
        let event = Event {
            schema_version: SCHEMA_VERSION,
            event_id: uuid::Uuid::now_v7(),
            ts: OffsetDateTime::now_utc(),
            host_id: host_id.clone(),
            agent_version: AGENT_VERSION.to_string(),
            severity: Severity::Info,
            source: SourceKind::Agent,
            subject: Subject::Self_,
            evidence: Evidence::PolicyReloaded {
                policy_version: version,
            },
            target_id: None,
        };
        let committable = CommittableEvent {
            event,
            new_hash: None,
            path_for_db: PathBuf::new(),
            target_id: String::new(),
        };
        if tx_sink.try_send(committable).is_err() {
            tracing::warn!("event channel full; deferred PolicyReloaded dropped");
        }
    }

    // Phase 2: build ApplyContext (used by control IPC's apply_policy handler)
    // and ControlContext (used by control IPC dispatch).
    let apply_ctx = Arc::new(crate::policy_apply::ApplyContext {
        keystore: keystore.clone(),
        cache: cache.clone(),
        policy_yaml_path: policy_path_for_apply.clone(),
        host_id: host_id.clone(),
        event_tx: tx_sink.clone(),
        policy_version_tx: policy_version_tx.clone(),
        active_valid_until: active_valid_until.clone(),
    });
    // The pipeline reads its matcher set from this watch channel; the
    // policy-reload task (spawned below) publishes new sets on `targets_tx`.
    let (targets_tx, targets_rx) = watch::channel(Arc::new(normalizer::compile_targets(
        &effective,
        &expanded_paths,
    )));
    // Phase 3b.1 — AI Guard shared state. Created here (before ControlContext)
    // so the IPC handler can read assessments via `ai_guard_state`. The broadcast
    // sender is created later, close to where the hasher needs it.
    let ai_guard_state: Arc<parking_lot::RwLock<crate::ai_guard::StateMap>> =
        Arc::new(parking_lot::RwLock::new(std::collections::HashMap::new()));
    let control_ctx = Arc::new(crate::control::ControlContext {
        stats: stats.clone(),
        apply_ctx: apply_ctx.clone(),
        active_valid_until: active_valid_until.clone(),
        #[cfg(feature = "operator-cli")]
        targets_rx: targets_rx.clone(),
        #[cfg(feature = "operator-cli")]
        ai_guard_state: ai_guard_state.clone(),
    });

    // Watcher (notify → raw events → tx_norm via normalizer wrapper).
    let runtime_handle = tokio::runtime::Handle::current();
    let poll_interval = if cfg.poll_watcher {
        tracing::info!("forcing polling watcher (--poll); OS-native FS events disabled");
        Some(std::time::Duration::from_secs(5))
    } else {
        None
    };
    tracing::info!(
        roots = watch_roots.len(),
        "runtime: spawning filesystem watcher"
    );
    let (raw_rx, watcher_handle) = watcher::spawn_watcher(
        watch_roots.clone(),
        runtime_handle.clone(),
        1024,
        poll_interval,
    )?;
    let backend_name = watcher_handle.backend_name;
    tracing::info!(
        backend = backend_name,
        "runtime: filesystem watcher started"
    );

    let mut sup = Supervisor::new();
    let cancel = sup.shutdown.clone();
    tracing::info!("runtime: spawning pipeline tasks");

    sup.track(
        "normalizer",
        tokio::spawn({
            let tx_norm = tx_norm.clone();
            let tx_dropped = tx_dropped.clone();
            let targets_rx = targets_rx.clone();
            async move {
                normalizer::run(targets_rx, raw_rx, tx_norm, tx_dropped).await;
            }
        }),
    );
    drop(tx_norm);
    drop(tx_dropped);

    sup.track(
        "debouncer",
        tokio::spawn(debouncer::run(rx_norm, tx_pending)),
    );

    // Phase 3b.1 — AI Guard Risk Index broadcast channel.
    // _ai_guard_fc_rx_init is held alive (named with underscore prefix to
    // suppress unused warnings) so that broadcast::Sender::send() doesn't
    // return SendError(no receivers) during the brief window between hasher
    // startup and ai_guard_task subscribing below. Once ai_guard_task calls
    // ai_guard_fc_tx.subscribe(), this initial receiver becomes redundant
    // but harmless — broadcast overwrites old slots without blocking.
    // Note: ai_guard_state was created above (before ControlContext).
    let (ai_guard_fc_tx, _ai_guard_fc_rx_init) =
        tokio::sync::broadcast::channel::<std::path::PathBuf>(256);

    sup.track(
        "hasher",
        tokio::spawn({
            let stats = stats.clone();
            // The hasher re-derives a `PendingEvent`'s target/tier by matching
            // the (already-canonical) path against the same compiled globs the
            // normalizer used.
            let lookup: Arc<dyn TargetLookup + Send + Sync> = Arc::new(GlobTargetLookup {
                targets_rx: targets_rx.clone(),
            });
            let ag_tx = ai_guard_fc_tx.clone();
            async move {
                crate::hasher::run(rx_pending, tx_hashed, lookup, stats, Some(ag_tx)).await;
            }
        }),
    );

    // Live policy reload: on a successful `apply_policy`, re-derive watch
    // targets/roots from the new policy.yaml and apply them to the running
    // pipeline + watcher (no restart). Owns the watcher handle + targets sender.
    sup.track(
        "policy_reload",
        tokio::spawn(crate::policy_reload_task::run(
            crate::policy_reload_task::ReloadCtx {
                policy_yaml_path: policy_path_for_apply.clone(),
                policy_version_rx: policy_version_tx.subscribe(),
                targets_tx,
                watcher: watcher_handle,
                watched_roots: watch_roots,
                cache: cache.clone(),
                shutdown: cancel.clone(),
                parsers: ai_guard_parsers.clone(),
                ai_guard_state: ai_guard_state.clone(),
            },
        )),
    );

    sup.track(
        "state_store",
        tokio::spawn({
            let cache = cache.clone();
            let stats = stats.clone();
            let host_id = host_id.clone();
            let tx_sink_st = tx_sink.clone();
            async move { state_task::run(rx_hashed, tx_sink_st, cache, host_id, stats).await }
        }),
    );

    sup.track(
        "sink",
        tokio::spawn({
            let cache = cache.clone();
            let stats = stats.clone();
            async move { sink_task::run(sink, rx_sink, cache, stats).await }
        }),
    );

    // Phase 3b.1 — ai_guard_task: scores Claude Code / Codex guard surfaces.
    // Phase 3b.6.1 — `parsers` is shared with `policy_reload_task` via an
    // `Arc<RwLock<..>>` so hot-reload can mutate the live parser set.
    {
        let ctx = crate::ai_guard::TaskCtx {
            parsers: ai_guard_parsers,
            fc_rx: ai_guard_fc_tx.subscribe(),
            event_tx: tx_sink.clone(),
            state: ai_guard_state.clone(),
            heartbeat_interval: std::time::Duration::from_secs(24 * 3600),
            home_dir: home_dir.clone(),
            host_id: host_id.clone(),
            // Phase 3b.3 Task 6 — registry populated from parser configs at
            // boot above. Task 7 will share the same handle with
            // policy_reload_task so hot-reload can refresh script paths.
            ext_scripts: ext_scripts_registry.clone(),
        };
        sup.track(
            "ai_guard",
            tokio::spawn(async move {
                crate::ai_guard::run(ctx).await;
            }),
        );
    }

    // Phase 3b.4-pre — host_meta_snapshot_task: hostname / IP / MAC / OS attestation.
    {
        let latest_snapshot = std::sync::Arc::new(parking_lot::RwLock::new(
            crate::host_meta_snapshot_task::LatestSnapshot::default(),
        ));
        let source: std::sync::Arc<crate::platform::ActivePlatform> =
            std::sync::Arc::new(crate::platform::ActivePlatform::new());
        let ctx = crate::host_meta_snapshot_task::TaskCtx {
            source,
            event_tx: tx_sink.clone(),
            host_id: host_id.clone(),
            latest: latest_snapshot,
            heartbeat_interval: std::time::Duration::from_secs(24 * 3600),
            change_check_interval: std::time::Duration::from_secs(5 * 60),
            shutdown: cancel.clone(),
        };
        sup.track(
            "host_meta_snapshot",
            tokio::spawn(crate::host_meta_snapshot_task::run(ctx)),
        );
    }

    // Best-effort startup snapshot: pick the lexicographically largest segment
    // as the "current" one. Full rotation-time wiring is a Plan A2 follow-up.
    {
        if let Ok(entries) = std::fs::read_dir(&cfg.events_dir) {
            let latest = entries
                .filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n.starts_with("events-") && n.ends_with(".jsonl"))
                .max();
            if let Some(n) = latest {
                *current_segment_filename.write() = n;
            }
        }
    }

    // Heartbeat
    {
        let stats_h = stats.clone();
        let cache_h = cache.clone();
        let expired_h = policy_expired_active.clone();
        let above_h = jsonl_above_soft_floor.clone();
        let host_id_h = host_id.clone();
        let cancel_h = cancel.clone();
        let tx_h = tx_sink.clone();
        let dbp = cfg.state_db_path.clone();
        sup.track(
            "heartbeat",
            tokio::spawn(async move {
                heartbeat::run(
                    stats_h,
                    cache_h,
                    expired_h,
                    above_h,
                    host_id_h,
                    backend_name,
                    dbp,
                    tx_h,
                    cancel_h,
                    started,
                )
                .await
            }),
        );
    }

    // JSONL GC task (Phase 2 Plan A).
    {
        let host_id_g = host_id.clone();
        let dir_g = cfg.events_dir.clone();
        let cur_g = current_segment_filename.clone();
        let above_g = jsonl_above_soft_floor.clone();
        let tx_g = tx_sink.clone();
        let cancel_g = cancel.clone();
        sup.track(
            "jsonl_gc",
            tokio::spawn(async move {
                crate::jsonl_gc_task::run(crate::jsonl_gc_task::GcTaskCtx {
                    host_id: host_id_g,
                    events_dir: dir_g,
                    current_segment_filename: cur_g,
                    above_soft_floor: above_g,
                    cfg: crate::gc_config::GcConfig::defaults(),
                    event_tx: tx_g,
                    shutdown: cancel_g,
                    tick: std::time::Duration::from_secs(10 * 60),
                })
                .await;
            }),
        );
    }

    // Policy expiry monitor (Phase 2). Reads `active_valid_until` and
    // `policy_version_tx`'s receiver, writes the shared `policy_expired_active`
    // flag, and emits exactly one `PolicyExpiredActive` event per version.
    {
        let host_id_e = host_id.clone();
        let tx_e = tx_sink.clone();
        let cancel_e = cancel.clone();
        let expired_e = policy_expired_active.clone();
        let vu_e = active_valid_until.clone();
        let v_rx = policy_version_tx.subscribe();
        sup.track(
            "policy_expiry",
            tokio::spawn(async move {
                crate::policy_expiry_task::run(crate::policy_expiry_task::ExpiryTaskCtx {
                    host_id: host_id_e,
                    policy_expired_active: expired_e,
                    active_valid_until: vu_e,
                    policy_version_rx: v_rx,
                    event_tx: tx_e,
                    shutdown: cancel_e,
                    tick: std::time::Duration::from_secs(60),
                })
                .await;
            }),
        );
    }

    // FDA permission check (macOS) — emit one PermissionMissing per target if denied.
    if matches!(plat.fda_state(), FdaState::Denied) {
        emit_permission_missing(&effective, &tx_sink, &host_id).await;
    }

    // Control IPC (Phase 2: dispatches Stats + ApplyPolicy + PolicyStatus).
    {
        #[cfg(unix)]
        let socket = cfg.control_socket.clone();
        #[cfg(windows)]
        let pipe = cfg.control_pipe_name.clone();
        let ctx_c = control_ctx.clone();
        sup.track(
            "control",
            tokio::spawn(async move {
                #[cfg(unix)]
                let _ = crate::control::serve(&socket, ctx_c).await;
                #[cfg(windows)]
                let _ = crate::control::serve(&pipe, ctx_c).await;
            }),
        );
    }

    // Drop-report fan-in: forward DropReports to sink as RateLimitExceeded events.
    {
        let tx_sink_dr = tx_sink.clone();
        let host_id_dr = host_id.clone();
        sup.track(
            "drop_reports",
            tokio::spawn(async move {
                while let Some(report) = rx_dropped.recv().await {
                    let _ = tx_sink_dr
                        .send(rate_limit_to_event(&host_id_dr, &report))
                        .await;
                }
            }),
        );
    }

    tracing::info!("runtime: all tasks spawned; running");
    // Wait for shutdown.
    let exit_code = sup.run(host_id.clone(), tx_sink.clone()).await?;
    Ok(exit_code)
}

pub(crate) fn perform_warmup(
    eff: &sigil_core::policy::EffectivePolicy,
    expanded: &HashMap<String, Vec<PathBuf>>,
    cache: &Arc<Mutex<HashCache>>,
) -> anyhow::Result<()> {
    use sigil_core::hashing::{hash_path, HashOutcome};
    for t in &eff.targets {
        if !matches!(t.tier, Tier::Critical) {
            continue;
        }
        let Some(paths) = expanded.get(&t.id) else {
            continue;
        };
        for p in paths {
            if !p.exists() {
                continue;
            }
            if let Ok(HashOutcome::Hashed { hex, size }) = hash_path(p) {
                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0);
                let _ = cache.lock().put(p, &hex, size, &t.id, now_ms);
            }
        }
    }
    Ok(())
}

/// Expand a policy's per-user path templates into concrete watch paths and the
/// set of (canonical) watch roots to register. Shared by `run` (startup) and
/// `policy_reload_task` (live reload).
#[allow(clippy::type_complexity)]
pub(crate) fn expand_targets(
    eff: &sigil_core::policy::EffectivePolicy,
    plat: &ActivePlatform,
) -> (HashMap<String, Vec<PathBuf>>, Vec<(PathBuf, bool)>) {
    let users = UserEnumerator::list(plat);
    let env = EnvLookup;
    let mut expanded_paths: HashMap<String, Vec<PathBuf>> = HashMap::new();
    let mut watch_roots: Vec<(PathBuf, bool)> = Vec::new();
    for t in &eff.targets {
        let mut paths = Vec::new();
        for tmpl in &t.paths {
            for p in expand_per_user(tmpl, &users, &env).into_iter().flatten() {
                // Resolve a symlinked directory prefix (macOS `/var` → `/private/var`,
                // etc.) so globs / warmup keys / watch roots all line up with the
                // canonical event paths the normalizer produces.
                let p = normalizer::canonicalize_glob_prefix(&p);
                let parent = if t.recursive {
                    p.clone()
                } else {
                    p.parent().map(PathBuf::from).unwrap_or_else(|| p.clone())
                };
                if parent.exists() {
                    watch_roots.push((parent, t.recursive));
                }
                paths.push(p);
            }
        }
        expanded_paths.insert(t.id.clone(), paths);
    }
    watch_roots.sort();
    watch_roots.dedup();
    (expanded_paths, watch_roots)
}

async fn emit_permission_missing(
    eff: &sigil_core::policy::EffectivePolicy,
    tx_sink: &mpsc::Sender<CommittableEvent>,
    host_id: &str,
) {
    use sigil_core::event::{
        Event, Evidence, Severity, SourceKind, Subject, AGENT_VERSION, SCHEMA_VERSION,
    };
    for t in &eff.targets {
        let event = Event {
            schema_version: SCHEMA_VERSION,
            event_id: uuid::Uuid::now_v7(),
            ts: OffsetDateTime::now_utc(),
            host_id: host_id.to_string(),
            agent_version: AGENT_VERSION.to_string(),
            severity: Severity::Warn,
            source: SourceKind::Agent,
            subject: Subject::Self_,
            evidence: Evidence::PermissionMissing {
                resource: "FullDiskAccess".into(),
                platform_hint: "Open System Settings → Privacy & Security → Full Disk Access"
                    .into(),
            },
            target_id: Some(t.id.clone()),
        };
        let _ = tx_sink
            .send(CommittableEvent {
                event,
                new_hash: None,
                path_for_db: PathBuf::new(),
                target_id: t.id.clone(),
            })
            .await;
    }
}

fn rate_limit_to_event(
    host_id: &str,
    report: &sigil_core::ratelimit::DropReport,
) -> CommittableEvent {
    use sigil_core::event::{
        Event, Evidence, Severity, SourceKind, Subject, AGENT_VERSION, SCHEMA_VERSION,
    };
    let event = Event {
        schema_version: SCHEMA_VERSION,
        event_id: uuid::Uuid::now_v7(),
        ts: OffsetDateTime::now_utc(),
        host_id: host_id.to_string(),
        agent_version: AGENT_VERSION.to_string(),
        severity: Severity::Warn,
        source: SourceKind::Agent,
        subject: Subject::Self_,
        evidence: Evidence::RateLimitExceeded {
            target_id: report.target_id.clone(),
            count_dropped_in_window: report.count_dropped,
            common_path_prefix: report.common_prefix.clone(),
        },
        target_id: Some(report.target_id.clone()),
    };
    CommittableEvent {
        event,
        new_hash: None,
        path_for_db: PathBuf::new(),
        target_id: report.target_id.clone(),
    }
}

struct GlobTargetLookup {
    targets_rx: watch::Receiver<Arc<Vec<normalizer::CompiledTarget>>>,
}
impl TargetLookup for GlobTargetLookup {
    fn find_for_path(
        &self,
        path: &std::path::Path,
        kind: sigil_core::event::FileChangeKind,
    ) -> Option<NormalizedEvent> {
        let targets: Arc<Vec<normalizer::CompiledTarget>> = self.targets_rx.borrow().clone();
        normalizer::lookup(&targets, path, kind)
    }
}

/// Per-OS path of the policy-signing keystore (spec §3.8.2).
fn keystore_path() -> PathBuf {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        PathBuf::from("/etc/sigil/policy-signing-pubkeys.pem")
    }
    #[cfg(target_os = "windows")]
    {
        PathBuf::from(r"C:\ProgramData\Sigil\policy-signing-pubkeys.pem")
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        PathBuf::from("/etc/sigil/policy-signing-pubkeys.pem")
    }
}

/// Default `policy.yaml` location when not overridden via `RuntimeConfig.policy_path`.
/// TODO: factor out a shared `defaults` module if/when other call sites need this.
fn default_policy_yaml_path() -> PathBuf {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        PathBuf::from("/etc/sigil/policy.yaml")
    }
    #[cfg(target_os = "windows")]
    {
        PathBuf::from(r"C:\ProgramData\Sigil\policy.yaml")
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        PathBuf::from("/etc/sigil/policy.yaml")
    }
}

/// Boot reconciliation: if the YAML on disk has been advanced past
/// `state.db.last_applied_policy_version` (crash between rename and version-bump),
/// advance state.db and return the new version so the caller can emit
/// `PolicyReloaded` once `tx_sink` is bound.
fn reconcile_policy_on_boot(cache: &HashCache, policy_path: &Path) -> anyhow::Result<Option<i64>> {
    if !policy_path.exists() {
        return Ok(None);
    }
    let yaml = std::fs::read_to_string(policy_path)?;
    let doc: serde_yaml::Value = serde_yaml::from_str(&yaml)?;
    let on_disk = doc.get("version").and_then(|v| v.as_i64()).unwrap_or(0);
    let in_db = cache.host_meta_get()?.last_applied_policy_version;
    if on_disk > in_db {
        cache.host_meta_set_policy_version(on_disk)?;
        Ok(Some(on_disk))
    } else {
        Ok(None)
    }
}

/// Phase 3b.6.2 — first 8 hex of a blake3 hash of the repo root path.
/// Used as the unique suffix for synthetic per-repo WatchTarget ids.
/// Collision probability is negligible at the scale we expect.
fn synthetic_target_id_suffix(repo_root: &std::path::Path) -> String {
    let hex = blake3::hash(repo_root.to_string_lossy().as_bytes()).to_hex();
    hex.as_str()[..8].to_string()
}

/// Phase 3b.6.1 — push ONE synthetic WatchTarget for a Continue.dev per-repo
/// config. Shared between boot (runtime::run) and hot-reload (policy_reload_task).
pub(crate) fn push_continue_synthetic_target(
    effective: &mut sigil_core::policy::EffectivePolicy,
    repo_root: &std::path::Path,
) {
    let config = repo_root.join(".continue").join("config.json");
    let h = synthetic_target_id_suffix(repo_root);
    effective.targets.push(sigil_core::policy::WatchTarget {
        id: format!("continue-project-{h}"),
        description: format!("Phase 3b.6.1 synthetic: {}", repo_root.display()),
        tier: sigil_core::policy::Tier::Critical,
        platform: sigil_core::policy::Platform::Any,
        paths: vec![config.to_string_lossy().to_string()],
        recursive: false,
        follow_symlinks: false,
        disabled: false,
    });
}

/// Phase 3b.6.2 — push TWO synthetic WatchTargets for a Claude Code per-repo
/// config: one for `settings.json` + `settings.local.json` (not recursive),
/// one for `.claude/hooks/` (recursive — hook scripts are watched as a dir).
pub(crate) fn push_claude_code_synthetic_targets(
    effective: &mut sigil_core::policy::EffectivePolicy,
    repo_root: &std::path::Path,
) {
    let cd = repo_root.join(".claude");
    let h = synthetic_target_id_suffix(repo_root);
    effective.targets.push(sigil_core::policy::WatchTarget {
        id: format!("claude_code-settings-{h}"),
        description: format!("Phase 3b.6.2 synthetic settings: {}", repo_root.display()),
        tier: sigil_core::policy::Tier::Critical,
        platform: sigil_core::policy::Platform::Any,
        paths: vec![
            cd.join("settings.json").to_string_lossy().to_string(),
            cd.join("settings.local.json").to_string_lossy().to_string(),
        ],
        recursive: false,
        follow_symlinks: false,
        disabled: false,
    });
    effective.targets.push(sigil_core::policy::WatchTarget {
        id: format!("claude_code-hooks-{h}"),
        description: format!("Phase 3b.6.2 synthetic hooks: {}", repo_root.display()),
        tier: sigil_core::policy::Tier::Critical,
        platform: sigil_core::policy::Platform::Any,
        paths: vec![cd.join("hooks").to_string_lossy().to_string()],
        recursive: true,
        follow_symlinks: false,
        disabled: false,
    });
}

/// Phase 3b.6.2 — push ONE synthetic WatchTarget for a Codex per-repo config.
pub(crate) fn push_codex_synthetic_target(
    effective: &mut sigil_core::policy::EffectivePolicy,
    repo_root: &std::path::Path,
) {
    let config = repo_root.join(".codex").join("config.toml");
    let h = synthetic_target_id_suffix(repo_root);
    effective.targets.push(sigil_core::policy::WatchTarget {
        id: format!("codex-project-{h}"),
        description: format!("Phase 3b.6.2 synthetic: {}", repo_root.display()),
        tier: sigil_core::policy::Tier::Critical,
        platform: sigil_core::policy::Platform::Any,
        paths: vec![config.to_string_lossy().to_string()],
        recursive: false,
        follow_symlinks: false,
        disabled: false,
    });
}

/// Phase 3b.3 — push ONE synthetic WatchTarget for an external hook-script
/// path. The id encodes the owning tool's display name and a blake3 hash of
/// the canonical path. In-memory only; never written back to disk.
pub(crate) fn push_ext_script_synthetic_target(
    effective: &mut sigil_core::policy::EffectivePolicy,
    tool_display: &str,
    canonical_script_path: &std::path::Path,
) {
    let h = synthetic_target_id_suffix(canonical_script_path);
    effective.targets.push(sigil_core::policy::WatchTarget {
        id: format!("{tool_display}-extscript-{h}"),
        description: format!(
            "Phase 3b.3 synthetic ext-script: {}",
            canonical_script_path.display()
        ),
        tier: sigil_core::policy::Tier::Critical,
        platform: sigil_core::policy::Platform::Any,
        paths: vec![canonical_script_path.to_string_lossy().to_string()],
        recursive: false,
        follow_symlinks: false,
        disabled: false,
    });
}

/// Phase 3b.3 — map `AiTool` to the display string used in synthetic
/// WatchTarget ids for ext-scripts. Matches the existing per-repo naming
/// convention (`continue`, `claude_code`, `codex`).
pub(crate) fn tool_display_for_extscript(tool: sigil_core::event::AiTool) -> &'static str {
    use sigil_core::event::AiTool;
    match tool {
        AiTool::ClaudeCode => "claude_code",
        AiTool::Codex => "codex",
        AiTool::ContinueDev => "continue",
        AiTool::ClaudeDesktop => "claude_desktop",
        AiTool::Gemini => "gemini",
        AiTool::Cursor => "cursor",
    }
}

/// Phase 3b.3 — best-effort expansion of `~` and `$VAR` in a script path.
/// Uses the existing sigil-core expand machinery (with the `EnvLookup` unit
/// type that defers to `std::env`) for parity with policy expansion. Falls
/// back to the original path on any error.
pub(crate) fn expand_user_path_for_ext_script(p: &std::path::Path) -> std::path::PathBuf {
    let raw = p.to_string_lossy();
    match sigil_core::policy::expand::expand(&raw, &EnvLookup) {
        Ok(pb) => pb,
        Err(_) => p.to_path_buf(),
    }
}

/// Phase 3b.3 — for every parser in `parsers`, call
/// `collect_external_script_paths`, expand + canonicalize each path,
/// deduplicate across parsers, register results in `registry`, and push one
/// synthetic WatchTarget per unique canonical path. Skips paths that fail
/// to expand or canonicalize (e.g., the script is not yet installed on
/// disk — registry will pick it up on the next reload after the operator
/// drops the file in).
pub(crate) fn discover_and_register_ext_scripts(
    parsers: &[std::sync::Arc<dyn crate::ai_guard::parser::AiGuardParser>],
    home_dir: &std::path::Path,
    registry: &crate::ai_guard::ExtScriptRegistry,
    effective: &mut sigil_core::policy::EffectivePolicy,
) {
    use std::collections::{BTreeSet, HashMap};

    let mut per_parser: HashMap<
        (sigil_core::event::AiTool, sigil_core::event::AiGuardScope),
        Vec<std::path::PathBuf>,
    > = HashMap::new();

    let mut already_synthesized: BTreeSet<std::path::PathBuf> = BTreeSet::new();

    for parser in parsers {
        let raw_paths = parser.collect_external_script_paths(home_dir);
        if raw_paths.is_empty() {
            continue;
        }
        let mut canon_paths = Vec::with_capacity(raw_paths.len());
        for raw in raw_paths {
            let expanded = expand_user_path_for_ext_script(&raw);
            let Ok(canon) = dunce::canonicalize(&expanded) else {
                continue;
            };
            if already_synthesized.insert(canon.clone()) {
                let display = tool_display_for_extscript(parser.tool());
                push_ext_script_synthetic_target(effective, display, &canon);
            }
            canon_paths.push(canon);
        }
        if !canon_paths.is_empty() {
            per_parser
                .entry((parser.tool(), parser.scope()))
                .or_default()
                .extend(canon_paths);
        }
    }

    let mut w = registry.write();
    w.clear();
    for (k, v) in per_parser {
        w.insert(k, v);
    }
}
