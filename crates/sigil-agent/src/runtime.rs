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
}

pub async fn run(cfg: RuntimeConfig) -> anyhow::Result<i32> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("SIGIL_LOG")
                .unwrap_or_else(|_| "info".into()),
        )
        .with_writer(std::io::stderr)
        .init();

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
    // Note: live watcher reload not implemented in Plan A — apply_policy
    // writes policy.yaml + state.db, but the running watcher subgraph does
    // NOT re-pick up the new file; restart the agent to refresh watch targets.
    let keystore = match Keystore::load_from_file(keystore_path()) {
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
    let effective = merge(defaults()?, user_doc, current_platform())?;
    // (host_id resolution moved up above; effective.host_id_strategy is no longer consulted)

    // 2. Expand paths per user.
    let users = UserEnumerator::list(&plat);
    let env = EnvLookup;
    let mut expanded_paths: HashMap<String, Vec<PathBuf>> = HashMap::new();
    let mut watch_roots: Vec<(PathBuf, bool)> = Vec::new();
    for t in &effective.targets {
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
    let control_ctx = Arc::new(crate::control::ControlContext {
        stats: stats.clone(),
        apply_ctx: apply_ctx.clone(),
        active_valid_until: active_valid_until.clone(),
    });

    // Watcher (notify → raw events → tx_norm via normalizer wrapper).
    let runtime_handle = tokio::runtime::Handle::current();
    let poll_interval = if cfg.poll_watcher {
        tracing::info!("forcing polling watcher (--poll); OS-native FS events disabled");
        Some(std::time::Duration::from_secs(5))
    } else {
        None
    };
    let watcher_handle = watcher::spawn_watcher(
        watch_roots.clone(),
        runtime_handle.clone(),
        1024,
        poll_interval,
    )?;
    let backend_name = watcher_handle.backend_name;
    let raw_rx = watcher_handle.rx;

    let targets = Arc::new(normalizer::compile_targets(&effective, &expanded_paths));
    let mut sup = Supervisor::new();
    let cancel = sup.shutdown.clone();

    sup.track(
        "normalizer",
        tokio::spawn({
            let tx_norm = tx_norm.clone();
            let tx_dropped = tx_dropped.clone();
            let targets = targets.clone();
            async move {
                normalizer::run(targets, raw_rx, tx_norm, tx_dropped).await;
            }
        }),
    );
    drop(tx_norm);
    drop(tx_dropped);

    sup.track(
        "debouncer",
        tokio::spawn(debouncer::run(rx_norm, tx_pending)),
    );

    sup.track(
        "hasher",
        tokio::spawn({
            let stats = stats.clone();
            // The hasher re-derives a `PendingEvent`'s target/tier by matching
            // the (already-canonical) path against the same compiled globs the
            // normalizer used.
            let lookup: Arc<dyn TargetLookup + Send + Sync> = Arc::new(GlobTargetLookup {
                targets: targets.clone(),
            });
            async move {
                crate::hasher::run(rx_pending, tx_hashed, lookup, stats).await;
            }
        }),
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

    // Wait for shutdown.
    let exit_code = sup.run(host_id.clone(), tx_sink.clone()).await?;
    Ok(exit_code)
}

fn perform_warmup(
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
    targets: Arc<Vec<normalizer::CompiledTarget>>,
}
impl TargetLookup for GlobTargetLookup {
    fn find_for_path(
        &self,
        path: &std::path::Path,
        kind: sigil_core::event::FileChangeKind,
    ) -> Option<NormalizedEvent> {
        normalizer::lookup(&self.targets, path, kind)
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
