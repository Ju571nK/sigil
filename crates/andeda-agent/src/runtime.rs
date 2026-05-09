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
use andeda_core::host_id::resolve as resolve_host_id;
use andeda_core::policy::expand::{expand_per_user, EnvLookup, UserEnumerator};
use andeda_core::policy::{current_platform, defaults, merge, Tier};
use andeda_core::sink::jsonl::JsonlSink;
use andeda_core::state::HashCache;
use andeda_core::stats::Stats;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use time::OffsetDateTime;
use tokio::sync::mpsc;

pub struct RuntimeConfig {
    pub policy_path: Option<PathBuf>,
    pub state_db_path: PathBuf,
    pub events_dir: PathBuf,
    pub control_socket: PathBuf,
    pub control_pipe_name: String,
}

pub async fn run(cfg: RuntimeConfig) -> anyhow::Result<i32> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("ANDEDA_LOG")
                .unwrap_or_else(|_| "info".into()),
        )
        .with_writer(std::io::stderr)
        .init();

    let plat = ActivePlatform::new();
    let started = Instant::now();

    // 1. Load + merge policy.
    let user_doc = match cfg.policy_path.as_ref() {
        Some(p) if p.exists() => Some(andeda_core::policy::parse(&std::fs::read_to_string(p)?)?),
        _ => None,
    };
    let effective = merge(defaults()?, user_doc, current_platform())?;
    let host_id = resolve_host_id(&effective.host_id_strategy, &plat);

    // 2. Expand paths per user.
    let users = UserEnumerator::list(&plat);
    let env = EnvLookup;
    let mut expanded_paths: HashMap<String, Vec<PathBuf>> = HashMap::new();
    let mut watch_roots: Vec<(PathBuf, bool)> = Vec::new();
    for t in &effective.targets {
        let mut paths = Vec::new();
        for tmpl in &t.paths {
            for r in expand_per_user(tmpl, &users, &env) {
                if let Ok(p) = r {
                    paths.push(p.clone());
                    let parent = if t.recursive {
                        p.clone()
                    } else {
                        p.parent().map(PathBuf::from).unwrap_or(p.clone())
                    };
                    if parent.exists() {
                        watch_roots.push((parent, t.recursive));
                    }
                }
            }
        }
        expanded_paths.insert(t.id.clone(), paths);
    }

    // 3. Open state.db, perform critical-tier warmup.
    if let Some(dir) = cfg.state_db_path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let cache = Arc::new(Mutex::new(HashCache::open(&cfg.state_db_path)?));
    perform_warmup(&effective, &expanded_paths, &cache)?;

    // 4. Open sink.
    let sink = JsonlSink::open(&cfg.events_dir, OffsetDateTime::now_utc())?;

    // 5. Bootstrap channels and tasks.
    let (tx_norm, rx_norm) = mpsc::channel::<NormalizedEvent>(512);
    let (tx_pending, rx_pending) = mpsc::channel::<andeda_core::debounce::PendingEvent>(512);
    let (tx_hashed, rx_hashed) = mpsc::channel::<HashedEvent>(512);
    let (tx_sink, rx_sink) = mpsc::channel::<CommittableEvent>(256);
    let (tx_dropped, mut rx_dropped) = mpsc::channel::<andeda_core::ratelimit::DropReport>(64);

    let stats = Stats::shared();

    // Watcher (notify → raw events → tx_norm via normalizer wrapper).
    let runtime_handle = tokio::runtime::Handle::current();
    let watcher_handle =
        watcher::spawn_watcher(watch_roots.clone(), runtime_handle.clone(), 1024)?;
    let backend_name = watcher_handle.backend_name;
    let raw_rx = watcher_handle.rx;

    let targets = normalizer::compile_targets(&effective, &expanded_paths);
    let mut sup = Supervisor::new();
    let cancel = sup.shutdown.clone();

    sup.track(
        "normalizer",
        tokio::spawn({
            let tx_norm = tx_norm.clone();
            let tx_dropped = tx_dropped.clone();
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
            // A simple `TargetLookup` placeholder: in Phase 1 we recover the
            // NormalizedEvent from the debouncer-side state. The hasher task here
            // is a stub for the wiring; the actual NormalizedEvent metadata is
            // forwarded inline through the Debouncer's `PendingEvent`.
            let lookup: Arc<dyn TargetLookup + Send + Sync> = Arc::new(NoopLookup);
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

    // Heartbeat
    {
        let stats_h = stats.clone();
        let host_id_h = host_id.clone();
        let cancel_h = cancel.clone();
        let tx_h = tx_sink.clone();
        let dbp = cfg.state_db_path.clone();
        sup.track(
            "heartbeat",
            tokio::spawn(async move {
                heartbeat::run(stats_h, host_id_h, backend_name, dbp, tx_h, cancel_h, started)
                    .await
            }),
        );
    }

    // FDA permission check (macOS) — emit one PermissionMissing per target if denied.
    if matches!(plat.fda_state(), FdaState::Denied) {
        emit_permission_missing(&effective, &tx_sink, &host_id).await;
    }

    // Control IPC
    {
        let stats_c = stats.clone();
        #[cfg(unix)]
        let socket = cfg.control_socket.clone();
        #[cfg(windows)]
        let pipe = cfg.control_pipe_name.clone();
        sup.track(
            "control",
            tokio::spawn(async move {
                #[cfg(unix)]
                let _ = crate::control::serve(&socket, stats_c).await;
                #[cfg(windows)]
                let _ = crate::control::serve(&pipe, stats_c).await;
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
    eff: &andeda_core::policy::EffectivePolicy,
    expanded: &HashMap<String, Vec<PathBuf>>,
    cache: &Arc<Mutex<HashCache>>,
) -> anyhow::Result<()> {
    use andeda_core::hashing::{hash_path, HashOutcome};
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
    eff: &andeda_core::policy::EffectivePolicy,
    tx_sink: &mpsc::Sender<CommittableEvent>,
    host_id: &str,
) {
    use andeda_core::event::{
        Event, Evidence, Severity, SourceKind, Subject, AGENT_VERSION, SCHEMA_VERSION,
    };
    for t in &eff.targets {
        let event = Event {
            schema_version: SCHEMA_VERSION,
            event_id: uuid::Uuid::now_v7(),
            ts: OffsetDateTime::now_utc(),
            host_id: host_id.to_string(),
            agent_version: AGENT_VERSION,
            severity: Severity::Warn,
            source: SourceKind::Agent,
            subject: Subject::Self_,
            evidence: Evidence::PermissionMissing {
                resource: "FullDiskAccess".into(),
                platform_hint:
                    "Open System Settings → Privacy & Security → Full Disk Access".into(),
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
    report: &andeda_core::ratelimit::DropReport,
) -> CommittableEvent {
    use andeda_core::event::{
        Event, Evidence, Severity, SourceKind, Subject, AGENT_VERSION, SCHEMA_VERSION,
    };
    let event = Event {
        schema_version: SCHEMA_VERSION,
        event_id: uuid::Uuid::now_v7(),
        ts: OffsetDateTime::now_utc(),
        host_id: host_id.to_string(),
        agent_version: AGENT_VERSION,
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

struct NoopLookup;
impl TargetLookup for NoopLookup {
    fn find_for_path(
        &self,
        _path: &std::path::Path,
        _kind: andeda_core::event::FileChangeKind,
    ) -> Option<NormalizedEvent> {
        None
    }
}
