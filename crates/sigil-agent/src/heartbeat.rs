//! Heartbeat task: emits an Event every 60s, plus one on shutdown with is_final=true.

use crate::state_task::CommittableEvent;
use parking_lot::{Mutex, RwLock};
use sigil_core::event::{
    Event, Evidence, Severity, SourceKind, Subject, AGENT_VERSION, SCHEMA_VERSION,
};
use sigil_core::state::HashCache;
use sigil_core::stats::Stats;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use time::OffsetDateTime;
use tokio::sync::mpsc;
use tokio::time::interval;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

#[allow(clippy::too_many_arguments)] // glue task; each arg is an independent dependency
pub async fn run(
    stats: Arc<Stats>,
    cache: Arc<Mutex<HashCache>>,
    policy_expired_active: Arc<RwLock<bool>>,
    jsonl_above_soft_floor: Arc<RwLock<bool>>,
    host_id: String,
    watcher_backend: &'static str,
    state_db_path: PathBuf,
    tx: mpsc::Sender<CommittableEvent>,
    shutdown: CancellationToken,
    started: std::time::Instant,
) {
    let mut tick = interval(Duration::from_secs(60));
    tick.tick().await;
    loop {
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => {
                emit(&stats, &cache, &policy_expired_active, &jsonl_above_soft_floor, &host_id, watcher_backend, &state_db_path, &tx, started, true).await;
                break;
            }
            _ = tick.tick() => {
                emit(&stats, &cache, &policy_expired_active, &jsonl_above_soft_floor, &host_id, watcher_backend, &state_db_path, &tx, started, false).await;
            }
        }
    }
}

#[allow(clippy::too_many_arguments)] // emit() mirrors run()'s dependency surface
pub(crate) async fn emit(
    stats: &Arc<Stats>,
    cache: &Arc<Mutex<HashCache>>,
    policy_expired_active: &Arc<RwLock<bool>>,
    jsonl_above_soft_floor_flag: &Arc<RwLock<bool>>,
    host_id: &str,
    watcher_backend: &'static str,
    state_db_path: &PathBuf,
    tx: &mpsc::Sender<CommittableEvent>,
    started: std::time::Instant,
    is_final: bool,
) {
    let snap = stats.snapshot();
    let state_db_size_bytes = std::fs::metadata(state_db_path)
        .map(|m| m.len())
        .unwrap_or(0);
    let last_applied_policy_version = cache
        .lock()
        .host_meta_get()
        .map(|m| m.last_applied_policy_version)
        .unwrap_or(0);
    let policy_expired = *policy_expired_active.read();
    let jsonl_above_soft_floor = *jsonl_above_soft_floor_flag.read();
    let evidence = Evidence::Heartbeat {
        uptime_s: started.elapsed().as_secs(),
        is_final,
        channel_stall_events_total: snap.channel_stall_events_total,
        events_emitted_total: snap.events_emitted_total,
        events_by_kind: snap.events_by_kind,
        hash_p50_ms: snap.hash_p50_ms,
        hash_p99_ms: snap.hash_p99_ms,
        watcher_backend: watcher_backend.to_string(),
        state_db_size_bytes,
        last_log_rotation_ts: None,
        last_applied_policy_version,
        policy_expired_active: policy_expired,
        jsonl_above_soft_floor,
    };
    let event = Event {
        schema_version: SCHEMA_VERSION,
        event_id: Uuid::now_v7(),
        ts: OffsetDateTime::now_utc(),
        host_id: host_id.to_string(),
        agent_version: AGENT_VERSION.to_string(),
        severity: Severity::Info,
        source: SourceKind::Agent,
        subject: Subject::Self_,
        evidence,
        target_id: None,
    };
    let _ = tx
        .send(CommittableEvent {
            event,
            new_hash: None,
            path_for_db: PathBuf::new(),
            target_id: String::new(),
        })
        .await;
}

#[cfg(test)]
mod field_tests {
    use super::*;
    use parking_lot::{Mutex, RwLock};
    use sigil_core::state::HashCache;
    use tempfile::tempdir;

    #[tokio::test]
    async fn heartbeat_carries_policy_fields() {
        let dir = tempdir().unwrap();
        let cache = HashCache::open(&dir.path().join("state.db")).unwrap();
        cache.host_meta_set_policy_version(42).unwrap();
        let cache = Arc::new(Mutex::new(cache));
        let expired = Arc::new(RwLock::new(true));
        let jsonl_above = Arc::new(RwLock::new(false));
        let stats = sigil_core::stats::Stats::shared();
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);

        emit(
            &stats,
            &cache,
            &expired,
            &jsonl_above,
            "test-host",
            "stub",
            &dir.path().join("state.db"),
            &tx,
            std::time::Instant::now(),
            false,
        )
        .await;

        let ev = rx.recv().await.unwrap();
        match ev.event.evidence {
            Evidence::Heartbeat {
                last_applied_policy_version,
                policy_expired_active,
                ..
            } => {
                assert_eq!(last_applied_policy_version, 42);
                assert!(policy_expired_active);
            }
            other => panic!("expected Heartbeat, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn heartbeat_carries_jsonl_above_soft_floor_flag() {
        let dir = tempdir().unwrap();
        let cache = Arc::new(Mutex::new(
            HashCache::open(&dir.path().join("state.db")).unwrap(),
        ));
        let expired = Arc::new(RwLock::new(false));
        let jsonl_above = Arc::new(RwLock::new(true));
        let stats = sigil_core::stats::Stats::shared();
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);

        emit(
            &stats,
            &cache,
            &expired,
            &jsonl_above,
            "test-host",
            "stub",
            &dir.path().join("state.db"),
            &tx,
            std::time::Instant::now(),
            false,
        )
        .await;

        let ev = rx.recv().await.unwrap();
        match ev.event.evidence {
            Evidence::Heartbeat {
                jsonl_above_soft_floor,
                ..
            } => {
                assert!(jsonl_above_soft_floor);
            }
            other => panic!("expected Heartbeat, got {other:?}"),
        }
    }
}
