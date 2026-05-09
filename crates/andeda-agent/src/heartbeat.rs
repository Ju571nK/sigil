//! Heartbeat task: emits an Event every 60s, plus one on shutdown with is_final=true.

use crate::state_task::CommittableEvent;
use andeda_core::event::{
    Event, Evidence, Severity, SourceKind, Subject, AGENT_VERSION, SCHEMA_VERSION,
};
use andeda_core::stats::Stats;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use time::OffsetDateTime;
use tokio::sync::mpsc;
use tokio::time::interval;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

pub async fn run(
    stats: Arc<Stats>,
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
                emit(&stats, &host_id, watcher_backend, &state_db_path, &tx, started, true).await;
                break;
            }
            _ = tick.tick() => {
                emit(&stats, &host_id, watcher_backend, &state_db_path, &tx, started, false).await;
            }
        }
    }
}

async fn emit(
    stats: &Arc<Stats>,
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
