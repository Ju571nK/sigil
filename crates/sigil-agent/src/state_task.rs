//! State-store task. Implements **event-first commit ordering** (spec 1.4):
//! 1. Read prior `before_hash` from state.db.
//! 2. Send Event to sink.
//! 3. After sink confirms write (returns Ok), update state.db.

use crate::hasher::HashedEvent;
use parking_lot::Mutex;
use sigil_core::event::{
    Event, Evidence, FileChangeKind, Severity, SourceKind, Subject, AGENT_VERSION, SCHEMA_VERSION,
};
use sigil_core::state::HashCache;
use sigil_core::stats::Stats;
use std::path::PathBuf;
use std::sync::Arc;
use time::OffsetDateTime;
use tokio::sync::mpsc;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct CommittableEvent {
    pub event: Event,
    pub new_hash: Option<String>,
    pub path_for_db: PathBuf,
    pub target_id: String,
}

pub async fn run(
    mut rx: mpsc::Receiver<HashedEvent>,
    tx_sink: mpsc::Sender<CommittableEvent>,
    cache: Arc<Mutex<HashCache>>,
    host_id: String,
    stats: Arc<Stats>,
) {
    while let Some(hashed) = rx.recv().await {
        let path = hashed.norm.path.clone();
        let before_hash = cache.lock().get(&path).ok().flatten();

        let evidence = Evidence::FileChange {
            change_kind: hashed.norm.kind,
            before_hash,
            after_hash: hashed.after_hash.clone(),
            recheck_hash: hashed.recheck_hash,
            rename_from: hashed.norm.rename_from.clone(),
            size_after: hashed.size_after,
            evidence_quality: hashed.quality,
        };

        let event = Event {
            schema_version: SCHEMA_VERSION,
            event_id: Uuid::now_v7(),
            ts: OffsetDateTime::now_utc(),
            host_id: host_id.clone(),
            agent_version: AGENT_VERSION.to_string(),
            severity: Severity::Warn,
            source: SourceKind::FileSystem,
            subject: Subject::Path {
                value: path.clone(),
            },
            evidence,
            target_id: Some(hashed.norm.target_id.clone()),
        };

        stats.record_emit("file_change");

        let committable = CommittableEvent {
            event,
            new_hash: hashed.after_hash,
            path_for_db: path,
            target_id: hashed.norm.target_id,
        };

        if tx_sink.send(committable).await.is_err() {
            return;
        }
    }
}

/// Called by the sink task **after** the JSONL line is written. Updates the DB.
pub fn commit_baseline(cache: &Mutex<HashCache>, committable: &CommittableEvent, now_ms: u64) {
    let g = cache.lock();
    match (&committable.new_hash, &committable.event.evidence) {
        (
            Some(hash),
            Evidence::FileChange {
                size_after: Some(size),
                change_kind,
                ..
            },
        ) if *change_kind != FileChangeKind::Removed => {
            let _ = g.put(
                &committable.path_for_db,
                hash,
                *size,
                &committable.target_id,
                now_ms,
            );
        }
        (
            None,
            Evidence::FileChange {
                change_kind: FileChangeKind::Removed,
                ..
            },
        ) => {
            let _ = g.delete(&committable.path_for_db);
        }
        _ => {}
    }
}
