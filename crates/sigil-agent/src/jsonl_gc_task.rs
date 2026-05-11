//! Periodic GC task — runs every 10 minutes, lists segments, applies
//! `jsonl_gc::decide`, deletes files, emits events, updates the heartbeat flag.

use crate::gc_config::GcConfig;
use crate::jsonl_gc::{decide, Segment};
use crate::sender_offset;
use crate::state_task::CommittableEvent;
use sigil_core::event::{
    Event, Evidence, Severity, SourceKind, Subject, AGENT_VERSION, SCHEMA_VERSION,
};
use parking_lot::RwLock;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use time::OffsetDateTime;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// Inputs handed to the GC task.
pub struct GcTaskCtx {
    pub host_id: String,
    pub events_dir: PathBuf,
    /// Updated by the JsonlSink each rotation; the task reads it at decision time.
    pub current_segment_filename: Arc<RwLock<String>>,
    /// Heartbeat reads this — set by the task each tick.
    pub above_soft_floor: Arc<RwLock<bool>>,
    pub cfg: GcConfig,
    pub event_tx: mpsc::Sender<CommittableEvent>,
    pub shutdown: CancellationToken,
    pub tick: Duration,
}

pub async fn run(ctx: GcTaskCtx) {
    let mut interval = tokio::time::interval(ctx.tick);
    interval.tick().await;
    loop {
        tokio::select! {
            biased;
            _ = ctx.shutdown.cancelled() => break,
            _ = interval.tick() => {
                tick(&ctx).await;
            }
        }
    }
}

#[doc(hidden)]
pub async fn tick_for_test(ctx: &GcTaskCtx) {
    tick(ctx).await;
}

async fn tick(ctx: &GcTaskCtx) {
    let now = OffsetDateTime::now_utc();
    let segs = match list_segments(&ctx.events_dir) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = ?e, "jsonl_gc: list_segments failed");
            return;
        }
    };
    let off = match sender_offset::read(&ctx.events_dir) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = ?e, "jsonl_gc: sender_offset read failed; treating as None");
            None
        }
    };
    // Defensive: refresh the snapshotted current-segment if the runtime's
    // boot-time snapshot has rotated away. Without this, Plan A's once-at-
    // startup snapshot can mis-identify the live writer's file as deletable
    // under a hard ceiling — see jsonl_gc.rs algorithm. Plan A2 will replace
    // this with a sink-pushed update on every rotation.
    {
        let stored = ctx.current_segment_filename.read().clone();
        let lex_max = segs.iter().map(|s| s.filename.as_str()).max();
        if let Some(latest) = lex_max {
            if stored.is_empty() || stored.as_str() < latest {
                *ctx.current_segment_filename.write() = latest.to_string();
            }
        }
    }
    let current = ctx.current_segment_filename.read().clone();
    let decision = decide(&segs, off.as_ref(), &current, &ctx.cfg, now);
    *ctx.above_soft_floor.write() = decision.above_soft_floor;

    // Delete files. We collected them oldest-first so removal order is
    // deterministic; if a remove fails we log and skip but continue.
    let mut deleted = 0u32;
    for path in &decision.to_delete {
        match std::fs::remove_file(path) {
            Ok(()) => deleted += 1,
            Err(e) => {
                tracing::warn!(path = ?path, error = ?e, "jsonl_gc: remove failed");
            }
        }
    }

    if decision.hard_ceiling_fired {
        let total: u64 = segs.iter().map(|s| s.size_bytes).sum();
        let oldest_age_s = segs
            .iter()
            .map(|s| (now - s.mtime).whole_seconds().max(0) as u64)
            .max()
            .unwrap_or(0);
        let ev = Event {
            schema_version: SCHEMA_VERSION,
            event_id: Uuid::now_v7(),
            ts: now,
            host_id: ctx.host_id.clone(),
            agent_version: AGENT_VERSION.to_string(),
            severity: Severity::Warn,
            source: SourceKind::Agent,
            subject: Subject::Self_,
            evidence: Evidence::AgentJsonlForceGc {
                total_bytes: total,
                oldest_segment_age_s: oldest_age_s,
                segments_deleted: deleted,
                segments_skipped_past_sender: decision.force_deleted_past_sender as u32,
            },
            target_id: None,
        };
        let _ = ctx
            .event_tx
            .send(CommittableEvent {
                event: ev,
                new_hash: None,
                path_for_db: PathBuf::new(),
                target_id: String::new(),
            })
            .await;
    }

    if decision.force_deleted_past_sender > 0 {
        // I1 (Plan A2): when consumed + force-deleted segments coexist in
        // one cycle, this is the oldest DELETED filename, not strictly the
        // oldest FORCE-DELETED past-sender filename. Tracked for diagnostic
        // precision once Plan B sender ships and SIEM operators rely on it.
        let oldest_dropped = decision
            .to_delete
            .first()
            .and_then(|p| p.file_name())
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        let ev = Event {
            schema_version: SCHEMA_VERSION,
            event_id: Uuid::now_v7(),
            ts: now,
            host_id: ctx.host_id.clone(),
            agent_version: AGENT_VERSION.to_string(),
            severity: Severity::Warn,
            source: SourceKind::Agent,
            subject: Subject::Self_,
            evidence: Evidence::SenderSkippedSegment {
                count: decision.force_deleted_past_sender as u32,
                oldest_dropped_filename: oldest_dropped,
            },
            target_id: None,
        };
        let _ = ctx
            .event_tx
            .send(CommittableEvent {
                event: ev,
                new_hash: None,
                path_for_db: PathBuf::new(),
                target_id: String::new(),
            })
            .await;
    }
}

fn list_segments(dir: &Path) -> std::io::Result<Vec<Segment>> {
    let mut out = Vec::new();
    if !dir.exists() {
        return Ok(out);
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        // Only files matching the JsonlSink naming convention.
        if !name.starts_with("events-") || !name.ends_with(".jsonl") {
            continue;
        }
        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        if !meta.is_file() {
            continue;
        }
        let mtime = meta
            .modified()
            .map(OffsetDateTime::from)
            .unwrap_or_else(|_| OffsetDateTime::now_utc());
        out.push(Segment {
            filename: name,
            path: entry.path(),
            size_bytes: meta.len(),
            mtime,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn write_seg(dir: &Path, name: &str, bytes: &[u8]) {
        std::fs::write(dir.join(name), bytes).unwrap();
    }

    fn ctx_for(
        dir: &Path,
        current: &str,
        cfg: GcConfig,
    ) -> (
        GcTaskCtx,
        mpsc::Receiver<CommittableEvent>,
        Arc<RwLock<bool>>,
    ) {
        let (tx, rx) = mpsc::channel(8);
        let above = Arc::new(RwLock::new(false));
        let curr = Arc::new(RwLock::new(current.to_string()));
        let ctx = GcTaskCtx {
            host_id: "h".into(),
            events_dir: dir.to_path_buf(),
            current_segment_filename: curr,
            above_soft_floor: above.clone(),
            cfg,
            event_tx: tx,
            shutdown: CancellationToken::new(),
            tick: Duration::from_secs(60),
        };
        (ctx, rx, above)
    }

    #[tokio::test]
    async fn empty_dir_no_events_no_above_soft() {
        let dir = tempdir().unwrap();
        let (ctx, mut rx, above) =
            ctx_for(dir.path(), "events-2026-05-15.jsonl", GcConfig::defaults());
        tick(&ctx).await;
        assert!(rx.try_recv().is_err());
        assert!(!*above.read());
    }

    #[tokio::test]
    async fn force_gc_above_hard_ceiling_emits_force_gc_and_skipped_events() {
        let dir = tempdir().unwrap();
        write_seg(dir.path(), "events-2026-05-13.jsonl", &[b'x'; 600]);
        write_seg(dir.path(), "events-2026-05-14.jsonl", &[b'x'; 600]);

        let cfg = GcConfig {
            soft_floor_bytes: 100,
            soft_floor_age: Duration::from_secs(3600),
            hard_ceiling_bytes: 1000,
            hard_ceiling_age: Duration::from_secs(7200),
        };
        let (ctx, mut rx, above) = ctx_for(dir.path(), "events-2026-05-14.jsonl", cfg);
        tick(&ctx).await;

        assert!(*above.read());
        // Two events in the channel: AgentJsonlForceGc + SenderSkippedSegment.
        let mut got_force = false;
        let mut got_skipped = false;
        for _ in 0..2 {
            let ev = rx.recv().await.unwrap();
            match ev.event.evidence {
                Evidence::AgentJsonlForceGc { .. } => got_force = true,
                Evidence::SenderSkippedSegment { count, .. } => {
                    got_skipped = true;
                    assert!(count >= 1);
                }
                other => panic!("unexpected evidence {other:?}"),
            }
        }
        assert!(got_force && got_skipped);
        // 05-13 should now be gone.
        assert!(!dir.path().join("events-2026-05-13.jsonl").exists());
        // 05-14 (current segment) MUST still exist.
        assert!(dir.path().join("events-2026-05-14.jsonl").exists());
    }

    #[tokio::test]
    async fn soft_floor_only_no_force_event() {
        let dir = tempdir().unwrap();
        write_seg(dir.path(), "events-2026-05-13.jsonl", &[b'x'; 80]);
        write_seg(dir.path(), "events-2026-05-15.jsonl", &[b'x'; 80]);
        // sender-offset.json says 05-13 has been consumed.
        let off = crate::sender_offset::SenderOffset {
            current_segment: "events-2026-05-15.jsonl".into(),
            byte_offset: 0,
            updated_at: OffsetDateTime::now_utc(),
        };
        std::fs::write(
            dir.path().join("sender-offset.json"),
            serde_json::to_vec(&off).unwrap(),
        )
        .unwrap();

        let cfg = GcConfig {
            soft_floor_bytes: 100,
            soft_floor_age: Duration::from_secs(3600 * 24 * 30),
            hard_ceiling_bytes: 1000,
            hard_ceiling_age: Duration::from_secs(3600 * 24 * 60),
        };
        let (ctx, mut rx, above) = ctx_for(dir.path(), "events-2026-05-15.jsonl", cfg);
        tick(&ctx).await;

        assert!(*above.read());
        // 05-13 deleted (consumed past sender → soft-eligible). NO force_gc event.
        assert!(!dir.path().join("events-2026-05-13.jsonl").exists());
        let ev = rx.try_recv();
        assert!(
            ev.is_err(),
            "expected no events for soft-floor-only GC, got {ev:?}"
        );
    }
}
