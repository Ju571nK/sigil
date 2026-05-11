//! e2e: jsonl_gc_task soft-floor / hard-ceiling behaviors.

use parking_lot::RwLock;
use sigil_agent::gc_config::GcConfig;
use sigil_agent::jsonl_gc_task::{tick_for_test, GcTaskCtx};
use sigil_agent::sender_offset::SenderOffset;
use sigil_core::event::Evidence;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;
use time::OffsetDateTime;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

fn write_segment(dir: &Path, name: &str, size_bytes: usize) {
    std::fs::write(dir.join(name), vec![b'.'; size_bytes]).unwrap();
}

fn write_sender_offset(dir: &Path, current: &str) {
    let off = SenderOffset {
        current_segment: current.into(),
        byte_offset: 0,
        updated_at: OffsetDateTime::now_utc(),
    };
    std::fs::write(
        dir.join("sender-offset.json"),
        serde_json::to_vec(&off).unwrap(),
    )
    .unwrap();
}

fn build_ctx(
    dir: &Path,
    current: &str,
    cfg: GcConfig,
) -> (
    GcTaskCtx,
    mpsc::Receiver<sigil_agent::state_task::CommittableEvent>,
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
async fn soft_floor_only_deletes_consumed_segments_no_force_events() {
    let dir = tempdir().unwrap();
    write_segment(dir.path(), "events-2026-05-13.jsonl", 80);
    write_segment(dir.path(), "events-2026-05-15.jsonl", 80);
    write_sender_offset(dir.path(), "events-2026-05-15.jsonl");

    let cfg = GcConfig {
        soft_floor_bytes: 100,
        soft_floor_age: Duration::from_secs(86400 * 30),
        hard_ceiling_bytes: 1000,
        hard_ceiling_age: Duration::from_secs(86400 * 60),
    };
    let (ctx, mut rx, above) = build_ctx(dir.path(), "events-2026-05-15.jsonl", cfg);
    tick_for_test(&ctx).await;

    assert!(*above.read());
    // Consumed 05-13 deleted; current 05-15 preserved.
    assert!(!dir.path().join("events-2026-05-13.jsonl").exists());
    assert!(dir.path().join("events-2026-05-15.jsonl").exists());
    // No force events.
    assert!(rx.try_recv().is_err());
}

#[tokio::test]
async fn hard_ceiling_forces_gc_and_emits_both_events() {
    let dir = tempdir().unwrap();
    write_segment(dir.path(), "events-2026-05-13.jsonl", 600);
    write_segment(dir.path(), "events-2026-05-14.jsonl", 600);
    // No sender-offset.json — agent treats nothing as consumed.

    let cfg = GcConfig {
        soft_floor_bytes: 100,
        soft_floor_age: Duration::from_secs(3600),
        hard_ceiling_bytes: 1000,
        hard_ceiling_age: Duration::from_secs(7200),
    };
    let (ctx, mut rx, above) = build_ctx(dir.path(), "events-2026-05-14.jsonl", cfg);
    tick_for_test(&ctx).await;

    assert!(*above.read());
    assert!(!dir.path().join("events-2026-05-13.jsonl").exists());
    assert!(dir.path().join("events-2026-05-14.jsonl").exists());

    let mut got_force = false;
    let mut got_skipped = false;
    while let Ok(ev) = rx.try_recv() {
        match ev.event.evidence {
            Evidence::AgentJsonlForceGc {
                segments_deleted,
                segments_skipped_past_sender,
                ..
            } => {
                got_force = true;
                assert!(segments_deleted >= 1);
                assert!(segments_skipped_past_sender >= 1);
            }
            Evidence::SenderSkippedSegment {
                count,
                oldest_dropped_filename,
            } => {
                got_skipped = true;
                assert!(count >= 1);
                assert!(oldest_dropped_filename.contains("05-13"));
            }
            other => panic!("unexpected evidence {other:?}"),
        }
    }
    assert!(got_force, "expected AgentJsonlForceGc event");
    assert!(got_skipped, "expected SenderSkippedSegment event");
}
