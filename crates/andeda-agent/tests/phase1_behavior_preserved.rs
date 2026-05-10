//! Regression test: Plan A's Phase 2 surface is no-op when no sender
//! offset and no apply_policy ever happen.

use andeda_agent::gc_config::GcConfig;
use andeda_agent::jsonl_gc_task::{tick_for_test, GcTaskCtx};
use andeda_agent::policy_expiry_task::{evaluate_for_test, ExpiryTaskCtx};
use andeda_core::state::HashCache;
use parking_lot::RwLock;
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;
use time::OffsetDateTime;
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn empty_environment_emits_no_phase2_events_and_no_above_soft_floor() {
    let dir = tempdir().unwrap();
    let cache = HashCache::open(&dir.path().join("state.db")).unwrap();

    // host_meta starts at version 0, no envelope ever applied.
    assert_eq!(
        cache.host_meta_get().unwrap().last_applied_policy_version,
        0
    );

    // GC tick on an empty events/ dir.
    let (tx, mut rx) = mpsc::channel(8);
    let above = Arc::new(RwLock::new(false));
    let curr = Arc::new(RwLock::new(String::new()));
    let gc_ctx = GcTaskCtx {
        host_id: "test-host".into(),
        events_dir: dir.path().join("events"),
        current_segment_filename: curr,
        above_soft_floor: above.clone(),
        cfg: GcConfig::defaults(),
        event_tx: tx.clone(),
        shutdown: CancellationToken::new(),
        tick: Duration::from_secs(60),
    };
    tick_for_test(&gc_ctx).await;
    assert!(rx.try_recv().is_err(), "no events expected from idle GC");
    assert!(!*above.read());

    // Expiry tick with no envelope ever applied.
    let expired = Arc::new(RwLock::new(false));
    let vu_cell = Arc::new(RwLock::new(None::<OffsetDateTime>));
    let (vtx, vrx) = watch::channel(0);
    let exp_ctx = ExpiryTaskCtx {
        host_id: "test-host".into(),
        policy_expired_active: expired.clone(),
        active_valid_until: vu_cell,
        policy_version_rx: vrx,
        event_tx: tx,
        shutdown: CancellationToken::new(),
        tick: Duration::from_millis(10),
    };
    let mut last = None;
    evaluate_for_test(&exp_ctx, &mut last).await;
    assert!(
        rx.try_recv().is_err(),
        "no events expected from idle expiry"
    );
    assert!(!*expired.read());
    drop(vtx);
}
