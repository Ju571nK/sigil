//! Background task monitoring the active policy's valid_until.
//!
//! Spec §3.10. Emits `policy_expired_active` exactly once per transition
//! into expired, and resets the transition when a new apply commits.

use crate::state_task::CommittableEvent;
use andeda_core::event::{
    Event, Evidence, Severity, SourceKind, Subject, AGENT_VERSION, SCHEMA_VERSION,
};
use parking_lot::RwLock;
use std::sync::Arc;
use std::time::Duration;
use time::OffsetDateTime;
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// Inputs for the task.
pub struct ExpiryTaskCtx {
    pub host_id: String,
    /// Shared flag the IPC's `PolicyStatus` reads. Updated by this task.
    pub policy_expired_active: Arc<RwLock<bool>>,
    /// Shared cell — set by `apply_policy` on success, read here every tick.
    pub active_valid_until: Arc<RwLock<Option<OffsetDateTime>>>,
    /// Active policy version — emitted in the event.
    pub policy_version_rx: watch::Receiver<i64>,
    pub event_tx: mpsc::Sender<CommittableEvent>,
    pub shutdown: CancellationToken,
    /// Tick interval. Production: 60s; tests pass shorter.
    pub tick: Duration,
}

pub async fn run(ctx: ExpiryTaskCtx) {
    let mut last_emitted_for_version: Option<i64> = None;
    let mut interval = tokio::time::interval(ctx.tick);
    interval.tick().await; // skip the immediate fire
    loop {
        tokio::select! {
            biased;
            _ = ctx.shutdown.cancelled() => break,
            _ = interval.tick() => {
                evaluate(&ctx, &mut last_emitted_for_version).await;
            }
        }
    }
}

async fn evaluate(ctx: &ExpiryTaskCtx, last_emitted_for_version: &mut Option<i64>) {
    let now = OffsetDateTime::now_utc();
    let valid_until = *ctx.active_valid_until.read();
    let current_version = *ctx.policy_version_rx.borrow();
    let is_expired = match valid_until {
        Some(t) => now >= t,
        None => false,
    };
    *ctx.policy_expired_active.write() = is_expired;
    if is_expired && *last_emitted_for_version != Some(current_version) {
        let ev = Event {
            schema_version: SCHEMA_VERSION,
            event_id: Uuid::now_v7(),
            ts: now,
            host_id: ctx.host_id.clone(),
            agent_version: AGENT_VERSION.to_string(),
            severity: Severity::Warn,
            source: SourceKind::Agent,
            subject: Subject::Self_,
            evidence: Evidence::PolicyExpiredActive {
                policy_version: current_version,
                valid_until: valid_until.unwrap_or(now),
            },
            target_id: None,
        };
        let _ = ctx
            .event_tx
            .send(CommittableEvent {
                event: ev,
                new_hash: None,
                path_for_db: std::path::PathBuf::new(),
                target_id: String::new(),
            })
            .await;
        *last_emitted_for_version = Some(current_version);
    }
    if !is_expired {
        // Reset the dedup so re-expiry fires again.
        *last_emitted_for_version = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(
        valid_until: Option<OffsetDateTime>,
        version: i64,
    ) -> (ExpiryTaskCtx, mpsc::Receiver<CommittableEvent>, Arc<RwLock<bool>>, Arc<RwLock<Option<OffsetDateTime>>>, watch::Sender<i64>) {
        let expired = Arc::new(RwLock::new(false));
        let vu_cell = Arc::new(RwLock::new(valid_until));
        let (tx, rx) = mpsc::channel(8);
        let (vtx, vrx) = watch::channel(version);
        let ctx = ExpiryTaskCtx {
            host_id: "h".into(),
            policy_expired_active: expired.clone(),
            active_valid_until: vu_cell.clone(),
            policy_version_rx: vrx,
            event_tx: tx,
            shutdown: CancellationToken::new(),
            tick: Duration::from_millis(10),
        };
        (ctx, rx, expired, vu_cell, vtx)
    }

    #[tokio::test]
    async fn expired_envelope_emits_event_exactly_once_per_version() {
        let now = OffsetDateTime::now_utc();
        let past = now - time::Duration::seconds(5);
        let (ctx, mut rx, expired_flag, _, _) = fixture(Some(past), 7);

        // Two evaluations — should emit only once.
        let mut last = None;
        evaluate(&ctx, &mut last).await;
        evaluate(&ctx, &mut last).await;

        let ev = rx.recv().await.unwrap();
        assert!(matches!(
            ev.event.evidence,
            Evidence::PolicyExpiredActive { policy_version: 7, .. }
        ));
        // No second event in the channel.
        assert!(rx.try_recv().is_err());
        assert!(*expired_flag.read());
    }

    #[tokio::test]
    async fn fresh_apply_resets_dedup_so_next_expiry_fires_again() {
        let now = OffsetDateTime::now_utc();
        let past = now - time::Duration::seconds(5);
        let (ctx, mut rx, _, vu_cell, vtx) = fixture(Some(past), 7);

        let mut last = None;
        evaluate(&ctx, &mut last).await;
        let _ = rx.recv().await.unwrap();

        // Simulate a fresh apply: new valid_until in the future, version bumps.
        *vu_cell.write() = Some(now + time::Duration::hours(1));
        vtx.send(8).unwrap();
        evaluate(&ctx, &mut last).await;
        assert!(rx.try_recv().is_err()); // not expired yet → no event

        // Now the new envelope expires too.
        *vu_cell.write() = Some(now - time::Duration::seconds(1));
        evaluate(&ctx, &mut last).await;
        let ev = rx.recv().await.unwrap();
        assert!(matches!(
            ev.event.evidence,
            Evidence::PolicyExpiredActive { policy_version: 8, .. }
        ));
    }

    #[tokio::test]
    async fn no_envelope_yet_means_no_event_no_flag() {
        let (ctx, mut rx, expired_flag, _, _) = fixture(None, 0);
        let mut last = None;
        evaluate(&ctx, &mut last).await;
        assert!(rx.try_recv().is_err());
        assert!(!*expired_flag.read());
    }
}
