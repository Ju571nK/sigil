//! Sink task. Owns the `JsonlSink`; calls `commit_baseline` after each write.

use crate::state_task::{commit_baseline, CommittableEvent};
use andeda_core::sink::jsonl::JsonlSink;
use andeda_core::sink::EventSink;
use andeda_core::state::HashCache;
use andeda_core::stats::Stats;
use parking_lot::Mutex;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

pub async fn run(
    mut sink: JsonlSink,
    mut rx: mpsc::Receiver<CommittableEvent>,
    cache: Arc<Mutex<HashCache>>,
    stats: Arc<Stats>,
) {
    let mut fsync_tick = tokio::time::interval(Duration::from_secs(1));
    fsync_tick.tick().await;
    loop {
        tokio::select! {
            biased;
            maybe = rx.recv() => {
                let Some(committable) = maybe else { break; };
                if let Err(e) = sink.write(&committable.event) {
                    tracing::error!(error = ?e, "sink write failed");
                    continue;
                }
                stats.record_emit(evidence_kind_str(&committable.event.evidence));
                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0);
                commit_baseline(&cache, &committable, now_ms);
            }
            _ = fsync_tick.tick() => {
                let _ = sink.flush_durable();
            }
        }
    }
    let _ = sink.shutdown();
}

fn evidence_kind_str(e: &andeda_core::event::Evidence) -> &'static str {
    use andeda_core::event::Evidence::*;
    match e {
        FileChange { .. } => "file_change",
        Heartbeat { .. } => "heartbeat",
        PermissionMissing { .. } => "permission_missing",
        ChannelStall { .. } => "channel_stall",
        WatcherDegraded { .. } => "watcher_degraded",
        AgentDying { .. } => "agent_dying",
        RateLimitExceeded { .. } => "rate_limit_exceeded",
        HostIdFingerprintDrift { .. } => "host_id_fingerprint_drift",
        PolicySignatureInvalid { .. } => "policy_signature_invalid",
        PolicyReloaded { .. } => "policy_reloaded",
        PolicyExpiredActive { .. } => "policy_expired_active",
        AgentJsonlForceGc { .. } => "agent_jsonl_force_gc",
        SenderSkippedSegment { .. } => "sender_skipped_segment",
    }
}
