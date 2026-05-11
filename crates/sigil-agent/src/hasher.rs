//! Hasher pool task. Performs blake3 hashing on `spawn_blocking` workers.

use crate::normalizer::NormalizedEvent;
use sigil_core::debounce::PendingEvent;
use sigil_core::event::{EvidenceQuality, FileChangeKind};
use sigil_core::hashing::{hash_path, HashOutcome};
use sigil_core::stats::Stats;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

#[derive(Debug, Clone)]
pub struct HashedEvent {
    pub norm: NormalizedEvent,
    pub after_hash: Option<String>,
    pub size_after: Option<u64>,
    pub recheck_hash: Option<String>,
    pub quality: EvidenceQuality,
    pub debounced_from: Option<PendingEvent>, // present when sourced via debouncer
}

pub async fn run(
    mut rx: mpsc::Receiver<PendingEvent>,
    tx: mpsc::Sender<HashedEvent>,
    target_lookup: Arc<dyn TargetLookup + Send + Sync>,
    stats: Arc<Stats>,
) {
    while let Some(pending) = rx.recv().await {
        let path = pending.path.clone();
        let started = Instant::now();
        let outcome = tokio::task::spawn_blocking(move || hash_path(&path)).await;
        let elapsed_us = started.elapsed().as_micros() as u64;
        stats.record_hash_us(elapsed_us);

        let norm = match target_lookup.find_for_path(&pending.path, pending.kind) {
            Some(n) => n,
            None => continue,
        };

        let (after_hash, size_after, mut quality) = match outcome {
            Ok(Ok(HashOutcome::Hashed { hex, size })) => {
                (Some(hex), Some(size), pending.evidence_quality())
            }
            Ok(Ok(HashOutcome::TooLarge { size })) => {
                (None, Some(size), EvidenceQuality::Incomplete)
            }
            Ok(Ok(HashOutcome::NotFound)) => (None, None, EvidenceQuality::Incomplete),
            _ => (None, None, EvidenceQuality::Incomplete),
        };

        if started.elapsed() > Duration::from_millis(1000) && quality == EvidenceQuality::Definitive
        {
            quality = EvidenceQuality::Delayed;
        }

        let recheck_hash = if pending.critical && pending.kind != FileChangeKind::Removed {
            // Schedule a 100ms recheck inline.
            tokio::time::sleep(Duration::from_millis(100)).await;
            let p = pending.path.clone();
            match tokio::task::spawn_blocking(move || hash_path(&p)).await {
                Ok(Ok(HashOutcome::Hashed { hex, .. })) => Some(hex),
                _ => None,
            }
        } else {
            None
        };

        let _ = tx
            .send(HashedEvent {
                norm,
                after_hash,
                size_after,
                recheck_hash,
                quality,
                debounced_from: Some(pending),
            })
            .await;
    }
}

/// Bridge that lets the hasher recover the canonical NormalizedEvent for a path.
/// In practice, the debouncer state map carries this; for the wiring task we
/// provide a trait that returns the matched target.
pub trait TargetLookup {
    fn find_for_path(
        &self,
        path: &std::path::Path,
        kind: FileChangeKind,
    ) -> Option<NormalizedEvent>;
}
