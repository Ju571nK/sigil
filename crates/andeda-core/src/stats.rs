//! Cross-task statistics with atomic counters and a 5-minute sliding hash latency histogram.

use hdrhistogram::Histogram;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

#[derive(Debug, Default)]
struct CounterMap {
    by_kind: parking_lot::Mutex<BTreeMap<String, u64>>,
}

#[derive(Debug)]
pub struct Stats {
    pub events_emitted_total: AtomicU64,
    pub channel_stall_events_total: AtomicU64,
    counters: CounterMap,
    hash_hist: Mutex<Histogram<u64>>,
}

impl Default for Stats {
    fn default() -> Self {
        Self {
            events_emitted_total: AtomicU64::new(0),
            channel_stall_events_total: AtomicU64::new(0),
            counters: CounterMap::default(),
            // Range 1us to 60s, 3 sig digits.
            hash_hist: Mutex::new(Histogram::<u64>::new_with_bounds(1, 60_000_000, 3).unwrap()),
        }
    }
}

impl Stats {
    pub fn shared() -> Arc<Stats> {
        Arc::new(Self::default())
    }

    pub fn record_emit(&self, kind: &str) {
        self.events_emitted_total.fetch_add(1, Ordering::Relaxed);
        let mut map = self.counters.by_kind.lock();
        *map.entry(kind.to_string()).or_default() += 1;
    }

    pub fn record_channel_stall(&self) {
        self.channel_stall_events_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_hash_us(&self, micros: u64) {
        let _ = self.hash_hist.lock().record(micros);
    }

    /// Snapshot for a Heartbeat payload.
    pub fn snapshot(&self) -> StatsSnapshot {
        let map = self.counters.by_kind.lock().clone();
        let h = self.hash_hist.lock();
        StatsSnapshot {
            events_emitted_total: self.events_emitted_total.load(Ordering::Relaxed),
            channel_stall_events_total: self
                .channel_stall_events_total
                .load(Ordering::Relaxed),
            events_by_kind: map,
            hash_p50_ms: (h.value_at_quantile(0.5) / 1_000) as u32,
            hash_p99_ms: (h.value_at_quantile(0.99) / 1_000) as u32,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct StatsSnapshot {
    pub events_emitted_total: u64,
    pub channel_stall_events_total: u64,
    pub events_by_kind: BTreeMap<String, u64>,
    pub hash_p50_ms: u32,
    pub hash_p99_ms: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_emit_increments_total_and_kind() {
        let s = Stats::default();
        s.record_emit("file_change");
        s.record_emit("file_change");
        s.record_emit("heartbeat");
        let snap = s.snapshot();
        assert_eq!(snap.events_emitted_total, 3);
        assert_eq!(snap.events_by_kind["file_change"], 2);
        assert_eq!(snap.events_by_kind["heartbeat"], 1);
    }

    #[test]
    fn percentiles_reflect_recorded_samples() {
        let s = Stats::default();
        for v in 0..1000u64 {
            s.record_hash_us(v * 1_000); // 0..1000ms
        }
        let snap = s.snapshot();
        assert!(snap.hash_p50_ms >= 490 && snap.hash_p50_ms <= 510);
        assert!(snap.hash_p99_ms >= 980 && snap.hash_p99_ms <= 1000);
    }

    #[test]
    fn channel_stall_counter_advances() {
        let s = Stats::default();
        s.record_channel_stall();
        s.record_channel_stall();
        let snap = s.snapshot();
        assert_eq!(snap.channel_stall_events_total, 2);
    }
}
