//! Per-target token bucket rate limiter.
//!
//! Bucket size: 200 tokens. Refill rate: 100 tokens/sec.
//! Empty bucket → `consume` returns `false` and the caller drops the event.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

pub const BUCKET_CAPACITY: f64 = 200.0;
pub const REFILL_PER_SEC: f64 = 100.0;
pub const REPORT_INTERVAL: Duration = Duration::from_secs(10);

#[derive(Debug, Clone)]
struct Bucket {
    tokens: f64,
    last_refill_ms: u64,
}

impl Bucket {
    fn new(now_ms: u64) -> Self {
        Self {
            tokens: BUCKET_CAPACITY,
            last_refill_ms: now_ms,
        }
    }

    fn refill(&mut self, now_ms: u64) {
        let elapsed_ms = now_ms.saturating_sub(self.last_refill_ms) as f64;
        let new_tokens = (elapsed_ms / 1000.0) * REFILL_PER_SEC;
        self.tokens = (self.tokens + new_tokens).min(BUCKET_CAPACITY);
        self.last_refill_ms = now_ms;
    }

    fn try_consume(&mut self, now_ms: u64) -> bool {
        self.refill(now_ms);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[derive(Debug, Default)]
pub struct DropAccumulator {
    pub count: u64,
    pub first_drop_ms: Option<u64>,
    pub paths_seen: Vec<PathBuf>,
}

impl DropAccumulator {
    pub fn record(&mut self, path: PathBuf, now_ms: u64) {
        self.count += 1;
        if self.first_drop_ms.is_none() {
            self.first_drop_ms = Some(now_ms);
        }
        if self.paths_seen.len() < 64 {
            self.paths_seen.push(path);
        }
    }

    pub fn common_prefix(&self) -> PathBuf {
        if self.paths_seen.is_empty() {
            return PathBuf::new();
        }
        let first = self.paths_seen[0].to_string_lossy().into_owned();
        let mut prefix_len = first.len();
        for other in &self.paths_seen[1..] {
            let s = other.to_string_lossy();
            let common = first
                .bytes()
                .zip(s.bytes())
                .take_while(|(a, b)| a == b)
                .count();
            prefix_len = prefix_len.min(common);
        }
        PathBuf::from(&first[..prefix_len])
    }

    pub fn reset(&mut self) {
        self.count = 0;
        self.first_drop_ms = None;
        self.paths_seen.clear();
    }
}

#[derive(Debug, Default)]
pub struct RateLimiter {
    buckets: HashMap<String, Bucket>,        // keyed by target_id
    drops: HashMap<String, DropAccumulator>, // keyed by target_id
    last_report_ms: u64,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Try to consume a token for `target_id`. Returns `true` if allowed,
    /// `false` if dropped (caller must record the drop).
    pub fn allow(&mut self, target_id: &str, now_ms: u64) -> bool {
        let bucket = self
            .buckets
            .entry(target_id.to_string())
            .or_insert_with(|| Bucket::new(now_ms));
        bucket.try_consume(now_ms)
    }

    /// Caller invokes this when `allow` returned false for an event.
    pub fn record_drop(&mut self, target_id: &str, path: PathBuf, now_ms: u64) {
        self.drops
            .entry(target_id.to_string())
            .or_default()
            .record(path, now_ms);
    }

    /// If `REPORT_INTERVAL` has elapsed since last report, drain drops and return
    /// per-target reports. Resets counters.
    pub fn drain_reports(&mut self, now_ms: u64) -> Vec<DropReport> {
        if now_ms.saturating_sub(self.last_report_ms) < REPORT_INTERVAL.as_millis() as u64 {
            return Vec::new();
        }
        self.last_report_ms = now_ms;
        let mut out = Vec::new();
        for (target_id, acc) in self.drops.iter_mut() {
            if acc.count == 0 {
                continue;
            }
            out.push(DropReport {
                target_id: target_id.clone(),
                count_dropped: acc.count,
                first_drop_ms: acc.first_drop_ms.unwrap_or(now_ms),
                common_prefix: acc.common_prefix(),
            });
            acc.reset();
        }
        out
    }

    pub fn reset_all(&mut self) {
        self.buckets.clear();
        self.drops.clear();
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct DropReport {
    pub target_id: String,
    pub count_dropped: u64,
    pub first_drop_ms: u64,
    pub common_prefix: PathBuf,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_n_events_allowed_up_to_capacity() {
        let mut r = RateLimiter::new();
        for _ in 0..200 {
            assert!(r.allow("t", 0));
        }
        assert!(!r.allow("t", 0));
    }

    #[test]
    fn refills_at_100_per_sec() {
        let mut r = RateLimiter::new();
        for _ in 0..200 {
            r.allow("t", 0);
        }
        assert!(!r.allow("t", 0));
        // 1 second later → 100 tokens added.
        for _ in 0..100 {
            assert!(r.allow("t", 1000));
        }
        assert!(!r.allow("t", 1000));
    }

    #[test]
    fn drops_reset_on_drain() {
        let mut r = RateLimiter::new();
        for _ in 0..201 {
            if !r.allow("t", 0) {
                r.record_drop("t", PathBuf::from("/x"), 0);
            }
        }
        let reports = r.drain_reports(REPORT_INTERVAL.as_millis() as u64);
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].count_dropped, 1);
        let next = r.drain_reports((REPORT_INTERVAL.as_millis() * 2) as u64);
        assert!(next.is_empty());
    }

    #[test]
    fn separate_targets_have_independent_buckets() {
        let mut r = RateLimiter::new();
        for _ in 0..200 {
            r.allow("a", 0);
        }
        assert!(!r.allow("a", 0));
        assert!(r.allow("b", 0));
    }

    #[test]
    fn common_prefix_finds_shared_root() {
        let mut acc = DropAccumulator::default();
        acc.record(PathBuf::from("/tmp/spam/a.json"), 0);
        acc.record(PathBuf::from("/tmp/spam/b.json"), 0);
        acc.record(PathBuf::from("/tmp/spam/c.json"), 0);
        let s = acc.common_prefix().to_string_lossy().to_string();
        assert!(s.starts_with("/tmp/spam"));
    }
}
