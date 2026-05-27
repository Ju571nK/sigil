//! In-memory FleetIndex schemas (Task 3 = types only; Task 5 adds FleetIndex wrapper).

use serde::{Deserialize, Serialize};
use sigil_core::event::{AiGuardBucket, AiGuardReason, AiGuardScope, AiTool, HostMetaSnapshot};
use std::collections::BTreeMap;
use time::OffsetDateTime;

/// One AI Guard risk reading, per tool. Mirrors `AiGuardRiskAssessed` evidence
/// but stored separately so `/v1/fleet/hosts/{host_id}` can return the latest
/// without re-reading JSONL.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct RiskEntry {
    pub score: f32,
    pub bucket: AiGuardBucket,
    #[serde(with = "time::serde::rfc3339")]
    pub assessed_ts: OffsetDateTime,
    pub is_reattestation: bool,
    pub scope: AiGuardScope,
    pub reasons: Vec<AiGuardReason>,
}

/// Per-host policy state. signature_failures_24h is derived from HourlyBuckets
/// at response time, not stored here.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct PolicyState {
    pub last_applied_policy_version: i64,
    pub policy_expired_active: bool,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub last_policy_reload_ts: Option<OffsetDateTime>,
}

/// Per-host agent health snapshot. recent_*_24h derived at response time.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct AgentHealth {
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub last_heartbeat_ts: Option<OffsetDateTime>,
    pub hash_p99_ms_latest: Option<u32>,
    pub jsonl_above_soft_floor_latest: Option<bool>,
}

/// 24 hourly count buckets, circular indexed by `cur_hour % 24`. Sum across
/// all 24 = "events in the last 24h" (approximate, advancing on each ingest).
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct HourlyBuckets {
    /// Current head hour as unix-epoch / 3600. Zero on a fresh struct.
    pub head_hour_unix: i64,
    pub warn: [u32; 24],
    pub info: [u32; 24],
    pub sig_failures: [u32; 24],
    pub channel_stalls: [u32; 24],
    pub watcher_degraded: [u32; 24],
    pub sender_lag_critical: [u32; 24],
    /// Events matching `/v1/meta.alerts_definition_default` (issue #21).
    /// Kept in sync with `fleet_index_update::is_alert_evidence`.
    pub alerts: [u32; 24],
}

impl HourlyBuckets {
    /// Advance head to `cur_hour_unix`, zeroing buckets for skipped hours.
    /// No-op if `cur_hour_unix <= head_hour_unix`.
    pub fn advance_to(&mut self, cur_hour_unix: i64) {
        if self.head_hour_unix == 0 {
            self.head_hour_unix = cur_hour_unix;
            return;
        }
        if cur_hour_unix <= self.head_hour_unix {
            return;
        }
        let skip = (cur_hour_unix - self.head_hour_unix).min(24) as usize;
        for i in 1..=skip {
            let slot = ((self.head_hour_unix + i as i64).rem_euclid(24)) as usize;
            self.warn[slot] = 0;
            self.info[slot] = 0;
            self.sig_failures[slot] = 0;
            self.channel_stalls[slot] = 0;
            self.watcher_degraded[slot] = 0;
            self.sender_lag_critical[slot] = 0;
            self.alerts[slot] = 0;
        }
        self.head_hour_unix = cur_hour_unix;
    }

    /// Slot for an event's hour. Returns `None` if event is > 24h older than head
    /// (caller should skip the bucket increment).
    pub fn slot_for(&self, event_hour_unix: i64) -> Option<usize> {
        if self.head_hour_unix == 0 {
            return None;
        }
        if event_hour_unix > self.head_hour_unix {
            return None; // future event — caller should advance_to first.
        }
        let age = self.head_hour_unix - event_hour_unix;
        if age >= 24 {
            None
        } else {
            Some((event_hour_unix.rem_euclid(24)) as usize)
        }
    }

    pub fn sum_warn(&self) -> u32 {
        self.warn.iter().sum()
    }
    pub fn sum_info(&self) -> u32 {
        self.info.iter().sum()
    }
    pub fn sum_sig_failures(&self) -> u32 {
        self.sig_failures.iter().sum()
    }
    pub fn sum_channel_stalls(&self) -> u32 {
        self.channel_stalls.iter().sum()
    }
    pub fn sum_watcher_degraded(&self) -> u32 {
        self.watcher_degraded.iter().sum()
    }
    pub fn sum_sender_lag_critical(&self) -> u32 {
        self.sender_lag_critical.iter().sum()
    }
    pub fn sum_alerts(&self) -> u32 {
        self.alerts.iter().sum()
    }
}

/// Everything the read API needs to answer fleet questions about one host
/// without going back to JSONL. Updated on every successful ingest.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct HostSummary {
    pub host_id: String,
    pub agent_version: String,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub last_seen_ts: Option<OffsetDateTime>,

    pub latest_host_meta: Option<HostMetaSnapshot>,

    pub current_risk: BTreeMap<AiTool, RiskEntry>,

    pub policy_state: PolicyState,
    pub agent_health: AgentHealth,
    pub counts_24h: HourlyBuckets,
}

impl HostSummary {
    pub fn new(host_id: String) -> Self {
        Self {
            host_id,
            ..Default::default()
        }
    }

    /// Convenience: `.hostname` lifted from `latest_host_meta`. None if no snapshot yet.
    pub fn hostname(&self) -> Option<&str> {
        self.latest_host_meta
            .as_ref()
            .and_then(|m| m.hostname.as_deref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hourly_buckets_first_advance_sets_head_no_zero() {
        let mut b = HourlyBuckets::default();
        b.warn[3] = 99; // leftover from some hypothetical reuse
        b.advance_to(100);
        assert_eq!(b.head_hour_unix, 100);
        assert_eq!(
            b.warn[3], 99,
            "first advance must not zero buckets — head was 0"
        );
    }

    #[test]
    fn hourly_buckets_advance_zeros_skipped_slots() {
        let mut b = HourlyBuckets {
            head_hour_unix: 1000,
            warn: [5; 24],
            ..Default::default()
        };
        // advance one hour
        b.advance_to(1001);
        let zeroed_slot = (1001 % 24) as usize;
        assert_eq!(
            b.warn[zeroed_slot], 0,
            "slot {zeroed_slot} should be zeroed"
        );
        // other slots untouched
        assert_eq!(b.warn[((1000) % 24) as usize], 5);
    }

    #[test]
    fn hourly_buckets_advance_24h_or_more_clears_everything() {
        let mut b = HourlyBuckets {
            head_hour_unix: 1000,
            warn: [7; 24],
            ..Default::default()
        };
        b.advance_to(1024); // 24 hours later → all 24 slots zeroed
        assert_eq!(b.warn, [0; 24]);
        assert_eq!(b.head_hour_unix, 1024);
    }

    #[test]
    fn hourly_buckets_advance_backwards_is_noop() {
        let mut b = HourlyBuckets {
            head_hour_unix: 1000,
            ..Default::default()
        };
        b.warn[(1000 % 24) as usize] = 9;
        b.advance_to(999);
        assert_eq!(b.head_hour_unix, 1000);
        assert_eq!(b.warn[(1000 % 24) as usize], 9);
    }

    #[test]
    fn hourly_buckets_slot_for_within_window() {
        let b = HourlyBuckets {
            head_hour_unix: 1000,
            ..Default::default()
        };
        assert_eq!(b.slot_for(1000), Some((1000 % 24) as usize));
        assert_eq!(b.slot_for(990), Some((990 % 24) as usize)); // 10h old, in window
        assert_eq!(b.slot_for(976), None); // 24h old → just out
        assert_eq!(b.slot_for(1001), None); // future
    }

    #[test]
    fn host_summary_hostname_reflects_meta() {
        let mut h = HostSummary::new("hid".into());
        assert_eq!(h.hostname(), None);
        h.latest_host_meta = Some(HostMetaSnapshot {
            hostname: Some("alice".into()),
            os_name: None,
            os_version: None,
            kernel_version: None,
            architecture: None,
            interfaces: vec![],
            default_gateway_v4: None,
            default_gateway_v6: None,
            dns_servers: vec![],
        });
        assert_eq!(h.hostname(), Some("alice"));
    }
}

use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;

/// Thread-safe wrapper around the per-host summary map.
/// All read endpoints hold a `read()` lock; ingest holds `write()`.
#[derive(Clone, Default)]
pub struct FleetIndex {
    inner: Arc<RwLock<HashMap<String, HostSummary>>>,
}

impl FleetIndex {
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply an event under write lock. Creates the host's HostSummary
    /// on first ingest (key = `event.host_id`).
    pub fn apply_event(&self, event: &sigil_core::event::Event) {
        let mut w = self.inner.write();
        let entry = w
            .entry(event.host_id.clone())
            .or_insert_with(|| HostSummary::new(event.host_id.clone()));
        crate::fleet_index_update::apply_event(entry, event);
    }

    /// Clone of one host's summary, or None.
    pub fn get_host(&self, host_id: &str) -> Option<HostSummary> {
        self.inner.read().get(host_id).cloned()
    }

    /// Snapshot of all hosts. Cloned so callers can release the lock fast.
    pub fn snapshot_all(&self) -> Vec<HostSummary> {
        self.inner.read().values().cloned().collect()
    }

    /// Replace internal map wholesale — used by boot rebuild to swap in the
    /// freshly built index without holding the write lock during the multi-second
    /// JSONL walk.
    pub fn replace(&self, fresh: HashMap<String, HostSummary>) {
        *self.inner.write() = fresh;
    }

    /// Used by /v1/fleet/hosts.total_estimated and by some tests.
    pub fn len(&self) -> usize {
        self.inner.read().len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Count hosts whose `last_seen_ts` is within `window` of `now`.
    /// Hosts with no `last_seen_ts` are excluded.
    pub fn active_host_count(&self, now: time::OffsetDateTime, window: time::Duration) -> u32 {
        self.inner
            .read()
            .values()
            .filter(|h| h.last_seen_ts.is_some_and(|ts| now - ts <= window))
            .count() as u32
    }
}

#[cfg(test)]
mod index_tests {
    use super::*;
    use sigil_core::event::{
        Event, Evidence, HostMetaSnapshot, Severity, SourceKind, Subject, SCHEMA_VERSION,
    };
    use time::macros::datetime;
    use uuid::Uuid;

    fn snap_ev(host_id: &str, hostname: &str) -> Event {
        Event {
            schema_version: SCHEMA_VERSION,
            event_id: Uuid::now_v7(),
            ts: datetime!(2026-05-17 12:00 UTC),
            host_id: host_id.into(),
            agent_version: "0.5.0".into(),
            severity: Severity::Info,
            source: SourceKind::Agent,
            subject: Subject::Self_,
            evidence: Evidence::HostMetaSnapshot {
                snapshot: HostMetaSnapshot {
                    hostname: Some(hostname.into()),
                    os_name: None,
                    os_version: None,
                    kernel_version: None,
                    architecture: None,
                    interfaces: vec![],
                    default_gateway_v4: None,
                    default_gateway_v6: None,
                    dns_servers: vec![],
                },
                is_reattestation: false,
            },
            target_id: None,
        }
    }

    #[test]
    fn apply_event_creates_host_on_first_seen() {
        let idx = FleetIndex::new();
        assert!(idx.is_empty());
        idx.apply_event(&snap_ev("h1", "alice"));
        assert_eq!(idx.len(), 1);
        let h = idx.get_host("h1").unwrap();
        assert_eq!(h.hostname(), Some("alice"));
    }

    #[test]
    fn apply_event_updates_existing_host_in_place() {
        let idx = FleetIndex::new();
        idx.apply_event(&snap_ev("h1", "alice"));
        idx.apply_event(&snap_ev("h1", "alice-renamed"));
        assert_eq!(idx.len(), 1);
        assert_eq!(
            idx.get_host("h1").unwrap().hostname(),
            Some("alice-renamed")
        );
    }

    #[test]
    fn snapshot_all_returns_clones() {
        let idx = FleetIndex::new();
        idx.apply_event(&snap_ev("h1", "alice"));
        idx.apply_event(&snap_ev("h2", "bob"));
        let all = idx.snapshot_all();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn replace_swaps_contents() {
        let idx = FleetIndex::new();
        idx.apply_event(&snap_ev("h1", "alice"));
        let mut fresh = HashMap::new();
        fresh.insert("h2".to_string(), HostSummary::new("h2".into()));
        idx.replace(fresh);
        assert_eq!(idx.len(), 1);
        assert!(idx.get_host("h1").is_none());
        assert!(idx.get_host("h2").is_some());
    }

    #[test]
    fn active_host_count_respects_window() {
        use time::Duration;
        let now = time::macros::datetime!(2026-05-20 12:00 UTC);
        let idx = FleetIndex::default();
        let mut fresh = std::collections::HashMap::new();

        let mut recent = HostSummary::new("recent".into());
        recent.last_seen_ts = Some(now - Duration::days(3));
        let mut stale = HostSummary::new("stale".into());
        stale.last_seen_ts = Some(now - Duration::days(10));
        let mut boundary = HostSummary::new("boundary".into());
        boundary.last_seen_ts = Some(now - Duration::days(7)); // exactly at window
        let never = HostSummary::new("never".into()); // last_seen_ts == None

        for h in [recent, stale, boundary, never] {
            fresh.insert(h.host_id.clone(), h);
        }
        idx.replace(fresh);

        let count = idx.active_host_count(now, Duration::days(7));
        // recent (3d) + boundary (exactly 7d) = 2; stale (10d) and never (None) excluded.
        assert_eq!(count, 2);
    }
}
