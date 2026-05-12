//! Per-path debouncer with kind-specific windows.
//!
//! This module is logical-time only — callers feed it timestamps; it does not
//! interact with any clock. The agent uses `tokio::time::Instant` upstream and
//! converts to a monotonic `u64` ms value here.

use crate::event::{EvidenceQuality, FileChangeKind};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

/// Logical timestamp in milliseconds since some reference epoch (monotonic).
pub type LogicalMs = u64;

/// Per-`FileChangeKind` debounce window in milliseconds (Standard tier).
pub const fn standard_window_ms(kind: FileChangeKind) -> u64 {
    match kind {
        FileChangeKind::Removed => 0,
        FileChangeKind::Created => 50,
        FileChangeKind::Renamed => 50,
        FileChangeKind::Modified => 100,
    }
}

/// Critical-tier window is always zero.
pub const CRITICAL_WINDOW_MS: u64 = 0;

#[derive(Debug, Clone, PartialEq)]
pub struct PendingEvent {
    pub path: PathBuf,
    pub kind: FileChangeKind,
    pub first_seen_ms: LogicalMs,
    pub last_seen_ms: LogicalMs,
    pub coalesced_count: u32,
    pub critical: bool,
    /// For `Renamed` events: the prior path. This module is path/kind only and
    /// always leaves it `None`; the agent's debouncer task pairs it in from the
    /// normalizer's output before handing the event downstream.
    pub rename_from: Option<PathBuf>,
}

impl PendingEvent {
    pub fn evidence_quality(&self) -> EvidenceQuality {
        if self.coalesced_count > 1 {
            EvidenceQuality::BestEffort
        } else {
            EvidenceQuality::Definitive
        }
    }
}

/// State machine: caller pushes raw events with timestamps, then calls `drain_due`
/// passing the current timestamp. Events whose window has elapsed are returned.
#[derive(Default, Debug)]
pub struct Debouncer {
    pending: HashMap<(PathBuf, FileChangeKind), PendingEvent>,
}

impl Debouncer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the events that immediately bypass debounce (window = 0).
    pub fn push(
        &mut self,
        path: PathBuf,
        kind: FileChangeKind,
        critical: bool,
        now_ms: LogicalMs,
    ) -> Option<PendingEvent> {
        let window = if critical {
            CRITICAL_WINDOW_MS
        } else {
            standard_window_ms(kind)
        };
        if window == 0 {
            // Bypass: emit immediately, do not enter pending map.
            return Some(PendingEvent {
                path,
                kind,
                first_seen_ms: now_ms,
                last_seen_ms: now_ms,
                coalesced_count: 1,
                critical,
                rename_from: None,
            });
        }
        let key = (path.clone(), kind);
        match self.pending.get_mut(&key) {
            Some(p) => {
                p.last_seen_ms = now_ms;
                p.coalesced_count += 1;
                None
            }
            None => {
                self.pending.insert(
                    key,
                    PendingEvent {
                        path,
                        kind,
                        first_seen_ms: now_ms,
                        last_seen_ms: now_ms,
                        coalesced_count: 1,
                        critical,
                        rename_from: None,
                    },
                );
                None
            }
        }
    }

    /// Return all pending events whose window has elapsed at `now_ms`.
    pub fn drain_due(&mut self, now_ms: LogicalMs) -> Vec<PendingEvent> {
        let mut out = Vec::new();
        self.pending.retain(|(_, kind), pending| {
            let window = if pending.critical {
                CRITICAL_WINDOW_MS
            } else {
                standard_window_ms(*kind)
            };
            if now_ms.saturating_sub(pending.last_seen_ms) >= window {
                out.push(pending.clone());
                false
            } else {
                true
            }
        });
        out
    }

    /// Drain everything regardless of window — used during shutdown.
    pub fn drain_all(&mut self) -> Vec<PendingEvent> {
        self.pending.drain().map(|(_, v)| v).collect()
    }

    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }
}

/// Convert a milliseconds duration to `Duration` for callers that need it.
pub fn duration_for_kind(kind: FileChangeKind, critical: bool) -> Duration {
    Duration::from_millis(if critical {
        CRITICAL_WINDOW_MS
    } else {
        standard_window_ms(kind)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> PathBuf {
        PathBuf::from(s)
    }

    #[test]
    fn removed_bypasses_immediately() {
        let mut d = Debouncer::new();
        let ev = d.push(p("/x"), FileChangeKind::Removed, false, 0).unwrap();
        assert_eq!(ev.coalesced_count, 1);
        assert_eq!(d.pending_len(), 0);
    }

    #[test]
    fn modified_held_for_100ms() {
        let mut d = Debouncer::new();
        assert!(d
            .push(p("/x"), FileChangeKind::Modified, false, 0)
            .is_none());
        assert!(d.drain_due(50).is_empty());
        let due = d.drain_due(100);
        assert_eq!(due.len(), 1);
    }

    #[test]
    fn modified_burst_coalesces() {
        let mut d = Debouncer::new();
        d.push(p("/x"), FileChangeKind::Modified, false, 0);
        d.push(p("/x"), FileChangeKind::Modified, false, 30);
        d.push(p("/x"), FileChangeKind::Modified, false, 60);
        let due = d.drain_due(60 + 100);
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].coalesced_count, 3);
        assert_eq!(due[0].evidence_quality(), EvidenceQuality::BestEffort);
    }

    #[test]
    fn created_uses_50ms_window() {
        let mut d = Debouncer::new();
        d.push(p("/x"), FileChangeKind::Created, false, 0);
        assert!(d.drain_due(40).is_empty());
        assert_eq!(d.drain_due(50).len(), 1);
    }

    #[test]
    fn critical_tier_bypasses_for_modified() {
        let mut d = Debouncer::new();
        let ev = d.push(p("/x"), FileChangeKind::Modified, true, 0).unwrap();
        assert!(ev.critical);
        assert_eq!(d.pending_len(), 0);
    }

    #[test]
    fn different_paths_are_independent() {
        let mut d = Debouncer::new();
        d.push(p("/a"), FileChangeKind::Modified, false, 0);
        d.push(p("/b"), FileChangeKind::Modified, false, 50);
        let due_at_100 = d.drain_due(100);
        assert_eq!(due_at_100.len(), 1);
        assert_eq!(due_at_100[0].path, p("/a"));
        let due_at_150 = d.drain_due(150);
        assert_eq!(due_at_150.len(), 1);
        assert_eq!(due_at_150[0].path, p("/b"));
    }

    #[test]
    fn drain_all_returns_everything() {
        let mut d = Debouncer::new();
        d.push(p("/a"), FileChangeKind::Modified, false, 0);
        d.push(p("/b"), FileChangeKind::Created, false, 0);
        let all = d.drain_all();
        assert_eq!(all.len(), 2);
    }
}
