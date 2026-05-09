//! Posture event types.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;
use time::OffsetDateTime;
use uuid::Uuid;

/// Coarse severity. Phase 1 emits only `Info` and `Warn`.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Warn,
}

/// Origin of an event.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SourceKind {
    FileSystem,
    Agent,
}

/// Technical identifier of the observed thing.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Subject {
    Path { value: PathBuf },
    #[serde(rename = "self")]
    Self_,
}

/// A filesystem change kind.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum FileChangeKind {
    Created,
    Modified,
    Removed,
    Renamed,
}

/// Quality marker on a `FileChange` event.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceQuality {
    /// Single event, clean debounce window.
    Definitive,
    /// Multiple events coalesced inside the debounce window.
    BestEffort,
    /// Event spent > 1 s in any queue before reaching the sink.
    Delayed,
    /// Observation could not be fully captured (e.g., file removed before hash).
    Incomplete,
}

/// Why the agent is shutting down abnormally.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AgentDyingReason {
    Panic,
    UnrecoverableSinkError,
    Signal,
}

/// The observation payload of an event.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Evidence {
    FileChange {
        change_kind: FileChangeKind,
        before_hash: Option<String>,
        after_hash: Option<String>,
        recheck_hash: Option<String>,
        rename_from: Option<PathBuf>,
        size_after: Option<u64>,
        evidence_quality: EvidenceQuality,
    },
    Heartbeat {
        uptime_s: u64,
        is_final: bool,
        channel_stall_events_total: u64,
        events_emitted_total: u64,
        events_by_kind: BTreeMap<String, u64>,
        hash_p50_ms: u32,
        hash_p99_ms: u32,
        watcher_backend: String,
        state_db_size_bytes: u64,
        #[serde(with = "time::serde::rfc3339::option")]
        last_log_rotation_ts: Option<OffsetDateTime>,
    },
    PermissionMissing {
        resource: String,
        platform_hint: String,
    },
    ChannelStall {
        channel: String,
        blocked_seconds_in_window: f32,
        block_events_in_window: u64,
        #[serde(with = "time::serde::rfc3339")]
        first_block_ts: OffsetDateTime,
    },
    WatcherDegraded {
        from: String,
        to: String,
        reason: String,
    },
    AgentDying {
        reason: AgentDyingReason,
        detail: String,
        task: Option<String>,
    },
    RateLimitExceeded {
        target_id: String,
        count_dropped_in_window: u64,
        common_path_prefix: PathBuf,
    },
}

/// Schema version. Bumps follow the policy in spec section 3.3.
pub const SCHEMA_VERSION: u32 = 1;

/// `env!("CARGO_PKG_VERSION")` of the agent crate at build time.
pub const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// A single posture event.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Event {
    pub schema_version: u32,
    pub event_id: Uuid,
    #[serde(with = "time::serde::rfc3339")]
    pub ts: OffsetDateTime,
    pub host_id: String,
    pub agent_version: &'static str,
    pub severity: Severity,
    pub source: SourceKind,
    pub subject: Subject,
    pub evidence: Evidence,
    pub target_id: Option<String>,
}

impl Event {
    /// Convenience builder used in tests and by callers that have all fields ready.
    pub fn new_file_change(
        ts: OffsetDateTime,
        host_id: impl Into<String>,
        path: PathBuf,
        evidence: Evidence,
        target_id: Option<String>,
    ) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            event_id: Uuid::now_v7(),
            ts,
            host_id: host_id.into(),
            agent_version: AGENT_VERSION,
            severity: Severity::Warn,
            source: SourceKind::FileSystem,
            subject: Subject::Path { value: path },
            evidence,
            target_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use time::macros::datetime;

    #[test]
    fn severity_round_trips_as_lower_snake() {
        let s = Severity::Warn;
        let j = serde_json::to_string(&s).unwrap();
        assert_eq!(j, r#""warn""#);
        let back: Severity = serde_json::from_str(&j).unwrap();
        assert_eq!(back, Severity::Warn);
    }

    #[test]
    fn source_kind_round_trips_with_kind_tag() {
        let s = SourceKind::FileSystem;
        let j = serde_json::to_string(&s).unwrap();
        assert_eq!(j, r#"{"kind":"file_system"}"#);
    }

    #[test]
    fn subject_path_round_trips() {
        let s = Subject::Path { value: PathBuf::from("/tmp/x.json") };
        let j = serde_json::to_string(&s).unwrap();
        assert_eq!(j, r#"{"kind":"path","value":"/tmp/x.json"}"#);
        let back: Subject = serde_json::from_str(&j).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn subject_self_serializes_with_self_tag() {
        let s = Subject::Self_;
        let j = serde_json::to_string(&s).unwrap();
        assert_eq!(j, r#"{"kind":"self"}"#);
    }

    #[test]
    fn file_change_kind_serializes_snake() {
        assert_eq!(
            serde_json::to_string(&FileChangeKind::Renamed).unwrap(),
            r#""renamed""#
        );
    }

    #[test]
    fn evidence_quality_has_four_variants() {
        for q in [
            EvidenceQuality::Definitive,
            EvidenceQuality::BestEffort,
            EvidenceQuality::Delayed,
            EvidenceQuality::Incomplete,
        ] {
            let j = serde_json::to_string(&q).unwrap();
            let back: EvidenceQuality = serde_json::from_str(&j).unwrap();
            assert_eq!(back, q);
        }
    }

    #[test]
    fn agent_dying_reason_round_trips() {
        let r = AgentDyingReason::Panic;
        let j = serde_json::to_string(&r).unwrap();
        assert_eq!(j, r#""panic""#);
    }

    #[test]
    fn file_change_round_trips() {
        let ev = Evidence::FileChange {
            change_kind: FileChangeKind::Modified,
            before_hash: Some("aa".into()),
            after_hash: Some("bb".into()),
            recheck_hash: None,
            rename_from: None,
            size_after: Some(42),
            evidence_quality: EvidenceQuality::Definitive,
        };
        let j = serde_json::to_string(&ev).unwrap();
        let back: Evidence = serde_json::from_str(&j).unwrap();
        assert_eq!(back, ev);
    }

    #[test]
    fn heartbeat_serializes_with_kind_tag() {
        let ev = Evidence::Heartbeat {
            uptime_s: 60,
            is_final: false,
            channel_stall_events_total: 0,
            events_emitted_total: 5,
            events_by_kind: BTreeMap::new(),
            hash_p50_ms: 1,
            hash_p99_ms: 4,
            watcher_backend: "fsevents".into(),
            state_db_size_bytes: 0,
            last_log_rotation_ts: None,
        };
        let j = serde_json::to_string(&ev).unwrap();
        assert!(j.starts_with(r#"{"kind":"heartbeat""#));
    }

    #[test]
    fn rate_limit_exceeded_round_trips() {
        let ev = Evidence::RateLimitExceeded {
            target_id: "t1".into(),
            count_dropped_in_window: 17,
            common_path_prefix: PathBuf::from("/tmp/spam"),
        };
        let j = serde_json::to_string(&ev).unwrap();
        let back: Evidence = serde_json::from_str(&j).unwrap();
        assert_eq!(back, ev);
    }

    #[test]
    fn channel_stall_uses_rfc3339_timestamp() {
        let ev = Evidence::ChannelStall {
            channel: "norm_to_hasher".into(),
            blocked_seconds_in_window: 5.5,
            block_events_in_window: 3,
            first_block_ts: datetime!(2026-05-08 14:23:45 UTC),
        };
        let j = serde_json::to_string(&ev).unwrap();
        assert!(j.contains("2026-05-08T14:23:45Z"));
    }

    #[test]
    fn snapshot_file_change_event_jsonl() {
        let ev = Event {
            schema_version: SCHEMA_VERSION,
            event_id: Uuid::parse_str("01910f5a-1234-7890-abcd-ef0123456789").unwrap(),
            ts: datetime!(2026-05-08 14:23:45.123 UTC),
            host_id: "5A7C3E91-FIXED-FOR-SNAPSHOT".into(),
            agent_version: AGENT_VERSION,
            severity: Severity::Warn,
            source: SourceKind::FileSystem,
            subject: Subject::Path { value: PathBuf::from("/Users/alice/.claude.json") },
            evidence: Evidence::FileChange {
                change_kind: FileChangeKind::Modified,
                before_hash: Some("a1b2c3".into()),
                after_hash: Some("d4e5f6".into()),
                recheck_hash: Some("d4e5f6".into()),
                rename_from: None,
                size_after: Some(1843),
                evidence_quality: EvidenceQuality::Definitive,
            },
            target_id: Some("claude-desktop-config-macos".into()),
        };
        let line = serde_json::to_string(&ev).unwrap();
        insta::assert_snapshot!(line);
    }
}
