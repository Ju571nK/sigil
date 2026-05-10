//! Data plane: builds batches, POSTs them, advances offset on ack.

use crate::manifest::BatchManifest;
use crate::state::SenderState;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum AckError {
    #[error("server's high_water_event_id {0} not in batch manifest")]
    HighWaterUnknown(Uuid),
    #[error("manifest empty — should not happen for a non-empty batch")]
    EmptyManifest,
}

/// Given the server-provided `high_water_event_id`, compute the
/// `SenderState` that should be persisted after this batch is acked.
/// Spec §3.8.3 — high_water is the last event_id in the batch in
/// submission order, regardless of accept/reject.
pub fn apply_ack(
    manifest: &BatchManifest,
    high_water_event_id: Uuid,
) -> Result<SenderState, AckError> {
    if manifest.is_empty() {
        return Err(AckError::EmptyManifest);
    }
    let entry = manifest
        .lookup(&high_water_event_id)
        .ok_or(AckError::HighWaterUnknown(high_water_event_id))?;
    Ok(SenderState {
        current_file: entry.current_file.clone(),
        byte_offset: entry.byte_range.end,
        last_acked_sequence: entry.provisional_sequence,
    })
}

use std::time::Duration;

/// Exponential backoff for retryable failures.
/// Spec §3.8.2 — ServerBusy (5xx): start 5s, cap 5min.
///                PermanentReject (426): start 5min, cap 1h.
#[derive(Clone, Copy, Debug)]
pub struct BackoffPolicy {
    pub initial: Duration,
    pub cap: Duration,
}

impl BackoffPolicy {
    pub fn server_busy() -> Self {
        BackoffPolicy {
            initial: Duration::from_secs(5),
            cap: Duration::from_secs(300),
        }
    }
    pub fn upgrade_required() -> Self {
        BackoffPolicy {
            initial: Duration::from_secs(300),
            cap: Duration::from_secs(3600),
        }
    }
    /// Returns the next sleep duration given the consecutive-failure count.
    /// `attempts == 0` returns `initial`. Doubles per attempt, clamped to `cap`.
    pub fn next_delay(&self, attempts: u32) -> Duration {
        let base = self.initial.as_secs();
        let cap = self.cap.as_secs();
        let mult = 1u64.checked_shl(attempts).unwrap_or(u64::MAX);
        let secs = base.saturating_mul(mult).min(cap);
        Duration::from_secs(secs)
    }
}

use crate::transport::{classify_send_error, classify_status, SendOutcome};
use crate::wire::{Envelope, EventsAccepted, EventsRequest};
use reqwest::Client;
use std::path::PathBuf;
use time::OffsetDateTime;

/// Inputs for one batch send (no loop).
pub struct BatchSendCtx<'a> {
    pub client: &'a Client,
    pub server_base_url: &'a str,
    pub host_id: &'a str,
    pub agent_version: &'a str,
    pub sender_version: &'a str,
    pub events: Vec<crate::wire::EventEntry>,
}

/// Outcome of `send_one_batch` — caller decides what to do with offset
/// advance and event emission.
#[derive(Debug)]
pub enum BatchOutcome {
    Accepted(EventsAccepted),
    PermanentReject { status: u16, body: String },
    ServerBusy { status: u16, body: String },
    TlsFailure(String),
    Network(String),
    ProtocolViolation(String),
}

pub async fn send_one_batch(ctx: BatchSendCtx<'_>) -> BatchOutcome {
    let req = EventsRequest {
        envelope: Envelope {
            schema_version: 1,
            batch_id: uuid::Uuid::now_v7(),
            host_id: ctx.host_id.to_string(),
            agent_version: ctx.agent_version.to_string(),
            sender_version: ctx.sender_version.to_string(),
            sent_at: OffsetDateTime::now_utc(),
        },
        events: ctx.events,
    };
    let url = format!("{}/v1/events", ctx.server_base_url.trim_end_matches('/'));
    let resp = match ctx.client.post(&url).json(&req).send().await {
        Ok(r) => r,
        Err(e) => match classify_send_error::<EventsAccepted>(e) {
            SendOutcome::TlsFailure(s) => return BatchOutcome::TlsFailure(s),
            SendOutcome::Network(s) => return BatchOutcome::Network(s),
            other => return BatchOutcome::ProtocolViolation(format!("{other:?}")),
        },
    };
    let status = resp.status().as_u16();
    let body_bytes = match resp.bytes().await {
        Ok(b) => b,
        Err(e) => {
            return BatchOutcome::ProtocolViolation(format!("body read: {e}"));
        }
    };
    let body_text = String::from_utf8_lossy(&body_bytes).to_string();
    let parsed: Option<EventsAccepted> = if (200..300).contains(&status) {
        serde_json::from_slice(&body_bytes).ok()
    } else {
        None
    };
    match classify_status(status, body_text.clone(), parsed) {
        SendOutcome::Ok2xx(r) => BatchOutcome::Accepted(r),
        SendOutcome::PermanentReject { status, body } => {
            BatchOutcome::PermanentReject { status, body }
        }
        SendOutcome::ServerBusy { status, body } => BatchOutcome::ServerBusy { status, body },
        SendOutcome::TlsFailure(s) => BatchOutcome::TlsFailure(s),
        SendOutcome::Network(s) => BatchOutcome::Network(s),
        SendOutcome::ProtocolViolation(s) => BatchOutcome::ProtocolViolation(s),
    }
}

// (silence unused-import warning when path types only used in tests)
#[allow(dead_code)]
fn _path_marker(_p: PathBuf) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{ByteRange, ManifestEntry};

    fn entry(id: u128, seq: u64, end: u64) -> ManifestEntry {
        ManifestEntry {
            event_id: Uuid::from_u128(id),
            byte_range: ByteRange {
                start: end - 100,
                end,
            },
            provisional_sequence: seq,
            current_file: "events-1.jsonl".into(),
        }
    }

    #[test]
    fn high_water_at_end_advances_to_last() {
        let mut m = BatchManifest::new();
        m.push(entry(1, 10, 100));
        m.push(entry(2, 11, 200));
        m.push(entry(3, 12, 300));
        let s = apply_ack(&m, Uuid::from_u128(3)).unwrap();
        assert_eq!(s.byte_offset, 300);
        assert_eq!(s.last_acked_sequence, 12);
    }

    #[test]
    fn high_water_in_middle_advances_to_middle() {
        let mut m = BatchManifest::new();
        m.push(entry(1, 10, 100));
        m.push(entry(2, 11, 200));
        m.push(entry(3, 12, 300));
        let s = apply_ack(&m, Uuid::from_u128(2)).unwrap();
        assert_eq!(s.byte_offset, 200);
        assert_eq!(s.last_acked_sequence, 11);
    }

    #[test]
    fn unknown_high_water_is_error() {
        let mut m = BatchManifest::new();
        m.push(entry(1, 10, 100));
        let err = apply_ack(&m, Uuid::from_u128(999)).unwrap_err();
        assert!(matches!(err, AckError::HighWaterUnknown(_)));
    }

    #[test]
    fn empty_manifest_is_error() {
        let m = BatchManifest::new();
        let err = apply_ack(&m, Uuid::from_u128(1)).unwrap_err();
        assert!(matches!(err, AckError::EmptyManifest));
    }

    #[test]
    fn server_busy_starts_at_5s() {
        let b = BackoffPolicy::server_busy();
        assert_eq!(b.next_delay(0).as_secs(), 5);
    }

    #[test]
    fn server_busy_doubles_then_caps_at_5min() {
        let b = BackoffPolicy::server_busy();
        assert_eq!(b.next_delay(1).as_secs(), 10);
        assert_eq!(b.next_delay(2).as_secs(), 20);
        assert_eq!(b.next_delay(20).as_secs(), 300); // capped
    }

    #[test]
    fn upgrade_required_starts_at_5min_caps_at_1h() {
        let b = BackoffPolicy::upgrade_required();
        assert_eq!(b.next_delay(0).as_secs(), 300);
        assert_eq!(b.next_delay(20).as_secs(), 3600);
    }
}
