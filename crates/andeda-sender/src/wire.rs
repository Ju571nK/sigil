//! HTTP wire types for /v1/events and /v1/policy.
//!
//! Spec §3.8.2.

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use time::OffsetDateTime;
use uuid::Uuid;

/// `POST /v1/events` request body.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EventsRequest {
    pub envelope: Envelope,
    pub events: Vec<EventEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Envelope {
    pub schema_version: u32,
    pub batch_id: Uuid,
    pub host_id: String,
    pub agent_version: String,
    pub sender_version: String,
    #[serde(with = "time::serde::rfc3339")]
    pub sent_at: OffsetDateTime,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EventEntry {
    pub event_id: Uuid,
    pub sequence: u64,
    /// Opaque ANDEDA Event payload — see `andeda-core::event::Event`.
    pub payload: JsonValue,
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn events_request_round_trips() {
        let req = EventsRequest {
            envelope: Envelope {
                schema_version: 1,
                batch_id: Uuid::nil(),
                host_id: "h".into(),
                agent_version: "0.2.0".into(),
                sender_version: "0.2.0".into(),
                sent_at: datetime!(2026-05-15 8:30:00 UTC),
            },
            events: vec![EventEntry {
                event_id: Uuid::nil(),
                sequence: 42,
                payload: serde_json::json!({"k":"v"}),
            }],
        };
        let s = serde_json::to_string(&req).unwrap();
        let back: EventsRequest = serde_json::from_str(&s).unwrap();
        assert_eq!(back, req);
    }

    #[test]
    fn envelope_serializes_sent_at_as_rfc3339() {
        let env = Envelope {
            schema_version: 1,
            batch_id: Uuid::nil(),
            host_id: "h".into(),
            agent_version: "0.2.0".into(),
            sender_version: "0.2.0".into(),
            sent_at: datetime!(2026-05-15 8:30:00 UTC),
        };
        let s = serde_json::to_string(&env).unwrap();
        assert!(s.contains("\"sent_at\":\"2026-05-15T08:30:00Z\""));
    }
}
