//! `POST /v1/events` — accept a batch, validate, dedup, persist, ack.
//!
//! Spec §3.8.2 reject reasons: `malformed_payload`, `schema_mismatch`,
//! `host_id_payload_mismatch`. `high_water_event_id` in the response is the
//! last `event_id` in submission order regardless of accept/reject/dup.

use crate::allowlist;
use crate::app::SharedState;
use crate::persist::{append_events, PersistEvent};
use crate::tls_accept::PeerIdentity;
use axum::{extract::State, http::StatusCode, response::IntoResponse, Extension, Json};
use serde_json::{json, Value as JsonValue};
use sigil_core::event::{Event, SCHEMA_VERSION};
use std::sync::Arc;
use time::OffsetDateTime;
use uuid::Uuid;

/// Wire shapes — kept local rather than depending on sigil-sender's `wire`
/// module, so the server doesn't pull the sender's HTTP-client deps.
#[derive(serde::Deserialize)]
pub struct EventsRequest {
    pub envelope: Envelope,
    pub events: Vec<EventEntry>,
}

#[derive(serde::Deserialize)]
pub struct Envelope {
    pub host_id: String,
    #[allow(dead_code)]
    #[serde(default)]
    pub schema_version: u32,
}

#[derive(serde::Deserialize)]
pub struct EventEntry {
    pub event_id: Uuid,
    pub sequence: u64,
    pub payload: JsonValue,
}

#[derive(serde::Serialize)]
struct EventsAccepted {
    accepted: Vec<Uuid>,
    rejected: Vec<EventRejection>,
    high_water_event_id: Uuid,
}

#[derive(serde::Serialize)]
struct EventRejection {
    event_id: Uuid,
    reason: &'static str,
    detail: Option<String>,
}

fn validate(payload: &JsonValue, envelope_host_id: &str) -> Result<(), &'static str> {
    let event: Event = match serde_json::from_value(payload.clone()) {
        Ok(e) => e,
        Err(_) => return Err("malformed_payload"),
    };
    if event.schema_version != SCHEMA_VERSION {
        return Err("schema_mismatch");
    }
    if event.host_id != envelope_host_id {
        return Err("host_id_payload_mismatch");
    }
    Ok(())
}

pub async fn post_events(
    State(state): State<SharedState>,
    // #194 — injected per-connection by `tls_accept::PeerCertAcceptor`.
    // Absent over plain HTTP (dev mode) or if rustls reported no peer cert.
    peer: Option<Extension<Arc<PeerIdentity>>>,
    Json(req): Json<EventsRequest>,
) -> impl IntoResponse {
    // #194.2 — cert↔host_id binding, checked BEFORE the allowlist so a
    // mismatched cert can never even probe allowlist membership. The response
    // is byte-identical to the allowlist rejection (no oracle distinguishing
    // "not allowlisted" from "wrong cert"); the fingerprint is logged for
    // operators. Boot validation guarantees mTLS is on when this flag is set.
    // Matching is ASCII-case-insensitive (codex review): DNS names are
    // case-insensitive and UUID host_ids appear in both hex cases in the wild;
    // hex case carries no identity, so folding removes false rejects without
    // weakening the binding. (Known limit, deliberate: this gate runs after
    // axum's Json extraction, so a malformed body still 400s before the 404 —
    // a parser-level oracle only, not a token/allowlist oracle.)
    if state.events_require_cert_host_match {
        let peer = peer.as_ref().map(|Extension(p)| p);
        let host_id = req.envelope.host_id.as_str();
        let matches = peer.is_some_and(|p| {
            p.cn.as_deref()
                .is_some_and(|cn| cn.eq_ignore_ascii_case(host_id))
                || p.san_dns.iter().any(|d| d.eq_ignore_ascii_case(host_id))
        });
        if !matches {
            tracing::warn!(
                host_id = %req.envelope.host_id,
                peer_fingerprint = peer.map(|p| p.fingerprint.as_str()).unwrap_or(""),
                peer_cn = peer.and_then(|p| p.cn.as_deref()).unwrap_or(""),
                "events: client cert does not match envelope host_id; rejecting"
            );
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "host_unknown", "host_id": req.envelope.host_id})),
            )
                .into_response();
        }
    }

    if !allowlist::permits(&state.allowlist.read(), &req.envelope.host_id) {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "host_unknown", "host_id": req.envelope.host_id})),
        )
            .into_response();
    }

    let high_water_event_id = req
        .events
        .last()
        .map(|e| e.event_id)
        .unwrap_or_else(Uuid::nil);

    let mut accepted = Vec::new();
    let mut rejected = Vec::new();
    let mut to_persist: Vec<PersistEvent<'_>> = Vec::new();
    for entry in &req.events {
        match validate(&entry.payload, &req.envelope.host_id) {
            Ok(()) => {
                accepted.push(entry.event_id);
                to_persist.push(PersistEvent {
                    sequence: entry.sequence,
                    payload: &entry.payload,
                });
            }
            Err(reason) => rejected.push(EventRejection {
                event_id: entry.event_id,
                reason,
                detail: None,
            }),
        }
    }

    {
        let mut hw = match state.high_water.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(), // poisoned: recover, this is a reference server
        };
        if let Err(e) = append_events(
            &state.events_out_dir,
            &req.envelope.host_id,
            &to_persist,
            &mut hw,
            OffsetDateTime::now_utc(),
        ) {
            tracing::error!(error = ?e, host_id = %req.envelope.host_id, "persist failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "persist_failed"})),
            )
                .into_response();
        }
        if let Err(e) = hw.store(&state.high_water_path) {
            tracing::warn!(error = ?e, "high_water store failed (non-fatal)");
        }
    }

    // Phase 3b.4 — update in-memory fleet index for each accepted event.
    // Best-effort: a parse failure here should not roll back the persist,
    // since the JSONL is the source of truth.
    for entry in &req.events {
        // Skip rejected entries by id lookup.
        if !accepted.iter().any(|id| id == &entry.event_id) {
            continue;
        }
        match serde_json::from_value::<sigil_core::event::Event>(entry.payload.clone()) {
            Ok(event) => state.fleet_index.apply_event(&event),
            Err(e) => {
                tracing::warn!(error = ?e, event_id = %entry.event_id, "fleet_index apply skipped")
            }
        }
    }

    let resp = EventsAccepted {
        accepted,
        rejected,
        high_water_event_id,
    };
    (StatusCode::OK, Json(serde_json::to_value(resp).unwrap())).into_response()
}
