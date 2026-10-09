//! GET /v1/meta — server build info + alerts default + fleet size + audit head.
//! Bearer auth.
use crate::app::SharedState;
use axum::{extract::State, response::IntoResponse, Json};
use serde_json::json;
use sigil_core::event::SCHEMA_VERSION;
use time::{Duration, OffsetDateTime};

/// Canonical alert definition surfaced by `GET /v1/meta`. Extracted so the
/// counter side (`fleet_index_update::is_alert_evidence`) can be tested for
/// drift against it — see the sync test (issue #52).
pub(crate) fn alerts_definition_default() -> serde_json::Value {
    json!({
        "evidence_kinds": ["ai_guard_risk_assessed"],
        "ai_guard_buckets": ["high", "critical"],
        "additional_kinds": [
            "ai_guard_toggle_drift",
            "policy_signature_invalid", "tls_failure",
            "host_id_fingerprint_drift", "agent_dying", "sender_lag_critical"
        ]
    })
}

pub async fn get_meta(State(state): State<SharedState>) -> impl IntoResponse {
    let now = OffsetDateTime::now_utc();
    let window = Duration::days(state.active_window_days as i64);
    let active = state.fleet_index.active_host_count(now, window);

    let audit_head = state.audit_head.lock().unwrap().clone();
    let audit_head_json = match &audit_head {
        Some(h) => {
            let mut head = json!({
                "seq": h.seq,
                "hash": h.hash,
                "sig": h.sig,
                "pubkey_id": h.pubkey_id,
            });
            // `pubkey` must be the key that signed the head. The chain is
            // frozen, so it may have been signed by a key other than the one
            // this server holds now (regenerated key, chain moved between
            // installs). Report `pubkey` only when the ids match; otherwise
            // leave it out and let `pubkey_id` name the key to verify with
            // (#237).
            if let Some(k) = state
                .audit_key
                .as_ref()
                .filter(|k| k.pubkey_id == h.pubkey_id)
            {
                head["pubkey"] = json!(format!("ed25519:{}", k.pubkey_b64));
            }
            head
        }
        None => serde_json::Value::Null,
    };

    Json(json!({
        "server_version": env!("CARGO_PKG_VERSION"),
        "schema_version": SCHEMA_VERSION,
        "ts": now
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap(),
        "alerts_definition_default": alerts_definition_default(),
        "fleet": {
            "active_host_count": active,
            "active_window_days": state.active_window_days,
        },
        "audit_head": audit_head_json
    }))
}
