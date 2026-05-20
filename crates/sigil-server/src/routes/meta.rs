//! GET /v1/meta — server build info + alerts default + license status. Bearer auth.
use crate::app::SharedState;
use axum::{extract::State, response::IntoResponse, Json};
use serde_json::json;
use sigil_core::event::SCHEMA_VERSION;
use sigil_core::license::status::compute_status;
use time::{Duration, OffsetDateTime};

pub async fn get_meta(State(state): State<SharedState>) -> impl IntoResponse {
    let now = OffsetDateTime::now_utc();
    let window = Duration::days(state.active_window_days as i64);
    let active = state.fleet_index.active_host_count(now, window);
    let license = compute_status(&state.license_state, active, state.active_window_days);

    let audit_head = state.audit_head.lock().unwrap().clone();
    let audit_head_json = match (&audit_head, state.audit_key.as_ref()) {
        (Some(h), Some(k)) => json!({
            "seq": h.seq,
            "hash": h.hash,
            "sig": h.sig,
            "pubkey_id": h.pubkey_id,
            "pubkey": format!("ed25519:{}", k.pubkey_b64),
        }),
        _ => serde_json::Value::Null,
    };

    Json(json!({
        "server_version": env!("CARGO_PKG_VERSION"),
        "schema_version": SCHEMA_VERSION,
        "ts": now
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap(),
        "alerts_definition_default": {
            "evidence_kinds": ["ai_guard_risk_assessed"],
            "ai_guard_buckets": ["high", "critical"],
            "additional_kinds": [
                "policy_signature_invalid", "tls_failure",
                "host_id_fingerprint_drift", "agent_dying", "sender_lag_critical"
            ]
        },
        "license": license,
        "audit_head": audit_head_json
    }))
}
