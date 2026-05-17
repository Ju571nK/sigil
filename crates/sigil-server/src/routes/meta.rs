//! GET /v1/meta — server build info + alerts default. Bearer auth.
use axum::{response::IntoResponse, Json};
use serde_json::json;
use sigil_core::event::SCHEMA_VERSION;
use time::OffsetDateTime;

pub async fn get_meta() -> impl IntoResponse {
    Json(json!({
        "server_version": env!("CARGO_PKG_VERSION"),
        "schema_version": SCHEMA_VERSION,
        "ts": OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap(),
        "alerts_definition_default": {
            "evidence_kinds": ["ai_guard_risk_assessed"],
            "ai_guard_buckets": ["high", "critical"],
            "additional_kinds": [
                "policy_signature_invalid", "tls_failure",
                "host_id_fingerprint_drift", "agent_dying", "sender_lag_critical"
            ]
        }
    }))
}
