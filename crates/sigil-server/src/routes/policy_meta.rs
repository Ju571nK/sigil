//! GET /v1/policy/meta — lightweight policy metadata (no full envelope).
//! Reads policy_bundle_path and extracts version + signing fields without
//! re-validating the signature. Auth: bearer.
use crate::app::SharedState;
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde_json::json;

pub async fn get_policy_meta(State(state): State<SharedState>) -> impl IntoResponse {
    let bytes = match std::fs::read(&state.policy_bundle_path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({
                    "error": {"code": "not_found", "message": "no policy bundle on disk"}
                })),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!(error = ?e, "read policy bundle failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": {"code": "internal", "message": "bundle read failed"}
                })),
            )
                .into_response();
        }
    };
    let v: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": {"code": "internal", "message": "bundle parse failed"}
                })),
            )
                .into_response();
        }
    };
    Json(json!({
        "policy_version": v.get("policy_version").cloned().unwrap_or(json!(null)),
        "signing_pubkey_id": v.get("signing_pubkey_id").cloned().unwrap_or(json!(null)),
        "signed_at": v.get("signed_at").cloned().unwrap_or(json!(null)),
        "valid_until": v.get("valid_until").cloned().unwrap_or(json!(null)),
    }))
    .into_response()
}
