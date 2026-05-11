//! `GET /v1/policy?host_id=X` — serve the operator-signed policy bundle
//! with ETag-based 304 handling.

use crate::allowlist;
use crate::app::SharedState;
use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde_json::json;

#[derive(serde::Deserialize)]
pub struct PolicyQuery {
    pub host_id: String,
}

pub async fn get_policy(
    State(state): State<SharedState>,
    Query(q): Query<PolicyQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !allowlist::permits(&state.allowlist, &q.host_id) {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "host_unknown", "host_id": q.host_id})),
        )
            .into_response();
    }

    let bytes = match std::fs::read(&state.policy_bundle_path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return (StatusCode::NOT_FOUND, Json(json!({"error": "no_policy"}))).into_response();
        }
        Err(e) => {
            tracing::error!(error = ?e, "read policy bundle failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "bundle_read_failed"})),
            )
                .into_response();
        }
    };

    // The bundle is a `SignedPolicyResponse` JSON whose `etag` field the
    // signer already computed. We trust it as the cache tag (verify_envelope
    // does not depend on etag content).
    let value: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = ?e, "policy bundle is not valid JSON");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "bundle_parse_failed"})),
            )
                .into_response();
        }
    };
    let etag = value
        .get("etag")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();

    if let Some(inm) = headers.get("if-none-match").and_then(|v| v.to_str().ok()) {
        if inm == etag {
            return (StatusCode::NOT_MODIFIED, [("etag", etag)]).into_response();
        }
    }
    (StatusCode::OK, [("etag", etag)], Json(value)).into_response()
}
