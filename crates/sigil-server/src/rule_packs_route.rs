//! `GET /v1/rule-packs?host_id=X` — serve the signed pack-set bundle with
//! ETag-based 304. Mirrors policy_route; 404 when no bundle is configured.
use crate::{allowlist, app::SharedState};
use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde_json::json;

#[derive(serde::Deserialize)]
pub struct RulePacksQuery {
    pub host_id: String,
}

pub async fn get_rule_packs(
    State(state): State<SharedState>,
    Query(q): Query<RulePacksQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !allowlist::permits(&state.allowlist, &q.host_id) {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "host_unknown", "host_id": q.host_id})),
        )
            .into_response();
    }
    let Some(path) = state.rule_packs_bundle_path.as_ref() else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "rule_packs_not_configured"})),
        )
            .into_response();
    };
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "no_rule_packs"})),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!(error = ?e, "read rule-packs bundle failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "bundle_read_failed"})),
            )
                .into_response();
        }
    };
    let value: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = ?e, "rule-packs bundle is not valid JSON");
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
