//! GET /v1/healthz — liveness probe. No auth.
use axum::{response::IntoResponse, Json};
use serde_json::json;
use time::OffsetDateTime;

pub async fn get_healthz() -> impl IntoResponse {
    Json(json!({
        "status": "ok",
        "ts": OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap()
    }))
}
