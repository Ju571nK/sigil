//! GET /v1/events — list (paged JSONL scan)
//! GET /v1/events/{event_id} — single event lookup via UUIDv7 timestamp

use crate::app::SharedState;
use crate::jsonl_scan::{find_by_id, scan, ScanFilters};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct EventsQuery {
    pub cursor: Option<String>,
    pub limit: Option<u32>,
    #[serde(default)]
    pub host_id: Vec<String>,
    pub since: Option<String>,
    pub until: Option<String>,
    pub evidence_kind: Option<String>,
    pub severity: Option<String>,
    pub source: Option<String>,
    pub min_ai_guard_bucket: Option<String>,
}

fn parse_rfc3339(s: &str) -> Option<time::OffsetDateTime> {
    time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).ok()
}

fn comma_split(s: &Option<String>) -> Option<Vec<String>> {
    s.as_ref()
        .map(|v| v.split(',').map(|p| p.trim().to_string()).collect())
}

pub async fn get_events(
    State(state): State<SharedState>,
    Query(q): Query<EventsQuery>,
) -> impl IntoResponse {
    let cursor = match q.cursor.as_deref() {
        None => None,
        Some(c) => match Uuid::parse_str(c) {
            Ok(u) => Some(u),
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": {"code": "invalid_query", "message": "cursor must be a UUID"}
                    })),
                )
                    .into_response()
            }
        },
    };
    let since = match q.since.as_deref().map(parse_rfc3339) {
        Some(None) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": {"code": "invalid_query", "message": "since must be RFC 3339"}
                })),
            )
                .into_response()
        }
        x => x.flatten(),
    };
    let until = match q.until.as_deref().map(parse_rfc3339) {
        Some(None) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": {"code": "invalid_query", "message": "until must be RFC 3339"}
                })),
            )
                .into_response()
        }
        x => x.flatten(),
    };
    let limit = q.limit.unwrap_or(100).clamp(1, 1000) as usize;

    let filters = ScanFilters {
        cursor,
        host_ids: if q.host_id.is_empty() {
            None
        } else {
            Some(q.host_id.clone())
        },
        since,
        until,
        evidence_kinds: comma_split(&q.evidence_kind),
        severity: comma_split(&q.severity),
        source: comma_split(&q.source),
        min_ai_guard_bucket: q.min_ai_guard_bucket.clone(),
        limit,
    };
    let r = match scan(&state.events_out_dir, &filters) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = ?e, "scan failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": {"code": "internal", "message": "scan failed"}
                })),
            )
                .into_response();
        }
    };
    Json(json!({
        "events": r.events,
        "next_cursor": r.next_cursor.map(|u| u.to_string()).map(Value::String).unwrap_or(Value::Null),
    }))
    .into_response()
}

pub async fn get_event_by_id(
    State(state): State<SharedState>,
    Path(event_id): Path<String>,
) -> impl IntoResponse {
    let uid = match Uuid::parse_str(&event_id) {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": {"code": "invalid_query", "message": "event_id must be a UUID"}
                })),
            )
                .into_response()
        }
    };
    match find_by_id(&state.events_out_dir, uid) {
        Ok(Some(v)) => Json(v).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({
                "error": {"code": "not_found", "message": "event_id not found"}
            })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = ?e, "find_by_id failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": {"code": "internal", "message": "lookup failed"}
                })),
            )
                .into_response()
        }
    }
}
