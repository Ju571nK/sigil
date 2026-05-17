//! GET /v1/fleet/hosts — list (paged, filterable, sortable)
//! GET /v1/fleet/hosts/{host_id} — single host detail (full host_meta block)

use crate::app::SharedState;
use crate::fleet_index::HostSummary;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use time::OffsetDateTime;

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    pub cursor: Option<String>,
    pub limit: Option<u32>,
    pub status: Option<String>,
    pub bucket: Option<String>,
    pub sort: Option<String>,
}

fn clamp_limit(req: Option<u32>) -> usize {
    req.unwrap_or(100).clamp(1, 1000) as usize
}

fn classify_status(last_seen: Option<OffsetDateTime>, now: OffsetDateTime) -> &'static str {
    match last_seen {
        None => "disconnected",
        Some(ts) => {
            let age = now - ts;
            if age <= time::Duration::minutes(5) {
                "healthy"
            } else if age <= time::Duration::hours(1) {
                "stale"
            } else {
                "disconnected"
            }
        }
    }
}

fn list_filter_match(
    h: &HostSummary,
    now: OffsetDateTime,
    status_filter: &Option<Vec<String>>,
    bucket_filter: &Option<Vec<String>>,
) -> bool {
    if let Some(ss) = status_filter {
        let s = classify_status(h.last_seen_ts, now);
        if !ss.iter().any(|x| x == s) {
            return false;
        }
    }
    if let Some(bf) = bucket_filter {
        let max = max_bucket_str(h);
        match max {
            Some(b) => {
                if !bf.iter().any(|x| x == b) {
                    return false;
                }
            }
            None => {
                if !bf.iter().any(|x| x == "low") {
                    return false;
                }
            } // no risk ≈ low
        }
    }
    true
}

fn max_bucket_str(h: &HostSummary) -> Option<&'static str> {
    use sigil_core::event::AiGuardBucket::*;
    let mut max: Option<sigil_core::event::AiGuardBucket> = None;
    for entry in h.current_risk.values() {
        let new_rank = bucket_rank(entry.bucket);
        let cur_rank = max.map(bucket_rank).unwrap_or(0);
        if new_rank >= cur_rank {
            max = Some(entry.bucket);
        }
    }
    max.map(|b| match b {
        Low => "low",
        Medium => "medium",
        High => "high",
        Critical => "critical",
    })
}

fn bucket_rank(b: sigil_core::event::AiGuardBucket) -> u8 {
    use sigil_core::event::AiGuardBucket::*;
    match b {
        Low => 1,
        Medium => 2,
        High => 3,
        Critical => 4,
    }
}

fn comma_split(s: &Option<String>) -> Option<Vec<String>> {
    s.as_ref()
        .map(|v| v.split(',').map(|p| p.trim().to_string()).collect())
}

pub async fn get_fleet_hosts(
    State(state): State<SharedState>,
    Query(q): Query<ListQuery>,
) -> impl IntoResponse {
    let now = OffsetDateTime::now_utc();
    let limit = clamp_limit(q.limit);
    let status_filter = comma_split(&q.status);
    let bucket_filter = comma_split(&q.bucket);
    let sort = q.sort.as_deref().unwrap_or("last_seen");

    let mut all: Vec<HostSummary> = state
        .fleet_index
        .snapshot_all()
        .into_iter()
        .filter(|h| list_filter_match(h, now, &status_filter, &bucket_filter))
        .collect();

    match sort {
        "risk" => {
            all.sort_by_key(|h| std::cmp::Reverse(bucket_rank(top_bucket(h))));
        }
        "host_id" => {
            all.sort_by(|a, b| a.host_id.cmp(&b.host_id));
        }
        _ => {
            // last_seen desc
            all.sort_by(|a, b| b.last_seen_ts.cmp(&a.last_seen_ts));
        }
    }

    // Cursor walk: skip everything up to and including the cursor's host_id.
    let start = match &q.cursor {
        None => 0usize,
        Some(c) => all
            .iter()
            .position(|h| &h.host_id == c)
            .map(|i| i + 1)
            .unwrap_or(all.len()),
    };
    let end = (start + limit).min(all.len());
    let page: Vec<Value> = all[start..end]
        .iter()
        .map(|h| render_host_summary_list(h, now))
        .collect();
    let next_cursor = if end < all.len() {
        all.get(end - 1)
            .map(|h| h.host_id.clone())
            .map(Value::String)
            .unwrap_or(Value::Null)
    } else {
        Value::Null
    };
    let total_estimated = all.len();

    Json(json!({
        "hosts": page,
        "next_cursor": next_cursor,
        "total_estimated": total_estimated,
    }))
    .into_response()
}

fn top_bucket(h: &HostSummary) -> sigil_core::event::AiGuardBucket {
    use sigil_core::event::AiGuardBucket::*;
    h.current_risk
        .values()
        .map(|e| e.bucket)
        .max_by_key(|b| bucket_rank(*b))
        .unwrap_or(Low)
}

fn rfc3339(ts: OffsetDateTime) -> String {
    ts.format(&time::format_description::well_known::Rfc3339)
        .unwrap()
}

fn render_risk_block(h: &HostSummary) -> Value {
    if h.current_risk.is_empty() {
        return Value::Null;
    }
    let by_tool: serde_json::Map<String, Value> = h
        .current_risk
        .iter()
        .map(|(tool, entry)| {
            let tool_str = serde_json::to_value(tool).unwrap();
            (
                tool_str.as_str().unwrap().to_string(),
                json!({
                    "score": entry.score,
                    "bucket": entry.bucket,
                    "assessed_ts": rfc3339(entry.assessed_ts),
                }),
            )
        })
        .collect();
    let max = top_bucket(h);
    let max_score = h
        .current_risk
        .values()
        .map(|e| e.score)
        .fold(0f32, f32::max);
    json!({
        "max_score": max_score,
        "max_bucket": max,
        "by_tool": by_tool,
    })
}

fn render_host_summary_list(h: &HostSummary, now: OffsetDateTime) -> Value {
    json!({
        "host_id": h.host_id,
        "hostname": h.hostname(),
        "agent_version": h.agent_version,
        "last_seen_ts": h.last_seen_ts.map(rfc3339),
        "status": classify_status(h.last_seen_ts, now),
        "current_risk": render_risk_block(h),
        "open_event_counts_24h": {
            "warn": h.counts_24h.sum_warn(),
            "info": h.counts_24h.sum_info(),
        }
    })
}

pub async fn get_fleet_host_by_id(
    State(state): State<SharedState>,
    Path(host_id): Path<String>,
) -> impl IntoResponse {
    let now = OffsetDateTime::now_utc();
    let h = match state.fleet_index.get_host(&host_id) {
        Some(h) => h,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({
                    "error": {"code": "not_found", "message": "host_id not in index"}
                })),
            )
                .into_response()
        }
    };

    // Build detail response = list shape + extra blocks
    let mut body = render_host_summary_list(&h, now);
    let body_obj = body.as_object_mut().unwrap();

    body_obj.insert(
        "host_meta".into(),
        h.latest_host_meta
            .as_ref()
            .map(|m| serde_json::to_value(m).unwrap())
            .unwrap_or(Value::Null),
    );

    body_obj.insert(
        "policy_state".into(),
        json!({
            "last_applied_policy_version": h.policy_state.last_applied_policy_version,
            "policy_expired_active": h.policy_state.policy_expired_active,
            "last_policy_reload_ts": h.policy_state.last_policy_reload_ts.map(rfc3339),
        }),
    );

    body_obj.insert(
        "agent_health".into(),
        json!({
            "recent_channel_stalls_24h": h.counts_24h.sum_channel_stalls(),
            "recent_watcher_degraded_24h": h.counts_24h.sum_watcher_degraded(),
            "recent_sender_lag_critical_24h": h.counts_24h.sum_sender_lag_critical(),
            "last_heartbeat_ts": h.agent_health.last_heartbeat_ts.map(rfc3339),
            "hash_p99_ms_latest": h.agent_health.hash_p99_ms_latest,
            "jsonl_above_soft_floor_latest": h.agent_health.jsonl_above_soft_floor_latest,
        }),
    );

    let by_tool: serde_json::Map<String, Value> = h
        .current_risk
        .iter()
        .map(|(tool, entry)| {
            let tool_str = serde_json::to_value(tool).unwrap();
            (
                tool_str.as_str().unwrap().to_string(),
                json!({
                    "score": entry.score,
                    "bucket": entry.bucket,
                    "assessed_ts": rfc3339(entry.assessed_ts),
                    "is_reattestation": entry.is_reattestation,
                    "scope": entry.scope,
                    "reasons": entry.reasons,
                }),
            )
        })
        .collect();
    body_obj.insert("ai_guard".into(), json!({ "by_tool": by_tool }));

    Json(body).into_response()
}
