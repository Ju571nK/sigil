//! GET /v1/fleet/compliance — raw policy compliance signals (no derived score).

use crate::app::SharedState;
use axum::extract::{Query, State};
use axum::response::IntoResponse;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Debug, Deserialize)]
pub struct CompQuery {
    pub cursor: Option<String>,
    pub limit: Option<u32>,
}

fn clamp_limit(req: Option<u32>) -> usize {
    req.unwrap_or(100).clamp(1, 1000) as usize
}

pub async fn get_fleet_compliance(
    State(state): State<SharedState>,
    Query(q): Query<CompQuery>,
) -> impl IntoResponse {
    let limit = clamp_limit(q.limit);

    // server_current_policy_version: peek the policy bundle on disk.
    let server_version: Option<i64> = std::fs::read(&state.policy_bundle_path)
        .ok()
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        .and_then(|v| v.get("policy_version").and_then(|n| n.as_i64()));

    let mut hosts = state.fleet_index.snapshot_all();
    hosts.sort_by(|a, b| a.host_id.cmp(&b.host_id));

    let start = match &q.cursor {
        None => 0,
        Some(c) => hosts
            .iter()
            .position(|h| &h.host_id == c)
            .map(|i| i + 1)
            .unwrap_or(hosts.len()),
    };
    let end = (start + limit).min(hosts.len());

    let rows: Vec<Value> = hosts[start..end]
        .iter()
        .map(|h| {
            let applied = h.policy_state.last_applied_policy_version;
            let drift = server_version.map(|s| (s - applied).max(0)).unwrap_or(0);
            json!({
                "host_id": h.host_id,
                "hostname": h.hostname(),
                "last_applied_policy_version": applied,
                "server_current_policy_version": server_version,
                "version_drift": drift,
                "policy_expired_active": h.policy_state.policy_expired_active,
                "last_policy_reload_ts": h.policy_state.last_policy_reload_ts
                    .map(|t| t.format(&time::format_description::well_known::Rfc3339).unwrap()),
                "signature_failures_24h": h.counts_24h.sum_sig_failures(),
            })
        })
        .collect();

    let next_cursor = if end < hosts.len() {
        hosts
            .get(end - 1)
            .map(|h| Value::String(h.host_id.clone()))
            .unwrap_or(Value::Null)
    } else {
        Value::Null
    };
    Json(json!({ "rows": rows, "next_cursor": next_cursor }))
}
