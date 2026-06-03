//! Happy-path coverage for the 9 read endpoints.
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use sigil_server::app::{build_router, AppState};
use sigil_server::auth::ReadToken;
use sigil_server::fleet_index::FleetIndex;
use sigil_server::persist::HighWater;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

fn state_with_token(dir: &std::path::Path, token: &str) -> Arc<AppState> {
    Arc::new(AppState {
        events_out_dir: dir.to_path_buf(),
        policy_bundle_path: dir.join("signed-policy.json"),
        high_water_path: dir.join(".high-water.json"),
        allowlist: None::<HashSet<String>>,
        high_water: Mutex::new(HighWater::default()),
        fleet_index: FleetIndex::new(),
        read_token: ReadToken(Some(token.into())),
        license_state: sigil_core::license::status::LicenseState::Free,
        active_window_days: 7,
        audit_key: None,
        rule_packs_bundle_path: None,
        audit_head: Mutex::new(None),
    })
}

async fn get(
    app: &axum::Router,
    path: &str,
    token: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    let mut b = Request::builder().method("GET").uri(path);
    if let Some(t) = token {
        b = b.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    let resp = app
        .clone()
        .oneshot(b.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let v = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, v)
}

#[tokio::test]
async fn healthz_returns_ok_without_auth() {
    let dir = tempfile::tempdir().unwrap();
    let app = build_router(state_with_token(dir.path(), "tok"));
    let (status, body) = get(&app, "/v1/healthz", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ok");
}

#[tokio::test]
async fn meta_returns_alerts_default() {
    let dir = tempfile::tempdir().unwrap();
    let app = build_router(state_with_token(dir.path(), "tok"));
    let (status, body) = get(&app, "/v1/meta", Some("tok")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["alerts_definition_default"]["evidence_kinds"][0],
        "ai_guard_risk_assessed"
    );
}

#[tokio::test]
async fn fleet_hosts_empty_index_returns_empty_list() {
    let dir = tempfile::tempdir().unwrap();
    let app = build_router(state_with_token(dir.path(), "tok"));
    let (status, body) = get(&app, "/v1/fleet/hosts", Some("tok")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["hosts"].as_array().unwrap().is_empty());
    assert_eq!(body["total_estimated"], 0);
}

#[tokio::test]
async fn fleet_risk_empty_returns_empty_rows() {
    let dir = tempfile::tempdir().unwrap();
    let app = build_router(state_with_token(dir.path(), "tok"));
    let (status, body) = get(&app, "/v1/fleet/risk", Some("tok")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["rows"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn fleet_compliance_empty_returns_empty_rows() {
    let dir = tempfile::tempdir().unwrap();
    let app = build_router(state_with_token(dir.path(), "tok"));
    let (status, body) = get(&app, "/v1/fleet/compliance", Some("tok")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["rows"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn events_empty_returns_empty_list() {
    let dir = tempfile::tempdir().unwrap();
    let app = build_router(state_with_token(dir.path(), "tok"));
    let (status, body) = get(&app, "/v1/events", Some("tok")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["events"].as_array().unwrap().is_empty());
    assert!(body["next_cursor"].is_null());
}

#[tokio::test]
async fn events_host_id_filter_does_not_400() {
    // #73: a host_id filter (single or comma-separated) must deserialize and
    // return 200 — the old `Vec<String>` field made serde_urlencoded reject it
    // with "expected a sequence" → HTTP 400, breaking the MCP query_events tool.
    let dir = tempfile::tempdir().unwrap();
    let app = build_router(state_with_token(dir.path(), "tok"));

    let (status, body) = get(
        &app,
        "/v1/events?host_id=4376ef7a-4fac-4644-b4cf-128fc471f783&limit=100",
        Some("tok"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "single host_id must not 400: {body}"
    );
    assert!(body["events"].as_array().unwrap().is_empty());

    let (status, body) = get(&app, "/v1/events?host_id=h1,h2&limit=100", Some("tok")).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "comma-separated host_id must not 400: {body}"
    );
    assert!(body["events"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn fleet_host_by_id_404_when_unknown() {
    let dir = tempfile::tempdir().unwrap();
    let app = build_router(state_with_token(dir.path(), "tok"));
    let (status, body) = get(&app, "/v1/fleet/hosts/no-such", Some("tok")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"]["code"], "not_found");
}

#[tokio::test]
async fn event_by_id_400_for_non_uuid() {
    let dir = tempfile::tempdir().unwrap();
    let app = build_router(state_with_token(dir.path(), "tok"));
    let (status, body) = get(&app, "/v1/events/not-a-uuid", Some("tok")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], "invalid_query");
}

#[tokio::test]
async fn policy_meta_404_when_no_bundle() {
    let dir = tempfile::tempdir().unwrap();
    let app = build_router(state_with_token(dir.path(), "tok"));
    let (status, body) = get(&app, "/v1/policy/meta", Some("tok")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"]["code"], "not_found");
}
