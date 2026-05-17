//! Bearer auth boundary tests.
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use sigil_server::app::{build_router, AppState};
use sigil_server::auth::ReadToken;
use sigil_server::fleet_index::FleetIndex;
use sigil_server::persist::HighWater;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

fn state(dir: &std::path::Path, token: ReadToken) -> Arc<AppState> {
    Arc::new(AppState {
        events_out_dir: dir.to_path_buf(),
        policy_bundle_path: dir.join("p.json"),
        high_water_path: dir.join(".hw.json"),
        allowlist: None::<HashSet<String>>,
        high_water: Mutex::new(HighWater::default()),
        fleet_index: FleetIndex::new(),
        read_token: token,
    })
}

async fn get_status(app: &axum::Router, path: &str, bearer: Option<&str>) -> StatusCode {
    let mut b = Request::builder().method("GET").uri(path);
    if let Some(t) = bearer {
        b = b.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    app.clone().oneshot(b.body(Body::empty()).unwrap()).await.unwrap().status()
}

#[tokio::test]
async fn token_unset_makes_read_endpoints_404() {
    let dir = tempfile::tempdir().unwrap();
    let app = build_router(state(dir.path(), ReadToken(None)));
    assert_eq!(get_status(&app, "/v1/meta", None).await, StatusCode::NOT_FOUND);
    assert_eq!(get_status(&app, "/v1/fleet/hosts", Some("any")).await, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn missing_bearer_when_enabled_returns_401() {
    let dir = tempfile::tempdir().unwrap();
    let app = build_router(state(dir.path(), ReadToken(Some("tok".into()))));
    assert_eq!(get_status(&app, "/v1/meta", None).await, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn wrong_bearer_returns_401() {
    let dir = tempfile::tempdir().unwrap();
    let app = build_router(state(dir.path(), ReadToken(Some("tok".into()))));
    assert_eq!(get_status(&app, "/v1/meta", Some("nope")).await, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn healthz_works_without_token_even_when_disabled() {
    let dir = tempfile::tempdir().unwrap();
    let app = build_router(state(dir.path(), ReadToken(None)));
    assert_eq!(get_status(&app, "/v1/healthz", None).await, StatusCode::OK);
}
