//! boot_gate middleware: 503 + Retry-After until ready; /v1/healthz always open.
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::middleware::from_fn_with_state;
use axum::routing::get;
use axum::Router;
use sigil_server::app::boot_gate;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tower::ServiceExt;

fn app(ready: bool) -> Router {
    let flag = Arc::new(AtomicBool::new(ready));
    Router::new()
        .route("/v1/fleet/risk", get(|| async { "ok" }))
        .route("/v1/healthz", get(|| async { "ok" }))
        .layer(from_fn_with_state(flag, boot_gate))
}

async fn get_status(app: &Router, path: &str) -> (StatusCode, Option<String>) {
    let resp = app
        .clone()
        .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let retry = resp
        .headers()
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    (status, retry)
}

#[tokio::test]
async fn gated_route_503_with_retry_after_while_rebuilding() {
    let (s, retry) = get_status(&app(false), "/v1/fleet/risk").await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(retry.as_deref(), Some("5"));

    // body shape: {"error":{"code":"rebuilding", ...}}
    let resp = app(false)
        .oneshot(
            Request::builder()
                .uri("/v1/fleet/risk")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let bytes = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["error"]["code"], "rebuilding");
}

#[tokio::test]
async fn healthz_open_during_rebuild() {
    let (s, _) = get_status(&app(false), "/v1/healthz").await;
    assert_eq!(s, StatusCode::OK);
}

#[tokio::test]
async fn all_open_once_ready() {
    let app = app(true);
    assert_eq!(get_status(&app, "/v1/fleet/risk").await.0, StatusCode::OK);
    assert_eq!(get_status(&app, "/v1/healthz").await.0, StatusCode::OK);
}
