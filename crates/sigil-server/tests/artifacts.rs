//! In-process integration tests for the #182 read-only artifact routes
//! (`GET /v1/artifacts`, `GET /v1/artifacts/:filename`) via
//! `tower::ServiceExt::oneshot` (no TLS, no real socket).

use axum::body::Body;
use axum::http::{Request, StatusCode};
use sigil_server::app::{build_router, AppState};
use sigil_server::auth::ReadToken;
use sigil_server::fleet_index::FleetIndex;
use sigil_server::persist::HighWater;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

const TOKEN: &str = "secret-read-token";

/// Build an AppState whose only test-relevant fields are `artifacts_dir` and the
/// read token; everything else points at the same throwaway dir.
fn state(scratch: &Path, artifacts_dir: Option<PathBuf>, token: Option<&str>) -> Arc<AppState> {
    Arc::new(AppState {
        events_out_dir: scratch.to_path_buf(),
        policy_bundle_path: scratch.join("signed-policy.json"),
        rule_packs_bundle_path: None,
        artifacts_dir,
        high_water_path: scratch.join(".high-water.json"),
        allowlist: None,
        high_water: Mutex::new(HighWater::default()),
        fleet_index: FleetIndex::new(),
        read_token: ReadToken(token.map(str::to_string)),
        license_state: sigil_core::license::status::LicenseState::Free,
        active_window_days: 7,
        audit_key: None,
        audit_head: Mutex::new(None),
    })
}

async fn get(
    app: &axum::Router,
    uri: &str,
    token: Option<&str>,
) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
    let mut b = Request::builder().method("GET").uri(uri);
    if let Some(t) = token {
        b = b.header("authorization", format!("Bearer {t}"));
    }
    let resp = app
        .clone()
        .oneshot(b.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    (status, headers, bytes)
}

fn write(dir: &Path, name: &str, body: &[u8]) {
    std::fs::write(dir.join(name), body).unwrap();
}

#[tokio::test]
async fn index_lists_files_sorted() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "sigil-0.6.2-aarch64-unknown-linux-musl.tar.gz",
        b"TARBALL",
    );
    write(dir.path(), "SHA256SUMS", b"hash  file\n");
    write(dir.path(), "build-manifest.json", b"{}");
    let app = build_router(state(
        dir.path(),
        Some(dir.path().to_path_buf()),
        Some(TOKEN),
    ));

    let (status, _h, body) = get(&app, "/v1/artifacts", Some(TOKEN)).await;
    assert_eq!(status, StatusCode::OK);
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let names: Vec<&str> = v["artifacts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        vec![
            "SHA256SUMS",
            "build-manifest.json",
            "sigil-0.6.2-aarch64-unknown-linux-musl.tar.gz",
        ]
    );
}

#[tokio::test]
async fn get_file_streams_bytes_with_content_length() {
    let dir = tempfile::tempdir().unwrap();
    let payload = b"\x1f\x8b\x08 binary tarball bytes \x00\x01\x02";
    write(
        dir.path(),
        "sigil-0.6.2-x86_64-unknown-linux-musl.tar.gz",
        payload,
    );
    let app = build_router(state(
        dir.path(),
        Some(dir.path().to_path_buf()),
        Some(TOKEN),
    ));

    let (status, headers, body) = get(
        &app,
        "/v1/artifacts/sigil-0.6.2-x86_64-unknown-linux-musl.tar.gz",
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, payload);
    assert_eq!(
        headers.get("content-length").unwrap().to_str().unwrap(),
        payload.len().to_string()
    );
    assert_eq!(
        headers.get("content-type").unwrap().to_str().unwrap(),
        "application/octet-stream"
    );
}

#[tokio::test]
async fn traversal_filename_is_rejected_400() {
    let dir = tempfile::tempdir().unwrap();
    let app = build_router(state(
        dir.path(),
        Some(dir.path().to_path_buf()),
        Some(TOKEN),
    ));
    // %2F decodes to '/', %2E to '.' — both reach the handler as one captured
    // segment, which is_safe_name rejects.
    for uri in [
        "/v1/artifacts/bad%2Fname",      // bad/name
        "/v1/artifacts/%2E%2E%2Fpasswd", // ../passwd
        "/v1/artifacts/..",
    ] {
        let (status, _h, _b) = get(&app, uri, Some(TOKEN)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "uri={uri}");
    }
}

#[tokio::test]
async fn missing_file_is_404() {
    let dir = tempfile::tempdir().unwrap();
    let app = build_router(state(
        dir.path(),
        Some(dir.path().to_path_buf()),
        Some(TOKEN),
    ));
    let (status, _h, _b) = get(&app, "/v1/artifacts/nope-0.0.0.tar.gz", Some(TOKEN)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn artifacts_dir_unset_is_404() {
    let dir = tempfile::tempdir().unwrap();
    let app = build_router(state(dir.path(), None, Some(TOKEN)));
    let (idx, _h, _b) = get(&app, "/v1/artifacts", Some(TOKEN)).await;
    assert_eq!(idx, StatusCode::NOT_FOUND);
    let (one, _h, _b) = get(&app, "/v1/artifacts/SHA256SUMS", Some(TOKEN)).await;
    assert_eq!(one, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn missing_bearer_is_401_when_token_configured() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "SHA256SUMS", b"x");
    let app = build_router(state(
        dir.path(),
        Some(dir.path().to_path_buf()),
        Some(TOKEN),
    ));
    // No Authorization header → 401.
    let (status, _h, _b) = get(&app, "/v1/artifacts", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // Wrong token → 401.
    let (status, _h, _b) = get(&app, "/v1/artifacts", Some("wrong")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn read_token_unset_hides_artifacts_404() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "SHA256SUMS", b"x");
    // Token unset on the server ⇒ require_bearer returns 404 (hide existence).
    let app = build_router(state(dir.path(), Some(dir.path().to_path_buf()), None));
    let (status, _h, _b) = get(&app, "/v1/artifacts", Some(TOKEN)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
