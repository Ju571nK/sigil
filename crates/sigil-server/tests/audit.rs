//! /v1/meta exposes the signed audit-chain head. Two cases: signing enabled
//! (audit_head is Some + audit_key is Some) and disabled (both None).
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use sigil_core::license::status::LicenseState;
use sigil_server::app::{build_router, AppState};
use sigil_server::auth::ReadToken;
use sigil_server::fleet_index::FleetIndex;
use sigil_server::persist::HighWater;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

#[tokio::test]
async fn meta_reports_audit_head_when_signing_enabled() {
    let dir = tempfile::tempdir().unwrap();
    let audit_key = sigil_server::audit_key::AuditKey::load_or_create(dir.path());

    let state = Arc::new(AppState {
        events_out_dir: dir.path().to_path_buf(),
        policy_bundle_path: dir.path().join("p.json"),
        high_water_path: dir.path().join(".hw.json"),
        allowlist: None::<HashSet<String>>,
        high_water: Mutex::new(HighWater::default()),
        fleet_index: FleetIndex::new(),
        read_token: ReadToken(Some("tok".into())),
        license_state: LicenseState::Free,
        active_window_days: 7,
        audit_key,
        audit_head: Mutex::new(Some(sigil_core::audit::AuditHead {
            seq: 5,
            hash: "abc123".into(),
            sig: "sigval".into(),
            pubkey_id: "sigil-audit-x".into(),
        })),
    });

    let app = build_router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/meta")
                .header(header::AUTHORIZATION, "Bearer tok")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

    assert_eq!(body["audit_head"]["seq"], 5);
    assert_eq!(body["audit_head"]["hash"], "abc123");
    assert!(body["audit_head"]["pubkey"]
        .as_str()
        .unwrap()
        .starts_with("ed25519:"));
}

#[tokio::test]
async fn meta_reports_null_audit_head_when_disabled() {
    let dir = tempfile::tempdir().unwrap();

    let state = Arc::new(AppState {
        events_out_dir: dir.path().to_path_buf(),
        policy_bundle_path: dir.path().join("p.json"),
        high_water_path: dir.path().join(".hw.json"),
        allowlist: None::<HashSet<String>>,
        high_water: Mutex::new(HighWater::default()),
        fleet_index: FleetIndex::new(),
        read_token: ReadToken(Some("tok".into())),
        license_state: LicenseState::Free,
        active_window_days: 7,
        audit_key: None,
        audit_head: Mutex::new(None),
    });

    let app = build_router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/meta")
                .header(header::AUTHORIZATION, "Bearer tok")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

    assert!(body["audit_head"].is_null());
}
