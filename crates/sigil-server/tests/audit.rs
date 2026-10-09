//! /v1/meta exposes the signed audit-chain head. `pubkey` is reported only
//! when the server's current key is the one that signed the head (#237).
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
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
    let key_id = audit_key.as_ref().unwrap().pubkey_id.clone();
    let key_b64 = audit_key.as_ref().unwrap().pubkey_b64.clone();

    let state = Arc::new(AppState {
        events_out_dir: dir.path().to_path_buf(),
        policy_bundle_path: dir.path().join("p.json"),
        rule_packs_bundle_path: None,
        artifacts_dir: None,
        high_water_path: dir.path().join(".hw.json"),
        allowlist: parking_lot::RwLock::new(None::<HashSet<String>>),
        high_water: Mutex::new(HighWater::default()),
        fleet_index: FleetIndex::new(),
        read_token: ReadToken(Some("tok".into())),
        active_window_days: 7,
        audit_key,
        audit_head: Mutex::new(Some(sigil_core::audit::AuditHead {
            seq: 5,
            hash: "abc123".into(),
            sig: "sigval".into(),
            pubkey_id: key_id.clone(),
        })),
        allowlist_path: None,
        enroll: None,
        events_require_cert_host_match: false,
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
    assert_eq!(body["audit_head"]["pubkey_id"], key_id.as_str());
    assert_eq!(
        body["audit_head"]["pubkey"],
        format!("ed25519:{key_b64}").as_str()
    );
}

#[tokio::test]
async fn meta_reports_null_audit_head_when_disabled() {
    let dir = tempfile::tempdir().unwrap();

    let state = Arc::new(AppState {
        events_out_dir: dir.path().to_path_buf(),
        policy_bundle_path: dir.path().join("p.json"),
        rule_packs_bundle_path: None,
        artifacts_dir: None,
        high_water_path: dir.path().join(".hw.json"),
        allowlist: parking_lot::RwLock::new(None::<HashSet<String>>),
        high_water: Mutex::new(HighWater::default()),
        fleet_index: FleetIndex::new(),
        read_token: ReadToken(Some("tok".into())),
        active_window_days: 7,
        audit_key: None,
        audit_head: Mutex::new(None),
        allowlist_path: None,
        enroll: None,
        events_require_cert_host_match: false,
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

/// A chain written by an earlier release is still surfaced read-only: the
/// boot path's `audit_chain::read_head` result lands in `/v1/meta.audit_head`.
#[tokio::test]
async fn meta_reports_head_of_existing_chain_file() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../sigil-core/tests/fixtures/audit/legacy-chain-v1.jsonl"
    );
    let chain = sigil_server::audit_chain::chain_path(dir.path());
    std::fs::copy(fixture, &chain).unwrap();
    let before = std::fs::read(&chain).unwrap();
    let head = sigil_server::audit_chain::read_head(&chain);
    assert!(head.is_some());

    let state = Arc::new(AppState {
        events_out_dir: dir.path().to_path_buf(),
        policy_bundle_path: dir.path().join("p.json"),
        rule_packs_bundle_path: None,
        artifacts_dir: None,
        high_water_path: dir.path().join(".hw.json"),
        allowlist: parking_lot::RwLock::new(None::<HashSet<String>>),
        high_water: Mutex::new(HighWater::default()),
        fleet_index: FleetIndex::new(),
        read_token: ReadToken(Some("tok".into())),
        active_window_days: 7,
        audit_key: sigil_server::audit_key::AuditKey::load_or_create(dir.path()),
        audit_head: Mutex::new(head),
        allowlist_path: None,
        enroll: None,
        events_require_cert_host_match: false,
    });
    let resp = build_router(state)
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
    assert_eq!(body["audit_head"]["seq"], 2);
    assert_eq!(
        body["audit_head"]["hash"],
        "3f119e2fe76f1c3cbf8a267419db1cda7e137514d1ba48e3ddfa9d763c8c8df2"
    );
    assert_eq!(body["audit_head"]["pubkey_id"], "sigil-audit-fixt01");
    // The fixture was signed by a different key than the one generated here,
    // so the server must not pair the head with its own pubkey (#237).
    assert!(body["audit_head"].get("pubkey").is_none());
    // Read-only: the chain file is never appended to.
    assert_eq!(std::fs::read(&chain).unwrap(), before);
}

/// Head present but no audit key loaded: the head is still reported, without
/// `pubkey` (#237).
#[tokio::test]
async fn meta_reports_head_without_pubkey_when_key_unavailable() {
    let dir = tempfile::tempdir().unwrap();
    let state = Arc::new(AppState {
        events_out_dir: dir.path().to_path_buf(),
        policy_bundle_path: dir.path().join("p.json"),
        rule_packs_bundle_path: None,
        artifacts_dir: None,
        high_water_path: dir.path().join(".hw.json"),
        allowlist: parking_lot::RwLock::new(None::<HashSet<String>>),
        high_water: Mutex::new(HighWater::default()),
        fleet_index: FleetIndex::new(),
        read_token: ReadToken(Some("tok".into())),
        active_window_days: 7,
        audit_key: None,
        audit_head: Mutex::new(Some(sigil_core::audit::AuditHead {
            seq: 3,
            hash: "def456".into(),
            sig: "sigval".into(),
            pubkey_id: "sigil-audit-old".into(),
        })),
        allowlist_path: None,
        enroll: None,
        events_require_cert_host_match: false,
    });
    let resp = build_router(state)
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
    assert_eq!(body["audit_head"]["seq"], 3);
    assert_eq!(body["audit_head"]["pubkey_id"], "sigil-audit-old");
    assert!(body["audit_head"].get("pubkey").is_none());
}
