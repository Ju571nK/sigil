//! /v1/meta exposes license status. Free tier over the 200-host limit
//! reports `over_limit` (status only — no enforcement).
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use sigil_core::license::status::LicenseState;
use sigil_server::app::{build_router, AppState};
use sigil_server::auth::ReadToken;
use sigil_server::fleet_index::{FleetIndex, HostSummary};
use sigil_server::persist::HighWater;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use time::OffsetDateTime;
use tower::ServiceExt;

#[tokio::test]
async fn meta_reports_over_limit_for_free_tier_above_200_active_hosts() {
    let dir = tempfile::tempdir().unwrap();
    let now = OffsetDateTime::now_utc();

    // 201 active hosts (last_seen = now) ⇒ above the free-tier limit of 200.
    let fleet_index = FleetIndex::new();
    let mut hosts = std::collections::HashMap::new();
    for i in 0..201 {
        let id = format!("h{i}");
        let mut h = HostSummary::new(id.clone());
        h.last_seen_ts = Some(now);
        hosts.insert(id, h);
    }
    fleet_index.replace(hosts);

    let state = Arc::new(AppState {
        events_out_dir: dir.path().to_path_buf(),
        policy_bundle_path: dir.path().join("p.json"),
        high_water_path: dir.path().join(".hw.json"),
        allowlist: None::<HashSet<String>>,
        high_water: Mutex::new(HighWater::default()),
        fleet_index,
        read_token: ReadToken(Some("tok".into())),
        license_state: LicenseState::Free,
        active_window_days: 7,
        audit_key: None,
        rule_packs_bundle_path: None,
        artifacts_dir: None,
        audit_head: Mutex::new(None),
        allowlist_path: None,
        enroll: None,
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

    assert_eq!(body["license"]["state"], "over_limit");
    assert_eq!(body["license"]["licensed"], false);
    assert_eq!(body["license"]["effective_max_hosts"], 200);
    assert!(body["license"]["current_host_count"].as_u64().unwrap() > 200);
}

#[tokio::test]
async fn meta_reports_ok_for_valid_license_under_its_limit() {
    let dir = tempfile::tempdir().unwrap();
    let now = OffsetDateTime::now_utc();

    let doc = sigil_core::license::LicenseDocument {
        license_id: "SIGIL-2026-ACME-a1b2c3".into(),
        customer_id: "ACME".into(),
        max_hosts: 1000,
        issued_at: now - time::Duration::days(30),
        not_after: now + time::Duration::days(365),
    };

    // 263 active hosts (last_seen = now) ⇒ under the valid-license limit of 1000.
    let fleet_index = FleetIndex::new();
    let mut hosts = std::collections::HashMap::new();
    for i in 0..263 {
        let id = format!("h{i}");
        let mut h = HostSummary::new(id.clone());
        h.last_seen_ts = Some(now);
        hosts.insert(id, h);
    }
    fleet_index.replace(hosts);

    let state = Arc::new(AppState {
        events_out_dir: dir.path().to_path_buf(),
        policy_bundle_path: dir.path().join("p.json"),
        high_water_path: dir.path().join(".hw.json"),
        allowlist: None::<HashSet<String>>,
        high_water: Mutex::new(HighWater::default()),
        fleet_index,
        read_token: ReadToken(Some("tok".into())),
        license_state: LicenseState::Valid(doc),
        active_window_days: 7,
        audit_key: None,
        rule_packs_bundle_path: None,
        artifacts_dir: None,
        audit_head: Mutex::new(None),
        allowlist_path: None,
        enroll: None,
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

    assert_eq!(body["license"]["state"], "ok");
    assert_eq!(body["license"]["licensed"], true);
    assert_eq!(body["license"]["effective_max_hosts"], 1000);
    assert_eq!(body["license"]["customer_id"], "ACME");
    assert_eq!(body["license"]["current_host_count"], 263);
}

#[tokio::test]
async fn meta_reports_expired_falls_back_to_free_tier() {
    let dir = tempfile::tempdir().unwrap();
    let now = OffsetDateTime::now_utc();

    let doc = sigil_core::license::LicenseDocument {
        license_id: "SIGIL-2026-ACME-a1b2c3".into(),
        customer_id: "ACME".into(),
        max_hosts: 1000,
        issued_at: now - time::Duration::days(400),
        not_after: now - time::Duration::days(1), // expired
    };

    // 250 active hosts (last_seen = now) ⇒ above the free-tier fallback of 200.
    let fleet_index = FleetIndex::new();
    let mut hosts = std::collections::HashMap::new();
    for i in 0..250 {
        let id = format!("h{i}");
        let mut h = HostSummary::new(id.clone());
        h.last_seen_ts = Some(now);
        hosts.insert(id, h);
    }
    fleet_index.replace(hosts);

    let state = Arc::new(AppState {
        events_out_dir: dir.path().to_path_buf(),
        policy_bundle_path: dir.path().join("p.json"),
        high_water_path: dir.path().join(".hw.json"),
        allowlist: None::<HashSet<String>>,
        high_water: Mutex::new(HighWater::default()),
        fleet_index,
        read_token: ReadToken(Some("tok".into())),
        license_state: LicenseState::Expired(doc),
        active_window_days: 7,
        audit_key: None,
        rule_packs_bundle_path: None,
        artifacts_dir: None,
        audit_head: Mutex::new(None),
        allowlist_path: None,
        enroll: None,
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

    assert_eq!(body["license"]["expired"], true);
    assert_eq!(body["license"]["licensed"], false);
    assert_eq!(body["license"]["effective_max_hosts"], 200);
    assert_eq!(body["license"]["state"], "over_limit"); // 250 > 200
    assert_eq!(body["license"]["current_host_count"], 250);
}
