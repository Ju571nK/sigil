//! /v1/meta reports fleet size under `fleet` (active hosts within the
//! configured rolling window) and no longer carries a `license` key.
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use sigil_server::app::{build_router, AppState};
use sigil_server::auth::ReadToken;
use sigil_server::fleet_index::{FleetIndex, HostSummary};
use sigil_server::persist::HighWater;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use time::{Duration, OffsetDateTime};
use tower::ServiceExt;

async fn get_meta(
    window_days: u32,
    hosts: Vec<(&str, Option<OffsetDateTime>)>,
) -> serde_json::Value {
    let dir = tempfile::tempdir().unwrap();
    let fleet_index = FleetIndex::new();
    let mut map = std::collections::HashMap::new();
    for (id, seen) in hosts {
        let mut h = HostSummary::new(id.to_string());
        h.last_seen_ts = seen;
        map.insert(id.to_string(), h);
    }
    fleet_index.replace(map);

    let state = Arc::new(AppState {
        events_out_dir: dir.path().to_path_buf(),
        policy_bundle_path: dir.path().join("p.json"),
        rule_packs_bundle_path: None,
        artifacts_dir: None,
        high_water_path: dir.path().join(".hw.json"),
        allowlist: parking_lot::RwLock::new(None::<HashSet<String>>),
        high_water: Mutex::new(HighWater::default()),
        fleet_index,
        read_token: ReadToken(Some("tok".into())),
        active_window_days: window_days,
        audit_key: None,
        audit_head: Mutex::new(None),
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
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn meta_reports_fleet_active_hosts_within_window() {
    let now = OffsetDateTime::now_utc();
    let body = get_meta(
        7,
        vec![
            ("a", Some(now)),
            ("b", Some(now - Duration::days(6))),
            ("stale", Some(now - Duration::days(8))),
            ("never", None),
        ],
    )
    .await;

    assert_eq!(
        body["fleet"],
        serde_json::json!({ "active_host_count": 2, "active_window_days": 7 })
    );
    assert!(body.get("license").is_none(), "license key removed: {body}");
    // Unchanged keys are still present.
    for k in [
        "server_version",
        "schema_version",
        "ts",
        "alerts_definition_default",
        "audit_head",
    ] {
        assert!(body.get(k).is_some(), "missing {k}: {body}");
    }
}

#[tokio::test]
async fn meta_fleet_uses_configured_window() {
    let now = OffsetDateTime::now_utc();
    let body = get_meta(
        30,
        vec![("a", Some(now)), ("b", Some(now - Duration::days(20)))],
    )
    .await;
    assert_eq!(body["fleet"]["active_host_count"], 2);
    assert_eq!(body["fleet"]["active_window_days"], 30);
}

/// Above the former 200-host threshold nothing changes shape: a plain count.
#[tokio::test]
async fn meta_fleet_count_has_no_threshold() {
    let now = OffsetDateTime::now_utc();
    let ids: Vec<String> = (0..201).map(|i| format!("h{i}")).collect();
    let hosts = ids.iter().map(|s| (s.as_str(), Some(now))).collect();
    let body = get_meta(7, hosts).await;
    assert_eq!(body["fleet"]["active_host_count"], 201);
    assert_eq!(body["fleet"].as_object().unwrap().len(), 2);
}
