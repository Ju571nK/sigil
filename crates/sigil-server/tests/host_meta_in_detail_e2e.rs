//! HostMetaSnapshot ingest → /v1/fleet/hosts/{host_id}.host_meta block populated.
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
async fn ingested_host_meta_appears_in_detail_block() {
    let dir = tempfile::tempdir().unwrap();
    let idx = FleetIndex::new();

    // Synthesize an ingest by calling apply_event directly on FleetIndex.
    let snap = sigil_core::event::HostMetaSnapshot {
        hostname: Some("alice".into()),
        os_name: Some("macOS".into()),
        os_version: Some("14.5".into()),
        kernel_version: Some("23.5.0".into()),
        architecture: Some("arm64".into()),
        interfaces: vec![sigil_core::event::NetworkInterface {
            name: "en0".into(),
            mac: Some("00:1b:44:11:3a:b7".into()),
            ipv4: vec!["192.168.1.42/24".into()],
            ipv6: vec![],
        }],
        default_gateway_v4: Some("192.168.1.1".into()),
        default_gateway_v6: None,
        dns_servers: vec!["1.1.1.1".into()],
    };
    let ev = sigil_core::event::Event {
        schema_version: sigil_core::event::SCHEMA_VERSION,
        event_id: uuid::Uuid::now_v7(),
        ts: time::OffsetDateTime::now_utc(),
        host_id: "h1".into(),
        agent_version: "0.5.0".into(),
        severity: sigil_core::event::Severity::Info,
        source: sigil_core::event::SourceKind::Agent,
        subject: sigil_core::event::Subject::Self_,
        evidence: sigil_core::event::Evidence::HostMetaSnapshot { snapshot: snap, is_reattestation: false },
        target_id: None,
    };
    idx.apply_event(&ev);

    let state = Arc::new(AppState {
        events_out_dir: dir.path().to_path_buf(),
        policy_bundle_path: dir.path().join("p.json"),
        high_water_path: dir.path().join(".hw.json"),
        allowlist: None::<HashSet<String>>,
        high_water: Mutex::new(HighWater::default()),
        fleet_index: idx,
        read_token: ReadToken(Some("tok".into())),
    });
    let app = build_router(state);
    let req = Request::builder().method("GET").uri("/v1/fleet/hosts/h1")
        .header(header::AUTHORIZATION, "Bearer tok").body(Body::empty()).unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap()).unwrap();
    assert_eq!(body["hostname"], "alice");
    assert_eq!(body["host_meta"]["os_name"], "macOS");
    assert_eq!(body["host_meta"]["interfaces"][0]["name"], "en0");
    assert_eq!(body["host_meta"]["default_gateway_v4"], "192.168.1.1");
    assert_eq!(body["host_meta"]["dns_servers"][0], "1.1.1.1");
}
