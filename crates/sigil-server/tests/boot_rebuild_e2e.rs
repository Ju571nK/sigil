//! End-to-end: drop JSONL into events_out_dir, run boot rebuild, query /v1/fleet/hosts.
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use serde_json::json;
use sigil_server::app::{build_router, AppState};
use sigil_server::auth::ReadToken;
use sigil_server::boot_rebuild::rebuild_from_jsonl;
use sigil_server::fleet_index::FleetIndex;
use sigil_server::persist::HighWater;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

fn host_meta_jsonl_line(host_id: &str, hostname: &str) -> String {
    let v = json!({
        "schema_version": 1,
        "event_id": uuid::Uuid::now_v7().to_string(),
        "ts": "2026-05-17T12:00:00Z",
        "host_id": host_id,
        "agent_version": "0.5.0",
        "severity": "info",
        "source": {"kind": "agent"},
        "subject": {"kind": "self"},
        "evidence": {
            "kind": "host_meta_snapshot",
            "snapshot": {
                "hostname": hostname,
                "os_name": null, "os_version": null, "kernel_version": null,
                "architecture": null, "interfaces": [],
                "default_gateway_v4": null, "default_gateway_v6": null,
                "dns_servers": []
            },
            "is_reattestation": false
        },
        "target_id": null
    });
    format!("{v}\n")
}

const HID: &str = "0190b8a0-1111-7abc-8def-000000000001";

#[tokio::test]
async fn boot_rebuild_populates_fleet_hosts() {
    let dir = tempfile::tempdir().unwrap();
    let host_dir = dir.path().join(HID);
    std::fs::create_dir_all(&host_dir).unwrap();
    std::fs::write(
        host_dir.join("received-2026-05-17.jsonl"),
        host_meta_jsonl_line(HID, "alice"),
    )
    .unwrap();

    let idx = FleetIndex::new();
    idx.replace(rebuild_from_jsonl(dir.path()).unwrap());

    let state = Arc::new(AppState {
        events_out_dir: dir.path().to_path_buf(),
        policy_bundle_path: dir.path().join("p.json"),
        high_water_path: dir.path().join(".hw.json"),
        allowlist: None::<HashSet<String>>,
        high_water: Mutex::new(HighWater::default()),
        fleet_index: idx,
        read_token: ReadToken(Some("tok".into())),
        license_state: sigil_core::license::status::LicenseState::Free,
        active_window_days: 7,
        audit_key: None,
        rule_packs_bundle_path: None,
        artifacts_dir: None,
        audit_head: Mutex::new(None),
    });
    let app = build_router(state);
    let req = Request::builder()
        .method("GET")
        .uri("/v1/fleet/hosts")
        .header(header::AUTHORIZATION, "Bearer tok")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(body["hosts"].as_array().unwrap().len(), 1);
    assert_eq!(body["hosts"][0]["hostname"], "alice");
}
