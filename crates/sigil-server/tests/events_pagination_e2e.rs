//! 5-event pagination walk via /v1/events with limit=2.
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use serde_json::json;
use sigil_server::app::{build_router, AppState};
use sigil_server::auth::ReadToken;
use sigil_server::fleet_index::FleetIndex;
use sigil_server::persist::HighWater;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

const HID: &str = "0190b8a0-1111-7abc-8def-000000000001";

fn ev_jsonl(uid: uuid::Uuid, ts: &str) -> String {
    let v = json!({
        "schema_version": 1, "event_id": uid.to_string(), "ts": ts,
        "host_id": HID, "agent_version": "0.5.0",
        "severity": "warn", "source": {"kind": "agent"}, "subject": {"kind": "self"},
        "evidence": {"kind": "host_id_conflict", "observed_status": 200},
        "target_id": null
    });
    format!("{v}\n")
}

#[tokio::test]
async fn events_pagination_walks_in_pages() {
    let dir = tempfile::tempdir().unwrap();
    let host_dir = dir.path().join(HID);
    std::fs::create_dir_all(&host_dir).unwrap();
    let f = host_dir.join("received-2026-05-17.jsonl");
    let mut all_ids: Vec<uuid::Uuid> = (0..5).map(|_| uuid::Uuid::now_v7()).collect();
    all_ids.sort(); // ascending; pagination returns descending.
    let mut buf = String::new();
    for u in &all_ids {
        buf.push_str(&ev_jsonl(*u, "2026-05-17T12:00:00Z"));
    }
    std::fs::write(&f, buf).unwrap();

    let state = Arc::new(AppState {
        events_out_dir: dir.path().to_path_buf(),
        policy_bundle_path: dir.path().join("p.json"),
        high_water_path: dir.path().join(".hw.json"),
        allowlist: parking_lot::RwLock::new(None::<HashSet<String>>),
        high_water: Mutex::new(HighWater::default()),
        fleet_index: FleetIndex::new(),
        read_token: ReadToken(Some("tok".into())),
        license_state: sigil_core::license::status::LicenseState::Free,
        active_window_days: 7,
        audit_key: None,
        rule_packs_bundle_path: None,
        artifacts_dir: None,
        audit_head: Mutex::new(None),
        allowlist_path: None,
        enroll: None,
        events_require_cert_host_match: false,
    });
    let app = build_router(state);

    async fn page(app: &axum::Router, cursor: Option<&str>) -> serde_json::Value {
        let uri = match cursor {
            None => "/v1/events?limit=2".to_string(),
            Some(c) => format!("/v1/events?limit=2&cursor={c}"),
        };
        let req = Request::builder()
            .method("GET")
            .uri(uri)
            .header(header::AUTHORIZATION, "Bearer tok")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        serde_json::from_slice(
            &axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap()
    }

    let p1 = page(&app, None).await;
    assert_eq!(p1["events"].as_array().unwrap().len(), 2);
    let c1 = p1["next_cursor"].as_str().unwrap().to_string();
    let p2 = page(&app, Some(&c1)).await;
    assert_eq!(p2["events"].as_array().unwrap().len(), 2);
    let c2 = p2["next_cursor"].as_str().unwrap().to_string();
    let p3 = page(&app, Some(&c2)).await;
    assert_eq!(p3["events"].as_array().unwrap().len(), 1);
    assert!(p3["next_cursor"].is_null());
}
