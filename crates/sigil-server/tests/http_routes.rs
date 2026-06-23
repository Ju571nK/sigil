//! In-process integration tests for the /v1/events and /v1/policy routes
//! via `tower::ServiceExt::oneshot` (no TLS, no real socket).

use axum::body::Body;
use axum::http::{Request, StatusCode};
use sigil_server::app::{build_router, AppState};
use sigil_server::persist::HighWater;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

fn state_in(dir: &std::path::Path, allowlist: Option<HashSet<String>>) -> Arc<AppState> {
    state_in_with_rule_packs(dir, allowlist, None)
}

fn state_in_with_rule_packs(
    dir: &std::path::Path,
    allowlist: Option<HashSet<String>>,
    rule_packs_bundle_path: Option<std::path::PathBuf>,
) -> Arc<AppState> {
    use sigil_server::auth::ReadToken;
    use sigil_server::fleet_index::FleetIndex;
    Arc::new(AppState {
        events_out_dir: dir.to_path_buf(),
        policy_bundle_path: dir.join("signed-policy.json"),
        rule_packs_bundle_path,
        artifacts_dir: None,
        high_water_path: dir.join(".high-water.json"),
        allowlist,
        high_water: Mutex::new(HighWater::default()),
        fleet_index: FleetIndex::new(),
        read_token: ReadToken(None),
        license_state: sigil_core::license::status::LicenseState::Free,
        active_window_days: 7,
        audit_key: None,
        audit_head: Mutex::new(None),
        allowlist_path: None,
        enroll: None,
    })
}

/// Minimal valid `sigil_core::event::Event` JSON for `host_id`.
fn sample_event_json(host_id: &str, event_id: &str) -> serde_json::Value {
    serde_json::json!({
        "schema_version": 1,
        "event_id": event_id,
        "ts": "2026-05-11T00:00:00Z",
        "host_id": host_id,
        "agent_version": "0.1.0",
        "severity": "warn",
        "source": {"kind": "agent"},
        "subject": {"kind": "self"},
        "evidence": {"kind": "host_id_conflict", "observed_status": 200},
        "target_id": null
    })
}

fn events_request(host_id: &str, entries: &[(&str, u64)]) -> serde_json::Value {
    serde_json::json!({
        "envelope": {"host_id": host_id, "schema_version": 1},
        "events": entries.iter().map(|(id, seq)| serde_json::json!({
            "event_id": id,
            "sequence": seq,
            "payload": sample_event_json(host_id, id),
        })).collect::<Vec<_>>(),
    })
}

async fn post_events(
    app: &axum::Router,
    body: &serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let req = Request::builder()
        .method("POST")
        .uri("/v1/events")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

const ID_A: &str = "00000000-0000-0000-0000-00000000000a";
const ID_B: &str = "00000000-0000-0000-0000-00000000000b";
const ID_C: &str = "00000000-0000-0000-0000-00000000000c";

#[tokio::test]
async fn post_events_persists_and_acks_high_water() {
    let dir = tempfile::tempdir().unwrap();
    let app = build_router(state_in(dir.path(), None));

    let (status, body) = post_events(&app, &events_request("h-1", &[(ID_A, 1), (ID_B, 2)])).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["accepted"].as_array().unwrap().len(), 2);
    assert_eq!(body["rejected"].as_array().unwrap().len(), 0);
    assert_eq!(body["high_water_event_id"], ID_B);

    // Two lines on disk under the host's segment.
    let host_dir = dir.path().join("h-1");
    let seg = std::fs::read_dir(&host_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .find(|e| e.file_name().to_string_lossy().starts_with("received-"))
        .unwrap();
    let on_disk = std::fs::read_to_string(seg.path()).unwrap();
    assert_eq!(on_disk.matches('\n').count(), 2);
}

#[tokio::test]
async fn host_id_payload_mismatch_is_rejected_others_accepted() {
    let dir = tempfile::tempdir().unwrap();
    let app = build_router(state_in(dir.path(), None));

    // Build a batch where event B carries a wrong host_id in its payload.
    let body = serde_json::json!({
        "envelope": {"host_id": "h-1", "schema_version": 1},
        "events": [
            {"event_id": ID_A, "sequence": 1, "payload": sample_event_json("h-1", ID_A)},
            {"event_id": ID_B, "sequence": 2, "payload": sample_event_json("WRONG", ID_B)},
        ],
    });
    let (status, resp) = post_events(&app, &body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(resp["accepted"], serde_json::json!([ID_A]));
    let rejected = resp["rejected"].as_array().unwrap();
    assert_eq!(rejected.len(), 1);
    assert_eq!(rejected[0]["event_id"], ID_B);
    assert_eq!(rejected[0]["reason"], "host_id_payload_mismatch");
    // high_water is still the last submitted event regardless of rejection.
    assert_eq!(resp["high_water_event_id"], ID_B);
}

#[tokio::test]
async fn malformed_payload_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let app = build_router(state_in(dir.path(), None));
    let body = serde_json::json!({
        "envelope": {"host_id": "h-1", "schema_version": 1},
        "events": [
            {"event_id": ID_A, "sequence": 1, "payload": {"not": "an event"}},
        ],
    });
    let (status, resp) = post_events(&app, &body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(resp["rejected"][0]["reason"], "malformed_payload");
}

#[tokio::test]
async fn resending_a_batch_does_not_double_write() {
    let dir = tempfile::tempdir().unwrap();
    let app = build_router(state_in(dir.path(), None));
    let batch = events_request("h-1", &[(ID_A, 1), (ID_B, 2)]);

    post_events(&app, &batch).await;
    post_events(&app, &batch).await; // resend — should be a no-op on disk

    let host_dir = dir.path().join("h-1");
    let seg = std::fs::read_dir(&host_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .find(|e| e.file_name().to_string_lossy().starts_with("received-"))
        .unwrap();
    let on_disk = std::fs::read_to_string(seg.path()).unwrap();
    assert_eq!(
        on_disk.matches('\n').count(),
        2,
        "resend must not duplicate lines"
    );

    // A follow-up batch with one overlap + one new event writes exactly 1.
    let (_status, resp) = post_events(&app, &events_request("h-1", &[(ID_B, 2), (ID_C, 3)])).await;
    assert_eq!(resp["high_water_event_id"], ID_C);
    let on_disk = std::fs::read_to_string(seg.path()).unwrap();
    assert_eq!(on_disk.matches('\n').count(), 3);
}

#[tokio::test]
async fn allowlist_blocks_unknown_host_on_events() {
    let dir = tempfile::tempdir().unwrap();
    let mut set = HashSet::new();
    set.insert("known-host".to_string());
    let app = build_router(state_in(dir.path(), Some(set)));

    let (status, _) = post_events(&app, &events_request("stranger", &[(ID_A, 1)])).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, _) = post_events(&app, &events_request("known-host", &[(ID_A, 1)])).await;
    assert_eq!(status, StatusCode::OK);
}

async fn get_policy(
    app: &axum::Router,
    host_id: &str,
    if_none_match: Option<&str>,
) -> (StatusCode, Option<String>, serde_json::Value) {
    let mut b = Request::builder()
        .method("GET")
        .uri(format!("/v1/policy?host_id={host_id}"));
    if let Some(inm) = if_none_match {
        b = b.header("if-none-match", inm);
    }
    let resp = app
        .clone()
        .oneshot(b.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let etag = resp
        .headers()
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, etag, json)
}

#[tokio::test]
async fn policy_404_when_no_bundle() {
    let dir = tempfile::tempdir().unwrap();
    let app = build_router(state_in(dir.path(), None));
    let (status, _, body) = get_policy(&app, "h-1", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"], "no_policy");
}

#[tokio::test]
async fn policy_200_then_304_with_matching_etag() {
    let dir = tempfile::tempdir().unwrap();
    // Write a minimal SignedPolicyResponse-shaped bundle with a known etag.
    let bundle = serde_json::json!({
        "etag": "deadbeef",
        "signed_envelope": {
            "policy_version": 1,
            "policy_bytes_b64": "dmVyc2lvbjogMQo=",
            "valid_until": "2027-01-01T00:00:00Z",
            "issued_at": "2026-05-11T00:00:00Z"
        },
        "signature": "AAAA",
        "signing_pubkey_id": "k1",
        "applied_at": "2026-05-11T00:00:01Z"
    });
    std::fs::write(
        dir.path().join("signed-policy.json"),
        serde_json::to_vec(&bundle).unwrap(),
    )
    .unwrap();
    let app = build_router(state_in(dir.path(), None));

    let (status, etag, body) = get_policy(&app, "h-1", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(etag.as_deref(), Some("deadbeef"));
    assert_eq!(body["signing_pubkey_id"], "k1");

    let (status, _, _) = get_policy(&app, "h-1", Some("deadbeef")).await;
    assert_eq!(status, StatusCode::NOT_MODIFIED);

    let (status, _, _) = get_policy(&app, "h-1", Some("stale-etag")).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn allowlist_blocks_unknown_host_on_policy() {
    let dir = tempfile::tempdir().unwrap();
    let mut set = HashSet::new();
    set.insert("known-host".to_string());
    let app = build_router(state_in(dir.path(), Some(set)));
    let (status, _, _) = get_policy(&app, "stranger", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

async fn get_rule_packs(
    app: &axum::Router,
    host_id: &str,
    if_none_match: Option<&str>,
) -> (StatusCode, Option<String>, serde_json::Value) {
    let mut b = Request::builder()
        .method("GET")
        .uri(format!("/v1/rule-packs?host_id={host_id}"));
    if let Some(inm) = if_none_match {
        b = b.header("if-none-match", inm);
    }
    let resp = app
        .clone()
        .oneshot(b.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let etag = resp
        .headers()
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, etag, json)
}

#[tokio::test]
async fn rule_packs_404_when_not_configured() {
    let dir = tempfile::tempdir().unwrap();
    let app = build_router(state_in(dir.path(), None));
    let (status, _, body) = get_rule_packs(&app, "h-1", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"], "rule_packs_not_configured");
}

#[tokio::test]
async fn rule_packs_200_then_304_with_matching_etag() {
    let dir = tempfile::tempdir().unwrap();
    // Write a minimal SignedPolicyResponse-shaped pack-set bundle.
    let bundle = serde_json::json!({
        "etag": "cafef00d",
        "signed_envelope": {
            "policy_version": 1,
            "policy_bytes_b64": "cGFja3M6IFtdCg==",
            "valid_until": "2027-01-01T00:00:00Z",
            "issued_at": "2026-05-11T00:00:00Z"
        },
        "signature": "AAAA",
        "signing_pubkey_id": "k1",
        "applied_at": "2026-05-11T00:00:01Z"
    });
    let bundle_path = dir.path().join("signed-rule-packs.json");
    std::fs::write(&bundle_path, serde_json::to_vec(&bundle).unwrap()).unwrap();
    let app = build_router(state_in_with_rule_packs(
        dir.path(),
        None,
        Some(bundle_path),
    ));

    let (status, etag, body) = get_rule_packs(&app, "h-1", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(etag.as_deref(), Some("cafef00d"));
    assert_eq!(body["signing_pubkey_id"], "k1");

    let (status, _, _) = get_rule_packs(&app, "h-1", Some("cafef00d")).await;
    assert_eq!(status, StatusCode::NOT_MODIFIED);

    let (status, _, _) = get_rule_packs(&app, "h-1", Some("stale-etag")).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn allowlist_blocks_unknown_host_on_rule_packs() {
    let dir = tempfile::tempdir().unwrap();
    let mut set = HashSet::new();
    set.insert("known-host".to_string());
    let app = build_router(state_in_with_rule_packs(
        dir.path(),
        Some(set),
        Some(dir.path().join("signed-rule-packs.json")),
    ));
    let (status, _, body) = get_rule_packs(&app, "stranger", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"], "host_unknown");
}
