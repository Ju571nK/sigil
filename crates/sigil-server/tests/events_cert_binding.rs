//! #194.2 — `POST /v1/events` cert↔host_id binding, driven in-process via
//! `tower::ServiceExt::oneshot` with a `PeerIdentity` request extension —
//! exactly what `tls_accept::PeerCertAcceptor` injects on a live mTLS
//! connection. (The acceptor itself is covered by unit tests and by the
//! live-TLS round trip in `tests/mtls_acceptor_e2e.rs`.)

use axum::body::Body;
use axum::http::{Request, StatusCode};
use sigil_server::app::{build_router, AppState};
use sigil_server::auth::ReadToken;
use sigil_server::fleet_index::FleetIndex;
use sigil_server::persist::HighWater;
use sigil_server::tls_accept::PeerIdentity;
use std::sync::{Arc, Mutex};

/// AppState with NO allowlist (permit-all) so only the #194.2 cert gate is
/// under test — a cert-mismatch rejection therefore proves the gate fires
/// BEFORE (independently of) the allowlist.
fn state(dir: &std::path::Path, require_match: bool) -> Arc<AppState> {
    Arc::new(AppState {
        events_out_dir: dir.to_path_buf(),
        policy_bundle_path: dir.join("signed-policy.json"),
        rule_packs_bundle_path: None,
        artifacts_dir: None,
        high_water_path: dir.join(".high-water.json"),
        allowlist: parking_lot::RwLock::new(None),
        high_water: Mutex::new(HighWater::default()),
        fleet_index: FleetIndex::new(),
        read_token: ReadToken(None),
        license_state: sigil_core::license::status::LicenseState::Free,
        active_window_days: 7,
        audit_key: None,
        audit_head: Mutex::new(None),
        allowlist_path: None,
        enroll: None,
        events_require_cert_host_match: require_match,
    })
}

fn sample_event_json(host_id: &str, event_id: &str) -> serde_json::Value {
    serde_json::json!({
        "schema_version": 1,
        "event_id": event_id,
        "ts": "2026-07-01T00:00:00Z",
        "host_id": host_id,
        "agent_version": "0.1.0",
        "severity": "warn",
        "source": {"kind": "agent"},
        "subject": {"kind": "self"},
        "evidence": {"kind": "host_id_conflict", "observed_status": 200},
        "target_id": null
    })
}

fn events_request(host_id: &str) -> serde_json::Value {
    serde_json::json!({
        "envelope": {"host_id": host_id, "schema_version": 1},
        "events": [{
            "event_id": EVENT_ID,
            "sequence": 1,
            "payload": sample_event_json(host_id, EVENT_ID),
        }],
    })
}

async fn post_events_as(
    app: &axum::Router,
    body: &serde_json::Value,
    peer: Option<Arc<PeerIdentity>>,
) -> (StatusCode, serde_json::Value) {
    use tower::ServiceExt;
    let mut builder = Request::builder()
        .method("POST")
        .uri("/v1/events")
        .header("content-type", "application/json");
    if let Some(peer) = peer {
        builder = builder.extension(peer);
    }
    let resp = app
        .clone()
        .oneshot(
            builder
                .body(Body::from(serde_json::to_vec(body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

const HOST: &str = "018f9c1a-0000-7000-8000-0000000000c1";
const EVENT_ID: &str = "00000000-0000-0000-0000-00000000000a";

fn peer(cn: Option<&str>, san: &[&str]) -> Arc<PeerIdentity> {
    Arc::new(PeerIdentity {
        fingerprint: "f".repeat(64),
        cn: cn.map(str::to_string),
        san_dns: san.iter().map(|s| s.to_string()).collect(),
    })
}

#[tokio::test]
async fn flag_on_cn_match_is_accepted() {
    let dir = tempfile::tempdir().unwrap();
    let app = build_router(state(dir.path(), true));
    let (status, body) =
        post_events_as(&app, &events_request(HOST), Some(peer(Some(HOST), &[]))).await;
    assert_eq!(status, StatusCode::OK, "body={body}");
    assert_eq!(body["accepted"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn flag_on_san_only_match_is_accepted() {
    let dir = tempfile::tempdir().unwrap();
    let app = build_router(state(dir.path(), true));
    // CN differs; SAN DNS carries the host_id (B-mint certs carry both, but
    // either alone must satisfy the gate).
    let (status, body) = post_events_as(
        &app,
        &events_request(HOST),
        Some(peer(Some("something-else"), &[HOST])),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body={body}");
}

#[tokio::test]
async fn flag_on_cn_mismatch_is_404_host_unknown() {
    let dir = tempfile::tempdir().unwrap();
    let app = build_router(state(dir.path(), true));
    let (status, body) = post_events_as(
        &app,
        &events_request(HOST),
        Some(peer(Some("other-host"), &["other-host"])),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    // SAME shape as the allowlist rejection — no oracle distinguishing the two.
    assert_eq!(body["error"], "host_unknown");
    assert_eq!(body["host_id"], HOST);
}

#[tokio::test]
async fn flag_on_missing_peer_identity_is_404_host_unknown() {
    let dir = tempfile::tempdir().unwrap();
    let app = build_router(state(dir.path(), true));
    let (status, body) = post_events_as(&app, &events_request(HOST), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"], "host_unknown");
}

#[tokio::test]
async fn flag_off_behavior_unchanged_no_peer_needed() {
    let dir = tempfile::tempdir().unwrap();
    let app = build_router(state(dir.path(), false));
    let (status, body) = post_events_as(&app, &events_request(HOST), None).await;
    assert_eq!(status, StatusCode::OK, "body={body}");
}

#[tokio::test]
async fn flag_off_mismatched_peer_is_still_accepted() {
    let dir = tempfile::tempdir().unwrap();
    let app = build_router(state(dir.path(), false));
    let (status, body) = post_events_as(
        &app,
        &events_request(HOST),
        Some(peer(Some("other-host"), &[])),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body={body}");
}
