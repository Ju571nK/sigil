//! #184 — in-process integration tests for `POST /v1/enroll` (B-mint) via
//! `tower::ServiceExt::oneshot`. Builds a REAL intermediate CA with openssl,
//! issues tokens through the token store, generates a host keypair + CSR, and
//! drives the endpoint end-to-end. Happy path → 200 + cert verifies vs the CA +
//! CN==host_id + clientAuth EKU + host added to allowlist + a signed audit line.
//! Negatives: expired→403, reused→403, CN!=host_id→403, bad CSR→400, off→404.
//!
//! These tests require `openssl` on PATH (CI ubuntu/macos/rocky all have it).

use axum::body::Body;
use axum::http::{Request, StatusCode};
use sigil_server::app::{build_router, AppState};
use sigil_server::auth::ReadToken;
use sigil_server::enroll::tokens::TokenStore;
use sigil_server::enroll::EnrollState;
use sigil_server::fleet_index::FleetIndex;
use sigil_server::persist::HighWater;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use time::{Duration, OffsetDateTime};
use tower::ServiceExt;

fn openssl() -> PathBuf {
    sigil_server::enroll::sign::resolve_openssl().expect("openssl must be installed")
}

fn run(args: &[&std::ffi::OsStr]) {
    let o = Command::new(openssl()).args(args).output().unwrap();
    assert!(
        o.status.success(),
        "openssl {args:?}: {}",
        String::from_utf8_lossy(&o.stderr)
    );
}

/// Make a CA:TRUE intermediate-style CA (self-signed for test purposes — the
/// leaf still verifies against it). Returns (cert_path, key_path), key at 0600.
fn make_ca(dir: &Path) -> (PathBuf, PathBuf) {
    let key = dir.join("ca.key");
    let crt = dir.join("ca.crt");
    run(&[
        "genpkey".as_ref(),
        "-algorithm".as_ref(),
        "RSA".as_ref(),
        "-pkeyopt".as_ref(),
        "rsa_keygen_bits:2048".as_ref(),
        "-out".as_ref(),
        key.as_os_str(),
    ]);
    run(&[
        "req".as_ref(),
        "-x509".as_ref(),
        "-new".as_ref(),
        "-key".as_ref(),
        key.as_os_str(),
        "-days".as_ref(),
        "3650".as_ref(),
        "-subj".as_ref(),
        "/CN=test-int-ca".as_ref(),
        "-addext".as_ref(),
        "basicConstraints=critical,CA:TRUE".as_ref(),
        "-out".as_ref(),
        crt.as_os_str(),
    ]);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    (crt, key)
}

/// Generate a host key + CSR with the given CN. Returns the CSR PEM.
fn make_csr(dir: &Path, cn: &str) -> String {
    let key = dir.join(format!("{cn}.key"));
    let csr = dir.join(format!("{cn}.csr"));
    run(&[
        "genpkey".as_ref(),
        "-algorithm".as_ref(),
        "RSA".as_ref(),
        "-pkeyopt".as_ref(),
        "rsa_keygen_bits:2048".as_ref(),
        "-out".as_ref(),
        key.as_os_str(),
    ]);
    let subj = format!("/CN={cn}");
    run(&[
        "req".as_ref(),
        "-new".as_ref(),
        "-key".as_ref(),
        key.as_os_str(),
        "-subj".as_ref(),
        subj.as_ref(),
        "-out".as_ref(),
        csr.as_os_str(),
    ]);
    std::fs::read_to_string(&csr).unwrap()
}

/// Verify a leaf cert against the CA via `openssl verify`.
fn verify_leaf(dir: &Path, ca: &Path, leaf_pem: &str) -> bool {
    let leaf = dir.join("leaf-verify.crt");
    std::fs::write(&leaf, leaf_pem).unwrap();
    Command::new(openssl())
        .arg("verify")
        .arg("-CAfile")
        .arg(ca)
        .arg(&leaf)
        .output()
        .unwrap()
        .status
        .success()
}

fn cert_text(dir: &Path, leaf_pem: &str) -> String {
    let leaf = dir.join("leaf-text.crt");
    std::fs::write(&leaf, leaf_pem).unwrap();
    let o = Command::new(openssl())
        .arg("x509")
        .arg("-in")
        .arg(&leaf)
        .args(["-noout", "-text"])
        .output()
        .unwrap();
    String::from_utf8_lossy(&o.stdout).into_owned()
}

/// Build an AppState with enrollment enabled (or not). `enroll` toggles whether
/// EnrollState is configured. Uses a fresh audit key in `scratch`.
fn state(scratch: &Path, with_enroll: bool) -> Arc<AppState> {
    let tokens_path = scratch.join("tokens.json");
    let allowlist_path = scratch.join("hosts.json");
    let enroll = if with_enroll {
        let (cert, key) = make_ca(scratch);
        EnrollState::load(
            Some(&cert),
            Some(&key),
            Some(&tokens_path),
            true,
            Some(30),
            scratch.join("enrollment-audit.jsonl"),
        )
    } else {
        None
    };
    let audit_key = sigil_server::audit_key::AuditKey::load_or_create(scratch);
    Arc::new(AppState {
        events_out_dir: scratch.to_path_buf(),
        policy_bundle_path: scratch.join("signed-policy.json"),
        rule_packs_bundle_path: None,
        artifacts_dir: None,
        high_water_path: scratch.join(".high-water.json"),
        allowlist: None,
        high_water: Mutex::new(HighWater::default()),
        fleet_index: FleetIndex::new(),
        read_token: ReadToken(None),
        license_state: sigil_core::license::status::LicenseState::Free,
        active_window_days: 7,
        audit_key,
        audit_head: Mutex::new(None),
        allowlist_path: Some(allowlist_path),
        enroll,
    })
}

async fn post_enroll(
    app: &axum::Router,
    token: &str,
    host_id: &str,
    csr_pem: &str,
) -> (StatusCode, serde_json::Value) {
    let body = serde_json::json!({
        "token": token,
        "host_id": host_id,
        "csr_pem": csr_pem,
    });
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/enroll")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

const HOST: &str = "018f9c1a-0000-7000-8000-000000000001";

#[tokio::test]
async fn happy_path_issues_verifiable_clientauth_cert() {
    let dir = tempfile::tempdir().unwrap();
    let st = state(dir.path(), true);
    let en = st.enroll.as_ref().unwrap();
    let tokens_path = en.tokens_path.clone();
    let ca_cert = en.ca_cert_path.clone();
    let audit_path = en.audit_path.clone();
    let allowlist_path = st.allowlist_path.clone().unwrap();
    let now = OffsetDateTime::now_utc();
    let token = TokenStore::issue(&tokens_path, HOST, now + Duration::hours(1), now).unwrap();
    let csr = make_csr(dir.path(), HOST);

    let app = build_router(st);
    let (status, body) = post_enroll(&app, &token, HOST, &csr).await;
    assert_eq!(status, StatusCode::OK, "body={body}");

    let cert = body["client_cert_pem"].as_str().unwrap();
    assert!(cert.contains("BEGIN CERTIFICATE"));
    assert_eq!(body["host_id"], HOST);
    assert!(
        verify_leaf(dir.path(), &ca_cert, cert),
        "leaf must verify vs CA"
    );
    let text = cert_text(dir.path(), cert);
    let lc = text.to_lowercase();
    assert!(
        lc.contains("tls web client authentication"),
        "clientAuth EKU"
    );
    assert!(
        !lc.contains("tls web server authentication"),
        "no serverAuth"
    );
    assert!(text.contains(HOST), "CN/SAN must carry host_id");

    // host added to allowlist file
    let hosts = std::fs::read_to_string(&allowlist_path).unwrap();
    assert!(hosts.contains(HOST), "host added to allowlist");

    // exactly one audit line written and it is an "issued" decision
    let audit = std::fs::read_to_string(&audit_path).unwrap();
    let lines: Vec<&str> = audit.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(lines.len(), 1, "one audit line");
    assert!(lines[0].contains("\"decision\":\"issued\""));
    assert!(lines[0].contains(HOST));
}

#[tokio::test]
async fn reused_token_is_denied_403() {
    let dir = tempfile::tempdir().unwrap();
    let st = state(dir.path(), true);
    let tokens_path = st.enroll.as_ref().unwrap().tokens_path.clone();
    let now = OffsetDateTime::now_utc();
    let token = TokenStore::issue(&tokens_path, HOST, now + Duration::hours(1), now).unwrap();
    let csr = make_csr(dir.path(), HOST);
    let app = build_router(st);

    let (s1, _) = post_enroll(&app, &token, HOST, &csr).await;
    assert_eq!(s1, StatusCode::OK);
    let (s2, body) = post_enroll(&app, &token, HOST, &csr).await;
    assert_eq!(s2, StatusCode::FORBIDDEN);
    assert_eq!(body["error"]["code"], "enrollment_denied");
}

#[tokio::test]
async fn expired_token_is_denied_403() {
    let dir = tempfile::tempdir().unwrap();
    let st = state(dir.path(), true);
    let tokens_path = st.enroll.as_ref().unwrap().tokens_path.clone();
    let now = OffsetDateTime::now_utc();
    // expires in the past
    let token = TokenStore::issue(&tokens_path, HOST, now - Duration::seconds(1), now).unwrap();
    let csr = make_csr(dir.path(), HOST);
    let app = build_router(st);

    let (status, body) = post_enroll(&app, &token, HOST, &csr).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"]["code"], "enrollment_denied");
}

#[tokio::test]
async fn cn_not_equal_host_id_is_denied_403() {
    let dir = tempfile::tempdir().unwrap();
    let st = state(dir.path(), true);
    let tokens_path = st.enroll.as_ref().unwrap().tokens_path.clone();
    let now = OffsetDateTime::now_utc();
    let token = TokenStore::issue(&tokens_path, HOST, now + Duration::hours(1), now).unwrap();
    // CSR CN is a DIFFERENT valid uuid than the host_id we send.
    let other = "018f9c1a-0000-7000-8000-0000000000ff";
    let csr = make_csr(dir.path(), other);
    let app = build_router(st);

    let (status, body) = post_enroll(&app, &token, HOST, &csr).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"]["code"], "enrollment_denied");
}

#[tokio::test]
async fn bad_csr_is_400() {
    let dir = tempfile::tempdir().unwrap();
    let st = state(dir.path(), true);
    let tokens_path = st.enroll.as_ref().unwrap().tokens_path.clone();
    let now = OffsetDateTime::now_utc();
    let token = TokenStore::issue(&tokens_path, HOST, now + Duration::hours(1), now).unwrap();
    let app = build_router(st);

    let (status, body) = post_enroll(&app, &token, HOST, "this is not a csr").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body={body}");
    assert_eq!(body["error"]["code"], "bad_request");
}

#[tokio::test]
async fn bad_host_id_is_400() {
    let dir = tempfile::tempdir().unwrap();
    let st = state(dir.path(), true);
    let tokens_path = st.enroll.as_ref().unwrap().tokens_path.clone();
    let now = OffsetDateTime::now_utc();
    let token = TokenStore::issue(&tokens_path, HOST, now + Duration::hours(1), now).unwrap();
    let csr = make_csr(dir.path(), HOST);
    let app = build_router(st);

    let (status, body) = post_enroll(&app, &token, "not-a-uuid", &csr).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], "bad_request");
}

#[tokio::test]
async fn feature_off_is_404() {
    let dir = tempfile::tempdir().unwrap();
    let st = state(dir.path(), false); // no enroll configured
    let csr = make_csr(dir.path(), HOST);
    let app = build_router(st);

    let (status, body) = post_enroll(&app, "irrelevant", HOST, &csr).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"]["code"], "enroll_not_configured");
}

#[tokio::test]
async fn unknown_token_is_denied_403() {
    let dir = tempfile::tempdir().unwrap();
    let st = state(dir.path(), true);
    let csr = make_csr(dir.path(), HOST);
    let app = build_router(st);

    let (status, body) = post_enroll(&app, "totally-bogus-token", HOST, &csr).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"]["code"], "enrollment_denied");
}
