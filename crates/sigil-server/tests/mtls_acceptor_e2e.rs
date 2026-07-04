//! #194 — live-TLS e2e for `tls_accept::PeerCertAcceptor`: a REAL rustls
//! handshake (WebPkiClientVerifier), a REAL client cert, and the
//! `events_require_cert_host_match` gate — proving the acceptor extracts the
//! peer identity from the wire and injects it into requests, end to end.
//!
//! Uses openssl (on PATH in CI) for the test PKI and reqwest (rustls) as the
//! mTLS client. Binds 127.0.0.1:0.

use sigil_server::app::{build_router, AppState};
use sigil_server::auth::ReadToken;
use sigil_server::fleet_index::FleetIndex;
use sigil_server::persist::HighWater;
use sigil_server::tls_accept::PeerCertAcceptor;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

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

/// Self-signed CA (RSA 2048 — same profile as the enroll tests; parses with
/// ring across openssl/LibreSSL PKCS#8 output variants) used for BOTH the server cert and client certs.
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
        "1".as_ref(),
        "-subj".as_ref(),
        "/CN=test-e2e-ca".as_ref(),
        "-addext".as_ref(),
        "basicConstraints=critical,CA:TRUE".as_ref(),
        "-out".as_ref(),
        crt.as_os_str(),
    ]);
    (crt, key)
}

/// CA-signed leaf: key + cert paths. `ext` is an openssl x509 v3 ext block.
fn make_leaf(dir: &Path, name: &str, cn: &str, ext: &str) -> (PathBuf, PathBuf) {
    let key = dir.join(format!("{name}.key"));
    let csr = dir.join(format!("{name}.csr"));
    let crt = dir.join(format!("{name}.crt"));
    let extf = dir.join(format!("{name}.ext"));
    std::fs::write(&extf, ext).unwrap();
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
    run(&[
        "x509".as_ref(),
        "-req".as_ref(),
        "-in".as_ref(),
        csr.as_os_str(),
        "-CA".as_ref(),
        dir.join("ca.crt").as_os_str(),
        "-CAkey".as_ref(),
        dir.join("ca.key").as_os_str(),
        "-CAcreateserial".as_ref(),
        "-days".as_ref(),
        "1".as_ref(),
        "-extfile".as_ref(),
        extf.as_os_str(),
        "-out".as_ref(),
        crt.as_os_str(),
    ]);
    (crt, key)
}

fn state(dir: &Path, require_match: bool) -> Arc<AppState> {
    Arc::new(AppState {
        events_out_dir: dir.to_path_buf(),
        policy_bundle_path: dir.join("signed-policy.json"),
        rule_packs_bundle_path: None,
        artifacts_dir: None,
        high_water_path: dir.join(".high-water.json"),
        allowlist: parking_lot::RwLock::new(None), // permit-all: only #194.2 gates
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

/// rustls ServerConfig mirroring main.rs `build_mtls` (WebPkiClientVerifier).
fn tls_config(server_crt: &Path, server_key: &Path, ca: &Path) -> rustls::ServerConfig {
    let certs: Vec<_> = rustls_pemfile::certs(&mut std::io::BufReader::new(
        &std::fs::read(server_crt).unwrap()[..],
    ))
    .collect::<Result<_, _>>()
    .unwrap();
    let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(
        &std::fs::read(server_key).unwrap()[..],
    ))
    .unwrap()
    .unwrap();
    let ca_certs: Vec<_> = rustls_pemfile::certs(&mut std::io::BufReader::new(
        &std::fs::read(ca).unwrap()[..],
    ))
    .collect::<Result<_, _>>()
    .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    for c in ca_certs {
        roots.add(c).unwrap();
    }
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .unwrap();
    rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .unwrap()
}

fn events_body(host_id: &str) -> serde_json::Value {
    serde_json::json!({
        "envelope": {"host_id": host_id, "schema_version": 1},
        "events": [{
            "event_id": "00000000-0000-0000-0000-00000000000a",
            "sequence": 1,
            "payload": {
                "schema_version": 1,
                "event_id": "00000000-0000-0000-0000-00000000000a",
                "ts": "2026-07-01T00:00:00Z",
                "host_id": host_id,
                "agent_version": "0.1.0",
                "severity": "warn",
                "source": {"kind": "agent"},
                "subject": {"kind": "self"},
                "evidence": {"kind": "host_id_conflict", "observed_status": 200},
                "target_id": null
            },
        }],
    })
}

/// mTLS reqwest client presenting `crt`+`key`, trusting the test CA.
fn client(ca: &Path, crt: &Path, key: &Path) -> reqwest::Client {
    let mut identity_pem = std::fs::read(key).unwrap();
    identity_pem.extend_from_slice(&std::fs::read(crt).unwrap());
    reqwest::Client::builder()
        .use_rustls_tls()
        .add_root_certificate(reqwest::Certificate::from_pem(&std::fs::read(ca).unwrap()).unwrap())
        .identity(reqwest::Identity::from_pem(&identity_pem).unwrap())
        .build()
        .unwrap()
}

const HOST: &str = "018f9c1a-0000-7000-8000-0000000000e1";

#[tokio::test]
async fn live_mtls_cert_host_binding_end_to_end() {
    // rustls 0.23 needs a process default provider (same as main.rs).
    let _ = rustls::crypto::ring::default_provider().install_default();

    let dir = tempfile::tempdir().unwrap();
    make_ca(dir.path());
    let (srv_crt, srv_key) = make_leaf(
        dir.path(),
        "server",
        "localhost",
        "subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n",
    );
    // Agent cert: CN == host_id and SAN DNS:host_id (B-mint profile).
    let good_ext = format!(
        "subjectAltName=DNS:{HOST}\nextendedKeyUsage=clientAuth\nbasicConstraints=CA:FALSE\n"
    );
    let (good_crt, good_key) = make_leaf(dir.path(), "agent-good", HOST, &good_ext);
    // Valid fleet cert (chains to the CA!) but for a DIFFERENT host.
    let (other_crt, other_key) = make_leaf(
        dir.path(),
        "agent-other",
        "018f9c1a-0000-7000-8000-0000000000ff",
        "subjectAltName=DNS:018f9c1a-0000-7000-8000-0000000000ff\nextendedKeyUsage=clientAuth\nbasicConstraints=CA:FALSE\n",
    );

    let ca = dir.path().join("ca.crt");
    let tls = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(tls_config(
        &srv_crt, &srv_key, &ca,
    )));
    let app = build_router(state(dir.path(), true));
    let handle = axum_server::Handle::new();
    let server_handle = handle.clone();
    tokio::spawn(async move {
        axum_server::bind("127.0.0.1:0".parse().unwrap())
            .handle(server_handle)
            .acceptor(PeerCertAcceptor::new(tls))
            .serve(app.into_make_service())
            .await
            .unwrap();
    });
    let addr = handle.listening().await.expect("server must bind");
    let url = format!("https://127.0.0.1:{}/v1/events", addr.port());

    // Matching cert (CN + SAN == host_id) over a REAL handshake ⇒ accepted.
    let resp = client(&ca, &good_crt, &good_key)
        .post(&url)
        .json(&events_body(HOST))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "matching cert must be accepted");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["accepted"].as_array().unwrap().len(), 1);

    // Valid fleet cert for ANOTHER host claiming this host_id ⇒ 404, no oracle.
    let resp = client(&ca, &other_crt, &other_key)
        .post(&url)
        .json(&events_body(HOST))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404, "cross-host cert must be rejected");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "host_unknown");

    handle.shutdown();
}
