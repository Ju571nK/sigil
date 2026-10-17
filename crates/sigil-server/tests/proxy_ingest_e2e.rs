//! T-11 S4 B2 — live-TLS e2e for `POST /v1/proxy-events`, `POST
//! /v1/proxy-metadata` and the retention sweep (PX-005/010/011, AC-05/06;
//! ledger L5 SV-1..SV-5, registry R2).
//!
//! Real rustls handshakes; openssl builds the PKI (host CA, proxy CA, one
//! bundle, as production). reqwest is the mTLS client. Binds 127.0.0.1:0.
#![cfg(unix)]

use sigil_proxy_api::verifier::verifier_for;
use sigil_proxy_api::{ApiError, ErrorCode};
use sigil_server::app::{build_router_with_proxy, AppState};
use sigil_server::auth::ReadToken;
use sigil_server::config::ServerConfig;
use sigil_server::fleet_index::FleetIndex;
use sigil_server::persist::HighWater;
use sigil_server::proxy::identity::proxy_san;
use sigil_server::proxy::verifiers::{Scope, VerifierEntry};
use sigil_server::proxy::ProxyContext;
use sigil_server::tls_accept::PeerCertAcceptor;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

const READ_TOKEN: &str = "read-bearer-token";
const T_ID: &str = "tok-identity-CANARY-7f3a";
const T_CFG: &str = "tok-config-CANARY-9b1c";
const T_OTHER: &str = "tok-other-caller";
const T_EXPIRED: &str = "tok-expired";

// ---- PKI helpers (same approach as proxy_identity_e2e.rs) -------------------

/// Unique certificate serial per leaf (hex with 0x prefix). Passing `-set_serial`
/// avoids the shared `ca.srl` state file of `-CAcreateserial`.
fn next_serial() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(1);
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos() as u64);
    format!("0x{:x}", (t << 20) | N.fetch_add(1, Ordering::Relaxed))
}

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

fn genkey(path: &Path) {
    run(&[
        "genpkey".as_ref(),
        "-algorithm".as_ref(),
        "RSA".as_ref(),
        "-pkeyopt".as_ref(),
        "rsa_keygen_bits:2048".as_ref(),
        "-out".as_ref(),
        path.as_os_str(),
    ]);
}

fn make_ca(dir: &Path, name: &str, cn: &str) {
    let key = dir.join(format!("{name}.key"));
    genkey(&key);
    let subj = format!("/CN={cn}");
    run(&[
        "req".as_ref(),
        "-x509".as_ref(),
        "-new".as_ref(),
        "-key".as_ref(),
        key.as_os_str(),
        "-days".as_ref(),
        "1".as_ref(),
        "-subj".as_ref(),
        subj.as_ref(),
        "-addext".as_ref(),
        "basicConstraints=critical,CA:TRUE".as_ref(),
        "-addext".as_ref(),
        "subjectKeyIdentifier=hash".as_ref(),
        "-out".as_ref(),
        dir.join(format!("{name}.crt")).as_os_str(),
    ]);
}

fn make_leaf(dir: &Path, ca: &str, name: &str, cn: &str, ext: &str) -> (PathBuf, PathBuf) {
    let key = dir.join(format!("{name}.key"));
    let csr = dir.join(format!("{name}.csr"));
    let crt = dir.join(format!("{name}.crt"));
    let extf = dir.join(format!("{name}.ext"));
    std::fs::write(&extf, ext).unwrap();
    genkey(&key);
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
        dir.join(format!("{ca}.crt")).as_os_str(),
        "-CAkey".as_ref(),
        dir.join(format!("{ca}.key")).as_os_str(),
        "-set_serial".as_ref(),
        next_serial().as_str().as_ref(),
        "-days".as_ref(),
        "1".as_ref(),
        "-extfile".as_ref(),
        extf.as_os_str(),
        "-out".as_ref(),
        crt.as_os_str(),
    ]);
    (crt, key)
}

fn proxy_leaf(dir: &Path, name: &str, proxy_id: &str) -> (PathBuf, PathBuf) {
    let ext = format!(
        "subjectAltName=DNS:{}\nextendedKeyUsage=clientAuth\nbasicConstraints=CA:FALSE\nauthorityKeyIdentifier=keyid\n",
        proxy_san(proxy_id)
    );
    make_leaf(dir, "proxyca", name, proxy_id, &ext)
}

fn host_leaf(dir: &Path, name: &str, host_id: &str) -> (PathBuf, PathBuf) {
    let ext = format!(
        "subjectAltName=DNS:{host_id}\nextendedKeyUsage=clientAuth\nbasicConstraints=CA:FALSE\n"
    );
    make_leaf(dir, "hostca", name, host_id, &ext)
}

fn fingerprint(crt: &Path) -> String {
    let pem = std::fs::read(crt).unwrap();
    let mut rd = std::io::BufReader::new(&pem[..]);
    let certs: Vec<_> = rustls_pemfile::certs(&mut rd)
        .collect::<Result<_, _>>()
        .unwrap();
    blake3::hash(certs[0].as_ref()).to_hex().to_string()
}

fn state(dir: &Path) -> Arc<AppState> {
    Arc::new(AppState {
        events_out_dir: dir.to_path_buf(),
        policy_bundle_path: dir.join("signed-policy.json"),
        rule_packs_bundle_path: None,
        artifacts_dir: None,
        high_water_path: dir.join(".high-water.json"),
        allowlist: parking_lot::RwLock::new(None),
        high_water: Mutex::new(HighWater::default()),
        fleet_index: FleetIndex::new(),
        read_token: ReadToken(Some(READ_TOKEN.into())),
        active_window_days: 7,
        audit_key: None,
        audit_head: Mutex::new(None),
        allowlist_path: None,
        enroll: None,
        events_require_cert_host_match: false,
    })
}

fn tls_config(server_crt: &Path, server_key: &Path, bundle: &Path) -> rustls::ServerConfig {
    let read = |p: &Path| std::fs::read(p).unwrap();
    let certs: Vec<_> = rustls_pemfile::certs(&mut std::io::BufReader::new(&read(server_crt)[..]))
        .collect::<Result<_, _>>()
        .unwrap();
    let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(&read(server_key)[..]))
        .unwrap()
        .unwrap();
    let cas: Vec<_> = rustls_pemfile::certs(&mut std::io::BufReader::new(&read(bundle)[..]))
        .collect::<Result<_, _>>()
        .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    for c in cas {
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

fn client(trust: &Path, crt: &Path, key: &Path) -> reqwest::Client {
    let mut id = std::fs::read(key).unwrap();
    id.extend_from_slice(&std::fs::read(crt).unwrap());
    reqwest::Client::builder()
        .use_rustls_tls()
        .add_root_certificate(
            reqwest::Certificate::from_pem(&std::fs::read(trust).unwrap()).unwrap(),
        )
        .identity(reqwest::Identity::from_pem(&id).unwrap())
        .build()
        .unwrap()
}

fn entry(id: &str, token: &str, scope: Scope, fp: &str, na: Option<&str>) -> VerifierEntry {
    VerifierEntry {
        key_id: id.into(),
        name: format!("{id}-name"),
        verifier: verifier_for(token),
        scope,
        caller_cert_fingerprint: fp.into(),
        not_after: na.map(str::to_string),
    }
}

fn write_verifiers(path: &Path, entries: &[VerifierEntry]) {
    std::fs::write(
        path,
        serde_json::to_vec(&serde_json::json!({"entries": entries})).unwrap(),
    )
    .unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

/// Test PKI + a running server with management enabled.
struct Fx {
    dir: tempfile::TempDir,
    port: u16,
    ctx: Arc<ProxyContext>,
    mgmt: (PathBuf, PathBuf),
    #[allow(dead_code)]
    mgmt_fp: String,
}

impl Fx {
    fn p(&self, f: &str) -> PathBuf {
        self.dir.path().join(f)
    }
    fn mgmt_client(&self) -> reqwest::Client {
        client(&self.p("hostca.crt"), &self.mgmt.0, &self.mgmt.1)
    }
    fn client_for(&self, crt: &Path, key: &Path) -> reqwest::Client {
        client(&self.p("hostca.crt"), crt, key)
    }

    fn prepare(
        extra_entries: impl FnOnce(&str, &str) -> Vec<VerifierEntry>,
    ) -> (tempfile::TempDir, (PathBuf, PathBuf), String) {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        make_ca(d, "hostca", "test-host-ca");
        make_ca(d, "proxyca", "test-proxy-ca");
        let mut bundle = std::fs::read(d.join("hostca.crt")).unwrap();
        bundle.extend(std::fs::read(d.join("proxyca.crt")).unwrap());
        std::fs::write(d.join("bundle.pem"), bundle).unwrap();
        make_leaf(
            d,
            "hostca",
            "server",
            "localhost",
            "subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n",
        );
        let mgmt = host_leaf(d, "mgmt", "mgmt-operator");
        let (m2, _) = host_leaf(d, "mgmt2", "mgmt-operator-2");
        let (fp, fp2) = (fingerprint(&mgmt.0), fingerprint(&m2));
        write_verifiers(&d.join("verifiers.json"), &extra_entries(&fp, &fp2));
        (dir, mgmt, fp)
    }

    fn default_entries(fp: &str, fp2: &str) -> Vec<VerifierEntry> {
        vec![
            entry("idk", T_ID, Scope::Identity, fp, None),
            entry("cfgk", T_CFG, Scope::Config, fp, None),
            entry("othk", T_OTHER, Scope::Identity, fp2, None),
            entry(
                "expk",
                T_EXPIRED,
                Scope::Config,
                fp,
                Some("2000-01-01T00:00:00Z"),
            ),
        ]
    }

    fn config(dir: &Path) -> ServerConfig {
        let p = |f: &str| dir.join(f).display().to_string();
        let y = format!(
            "bind: \"127.0.0.1:0\"\ntls_cert_path: {}\ntls_key_path: {}\nclient_ca_path: {}\n\
             events_out_dir: {}\npolicy_bundle_path: {}\n\
             proxy:\n  ca_path: {}\n  registry_path: {}\n  registry_init: true\n  management_verifiers: {}\n",
            p("server.crt"),
            p("server.key"),
            p("bundle.pem"),
            dir.display(),
            p("signed-policy.json"),
            p("proxyca.crt"),
            p("proxies.json"),
            p("verifiers.json"),
        );
        serde_yaml::from_str(&y).unwrap()
    }

    async fn start_with(
        dir: tempfile::TempDir,
        mgmt: (PathBuf, PathBuf),
        mgmt_fp: String,
        cfg: ServerConfig,
    ) -> Fx {
        let d = dir.path();
        let ctx = Arc::new(ProxyContext::load(&cfg).unwrap().unwrap());
        let tls = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(tls_config(
            &d.join("server.crt"),
            &d.join("server.key"),
            &d.join("bundle.pem"),
        )));
        let app = build_router_with_proxy(state(d), Some(ctx.clone()));
        let handle = axum_server::Handle::new();
        let h = handle.clone();
        tokio::spawn(async move {
            axum_server::bind("127.0.0.1:0".parse().unwrap())
                .handle(h)
                .acceptor(PeerCertAcceptor::new(tls))
                .serve(app.into_make_service())
                .await
                .unwrap();
        });
        let port = handle.listening().await.expect("server must bind").port();
        Fx {
            dir,
            port,
            ctx,
            mgmt,
            mgmt_fp,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Resp {
    status: u16,
    content_type: Option<String>,
    body: Vec<u8>,
}

impl Resp {
    fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap_or(serde_json::Value::Null)
    }
    fn code(&self) -> String {
        self.json()["error"]["code"]
            .as_str()
            .unwrap_or("")
            .to_string()
    }
}

async fn send(
    c: &reqwest::Client,
    port: u16,
    method: &str,
    path: &str,
    bearer: Option<&str>,
    body: Option<&str>,
) -> Resp {
    try_send(c, port, method, path, bearer, body).await.unwrap()
}

/// Like `send`, but a transport error is returned. The server answers before it
/// reads a big body, so the client may see the connection close while it is
/// still writing (broken pipe) instead of the response: both are a refusal.
async fn try_send(
    c: &reqwest::Client,
    port: u16,
    method: &str,
    path: &str,
    bearer: Option<&str>,
    body: Option<&str>,
) -> Result<Resp, reqwest::Error> {
    let url = format!("https://127.0.0.1:{port}{path}");
    let mut rb = c.request(reqwest::Method::from_bytes(method.as_bytes()).unwrap(), url);
    if let Some(b) = bearer {
        rb = rb.bearer_auth(b);
    }
    if let Some(b) = body {
        rb = rb
            .header("content-type", "application/json")
            .body(b.to_string());
    }
    let r = rb.send().await?;
    let content_type = r
        .headers()
        .get("content-type")
        .map(|v| v.to_str().unwrap().to_string());
    Ok(Resp {
        status: r.status().as_u16(),
        content_type,
        body: r.bytes().await?.to_vec(),
    })
}

/// A proxy with one active certificate and its client.
struct Px {
    id: String,
    client: reqwest::Client,
}

async fn proxy(fx: &Fx, id: &str) -> Px {
    let cert = proxy_leaf(fx.dir.path(), id, id);
    let mc = fx.mgmt_client();
    let r = send(
        &mc,
        fx.port,
        "POST",
        "/v1/proxies",
        Some(T_ID),
        Some(&format!(
            r#"{{"proxy_id":"{id}","display_name":"Proxy {id}"}}"#
        )),
    )
    .await;
    assert_eq!(r.status, 201);
    let r = send(
        &mc,
        fx.port,
        "POST",
        &format!("/v1/proxies/{id}/fingerprints"),
        Some(T_ID),
        Some(&format!(r#"{{"fingerprint":"{}"}}"#, fingerprint(&cert.0))),
    )
    .await;
    assert_eq!(r.status, 200);
    let client = fx.client_for(&cert.0, &cert.1);
    Px {
        id: id.into(),
        client,
    }
}

fn spec(proxy_id: &str, token: &str) -> serde_json::Value {
    serde_json::json!({
        "schema_version": 1,
        "proxy_id": proxy_id,
        "allowed_origins": ["https://app.example.com"],
        "routes": [{
            "route_id": "r1",
            "upstream_id": "up1",
            "upstream_url": "https://api.example.com/mcp",
            "upstream_protocol": "2025-11-25",
            "credential_ref": "gh",
        }],
        "principals": [{
            "principal_id": "claude",
            "verifiers": [{"key_id": "k1", "verifier": verifier_for(token)}],
            "routes": ["r1"],
        }],
    })
}

fn put_body(expected: u64, spec: &serde_json::Value) -> String {
    serde_json::json!({"expected_revision": expected, "config": spec}).to_string()
}

async fn put(fx: &Fx, id: &str, bearer: Option<&str>, body: &str) -> Resp {
    send(
        &fx.mgmt_client(),
        fx.port,
        "PUT",
        &format!("/v1/proxies/{id}/config"),
        bearer,
        Some(body),
    )
    .await
}

fn status_body(proxy_id: &str, epoch: &str, seq: u32, gaps: Vec<serde_json::Value>) -> String {
    serde_json::json!({
        "schema_version": 1, "report_id": uid(5000 + seq), "proxy_id": proxy_id,
        "epoch_id": epoch, "status_sequence": seq, "sent_at": "2026-10-11T00:00:00Z",
        "config": {"state": "none", "applied_revision": null,
            "observed_desired_revision": null, "expires_at": null},
        "spool": {"state": "ok", "depth_events": 0, "unsent_events": 0, "bytes": 0,
            "capacity_bytes": 1000, "oldest_unsent_age_seconds": null,
            "quarantined_events": 0},
        "registry": {"pending_entries": 0, "sync_stalled": false},
        "central": {"last_ingest_ack_at": null, "consecutive_failures": 0},
        "routes": [], "counters": {"auth_failures": [], "unmatched_cancels": []},
        "gaps": gaps, "last_assigned_sequence": 0,
    })
    .to_string()
}

const EPOCH: &str = "00000000-0000-4000-8000-0000000000e1";

async fn post_status(fx: &Fx, px: &Px, body: &str) -> Resp {
    send(
        &px.client,
        fx.port,
        "POST",
        "/v1/proxy-status",
        None,
        Some(body),
    )
    .await
}

// ---- S4 B2 helpers ---------------------------------------------------------------

use serde_json::{json, Value};

const EP: &str = "00000000-0000-4000-8000-0000000000e1";

fn uid(n: u32) -> String {
    format!("00000000-0000-4000-8000-{n:012}")
}

/// RFC 9562 version-8 UUID, the shape `metadata_ref` requires.
fn mref(n: u32) -> String {
    format!("00000000-0000-8000-8000-{n:012}")
}

fn err_body(code: ErrorCode) -> Vec<u8> {
    serde_json::to_vec(&ApiError::from_code(code)).unwrap()
}

/// `invocation.started`. `n` is the event id and the sequence; `inv` the
/// invocation. With `tool`, a `tools/call` naming that metadata ref.
fn started(
    proxy: &str,
    n: u32,
    inv: u32,
    tool: Option<&str>,
    upstream: &str,
    proto: &str,
) -> Value {
    let mut payload = json!({
        "invocation_id": uid(1000 + inv),
        "upstream_id": upstream,
        "route_revision": 1,
        "protocol_version": proto,
        "method": "ping",
        "actor": {
            "actor_id": "actor-1",
            "actor_kind": "non_human",
            "authentication_method": "bearer",
            "evidence_source": "proxy_credential_mapping"
        }
    });
    if let Some(r) = tool {
        payload["method"] = "tools/call".into();
        payload["tool"] = json!({"status": "identified", "metadata_ref": r});
    }
    json!({
        "schema_version": 1,
        "event_id": uid(n),
        "proxy_id": proxy,
        "epoch_id": EP,
        "sequence": n,
        "occurred_at": "2026-10-10T00:00:00Z",
        "event_type": "invocation.started",
        "payload": payload,
    })
}

fn ping(proxy: &str, n: u32) -> Value {
    started(proxy, n, n, None, "up1", "unknown")
}

fn call(proxy: &str, n: u32, r: &str) -> Value {
    started(proxy, n, n, Some(r), "up1", "2025-11-25")
}

fn batch(evs: &[Value]) -> String {
    json!({ "events": evs }).to_string()
}

fn entry_json(proxy: &str, r: &str, scope: &str, fp: char) -> Value {
    json!({
        "proxy_id": proxy,
        "metadata_ref": r,
        "upstream_id": "up1",
        "credential_scope_id": scope,
        "protocol_version": "2025-11-25",
        "observation_source": "proxy_live",
        "canon": "sigil-tooldef-fp-v1",
        "key_id": "kid-000000000000000000000001",
        "fingerprint": fp.to_string().repeat(64),
        "observed_at": "2026-10-10T00:00:00Z",
        "definition": {"name": "CANARY-TOOL-NAME", "description": "CANARY-DESC"},
    })
}

fn upload_body(proxy: &str, entries: &[Value]) -> String {
    json!({"schema_version": 1, "proxy_id": proxy, "entries": entries}).to_string()
}

async fn events(fx: &Fx, px: &Px, body: &str) -> Resp {
    send(
        &px.client,
        fx.port,
        "POST",
        "/v1/proxy-events",
        None,
        Some(body),
    )
    .await
}

async fn upload(fx: &Fx, px: &Px, body: &str) -> Resp {
    send(
        &px.client,
        fx.port,
        "POST",
        "/v1/proxy-metadata",
        None,
        Some(body),
    )
    .await
}

fn items(r: &Resp) -> Vec<Value> {
    r.json()["error"]["items"]
        .as_array()
        .cloned()
        .unwrap_or_default()
}

fn ids(v: &Value) -> Vec<String> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap().to_string())
        .collect()
}

/// Two registered proxies with a config each (so scopes are assigned).
struct Env {
    fx: Fx,
    a: Px,
    b: Px,
}

impl Env {
    async fn new() -> Env {
        Self::with(|_| {}).await
    }

    async fn with(f: impl FnOnce(&mut sigil_server::config::ProxyConfig)) -> Env {
        let (dir, mgmt, fp) = Fx::prepare(Fx::default_entries);
        let mut cfg = Fx::config(dir.path());
        f(cfg.proxy.as_mut().unwrap());
        let fx = Fx::start_with(dir, mgmt, fp, cfg).await;
        let a = proxy(&fx, "pxa").await;
        let b = proxy(&fx, "pxb").await;
        for (id, tok) in [("pxa", "tok-a"), ("pxb", "tok-b")] {
            let r = put(&fx, id, Some(T_CFG), &put_body(0, &spec(id, tok))).await;
            assert_eq!(r.status, 200);
        }
        Env { fx, a, b }
    }

    fn scope(&self, id: &str) -> String {
        self.fx.ctx.store.config(id).unwrap().config.routes[0]
            .credential_scope_id
            .as_str()
            .to_string()
    }

    async fn register(&self, px: &Px, r: &str) {
        let e = entry_json(&px.id, r, &self.scope(&px.id), 'a');
        let resp = upload(&self.fx, px, &upload_body(&px.id, &[e])).await;
        assert_eq!(resp.status, 200, "{}", String::from_utf8_lossy(&resp.body));
    }

    fn stored(&self, px: &str, n: u32) -> bool {
        self.fx
            .ctx
            .ledger
            .stored_event(px, &uid(n))
            .unwrap()
            .is_some()
    }
}

// ---- tests -------------------------------------------------------------------------

#[tokio::test]
async fn identity_is_checked_before_the_body_is_read() {
    let env = Env::new().await;
    let fx = &env.fx;
    let big = "x".repeat(2 * 1024 * 1024);

    // A host-class certificate, and a proxy certificate nobody registered, get
    // the same bytes as any other unknown proxy, whatever the body is.
    let host = host_leaf(fx.dir.path(), "h1", "host-1");
    let ghost = proxy_leaf(fx.dir.path(), "ghost", "ghost");
    let clients = [
        fx.client_for(&host.0, &host.1),
        fx.client_for(&ghost.0, &ghost.1),
    ];
    for c in &clients {
        for path in ["/v1/proxy-events", "/v1/proxy-metadata"] {
            for body in [big.as_str(), "{", ""] {
                // A transport error is only acceptable for the big body: the
                // server refused before reading it.
                match try_send(c, fx.port, "POST", path, None, Some(body)).await {
                    Ok(r) => assert_eq!(
                        (r.status, r.body.clone()),
                        (404, err_body(ErrorCode::ProxyUnknown))
                    ),
                    Err(_) => assert_eq!(body.len(), big.len(), "small bodies must get the 404"),
                }
            }
        }
    }

    // A disabled proxy is a 403 before the size check and before the parse.
    let r = send(
        &fx.mgmt_client(),
        fx.port,
        "POST",
        "/v1/proxies/pxa/disable",
        Some(T_CFG),
        None,
    )
    .await;
    assert_eq!(r.status, 200);
    for path in ["/v1/proxy-events", "/v1/proxy-metadata"] {
        for body in [big.as_str(), "{"] {
            match try_send(&env.a.client, fx.port, "POST", path, None, Some(body)).await {
                Ok(r) => assert_eq!((r.status, r.body), (403, err_body(ErrorCode::Disabled))),
                Err(_) => assert_eq!(body.len(), big.len(), "small bodies must get the 403"),
            }
        }
    }
    assert!(!env.stored("pxa", 1));
    // The other proxy is unaffected.
    let r = events(fx, &env.b, &batch(&[ping("pxb", 1)])).await;
    assert_eq!(r.status, 200);
}

#[tokio::test]
async fn event_answers_and_precedence() {
    let env = Env::new().await;
    let (fx, a) = (&env.fx, &env.a);

    // 200 accepted, then the same event is a duplicate.
    let r = events(fx, a, &batch(&[ping("pxa", 1), ping("pxa", 2)])).await;
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(ids(&r.json()["accepted_event_ids"]), [uid(1), uid(2)]);
    assert!(ids(&r.json()["duplicate_event_ids"]).is_empty());
    let r = events(fx, a, &batch(&[ping("pxa", 1), ping("pxa", 3)])).await;
    assert_eq!(r.status, 200);
    assert_eq!(ids(&r.json()["accepted_event_ids"]), [uid(3)]);
    assert_eq!(ids(&r.json()["duplicate_event_ids"]), [uid(1)]);

    // 422 at request level; the index of the first bad event when known;
    // nothing of the batch is stored; no input value is echoed.
    let r = events(fx, a, "{").await;
    assert_eq!((r.status, r.code().as_str()), (422, "semantic_invalid"));
    assert!(items(&r).is_empty());
    let mut bad = ping("pxa", 11);
    bad["payload"]["actor"]["actor_id"] = "CANARY-ACTOR".into();
    bad["payload"]["CANARY_FIELD"] = "CANARY-VALUE".into();
    let r = events(fx, a, &batch(&[ping("pxa", 10), bad])).await;
    assert_eq!((r.status, r.code().as_str()), (422, "semantic_invalid"));
    let it = items(&r);
    assert_eq!(it.len(), 1);
    assert_eq!(
        (it[0]["index"].as_u64(), it[0]["code"].as_str()),
        (Some(1), Some("semantic_invalid"))
    );
    assert!(it[0].get("event_id").is_none());
    assert!(!String::from_utf8_lossy(&r.body).contains("CANARY"));
    assert!(!env.stored("pxa", 10), "all or nothing");

    // A foreign proxy_id is the identity 404, even next to a malformed event.
    let r = events(fx, a, &batch(&[ping("pxb", 12)])).await;
    assert_eq!((r.status, r.body), (404, err_body(ErrorCode::ProxyUnknown)));
    let r = events(fx, a, &batch(&[ping("pxa", 13), ping("pxb", 14)])).await;
    assert_eq!(r.status, 404);
    let mut malformed = ping("pxa", 15);
    malformed["sequence"] = "CANARY".into();
    let r = events(fx, a, &batch(&[malformed, ping("pxb", 16)])).await;
    assert_eq!((r.status, r.body), (404, err_body(ErrorCode::ProxyUnknown)));
    assert!(!env.stored("pxa", 13) && !env.stored("pxb", 14));

    // 413: over 1 MiB, and more than 100 events.
    let pad = "x".repeat(1024 * 1024 + 1);
    let r = events(fx, a, &pad).await;
    assert_eq!(
        (r.status, r.body),
        (413, err_body(ErrorCode::PayloadTooLarge))
    );
    let many: Vec<Value> = (100..201).map(|n| ping("pxa", n)).collect();
    let r = events(fx, a, &batch(&many)).await;
    assert_eq!((r.status, r.code().as_str()), (413, "payload_too_large"));
    assert!(!env.stored("pxa", 100));

    // 409: conflict, sequence_conflict, invocation_owner_conflict. A fresh
    // event in the same batch is not stored.
    let mut changed = ping("pxa", 1);
    changed["occurred_at"] = "2026-10-10T00:00:05Z".into();
    let r = events(fx, a, &batch(&[ping("pxa", 20), changed])).await;
    assert_eq!((r.status, r.code().as_str()), (409, "conflict"));
    let it = items(&r);
    assert_eq!(it.len(), 1);
    assert_eq!(
        (
            it[0]["index"].as_u64(),
            it[0]["event_id"].as_str(),
            it[0]["code"].as_str()
        ),
        (Some(1), Some(uid(1).as_str()), Some("conflict"))
    );
    assert!(!env.stored("pxa", 20));
    let mut same_seq = ping("pxa", 21);
    same_seq["sequence"] = 1.into();
    let r = events(fx, a, &batch(&[same_seq])).await;
    assert_eq!(r.status, 409);
    assert_eq!(items(&r)[0]["code"], "sequence_conflict");
    let r = events(
        fx,
        &env.b,
        &batch(&[started("pxb", 30, 77, None, "up1", "unknown")]),
    )
    .await;
    assert_eq!(r.status, 200);
    let r = events(
        fx,
        a,
        &batch(&[started("pxa", 31, 77, None, "up1", "unknown")]),
    )
    .await;
    assert_eq!(r.status, 409);
    assert_eq!(items(&r)[0]["code"], "invocation_owner_conflict");
    assert_eq!(items(&r)[0]["event_id"], uid(31));
    assert!(!env.stored("pxa", 31));

    // 424 with the pending refs; the valid event next to it is not stored.
    let r = events(fx, a, &batch(&[ping("pxa", 40), call("pxa", 41, &mref(1))])).await;
    assert_eq!((r.status, r.code().as_str()), (424, "metadata_ref_pending"));
    let it = items(&r);
    assert_eq!(it.len(), 1);
    assert_eq!(
        (
            it[0]["index"].as_u64(),
            it[0]["event_id"].as_str(),
            it[0]["code"].as_str()
        ),
        (
            Some(1),
            Some(uid(41).as_str()),
            Some("metadata_ref_pending")
        )
    );
    assert_eq!(ids(&r.json()["error"]["pending_metadata_refs"]), [mref(1)]);
    assert!(!env.stored("pxa", 40) && !env.stored("pxa", 41));

    // Precedence 409 > 424: a conflict and a pending ref answer 409.
    let r = events(fx, a, &batch(&[changed_copy(), call("pxa", 42, &mref(1))])).await;
    assert_eq!((r.status, r.code().as_str()), (409, "conflict"));
    assert!(r.json()["error"].get("pending_metadata_refs").is_none());

    // Precedence 422 > 409 > 424: SV-3 (ref registered only under pxb).
    env.register(&env.b, &mref(9)).await;
    let r = events(
        fx,
        a,
        &batch(&[
            call("pxa", 43, &mref(9)),
            changed_copy(),
            call("pxa", 44, &mref(1)),
        ]),
    )
    .await;
    assert_eq!((r.status, r.code().as_str()), (422, "semantic_invalid"));
    let it = items(&r);
    assert_eq!(it.len(), 1);
    assert_eq!(it[0]["index"], 0);
    assert!(!String::from_utf8_lossy(&r.body).contains(&mref(9)));
    assert!(!env.stored("pxa", 43));

    // Once registered the same batch is accepted.
    env.register(a, &mref(1)).await;
    let r = events(fx, a, &batch(&[ping("pxa", 40), call("pxa", 41, &mref(1))])).await;
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(ids(&r.json()["accepted_event_ids"]), [uid(40), uid(41)]);
    assert!(env.stored("pxa", 41));
}

/// An event that conflicts with the stored event 1.
fn changed_copy() -> Value {
    let mut c = ping("pxa", 1);
    c["occurred_at"] = "2026-10-10T00:00:09Z".into();
    c
}

#[tokio::test]
async fn sv4_reference_scope_is_checked() {
    let env = Env::new().await;
    let (fx, a) = (&env.fx, &env.a);
    env.register(a, &mref(2)).await;
    // The entry is for up1: a start on up2 naming it is permanent 422.
    let r = events(
        fx,
        a,
        &batch(&[started("pxa", 1, 1, Some(&mref(2)), "up2", "2025-11-25")]),
    )
    .await;
    assert_eq!((r.status, r.code().as_str()), (422, "semantic_invalid"));
    assert_eq!(items(&r)[0]["index"], 0);
    // protocol_version unknown with a 2025-11-25 entry is accepted.
    let r = events(
        fx,
        a,
        &batch(&[started("pxa", 2, 2, Some(&mref(2)), "up1", "unknown")]),
    )
    .await;
    assert_eq!(r.status, 200);
    let r = events(fx, a, &batch(&[call("pxa", 3, &mref(2))])).await;
    assert_eq!(r.status, 200);
}

#[tokio::test]
async fn metadata_upload_rules() {
    let env = Env::new().await;
    let (fx, a, b) = (&env.fx, &env.a, &env.b);
    let sa = env.scope("pxa");

    // 200 registered, then an equal entry is a duplicate (first write wins).
    let e1 = entry_json("pxa", &mref(1), &sa, 'a');
    let r = upload(
        fx,
        a,
        &upload_body("pxa", &[e1.clone(), entry_json("pxa", &mref(2), &sa, 'b')]),
    )
    .await;
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(
        ids(&r.json()["registered_metadata_refs"]),
        [mref(1), mref(2)]
    );
    let mut again = e1.clone();
    again["definition"] = json!({"name": "other"});
    again["observed_at"] = "2026-10-11T00:00:00Z".into();
    let r = upload(
        fx,
        a,
        &upload_body("pxa", &[again, entry_json("pxa", &mref(3), &sa, 'c')]),
    )
    .await;
    assert_eq!(r.status, 200);
    assert_eq!(ids(&r.json()["registered_metadata_refs"]), [mref(3)]);
    assert_eq!(ids(&r.json()["duplicate_metadata_refs"]), [mref(1)]);
    assert_eq!(fx.ctx.metadata.count("pxa").unwrap(), 3);

    // 409 registry_conflict on a different immutable field; all or nothing.
    let mut conflict = e1.clone();
    conflict["fingerprint"] = "f".repeat(64).into();
    let r = upload(
        fx,
        a,
        &upload_body("pxa", &[entry_json("pxa", &mref(4), &sa, 'd'), conflict]),
    )
    .await;
    assert_eq!((r.status, r.code().as_str()), (409, "registry_conflict"));
    let it = items(&r);
    assert_eq!(
        (it.len(), it[0]["index"].as_u64(), it[0]["code"].as_str()),
        (1, Some(1), Some("registry_conflict"))
    );
    assert!(!String::from_utf8_lossy(&r.body).contains(&"f".repeat(64)));
    assert_eq!(
        fx.ctx.metadata.count("pxa").unwrap(),
        3,
        "mref(4) not stored"
    );
    // The same ref under another proxy is a different key and is fine.
    env.register(b, &mref(1)).await;

    // 422: a scope the server did not assign; an oversized definition. 422
    // outranks the 409 in the same batch. Index only, no echo.
    let mut wrong = entry_json("pxa", &mref(5), "cs-CANARYSCOPE", 'e');
    let r = upload(fx, a, &upload_body("pxa", &[e1.clone(), wrong.clone()])).await;
    assert_eq!((r.status, r.code().as_str()), (422, "semantic_invalid"));
    assert_eq!(items(&r).len(), 1);
    assert_eq!(items(&r)[0]["index"], 1);
    assert!(!String::from_utf8_lossy(&r.body).contains("CANARY"));
    wrong = entry_json("pxa", &mref(5), &sa, 'e');
    wrong["definition"] = json!({"pad": "x".repeat(257 * 1024)});
    let r = upload(fx, a, &upload_body("pxa", &[wrong])).await;
    assert_eq!((r.status, r.code().as_str()), (422, "semantic_invalid"));
    // pxb's scope is not pxa's.
    let r = upload(
        fx,
        a,
        &upload_body(
            "pxa",
            &[entry_json("pxa", &mref(6), &env.scope("pxb"), 'e')],
        ),
    )
    .await;
    assert_eq!(r.status, 422);
    // Schema violations are 422 with the entry's index when known.
    let mut broken = entry_json("pxa", &mref(7), &sa, 'e');
    broken["fingerprint"] = "short".into();
    let r = upload(
        fx,
        a,
        &upload_body("pxa", &[entry_json("pxa", &mref(8), &sa, 'e'), broken]),
    )
    .await;
    assert_eq!(r.status, 422);
    assert_eq!(items(&r)[0]["index"], 1);
    assert_eq!(fx.ctx.metadata.count("pxa").unwrap(), 3);

    // Cross-identity: the body proxy_id, or any entry's, must be the caller's.
    let r = upload(
        fx,
        a,
        &upload_body(
            "pxb",
            &[entry_json("pxb", &mref(20), &env.scope("pxb"), 'e')],
        ),
    )
    .await;
    assert_eq!((r.status, r.body), (404, err_body(ErrorCode::ProxyUnknown)));
    let r = upload(
        fx,
        a,
        &upload_body(
            "pxa",
            &[
                entry_json("pxa", &mref(21), &sa, 'e'),
                entry_json("pxb", &mref(22), &env.scope("pxb"), 'e'),
            ],
        ),
    )
    .await;
    assert_eq!((r.status, r.body), (404, err_body(ErrorCode::ProxyUnknown)));
    // ... even when the rest of the body is malformed.
    let r = upload(fx, a, r#"{"proxy_id":"pxb","entries":"CANARY"}"#).await;
    assert_eq!((r.status, r.body), (404, err_body(ErrorCode::ProxyUnknown)));
    assert_eq!(fx.ctx.metadata.count("pxb").unwrap(), 1);

    // Request-level failures.
    let r = upload(fx, a, "{").await;
    assert_eq!(r.status, 422);
    let r = upload(fx, a, &"x".repeat(4 * 1024 * 1024 + 1)).await;
    assert_eq!(
        (r.status, r.body),
        (413, err_body(ErrorCode::PayloadTooLarge))
    );
    let many: Vec<Value> = (100..201)
        .map(|n| entry_json("pxa", &mref(n), &sa, 'a'))
        .collect();
    let r = upload(fx, a, &upload_body("pxa", &many)).await;
    assert_eq!(r.status, 413);
}

#[tokio::test]
async fn sv5_accepts_the_previous_and_current_scope_across_a_route_edit() {
    let env = Env::new().await;
    let (fx, a) = (&env.fx, &env.a);
    let s1 = env.scope("pxa");
    env.register(a, &mref(1)).await;

    // Edit 1: a new credential_ref changes the scope id.
    let edit = |cred: &str| {
        let mut s = spec("pxa", "tok-a");
        s["routes"][0]["credential_ref"] = cred.into();
        s
    };
    let r = put(fx, "pxa", Some(T_CFG), &put_body(1, &edit("gh2"))).await;
    assert_eq!(r.status, 200);
    let s2 = env.scope("pxa");
    assert_ne!(s1, s2);
    // The proxy still mints under the old scope until it applies revision 2:
    // events naming the old entry and uploads under the old scope are fine.
    let r = events(fx, a, &batch(&[call("pxa", 1, &mref(1))])).await;
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let r = upload(
        fx,
        a,
        &upload_body("pxa", &[entry_json("pxa", &mref(2), &s1, 'b')]),
    )
    .await;
    assert_eq!(r.status, 200);
    // New-scope entries work too.
    let r = upload(
        fx,
        a,
        &upload_body("pxa", &[entry_json("pxa", &mref(3), &s2, 'c')]),
    )
    .await;
    assert_eq!(r.status, 200);
    let r = events(fx, a, &batch(&[call("pxa", 2, &mref(3))])).await;
    assert_eq!(r.status, 200);

    // Edit 2: only the previous revision's scope (s2) and the current (s3)
    // are accepted; s1 is two revisions back.
    let r = put(fx, "pxa", Some(T_CFG), &put_body(2, &edit("gh3"))).await;
    assert_eq!(r.status, 200);
    let s3 = env.scope("pxa");
    let r = events(fx, a, &batch(&[call("pxa", 3, &mref(1))])).await;
    assert_eq!((r.status, r.code().as_str()), (422, "semantic_invalid"));
    assert_eq!(items(&r)[0]["index"], 0);
    let r = events(fx, a, &batch(&[call("pxa", 3, &mref(3))])).await;
    assert_eq!(r.status, 200);
    let r = upload(
        fx,
        a,
        &upload_body("pxa", &[entry_json("pxa", &mref(4), &s1, 'd')]),
    )
    .await;
    assert_eq!(r.status, 422);
    let r = upload(
        fx,
        a,
        &upload_body("pxa", &[entry_json("pxa", &mref(5), &s3, 'e')]),
    )
    .await;
    assert_eq!(r.status, 200);

    // A status report (same revision) does not disturb the history.
    let r = post_status(fx, a, &status_body("pxa", EPOCH, 1, vec![])).await;
    assert_eq!(r.status, 200);
    let r = events(fx, a, &batch(&[call("pxa", 4, &mref(3))])).await;
    assert_eq!(r.status, 200);
}

#[tokio::test]
async fn backpressure_and_storage_answers() {
    // 429: with the only slot taken the body is not even read.
    let env = Env::with(|p| p.ingest_max_concurrent = Some(1)).await;
    let (fx, a) = (&env.fx, &env.a);
    let permit = fx.ctx.ingest_slots.clone().try_acquire_owned().unwrap();
    let r = events(fx, a, &batch(&[ping("pxa", 1)])).await;
    assert_eq!((r.status, r.body), (429, err_body(ErrorCode::RateLimited)));
    let r = upload(fx, a, "{").await;
    assert_eq!((r.status, r.code().as_str()), (429, "rate_limited"));
    assert!(!env.stored("pxa", 1));
    drop(permit);
    let r = events(fx, a, &batch(&[ping("pxa", 1)])).await;
    assert_eq!(r.status, 200);
    // The slot is released after every request.
    let r = events(fx, a, &batch(&[ping("pxa", 2)])).await;
    assert_eq!(r.status, 200);
    assert_eq!(fx.ctx.ingest_slots.available_permits(), 1);

    // 503 storage_limit: one row allowed.
    let env = Env::with(|p| {
        p.ledger_max_rows_per_proxy = Some(1);
        p.metadata_max_entries_per_proxy = Some(1);
    })
    .await;
    let (fx, a) = (&env.fx, &env.a);
    let r = events(fx, a, &batch(&[ping("pxa", 1)])).await;
    assert_eq!(r.status, 200);
    let r = events(fx, a, &batch(&[ping("pxa", 2)])).await;
    assert_eq!((r.status, r.body), (503, err_body(ErrorCode::StorageLimit)));
    assert!(env.stored("pxa", 1) && !env.stored("pxa", 2));
    env.register(a, &mref(1)).await;
    let sa = env.scope("pxa");
    let r = upload(
        fx,
        a,
        &upload_body("pxa", &[entry_json("pxa", &mref(2), &sa, 'b')]),
    )
    .await;
    assert_eq!((r.status, r.body), (503, err_body(ErrorCode::StorageLimit)));
    assert_eq!(fx.ctx.metadata.count("pxa").unwrap(), 1);

    // 503 storage_unavailable: break the ledger table behind the server's back.
    let env = Env::new().await;
    let (fx, a) = (&env.fx, &env.a);
    let conn = rusqlite::Connection::open(fx.p("proxy-ledger.sqlite")).unwrap();
    conn.execute_batch("DROP TABLE tombstones;").unwrap();
    let r = events(fx, a, &batch(&[ping("pxa", 1)])).await;
    assert_eq!(
        (r.status, r.body),
        (503, err_body(ErrorCode::StorageUnavailable))
    );
}

#[tokio::test]
async fn the_retention_sweep_runs_on_a_schedule() {
    let env = Env::new().await;
    let (fx, a) = (&env.fx, &env.a);
    let r = events(fx, a, &batch(&[ping("pxa", 1)])).await;
    assert_eq!(r.status, 200);
    // An event received 200 days ago is past E (90 days) and T (90 days).
    let old = sigil_proxy_api::parse_event_batch(batch(&[ping("pxa", 2)]).as_bytes())
        .unwrap()
        .events;
    let long_ago = time::OffsetDateTime::now_utc().unix_timestamp() - 200 * 86_400;
    fx.ctx.ledger.insert_batch("pxa", &old, long_ago).unwrap();
    assert!(env.stored("pxa", 2));

    let h = sigil_server::proxy::spawn_ledger_sweep(
        fx.ctx.clone(),
        std::time::Duration::from_millis(50),
    );
    let mut gone = false;
    for _ in 0..100 {
        if !env.stored("pxa", 2) {
            gone = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    h.abort();
    assert!(gone, "the old event was swept");
    assert!(env.stored("pxa", 1), "the fresh event stays");
    // The sweep did not stop the server from ingesting.
    let r = events(fx, a, &batch(&[ping("pxa", 3)])).await;
    assert_eq!(r.status, 200);
}

#[tokio::test]
async fn a_slow_body_frees_its_slot_and_one_proxy_cannot_take_them_all() {
    // N = 4 slots, so one proxy may hold max(1, 4/4) = 1. Body timeout 1 s.
    let env = Env::with(|p| {
        p.ingest_max_concurrent = Some(4);
        p.ingest_body_timeout_seconds = Some(1);
    })
    .await;
    let (fx, a, b) = (&env.fx, &env.a, &env.b);

    // pxa starts a request and never finishes the body.
    let (mut w, rd) = tokio::io::duplex(64);
    let stream = tokio_util::io::ReaderStream::new(rd);
    let url = format!("https://127.0.0.1:{}/v1/proxy-events", fx.port);
    let client = a.client.clone();
    let slow = tokio::spawn(async move {
        client
            .post(url)
            .header("content-type", "application/json")
            .body(reqwest::Body::wrap_stream(stream))
            .send()
            .await
    });
    tokio::io::AsyncWriteExt::write_all(&mut w, b"{\"events\":[")
        .await
        .unwrap();
    // Wait until the server holds the slot.
    for _ in 0..100 {
        if fx.ctx.ingest_slots.available_permits() < 4 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(fx.ctx.ingest_slots.available_permits(), 3);

    // Per-proxy cap: a second request of pxa is refused at once, while pxb
    // still gets through.
    let r = events(fx, a, &batch(&[ping("pxa", 1)])).await;
    assert_eq!((r.status, r.body), (429, err_body(ErrorCode::RateLimited)));
    let r = events(fx, b, &batch(&[ping("pxb", 2)])).await;
    assert_eq!(r.status, 200);

    // After the timeout the slow request is answered 429 and the slot is free.
    let resp = tokio::time::timeout(std::time::Duration::from_secs(10), slow)
        .await
        .expect("the server must end the slow request")
        .unwrap()
        .expect("a response, not a transport error");
    assert_eq!(resp.status().as_u16(), 429);
    assert_eq!(fx.ctx.ingest_slots.available_permits(), 4);
    assert!(fx.ctx.ingest_per_proxy.lock().is_empty());
    let r = events(fx, a, &batch(&[ping("pxa", 1)])).await;
    assert_eq!(r.status, 200);
    drop(w);
}

#[tokio::test]
async fn a_retransmission_after_route_edits_is_a_duplicate_not_a_422() {
    let env = Env::new().await;
    let (fx, a) = (&env.fx, &env.a);
    let s1 = env.scope("pxa");
    env.register(a, &mref(1)).await;
    let ev = batch(&[call("pxa", 1, &mref(1))]);
    let up = upload_body("pxa", &[entry_json("pxa", &mref(1), &s1, 'a')]);
    assert_eq!(events(fx, a, &ev).await.status, 200);

    // Two route edits: s1 is now two revisions back.
    for (rev, cred) in [(1, "gh2"), (2, "gh3")] {
        let mut s = spec("pxa", "tok-a");
        s["routes"][0]["credential_ref"] = cred.into();
        assert_eq!(
            put(fx, "pxa", Some(T_CFG), &put_body(rev, &s)).await.status,
            200
        );
    }
    // A new event naming the old entry is a 422 ...
    let r = events(fx, a, &batch(&[call("pxa", 2, &mref(1))])).await;
    assert_eq!(r.status, 422);
    // ... but the ack-lost retransmission of the stored one is a duplicate.
    let r = events(fx, a, &ev).await;
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(ids(&r.json()["duplicate_event_ids"]), [uid(1)]);
    assert!(ids(&r.json()["accepted_event_ids"]).is_empty());

    // Same for the upload: the equal entry is a duplicate, a new one with the
    // stale scope is a 422.
    let r = upload(fx, a, &up).await;
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(ids(&r.json()["duplicate_metadata_refs"]), [mref(1)]);
    let r = upload(
        fx,
        a,
        &upload_body("pxa", &[entry_json("pxa", &mref(2), &s1, 'b')]),
    )
    .await;
    assert_eq!(r.status, 422);
}

#[tokio::test]
async fn metadata_bytes_are_capped_per_proxy_on_the_full_row_size() {
    let env = Env::with(|p| p.metadata_max_bytes_per_proxy = Some(1024 * 1024)).await;
    let (fx, a, b) = (&env.fx, &env.a, &env.b);
    let sa = env.scope("pxa");
    let big = |n: u32| {
        let mut e = entry_json("pxa", &mref(n), &sa, 'a');
        e["definition"] = json!({"pad": "x".repeat(250 * 1024)});
        e
    };
    // 4 x ~250 KiB fit in 1 MiB; the 5th does not.
    for n in 1..=4 {
        let r = upload(fx, a, &upload_body("pxa", &[big(n)])).await;
        assert_eq!(r.status, 200, "{n}: {}", String::from_utf8_lossy(&r.body));
    }
    let r = upload(fx, a, &upload_body("pxa", &[big(5)])).await;
    assert_eq!((r.status, r.body), (503, err_body(ErrorCode::StorageLimit)));
    assert_eq!(fx.ctx.metadata.count("pxa").unwrap(), 4);
    // The cap is per proxy: pxb is unaffected.
    env.register(b, &mref(1)).await;
}

#[tokio::test]
async fn get_on_the_new_routes_does_not_reach_the_handlers() {
    let env = Env::new().await;
    let (fx, a) = (&env.fx, &env.a);
    for path in ["/v1/proxy-events", "/v1/proxy-metadata"] {
        let r = send(&a.client, fx.port, "GET", path, None, None).await;
        assert_eq!(r.status, 405, "{path}");
    }
    assert_eq!(fx.ctx.ingest_slots.available_permits(), 16);
}

// ---- T-11 S5 slice B: status-driven tail gaps and ingest last_seen (#289) -----------

fn status_last(proxy: &str, epoch: &str, seq: u32, last_assigned: i64) -> String {
    let mut v: Value = serde_json::from_str(&status_body(proxy, epoch, seq, vec![])).unwrap();
    v["last_assigned_sequence"] = last_assigned.into();
    v.to_string()
}

/// `(from, to, open, tail)` of every sequence_gap record of `proxy`.
fn seq_gaps(env: &Env, proxy: &str) -> Vec<(i64, i64, bool, bool)> {
    env.fx
        .ctx
        .ledger
        .gaps(proxy)
        .unwrap()
        .into_iter()
        .filter(|g| g.kind == sigil_server::proxy::ledger::GapKind::SequenceGap)
        .map(|g| {
            (
                g.from_sequence.unwrap(),
                g.to_sequence.unwrap(),
                g.open,
                g.tail,
            )
        })
        .collect()
}

#[tokio::test]
async fn a_status_report_opens_extends_and_arrival_closes_a_tail_gap() {
    let env = Env::new().await;
    let (fx, a) = (&env.fx, &env.a);
    let r = events(fx, a, &batch(&[ping("pxa", 1), ping("pxa", 2)])).await;
    assert_eq!(r.status, 200);
    assert!(seq_gaps(&env, "pxa").is_empty());

    // Nothing above the highest stored sequence: no gap.
    let r = post_status(fx, a, &status_last("pxa", EPOCH, 1, 2)).await;
    assert_eq!(r.status, 200);
    assert!(seq_gaps(&env, "pxa").is_empty());

    // Opened by one report.
    let r = post_status(fx, a, &status_last("pxa", EPOCH, 2, 5)).await;
    assert_eq!(r.status, 200);
    assert_eq!(seq_gaps(&env, "pxa"), [(3, 5, true, true)]);

    // Extended by a later one (same record).
    let r = post_status(fx, a, &status_last("pxa", EPOCH, 3, 8)).await;
    assert_eq!(r.status, 200);
    assert_eq!(seq_gaps(&env, "pxa"), [(3, 8, true, true)]);

    // Closed by arrival; the record is kept.
    let evs: Vec<Value> = (3..=8).map(|n| ping("pxa", n)).collect();
    let r = events(fx, a, &batch(&evs)).await;
    assert_eq!(r.status, 200);
    let gaps = seq_gaps(&env, "pxa");
    assert_eq!(gaps.len(), 1);
    assert!(!gaps[0].2 && gaps[0].3, "{gaps:?}");
}

#[tokio::test]
async fn stale_and_wrong_epoch_reports_create_no_tail_gap() {
    let env = Env::new().await;
    let (fx, a) = (&env.fx, &env.a);
    events(fx, a, &batch(&[ping("pxa", 1)])).await;
    let r = post_status(fx, a, &status_last("pxa", EPOCH, 5, 3)).await;
    assert_eq!(r.status, 200);
    assert_eq!(seq_gaps(&env, "pxa"), [(2, 3, true, true)]);

    // Older and equal status_sequence: not applied, so no tail change.
    for seq in [4, 5] {
        let r = post_status(fx, a, &status_last("pxa", EPOCH, seq, 40)).await;
        assert_eq!(r.status, 200);
        assert_eq!(r.json()["state_applied"], false);
    }
    assert_eq!(seq_gaps(&env, "pxa"), [(2, 3, true, true)]);

    // A known epoch that is no longer the latest: the report is not a
    // current-epoch report, so it opens nothing in that epoch.
    let epoch_b = "00000000-0000-4000-8000-0000000000e2";
    let mut e = ping("pxa", 100);
    e["epoch_id"] = epoch_b.into();
    e["sequence"] = 1.into();
    assert_eq!(events(fx, a, &batch(&[e])).await.status, 200);
    let before = seq_gaps(&env, "pxa");
    let r = post_status(fx, a, &status_last("pxa", EPOCH, 9, 60)).await;
    assert_eq!(r.status, 200);
    assert_eq!(seq_gaps(&env, "pxa"), before);
}

#[tokio::test]
async fn the_open_gap_cap_does_not_reject_the_report_and_the_next_one_retries() {
    let env = Env::new().await;
    let (fx, a) = (&env.fx, &env.a);
    events(fx, a, &batch(&[ping("pxa", 1)])).await;
    let conn = rusqlite::Connection::open(fx.p("proxy-ledger.sqlite")).unwrap();
    conn.execute_batch(
        "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 10000)
         INSERT INTO gaps (gap_id, proxy_id, kind, detected_at, epoch_id, from_sequence,
                           to_sequence, open, tail)
         SELECT 'filler-' || i, 'pxa', 'sequence_gap', 1,
                '00000000-0000-4000-8000-0000000000f9', i, i, 1, 0 FROM n;",
    )
    .unwrap();

    let r = post_status(fx, a, &status_last("pxa", EPOCH, 1, 4)).await;
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["state_applied"], true);
    let st = fx.ctx.store.entry("pxa").unwrap().status.unwrap();
    assert_eq!(st.status_sequence.get(), 1);
    assert!(seq_gaps(&env, "pxa").iter().all(|g| !g.3));

    // Room again: the next report retries and records it.
    conn.execute_batch("DELETE FROM gaps WHERE gap_id = 'filler-1';")
        .unwrap();
    let r = post_status(fx, a, &status_last("pxa", EPOCH, 2, 4)).await;
    assert_eq!(r.status, 200);
    assert!(seq_gaps(&env, "pxa").contains(&(2, 4, true, true)));
}

#[tokio::test]
async fn a_ledger_failure_in_the_tail_step_still_applies_the_report() {
    let env = Env::new().await;
    let (fx, a) = (&env.fx, &env.a);
    let conn = rusqlite::Connection::open(fx.p("proxy-ledger.sqlite")).unwrap();
    conn.execute_batch("DROP TABLE gaps;").unwrap();
    let r = post_status(fx, a, &status_last("pxa", EPOCH, 1, 9)).await;
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["state_applied"], true);
    let e = fx.ctx.store.entry("pxa").unwrap();
    assert_eq!(e.status.unwrap().status_sequence.get(), 1);
    assert!(e.last_seen.is_some());
}

fn set_last_seen(env: &Env, proxy: &str, v: &str) {
    let txn = env.fx.ctx.store.begin();
    let mut e = txn.entry(proxy);
    e.last_seen = Some(v.to_string());
    txn.commit(proxy, e).unwrap();
}

fn ts(secs_ago: i64) -> String {
    (time::OffsetDateTime::now_utc() - time::Duration::seconds(secs_ago))
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap()
}

#[tokio::test]
async fn an_accepted_batch_updates_last_seen_at_a_bounded_rate() {
    let env = Env::new().await;
    let (fx, a) = (&env.fx, &env.a);
    assert_eq!(fx.ctx.store.last_seen("pxa"), None);
    assert_eq!(events(fx, a, &batch(&[ping("pxa", 1)])).await.status, 200);
    let first = fx.ctx.store.last_seen("pxa").expect("set by ingest");

    // A fresh value is not rewritten.
    let recent = ts(5);
    set_last_seen(&env, "pxa", &recent);
    assert_eq!(events(fx, a, &batch(&[ping("pxa", 2)])).await.status, 200);
    assert_eq!(fx.ctx.store.last_seen("pxa"), Some(recent));

    // A value older than the interval is refreshed (also by a duplicate-only batch).
    let old = ts(sigil_server::proxy::store::LAST_SEEN_MIN_INTERVAL_SECS + 30);
    set_last_seen(&env, "pxa", &old);
    let r = events(fx, a, &batch(&[ping("pxa", 2)])).await;
    assert_eq!(r.status, 200);
    assert!(r.json()["accepted_event_ids"]
        .as_array()
        .unwrap()
        .is_empty());
    assert_eq!(ids(&r.json()["duplicate_event_ids"]), [uid(2)]);
    let now = fx.ctx.store.last_seen("pxa").unwrap();
    assert!(now > old && now >= first, "{now} {old}");
    // other proxies are untouched
    assert_eq!(fx.ctx.store.last_seen("pxb"), None);
}

#[tokio::test]
async fn a_rejected_batch_does_not_touch_last_seen() {
    let env = Env::new().await;
    let (fx, a) = (&env.fx, &env.a);
    assert_eq!(events(fx, a, &batch(&[ping("pxa", 1)])).await.status, 200);
    let old = ts(600);
    set_last_seen(&env, "pxa", &old);

    let r = events(fx, a, "{").await; // 422 parse
    assert_eq!(r.status, 422);
    let r = events(fx, a, &batch(&[ping("pxb", 7)])).await; // 404 foreign id
    assert_eq!(r.status, 404);
    let r = events(fx, a, &batch(&[changed_copy()])).await; // 409
    assert_eq!(r.status, 409);
    let r = events(fx, a, &batch(&[call("pxa", 9, &mref(9))])).await; // 424 pending
    assert_eq!(r.status, 424);
    assert_eq!(fx.ctx.store.last_seen("pxa"), Some(old));
}

#[tokio::test]
async fn unknown_epochs_keep_at_most_one_open_tail_gap() {
    let env = Env::new().await;
    let (fx, a) = (&env.fx, &env.a);
    // N distinct epochs the ledger has never seen (nor any event of).
    for n in 1..=30u32 {
        let epoch = format!("00000000-0000-4000-8000-{:012x}", 0xa000 + n);
        let r = post_status(fx, a, &status_last("pxa", &epoch, 1, 7)).await;
        assert_eq!(r.status, 200);
    }
    let open_tails = |env: &Env| {
        seq_gaps(env, "pxa")
            .into_iter()
            .filter(|g| g.2 && g.3)
            .count()
    };
    assert_eq!(open_tails(&env), 1);
    // Superseded ones are closed, not deleted.
    assert_eq!(seq_gaps(&env, "pxa").len(), 30);

    // A real epoch announcement for the surviving unknown epoch makes it a
    // normal tail, and genuine gaps are still accepted afterwards.
    let epoch = format!("00000000-0000-4000-8000-{:012x}", 0xa000 + 30);
    let mut e = ping("pxa", 500);
    e["epoch_id"] = epoch.clone().into();
    e["sequence"] = 1.into();
    assert_eq!(events(fx, a, &batch(&[e])).await.status, 200);
    let r = post_status(fx, a, &status_last("pxa", &epoch, 2, 9)).await;
    assert_eq!(r.status, 200);
    assert!(seq_gaps(&env, "pxa").contains(&(2, 9, true, true)));
    assert_eq!(open_tails(&env), 1);
}
