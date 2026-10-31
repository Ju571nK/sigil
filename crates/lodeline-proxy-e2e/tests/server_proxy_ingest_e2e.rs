#![cfg(unix)]
//! #282 (T-11 S4): the real `lodeline-server` ingest routes and the proxy's real
//! `IngestClient` / `run_ingest`, over loopback rustls mTLS.
//!
//! The proxy side uses the production transport (`MtlsFetcher`, wrapped only by
//! a recording `Tap` that can also drop a reply after the server answered, to
//! model an ack loss). Events come from a fixture `EventSource` because relay
//! event production is T-13/T-14. The server side is read through its own
//! ledger / store / metadata types on the same files; there is no test-only
//! production route. Gaps travel to the server through the real
//! `run_status_reporter` over the same `GapQueue`.
//!
//! Requirements: PX-010, PX-011, PX-012; acceptance AC-05, AC-06, AC-12.
//! Real-time polling with tuned short intervals; no paused clock.

use std::collections::HashSet;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use lodeline_proxy::bootstrap::Bootstrap;
use lodeline_proxy::config_sync::{ConfigView, MtlsFetcher};
use lodeline_proxy::ingest_client::{
    run_ingest, EventSource, IngestClient, IngestOutcome, IngestParams, IngestTransport,
    MAX_CONSECUTIVE_SINGLE_QUARANTINES,
};
use lodeline_proxy::status_report::{
    run_status_reporter, CentralHealth, GapQueue, PostFuture, Reporter, ReporterParams,
};
use lodeline_proxy_api::status::{ConfigState, QuarantineCode};
use lodeline_proxy_api::verifier::verifier_for;
use lodeline_proxy_api::ProxyEvent;
use lodeline_server::app::{build_router_with_proxy, AppState};
use lodeline_server::auth::ReadToken;
use lodeline_server::config::{ProxyConfig, ServerConfig};
use lodeline_server::fleet_index::FleetIndex;
use lodeline_server::persist::HighWater;
use lodeline_server::proxy::identity::proxy_san;
use lodeline_server::proxy::ledger::GapKind;
use lodeline_server::proxy::verifiers::{Scope, VerifierEntry};
use lodeline_server::proxy::ProxyContext;
use lodeline_server::tls_accept::PeerCertAcceptor;
use serde_json::{json, Value};
use tokio::sync::{oneshot, watch};

const T_ID: &str = "tok-identity-ingest";
const T_CFG: &str = "tok-config-ingest";
const PROXY: &str = "px-ing";
const WAIT: Duration = Duration::from_secs(20);

// ---------------------------------------------------------------- openssl

fn find_openssl() -> Option<PathBuf> {
    [
        "/usr/bin/openssl",
        "/opt/homebrew/bin/openssl",
        "/opt/homebrew/opt/openssl@3/bin/openssl",
        "/usr/local/bin/openssl",
        "/usr/local/opt/openssl@3/bin/openssl",
    ]
    .iter()
    .map(PathBuf::from)
    .find(|p| p.exists())
}

fn run_ossl(ossl: &Path, args: &[&std::ffi::OsStr]) {
    let o = Command::new(ossl)
        .env_remove("OPENSSL_CONF")
        .args(args)
        .output()
        .unwrap();
    assert!(
        o.status.success(),
        "openssl {args:?}: {}",
        String::from_utf8_lossy(&o.stderr)
    );
}

struct Pki {
    dir: tempfile::TempDir,
    ossl: PathBuf,
    serial: AtomicUsize,
}

impl Pki {
    fn p(&self, f: &str) -> PathBuf {
        self.dir.path().join(f)
    }

    fn ca(&self, name: &str, cn: &str, serial: &str) {
        let key = self.p(&format!("{name}.key"));
        run_ossl(
            &self.ossl,
            &[
                "req".as_ref(),
                "-x509".as_ref(),
                "-new".as_ref(),
                "-newkey".as_ref(),
                "rsa:2048".as_ref(),
                "-nodes".as_ref(),
                "-keyout".as_ref(),
                key.as_os_str(),
                "-days".as_ref(),
                "2".as_ref(),
                "-set_serial".as_ref(),
                serial.as_ref(),
                "-subj".as_ref(),
                format!("/CN={cn}").as_ref(),
                "-addext".as_ref(),
                "basicConstraints=critical,CA:TRUE".as_ref(),
                "-addext".as_ref(),
                "subjectKeyIdentifier=hash".as_ref(),
                "-out".as_ref(),
                self.p(&format!("{name}.crt")).as_os_str(),
            ],
        );
    }

    /// CA-signed RSA-2048 leaf, `-set_serial` (never `-CAcreateserial`).
    fn leaf(&self, ca: &str, name: &str, cn: &str, ext: &str) -> (PathBuf, PathBuf) {
        let (key, csr, crt, extf) = (
            self.p(&format!("{name}.key")),
            self.p(&format!("{name}.csr")),
            self.p(&format!("{name}.crt")),
            self.p(&format!("{name}.ext")),
        );
        std::fs::write(&extf, ext).unwrap();
        run_ossl(
            &self.ossl,
            &[
                "req".as_ref(),
                "-new".as_ref(),
                "-newkey".as_ref(),
                "rsa:2048".as_ref(),
                "-nodes".as_ref(),
                "-keyout".as_ref(),
                key.as_os_str(),
                "-subj".as_ref(),
                format!("/CN={cn}").as_ref(),
                "-out".as_ref(),
                csr.as_os_str(),
            ],
        );
        let serial = format!("{}", 100 + self.serial.fetch_add(1, Ordering::Relaxed));
        run_ossl(
            &self.ossl,
            &[
                "x509".as_ref(),
                "-req".as_ref(),
                "-in".as_ref(),
                csr.as_os_str(),
                "-CA".as_ref(),
                self.p(&format!("{ca}.crt")).as_os_str(),
                "-CAkey".as_ref(),
                self.p(&format!("{ca}.key")).as_os_str(),
                "-set_serial".as_ref(),
                serial.as_ref(),
                "-days".as_ref(),
                "2".as_ref(),
                "-extfile".as_ref(),
                extf.as_os_str(),
                "-out".as_ref(),
                crt.as_os_str(),
            ],
        );
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        (crt, key)
    }
}

/// `None` when openssl is missing and `CI` is unset (skip); panics under CI.
fn pki() -> Option<Pki> {
    let Some(ossl) = find_openssl() else {
        assert!(
            std::env::var_os("CI").is_none(),
            "openssl CLI not found but CI is set"
        );
        eprintln!("skipped: openssl CLI not found");
        return None;
    };
    let pki = Pki {
        dir: tempfile::tempdir().unwrap(),
        ossl,
        serial: AtomicUsize::new(0),
    };
    pki.ca("hostca", "ing-host-ca", "1");
    pki.ca("proxyca", "ing-proxy-ca", "2");
    let mut bundle = std::fs::read(pki.p("hostca.crt")).unwrap();
    bundle.extend(std::fs::read(pki.p("proxyca.crt")).unwrap());
    std::fs::write(pki.p("bundle.pem"), bundle).unwrap();
    pki.leaf(
        "hostca",
        "server",
        "localhost",
        "subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n",
    );
    Some(pki)
}

fn fingerprint(crt: &Path) -> String {
    let pem = std::fs::read(crt).unwrap();
    let certs: Vec<_> = rustls_pemfile::certs(&mut std::io::BufReader::new(&pem[..]))
        .collect::<Result<_, _>>()
        .unwrap();
    blake3::hash(certs[0].as_ref()).to_hex().to_string()
}

fn mtls_client(trust: &Path, crt: &Path, key: &Path) -> reqwest::Client {
    let mut id = std::fs::read(key).unwrap();
    id.extend_from_slice(&std::fs::read(crt).unwrap());
    reqwest::Client::builder()
        .use_rustls_tls()
        .pool_max_idle_per_host(0)
        .add_root_certificate(
            reqwest::Certificate::from_pem(&std::fs::read(trust).unwrap()).unwrap(),
        )
        .identity(reqwest::Identity::from_pem(&id).unwrap())
        .build()
        .unwrap()
}

// ----------------------------------------------------------------- server

fn tls_config(pki: &Pki) -> rustls::ServerConfig {
    let rd = |f: &str| std::fs::read(pki.p(f)).unwrap();
    let certs: Vec<_> = rustls_pemfile::certs(&mut std::io::BufReader::new(&rd("server.crt")[..]))
        .collect::<Result<_, _>>()
        .unwrap();
    let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(&rd("server.key")[..]))
        .unwrap()
        .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    for c in rustls_pemfile::certs(&mut std::io::BufReader::new(&rd("bundle.pem")[..])) {
        roots.add(c.unwrap()).unwrap();
    }
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .unwrap();
    rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .unwrap()
}

fn app_state(dir: &Path) -> Arc<AppState> {
    Arc::new(AppState {
        events_out_dir: dir.to_path_buf(),
        policy_bundle_path: dir.join("signed-policy.json"),
        rule_packs_bundle_path: None,
        artifacts_dir: None,
        high_water_path: dir.join(".high-water.json"),
        allowlist: parking_lot::RwLock::new(None),
        high_water: Mutex::new(HighWater::default()),
        fleet_index: FleetIndex::new(),
        read_token: ReadToken(Some("read-bearer".into())),
        active_window_days: 7,
        audit_key: None,
        audit_head: Mutex::new(None),
        allowlist_path: None,
        enroll: None,
        events_require_cert_host_match: false,
    })
}

type Tweak = Arc<dyn Fn(&mut ProxyConfig) + Send + Sync>;

struct Server {
    port: u16,
    ctx: Arc<ProxyContext>,
    handle: axum_server::Handle,
    task: tokio::task::JoinHandle<()>,
}

impl Server {
    /// `port == 0` picks one; a restart passes the old port. State files are the
    /// same on every start (they live in the PKI temp dir).
    async fn start(pki: &Pki, port: u16, first: bool, tweak: &Tweak) -> Server {
        Self::try_start(pki, port, first, tweak)
            .await
            .expect("server must bind")
    }

    /// `None` when the port could not be bound.
    async fn try_start(pki: &Pki, port: u16, first: bool, tweak: &Tweak) -> Option<Server> {
        let d = pki.dir.path();
        let p = |f: &str| d.join(f).display().to_string();
        let y = format!(
            "bind: \"127.0.0.1:0\"\ntls_cert_path: {}\ntls_key_path: {}\nclient_ca_path: {}\n\
             events_out_dir: {}\npolicy_bundle_path: {}\n\
             proxy:\n  ca_path: {}\n  registry_path: {}\n  registry_init: {first}\n  management_verifiers: {}\n",
            p("server.crt"),
            p("server.key"),
            p("bundle.pem"),
            d.display(),
            p("signed-policy.json"),
            p("proxyca.crt"),
            p("proxies.json"),
            p("verifiers.json"),
        );
        let mut cfg: ServerConfig = serde_yaml::from_str(&y).unwrap();
        tweak(cfg.proxy.as_mut().unwrap());
        let ctx = Arc::new(ProxyContext::load(&cfg).unwrap().unwrap());
        let tls = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(tls_config(pki)));
        let app = build_router_with_proxy(app_state(d), Some(ctx.clone()));
        let handle = axum_server::Handle::new();
        let h = handle.clone();
        let task = tokio::spawn(async move {
            let _ = axum_server::bind(format!("127.0.0.1:{port}").parse().unwrap())
                .handle(h)
                .acceptor(PeerCertAcceptor::new(tls))
                .serve(app.into_make_service())
                .await;
        });
        let port = handle.listening().await?.port();
        Some(Server {
            port,
            ctx,
            handle,
            task,
        })
    }

    /// Stop the server for sure: graceful shutdown with a short deadline, then
    /// abort the task and wait for the abort, so the listener is dropped. Returns
    /// the port; the caller checks that connections are refused.
    async fn stop(self) -> u16 {
        self.handle
            .graceful_shutdown(Some(Duration::from_millis(200)));
        let mut task = self.task;
        if tokio::time::timeout(Duration::from_secs(2), &mut task)
            .await
            .is_err()
        {
            task.abort();
            let _ = task.await;
        }
        self.port
    }
}

// ---------------------------------------------------------------- harness

fn verifier_entry(id: &str, token: &str, scope: Scope, fp: &str) -> VerifierEntry {
    VerifierEntry {
        key_id: id.into(),
        name: format!("{id}-name"),
        verifier: verifier_for(token),
        scope,
        caller_cert_fingerprint: fp.into(),
        not_after: None,
    }
}

fn spec() -> Value {
    json!({
        "schema_version": 1,
        "proxy_id": PROXY,
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
            "verifiers": [{"key_id": "k1", "verifier": verifier_for("client-tok")}],
            "routes": ["r1"],
        }],
    })
}

struct H {
    pki: Pki,
    mgmt: reqwest::Client,
    proxy_cert: (PathBuf, PathBuf),
    srv: Option<Server>,
    last_port: u16,
    tweak: Tweak,
    fetcher: Arc<MtlsFetcher>,
}

impl H {
    async fn new(tweak: impl Fn(&mut ProxyConfig) + Send + Sync + 'static) -> Option<H> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let pki = pki()?;
        let mgmt_cert = pki.leaf(
            "hostca",
            "mgmt",
            "mgmt-operator",
            "subjectAltName=DNS:mgmt-operator\nextendedKeyUsage=clientAuth\nbasicConstraints=CA:FALSE\n",
        );
        let fp = fingerprint(&mgmt_cert.0);
        let vpath = pki.p("verifiers.json");
        std::fs::write(
            &vpath,
            serde_json::to_vec(&json!({"entries": [
                verifier_entry("idk", T_ID, Scope::Identity, &fp),
                verifier_entry("cfgk", T_CFG, Scope::Config, &fp),
            ]}))
            .unwrap(),
        )
        .unwrap();
        std::fs::set_permissions(&vpath, std::fs::Permissions::from_mode(0o600)).unwrap();
        let proxy_cert = pki.leaf(
            "proxyca",
            "proxy",
            PROXY,
            &format!(
                "subjectAltName=DNS:{}\nextendedKeyUsage=clientAuth\nbasicConstraints=CA:FALSE\n",
                proxy_san(PROXY)
            ),
        );
        let tweak: Tweak = Arc::new(tweak);
        let srv = Server::start(&pki, 0, true, &tweak).await;
        let mgmt = mtls_client(&pki.p("hostca.crt"), &mgmt_cert.0, &mgmt_cert.1);
        let fetcher = Arc::new(fetcher_for(&pki, srv.port, &proxy_cert));
        let h = H {
            pki,
            mgmt,
            proxy_cert,
            last_port: srv.port,
            srv: Some(srv),
            tweak,
            fetcher,
        };
        // Register, bind the certificate, store a config (gives the scope id).
        let (st, _) = h
            .mgmt_call(
                "POST",
                "/v1/proxies",
                T_ID,
                Some(json!({"proxy_id": PROXY, "display_name": "ing"})),
            )
            .await;
        assert_eq!(st, 201, "register");
        let (st, _) = h
            .mgmt_call(
                "POST",
                &format!("/v1/proxies/{PROXY}/fingerprints"),
                T_ID,
                Some(json!({"fingerprint": fingerprint(&h.proxy_cert.0)})),
            )
            .await;
        assert_eq!(st, 200, "fingerprint");
        let (st, body) = h
            .mgmt_call(
                "PUT",
                &format!("/v1/proxies/{PROXY}/config"),
                T_CFG,
                Some(json!({"expected_revision": 0, "config": spec()})),
            )
            .await;
        assert_eq!(st, 200, "config put: {body}");
        Some(h)
    }

    fn srv(&self) -> &Server {
        self.srv.as_ref().expect("server is up")
    }

    fn ctx(&self) -> Arc<ProxyContext> {
        self.srv().ctx.clone()
    }

    async fn mgmt_call(
        &self,
        method: &str,
        path: &str,
        bearer: &str,
        body: Option<Value>,
    ) -> (u16, Value) {
        let url = format!("https://127.0.0.1:{}{path}", self.srv().port);
        let mut rb = self
            .mgmt
            .request(reqwest::Method::from_bytes(method.as_bytes()).unwrap(), url)
            .bearer_auth(bearer);
        if let Some(b) = body {
            rb = rb.json(&b);
        }
        let r = rb.send().await.unwrap();
        let st = r.status().as_u16();
        let bytes = r.bytes().await.unwrap();
        (st, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
    }

    /// Stop the server (connections are refused afterwards).
    async fn server_down(&mut self) {
        let port = self.srv.take().expect("server is up").stop().await;
        // The outage phase starts only when the port really refuses connections.
        let start = Instant::now();
        loop {
            if tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .is_err()
            {
                break;
            }
            assert!(
                start.elapsed() < Duration::from_secs(5),
                "server still accepts connections after stop"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// Start the server again on the same port and the same files.
    async fn server_up(&mut self) {
        let tweak = self.tweak.clone();
        self.server_up_with(tweak).await;
    }

    /// As `server_up`, with other server settings (for example a raised cap).
    ///
    /// The bind is retried a few times: `axum_server::bind` uses
    /// `std::net::TcpListener::bind`, which sets SO_REUSEADDR on Unix, so the
    /// port is reusable at once despite TIME_WAIT connections. The retry only
    /// covers the short window in which the old socket is still being released.
    async fn server_up_with(&mut self, tweak: Tweak) {
        for _ in 0..20 {
            if let Some(s) = Server::try_start(&self.pki, self.last_port, false, &tweak).await {
                self.srv = Some(s);
                self.tweak = tweak;
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("server could not rebind port {}", self.last_port);
    }

    fn scope_id(&self) -> String {
        self.ctx().store.config(PROXY).unwrap().config.routes[0]
            .credential_scope_id
            .as_str()
            .to_string()
    }

    /// Upload one registry entry as the proxy (`POST /v1/proxy-metadata`).
    async fn upload_metadata(&self, mref: &str) {
        let c = mtls_client(
            &self.pki.p("hostca.crt"),
            &self.proxy_cert.0,
            &self.proxy_cert.1,
        );
        let entry = json!({
            "proxy_id": PROXY,
            "metadata_ref": mref,
            "upstream_id": "up1",
            "credential_scope_id": self.scope_id(),
            "protocol_version": "2025-11-25",
            "observation_source": "proxy_live",
            "canon": "sigil-tooldef-fp-v1",
            "key_id": "kid-000000000000000000000001",
            "fingerprint": "a".repeat(64),
            "observed_at": "2026-10-10T00:00:00Z",
            "definition": {"name": "tool-x", "description": "d"},
        });
        let r = c
            .post(format!(
                "https://127.0.0.1:{}/v1/proxy-metadata",
                self.srv().port
            ))
            .header("content-type", "application/json")
            .body(json!({"schema_version": 1, "proxy_id": PROXY, "entries": [entry]}).to_string())
            .send()
            .await
            .unwrap();
        let st = r.status().as_u16();
        assert_eq!(st, 200, "metadata upload: {:?}", r.text().await);
    }

    fn stored(&self, n: u32) -> bool {
        self.ctx()
            .ledger
            .stored_event(PROXY, &uid(n))
            .unwrap()
            .is_some()
    }

    /// Gap records the server holds from status reports, as JSON.
    fn server_gaps(&self) -> Vec<Value> {
        self.ctx()
            .store
            .entry(PROXY)
            .map(|e| {
                e.gaps
                    .iter()
                    .map(|g| serde_json::to_value(g).unwrap())
                    .collect()
            })
            .unwrap_or_default()
    }
}

fn fetcher_for(pki: &Pki, server_port: u16, cert: &(PathBuf, PathBuf)) -> MtlsFetcher {
    let d = pki.dir.path();
    let secret = d.join("upstream-secret");
    std::fs::write(&secret, "UPSTREAM-SECRET-VALUE\n").unwrap();
    std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600)).unwrap();
    let yaml = format!(
        "proxy_id: {PROXY}\nlisten: \"127.0.0.1:0\"\n\
         control_plane_url: \"https://127.0.0.1:{server_port}\"\n\
         state_dir: {}\nclient_cert_file: {}\nclient_key_file: {}\nca_file: {}\n\
         credentials:\n  gh:\n    secret_file: {}\n    upstream_origins: [\"https://api.example.com\"]\n",
        d.join("proxy-state").display(),
        cert.0.display(),
        cert.1.display(),
        pki.p("hostca.crt").display(),
        secret.display(),
    );
    let b = Bootstrap::from_yaml(&yaml, d).expect("bootstrap loads");
    MtlsFetcher::from_bootstrap(&b)
        .expect("fetcher builds")
        .with_timeout(Duration::from_secs(5))
}

async fn eventually<F: FnMut() -> bool>(what: &str, mut f: F) {
    let start = Instant::now();
    while start.elapsed() < WAIT {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("timed out waiting for: {what}");
}

// ------------------------------------------------------------------ events

fn uid(n: u32) -> String {
    format!("00000000-0000-4000-8000-{n:012}")
}

fn mref(n: u32) -> String {
    format!("00000000-0000-8000-8000-{n:012}")
}

fn epoch(n: u32) -> String {
    uid(9000 + n)
}

/// `invocation.started`: event id `n`, epoch `ep`, sequence `seq`. With `tool`,
/// a `tools/call` naming that metadata ref. `upstream` varies the body.
fn ev(n: u32, ep: u32, seq: u32, tool: Option<&str>, upstream: &str) -> ProxyEvent {
    let mut payload = json!({
        "invocation_id": uid(1000 + n),
        "upstream_id": upstream,
        "route_revision": 1,
        "protocol_version": "unknown",
        "method": "ping",
        "actor": {
            "actor_id": "actor-1",
            "actor_kind": "non_human",
            "authentication_method": "bearer",
            "evidence_source": "proxy_credential_mapping"
        }
    });
    if let Some(r) = tool {
        payload["protocol_version"] = "2025-11-25".into();
        payload["method"] = "tools/call".into();
        payload["tool"] = json!({"status": "identified", "metadata_ref": r});
    }
    serde_json::from_value(json!({
        "schema_version": 1,
        "event_id": uid(n),
        "proxy_id": PROXY,
        "epoch_id": epoch(ep),
        "sequence": seq,
        "occurred_at": "2026-10-10T00:00:00Z",
        "event_type": "invocation.started",
        "payload": payload,
    }))
    .unwrap()
}

fn ping(n: u32) -> ProxyEvent {
    ev(n, 1, n, None, "up1")
}

// ----------------------------------------------------------------- fixture

#[derive(Default)]
struct FxInner {
    unsent: Vec<ProxyEvent>,
    acked: Vec<String>,
    quarantined: Vec<(String, QuarantineCode)>,
    paused: bool,
    /// When set, every acknowledgement checks the server already stores the id.
    ledger_probe: Option<Arc<ProxyContext>>,
    acked_before_stored: Vec<String>,
}

/// Fixture `EventSource`: hands out the oldest unsent events.
#[derive(Clone, Default)]
struct Fixture(Arc<Mutex<FxInner>>);

impl Fixture {
    fn push(&self, evs: impl IntoIterator<Item = ProxyEvent>) {
        self.0.lock().unwrap().unsent.extend(evs);
    }
    fn set_paused(&self, p: bool) {
        self.0.lock().unwrap().paused = p;
    }
    fn probe(&self, ctx: Arc<ProxyContext>) {
        self.0.lock().unwrap().ledger_probe = Some(ctx);
    }
    fn acked(&self) -> Vec<String> {
        self.0.lock().unwrap().acked.clone()
    }
    fn acked_count(&self) -> usize {
        self.0.lock().unwrap().acked.len()
    }
    fn unsent_count(&self) -> usize {
        self.0.lock().unwrap().unsent.len()
    }
    fn quarantined(&self) -> Vec<(String, QuarantineCode)> {
        self.0.lock().unwrap().quarantined.clone()
    }
    fn acked_before_stored(&self) -> Vec<String> {
        self.0.lock().unwrap().acked_before_stored.clone()
    }
}

impl EventSource for Fixture {
    fn next_events(&mut self, max: usize, skip: &HashSet<String>) -> Vec<ProxyEvent> {
        let g = self.0.lock().unwrap();
        if g.paused {
            return Vec::new();
        }
        g.unsent
            .iter()
            .filter(|e| !skip.contains(e.event_id.as_str()))
            .take(max)
            .cloned()
            .collect()
    }
    fn acknowledged(&mut self, ids: &[String]) {
        let mut g = self.0.lock().unwrap();
        if let Some(ctx) = g.ledger_probe.clone() {
            for id in ids {
                if ctx.ledger.stored_event(PROXY, id).unwrap().is_none() {
                    g.acked_before_stored.push(id.clone());
                }
            }
        }
        g.unsent
            .retain(|e| !ids.iter().any(|i| i == e.event_id.as_str()));
        g.acked.extend(ids.iter().cloned());
    }
    fn quarantined(&mut self, ids: &[String], code: QuarantineCode) {
        let mut g = self.0.lock().unwrap();
        g.unsent
            .retain(|e| !ids.iter().any(|i| i == e.event_id.as_str()));
        g.quarantined.extend(ids.iter().map(|i| (i.clone(), code)));
    }
}

// --------------------------------------------------------------------- tap

#[derive(Clone, Debug)]
struct Post {
    ids: Vec<String>,
    /// The server's real answer (`None`: no connection could be made).
    status: Option<u16>,
    body: Vec<u8>,
    /// The reply was withheld from the client (modelled ack loss).
    dropped: bool,
    /// When the answer (or the failure) came back.
    at: Instant,
}

/// The production transport, recording every request and its real answer. It can
/// withhold the reply of the next requests after the server has answered.
/// Decrement `n` if it is above zero. A compare-exchange loop, because
/// `fetch_update` is deprecated on current stable and its replacement
/// `try_update` is newer than the MSRV.
fn take_one(n: &AtomicUsize) -> bool {
    let mut cur = n.load(Ordering::SeqCst);
    while cur > 0 {
        match n.compare_exchange(cur, cur - 1, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => return true,
            Err(seen) => cur = seen,
        }
    }
    false
}

struct Tap {
    inner: Arc<MtlsFetcher>,
    log: Mutex<Vec<Post>>,
    drop_replies: AtomicUsize,
    /// Add a field the server's closed envelope refuses, as a proxy upgraded
    /// before the server would. The client's own parse has already passed.
    newer_shape: AtomicBool,
    /// Source whose acknowledged count is noted whenever a reply is dropped.
    watch: Mutex<Option<Fixture>>,
    acked_at_drop: Mutex<Vec<usize>>,
}

impl Tap {
    fn new(inner: Arc<MtlsFetcher>) -> Arc<Tap> {
        Arc::new(Tap {
            inner,
            log: Mutex::default(),
            drop_replies: AtomicUsize::new(0),
            newer_shape: AtomicBool::new(false),
            watch: Mutex::default(),
            acked_at_drop: Mutex::default(),
        })
    }
    fn posts(&self) -> Vec<Post> {
        self.log.lock().unwrap().clone()
    }
    fn count_status(&self, s: u16) -> usize {
        self.posts().iter().filter(|p| p.status == Some(s)).count()
    }
}

fn with_newer_shape(body: &[u8]) -> Vec<u8> {
    let mut v: Value = serde_json::from_slice(body).unwrap();
    for e in v["events"].as_array_mut().unwrap() {
        e["field_of_a_newer_proxy"] = json!(1);
    }
    serde_json::to_vec(&v).unwrap()
}

impl IngestTransport for Tap {
    fn post_events(&self, body: Vec<u8>) -> PostFuture<'_> {
        Box::pin(async move {
            let ids: Vec<String> = serde_json::from_slice::<Value>(&body)
                .ok()
                .and_then(|v| {
                    v["events"].as_array().map(|a| {
                        a.iter()
                            .filter_map(|e| e["event_id"].as_str().map(str::to_string))
                            .collect()
                    })
                })
                .unwrap_or_default();
            let body = if self.newer_shape.load(Ordering::SeqCst) {
                with_newer_shape(&body)
            } else {
                body
            };
            let reply = self.inner.post_events(body).await;
            let dropped = reply.is_some() && take_one(&self.drop_replies);
            if dropped {
                if let Some(fx) = self.watch.lock().unwrap().as_ref() {
                    self.acked_at_drop.lock().unwrap().push(fx.acked_count());
                }
            }
            self.log.lock().unwrap().push(Post {
                ids,
                status: reply.as_ref().map(|r| r.status),
                body: reply.as_ref().map(|r| r.body.clone()).unwrap_or_default(),
                dropped,
                at: Instant::now(),
            });
            if dropped {
                None
            } else {
                reply
            }
        })
    }
}

// -------------------------------------------------------------- run helpers

fn fast_params() -> IngestParams {
    IngestParams {
        poll: Duration::from_millis(30),
        retry: Duration::from_millis(100),
        max_backoff: Duration::from_millis(400),
        min_spacing: Duration::from_millis(10),
    }
}

struct Running {
    stop: oneshot::Sender<()>,
    task: tokio::task::JoinHandle<()>,
}

impl Running {
    async fn stop(self) {
        let _ = self.stop.send(());
        tokio::time::timeout(Duration::from_secs(5), self.task)
            .await
            .expect("stops promptly")
            .expect("joins");
    }
}

fn spawn_ingest(tap: &Arc<Tap>, fx: &Fixture, client: IngestClient) -> Running {
    let (stop, rx) = oneshot::channel::<()>();
    let (tap, fx) = (tap.clone(), fx.clone());
    let task = tokio::spawn(async move {
        run_ingest(&*tap, fx, client, async move {
            let _ = rx.await;
        })
        .await;
    });
    Running { stop, task }
}

/// The real status reporter over the same gap queue, so gaps reach the server.
fn spawn_reporter(
    fetcher: &Arc<MtlsFetcher>,
    gaps: &GapQueue,
    central: &CentralHealth,
) -> (Running, watch::Sender<ConfigView>) {
    let view = ConfigView {
        state: ConfigState::None,
        last_update_error: None,
        applied_revision: None,
        config_hash: None,
        observed_revision: None,
        expires_at: None,
        max_offline_retry_age_seconds: None,
        event_retention_seconds: None,
        route_upstreams: Vec::new(),
    };
    let (tx, rx) = watch::channel(view);
    let params = ReporterParams {
        heartbeat: Duration::from_millis(150),
        retry: Duration::from_millis(100),
        max_backoff: Duration::from_millis(400),
        min_spacing: Duration::from_millis(30),
    };
    let reporter =
        Reporter::new(PROXY, &epoch(77), gaps.clone(), params).with_central(central.clone());
    let (stop, srx) = oneshot::channel::<()>();
    let f = fetcher.clone();
    let task = tokio::spawn(async move {
        run_status_reporter(&*f, reporter, rx, async move {
            let _ = srx.await;
        })
        .await;
    });
    (Running { stop, task }, tx)
}

struct Proxy {
    tap: Arc<Tap>,
    fx: Fixture,
    gaps: GapQueue,
    central: CentralHealth,
}

impl Proxy {
    fn new(h: &H) -> Proxy {
        Proxy {
            tap: Tap::new(h.fetcher.clone()),
            fx: Fixture::default(),
            gaps: GapQueue::new(),
            central: CentralHealth::new(),
        }
    }
    fn client(&self) -> IngestClient {
        IngestClient::new(self.gaps.clone(), self.central.clone(), fast_params())
    }
    fn gap_kinds(&self) -> Vec<String> {
        self.gaps
            .pending_batch()
            .iter()
            .map(|g| {
                serde_json::to_value(g).unwrap()["kind"]
                    .as_str()
                    .unwrap()
                    .to_string()
            })
            .collect()
    }
}

// ------------------------------------------------------------------- tests

/// #339: the real server parse path refuses every event at index 0. The client
/// stops after the limit, keeps the rest unsent, and sends them after the upgrade.
#[tokio::test]
async fn shape_the_server_cannot_parse_stops_at_the_limit_and_resumes() {
    let Some(h) = H::new(|_| {}).await else {
        return;
    };
    let cap = MAX_CONSECUTIVE_SINGLE_QUARANTINES as usize;
    let px = Proxy::new(&h);
    px.tap.newer_shape.store(true, Ordering::SeqCst);
    px.fx.push((1..=30).map(ping));
    let run = spawn_ingest(&px.tap, &px.fx, px.client());
    eventually("the client keeps retrying past the limit", || {
        px.tap.count_status(422) >= cap + 3
    })
    .await;

    assert_eq!(px.fx.quarantined().len(), cap);
    assert_eq!(px.fx.unsent_count(), 30 - cap);
    assert_eq!(px.fx.acked_count(), 0);
    assert!(!h.stored(1));
    assert!(px
        .fx
        .quarantined()
        .iter()
        .all(|(_, code)| *code == QuarantineCode::SemanticInvalid));
    let refusal: Value = serde_json::from_slice(&px.tap.posts()[0].body).unwrap();
    assert_eq!(refusal["error"]["items"][0]["index"], 0);
    assert_eq!(px.gaps.pending_batch().len(), cap);
    assert_eq!(px.central.consecutive_failures(), 0);
    assert!(px.central.last_ingest_ack_at().is_none());

    px.tap.newer_shape.store(false, Ordering::SeqCst);
    eventually("the rest is accepted after the upgrade", || {
        px.fx.acked_count() == 30 - cap
    })
    .await;
    run.stop().await;
    assert_eq!(px.fx.quarantined().len(), cap);
    assert_eq!(px.fx.unsent_count(), 0);
    assert!(!h.stored(cap as u32));
    assert!(h.stored(cap as u32 + 1));
    assert!(h.stored(30));
}

/// Happy path: events reach the ledger; the source is acknowledged only after
/// the 200 (checked inside the acknowledgement); a reply lost after the server
/// stored the events is answered `duplicate` on the resend.
#[tokio::test]
async fn happy_path_ack_after_200_and_duplicate_on_resend() {
    let Some(h) = H::new(|_| {}).await else {
        return;
    };
    let px = Proxy::new(&h);
    px.fx.probe(h.ctx());
    px.fx.push((1..=5).map(ping));
    let run = spawn_ingest(&px.tap, &px.fx, px.client());
    eventually("5 events acked", || px.fx.acked_count() == 5).await;
    assert!((1..=5).all(|n| h.stored(n)));
    assert_eq!(px.fx.acked(), (1..=5).map(uid).collect::<Vec<_>>());
    assert!(
        px.fx.acked_before_stored().is_empty(),
        "an id was acknowledged before the server stored it"
    );
    let posts = px.tap.posts();
    assert_eq!(posts.len(), 1);
    assert_eq!(posts[0].status, Some(200));
    let v: Value = serde_json::from_slice(&posts[0].body).unwrap();
    assert_eq!(v["accepted_event_ids"].as_array().unwrap().len(), 5);
    assert!(px.central.last_ingest_ack_at().is_some());

    // Ack loss: the server stores, the client never sees the 200.
    *px.tap.watch.lock().unwrap() = Some(px.fx.clone());
    px.tap.drop_replies.store(1, Ordering::SeqCst);
    px.fx.push([ping(6), ping(7)]);
    eventually("6 and 7 acked after the resend", || {
        px.fx.acked_count() == 7
    })
    .await;
    run.stop().await;
    // The source was not acknowledged while the reply was lost.
    assert_eq!(*px.tap.acked_at_drop.lock().unwrap(), vec![5]);
    let posts = px.tap.posts();
    let lost = posts.iter().find(|p| p.dropped).expect("one reply dropped");
    assert_eq!(lost.status, Some(200));
    assert_eq!(lost.ids, vec![uid(6), uid(7)]);
    let resend = posts
        .iter()
        .find(|p| !p.dropped && p.ids == lost.ids)
        .expect("resent");
    assert_eq!(resend.status, Some(200));
    let v: Value = serde_json::from_slice(&resend.body).unwrap();
    assert_eq!(v["accepted_event_ids"], json!([]));
    assert_eq!(v["duplicate_event_ids"], json!([uid(6), uid(7)]));
    assert!(px.fx.acked_before_stored().is_empty());
    // One lost reply is a single failure: far from a central outage.
    assert!(px.gap_kinds().is_empty() && px.gaps.open_outage().is_none());
    // Stored once each.
    assert_eq!(h.ctx().ledger.usage(PROXY).unwrap().event_rows, 7);
}

/// 250 events split 100/100/50 in order; a byte limit splits further. Nothing is
/// lost or reordered and the contiguous sequences derive no gap.
#[tokio::test]
async fn batches_are_split_by_count_and_by_bytes_in_order() {
    let Some(h) = H::new(|_| {}).await else {
        return;
    };
    // Count: the production limits.
    let px = Proxy::new(&h);
    px.fx.push((1..=250).map(ping));
    let run = spawn_ingest(&px.tap, &px.fx, px.client());
    eventually("250 acked", || px.fx.acked_count() == 250).await;
    run.stop().await;
    let sizes: Vec<usize> = px.tap.posts().iter().map(|p| p.ids.len()).collect();
    assert_eq!(sizes, vec![100, 100, 50]);
    let sent: Vec<String> = px.tap.posts().into_iter().flat_map(|p| p.ids).collect();
    assert_eq!(sent, (1..=250).map(uid).collect::<Vec<_>>(), "in order");
    assert_eq!(px.fx.acked(), sent);
    assert!(px.tap.posts().iter().all(|p| p.status == Some(200)));
    assert!((1..=250).all(|n| h.stored(n)));
    assert!(h.ctx().ledger.gaps(PROXY).unwrap().is_empty());

    // Bytes: a limit that fits 4 events but not 5 (test knob; a real event is far
    // from 1 MiB / 100, so the production byte limit cannot be reached here).
    let px = Proxy::new(&h);
    let evs: Vec<ProxyEvent> = (301..=310)
        .map(|n| ev(n, 2, n - 300, None, "up1"))
        .collect();
    let max_one = evs
        .iter()
        .map(|e| serde_json::to_vec(e).unwrap().len())
        .max()
        .unwrap();
    // Framing as the client counts it: `{"events":[` + `]}` is 13 bytes, and a
    // batch of 4 events has 3 commas. 4 events fit, 5 do not (events differ in
    // size by a byte or so at most).
    let limit = 13 + 4 * max_one + 3;
    px.fx.push(evs);
    let run = spawn_ingest(&px.tap, &px.fx, px.client().with_batch_limits(100, limit));
    eventually("10 acked", || px.fx.acked_count() == 10).await;
    run.stop().await;
    let sizes: Vec<usize> = px.tap.posts().iter().map(|p| p.ids.len()).collect();
    assert_eq!(sizes, vec![4, 4, 2]);
    let sent: Vec<String> = px.tap.posts().into_iter().flat_map(|p| p.ids).collect();
    assert_eq!(sent, (301..=310).map(uid).collect::<Vec<_>>());
    assert!((301..=310).all(|n| h.stored(n)));
}

/// L4: a sequence jump opens a server `sequence_gap` that a late fill closes; a
/// new epoch records `producer_epoch_change`.
#[tokio::test]
async fn server_derived_gaps_open_close_and_epoch_change() {
    let Some(h) = H::new(|_| {}).await else {
        return;
    };
    let px = Proxy::new(&h);
    let run = spawn_ingest(&px.tap, &px.fx, px.client());

    px.fx
        .push([ev(1, 1, 1, None, "up1"), ev(2, 1, 2, None, "up1")]);
    px.fx.push([ev(5, 1, 5, None, "up1")]);
    eventually("1, 2, 5 acked", || px.fx.acked_count() == 3).await;
    let gaps = h.ctx().ledger.gaps(PROXY).unwrap();
    assert_eq!(gaps.len(), 1);
    assert_eq!(gaps[0].kind, GapKind::SequenceGap);
    assert!(gaps[0].open && gaps[0].closed_at.is_none());
    assert_eq!(gaps[0].epoch_id, epoch(1));
    assert_eq!(
        (gaps[0].from_sequence, gaps[0].to_sequence),
        (Some(3), Some(4))
    );

    // The late fill closes it.
    px.fx
        .push([ev(3, 1, 3, None, "up1"), ev(4, 1, 4, None, "up1")]);
    eventually("3 and 4 acked", || px.fx.acked_count() == 5).await;
    let gaps = h.ctx().ledger.gaps(PROXY).unwrap();
    assert_eq!(gaps.len(), 1);
    assert!(!gaps[0].open && gaps[0].closed_at.is_some(), "{gaps:?}");

    // A new epoch.
    px.fx.push([ev(10, 2, 1, None, "up1")]);
    eventually("epoch 2 event acked", || px.fx.acked_count() == 6).await;
    run.stop().await;
    let gaps = h.ctx().ledger.gaps(PROXY).unwrap();
    let change: Vec<_> = gaps
        .iter()
        .filter(|g| g.kind == GapKind::ProducerEpochChange)
        .collect();
    assert_eq!(change.len(), 1);
    assert_eq!(change[0].epoch_id, epoch(2));
    assert_eq!(
        change[0].previous_epoch_id.as_deref(),
        Some(epoch(1).as_str())
    );
    assert!(px.gap_kinds().is_empty(), "no proxy-side gap for these");
}

/// A conflicting event (same id, different body) is quarantined unchanged on the
/// proxy with an `event_quarantined` gap; the rest of the batch is delivered; the
/// gap reaches the server through the status report.
#[tokio::test]
async fn conflicting_event_is_quarantined_with_a_gap() {
    let Some(h) = H::new(|_| {}).await else {
        return;
    };
    let px = Proxy::new(&h);
    let run = spawn_ingest(&px.tap, &px.fx, px.client());
    px.fx.push([ping(1)]);
    eventually("1 acked", || px.fx.acked_count() == 1).await;
    let original = h
        .ctx()
        .ledger
        .stored_event(PROXY, &uid(1))
        .unwrap()
        .unwrap()
        .canonical;

    // Same id, other body, in one batch with a good event.
    px.fx.push([ev(1, 1, 1, None, "up-other"), ping(2)]);
    eventually("conflict quarantined and 2 acked", || {
        px.fx.quarantined().len() == 1 && px.fx.acked_count() == 2
    })
    .await;
    run.stop().await;
    assert_eq!(px.fx.quarantined()[0].0, uid(1));
    assert_eq!(px.fx.quarantined()[0].1, QuarantineCode::Conflict);
    assert_eq!(px.fx.unsent_count(), 0);
    assert!(px.tap.count_status(409) >= 1);
    // The stored event is untouched; the good one landed.
    assert_eq!(
        h.ctx()
            .ledger
            .stored_event(PROXY, &uid(1))
            .unwrap()
            .unwrap()
            .canonical,
        original
    );
    assert!(h.stored(2));
    // The proxy queued the gap ...
    let pending = px.gaps.pending_batch();
    assert_eq!(pending.len(), 1);
    let g = serde_json::to_value(&pending[0]).unwrap();
    assert_eq!(g["kind"], "event_quarantined");
    assert_eq!(g["code"], "conflict");
    assert_eq!(g["event_ids"], json!([uid(1)]));
    // ... and the server stores it once reported.
    let (rep, _tx) = spawn_reporter(&h.fetcher, &px.gaps, &px.central);
    eventually("server holds the quarantine gap", || {
        h.server_gaps().iter().any(|s| s["gap_id"] == g["gap_id"])
    })
    .await;
    eventually("gap acknowledged on the proxy", || {
        px.gaps.pending_ids().is_empty()
    })
    .await;
    rep.stop().await;
    let stored = h
        .server_gaps()
        .into_iter()
        .find(|s| s["gap_id"] == g["gap_id"])
        .unwrap();
    assert_eq!(stored["kind"], "event_quarantined");
    assert_eq!(stored["code"], "conflict");
    assert_eq!(stored["event_ids"], json!([uid(1)]));
}

/// 424: an event naming an unregistered metadata ref is held (not quarantined,
/// not acknowledged) and retried; once the entry is uploaded it is accepted.
#[tokio::test]
async fn unregistered_metadata_ref_is_held_then_accepted_after_upload() {
    let Some(h) = H::new(|_| {}).await else {
        return;
    };
    let px = Proxy::new(&h);
    let run = spawn_ingest(&px.tap, &px.fx, px.client());
    px.fx.push([ev(1, 1, 1, Some(&mref(1)), "up1")]);
    eventually("two 424 answers (held, retried later)", || {
        px.tap.count_status(424) >= 2
    })
    .await;
    assert!(!h.stored(1));
    assert_eq!(px.fx.acked_count(), 0);
    assert!(px.fx.quarantined().is_empty());
    assert!(px.gap_kinds().is_empty(), "a hold is not a gap");
    assert_eq!(px.central.consecutive_failures(), 0);
    assert!(px.gaps.open_outage().is_none());
    assert!(px.tap.posts().iter().all(|p| p.status == Some(424)));
    let v: Value = serde_json::from_slice(&px.tap.posts()[0].body).unwrap();
    assert_eq!(v["error"]["code"], "metadata_ref_pending");

    h.upload_metadata(&mref(1)).await;
    eventually("accepted after the upload", || px.fx.acked_count() == 1).await;
    run.stop().await;
    assert!(h.stored(1));
    assert_eq!(px.tap.posts().last().unwrap().status, Some(200));
    assert!(px.fx.quarantined().is_empty());
}

/// 503 `storage_limit`: backoff, never a `central_outage`; delivery resumes once
/// the server's data is swept.
#[tokio::test]
async fn storage_limit_backs_off_without_outage_and_resumes_after_sweep() {
    let Some(h) = H::new(|p| p.ledger_max_rows_per_proxy = Some(2)).await else {
        return;
    };
    let px = Proxy::new(&h);
    let run = spawn_ingest(&px.tap, &px.fx, px.client());
    px.fx.push([ping(1), ping(2)]);
    eventually("1 and 2 acked", || px.fx.acked_count() == 2).await;

    px.fx.push([ping(3), ping(4)]);
    // More refusals than the outage threshold (3), so an outage would have opened.
    eventually("four storage_limit answers", || {
        px.tap.count_status(503) >= 4
    })
    .await;
    let v: Value = serde_json::from_slice(&px.tap.posts().last().unwrap().body).unwrap();
    assert_eq!(v["error"]["code"], "storage_limit");
    assert_eq!(px.fx.acked_count(), 2);
    assert!(!h.stored(3) && !h.stored(4));
    assert!(px.gaps.open_outage().is_none());
    assert!(px.gap_kinds().is_empty(), "no central_outage gap");
    assert_eq!(px.central.consecutive_failures(), 0);
    // Backoff: the last two refusals are at least the base retry (100 ms, minus
    // the 20% jitter) apart. A lower bound only, so load cannot break it.
    let posts = px.tap.posts();
    let [.., prev, last] = &posts[..] else {
        panic!("at least two posts");
    };
    assert!(
        last.at.duration_since(prev.at) >= Duration::from_millis(60),
        "refusals are backed off, not retried at the 10 ms spacing"
    );

    // Relief: sweep as if 200 days had passed (past E and T).
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    h.ctx().ledger_sweep(now + 200 * 86_400).unwrap();
    eventually("3 and 4 acked after the sweep", || px.fx.acked_count() == 4).await;
    run.stop().await;
    assert!(h.stored(3) && h.stored(4));
    assert!(px.gaps.open_outage().is_none() && px.gap_kinds().is_empty());
    // The resumed events continue the sequence: no server gap.
    assert!(h.ctx().ledger.gaps(PROXY).unwrap().is_empty());
}

/// 503 `storage_limit` relieved by a raised cap: the server restarts on the same
/// files with a bigger limit and delivery resumes.
#[tokio::test]
async fn storage_limit_resumes_after_the_cap_is_raised() {
    let Some(mut h) = H::new(|p| p.ledger_max_rows_per_proxy = Some(1)).await else {
        return;
    };
    let px = Proxy::new(&h);
    let run = spawn_ingest(&px.tap, &px.fx, px.client());
    px.fx.push([ping(1), ping(2)]);
    eventually("a refusal for the second event", || {
        px.tap.count_status(503) >= 1
    })
    .await;
    assert!(px.fx.acked_count() <= 1 && !h.stored(2));
    // Keep the producer quiet while the server is restarted, so no outage forms.
    px.fx.set_paused(true);
    tokio::time::sleep(Duration::from_millis(100)).await;
    h.server_down().await;
    h.server_up_with(Arc::new(|p: &mut ProxyConfig| {
        p.ledger_max_rows_per_proxy = Some(100)
    }))
    .await;
    px.fx.set_paused(false);
    eventually("both acked after the cap is raised", || {
        px.fx.acked_count() == 2
    })
    .await;
    run.stop().await;
    assert!(h.stored(1) && h.stored(2));
    assert!(px.gaps.open_outage().is_none() && px.gap_kinds().is_empty());
    assert!(h.ctx().ledger.gaps(PROXY).unwrap().is_empty());
}

/// Server down: after 3 failures a `central_outage` gap opens. On restart (same
/// port, same files) the close resends the original gap with only `ended_at`
/// added, and the server accepts it.
#[tokio::test]
async fn outage_opens_after_three_failures_and_closes_after_restart() {
    let Some(mut h) = H::new(|_| {}).await else {
        return;
    };
    let px = Proxy::new(&h);
    let run = spawn_ingest(&px.tap, &px.fx, px.client());
    px.fx.push([ping(1)]);
    eventually("1 acked", || px.fx.acked_count() == 1).await;

    h.server_down().await;
    px.fx.push([ping(2)]);
    eventually("outage opened", || px.gaps.open_outage().is_some()).await;
    assert!(
        px.tap.posts().iter().filter(|p| p.status.is_none()).count() >= 3,
        "opened by at least three failures"
    );
    // Hold the producer so the close cannot race the open gap's delivery.
    px.fx.set_paused(true);
    let open = px.gaps.open_outage().unwrap();
    assert!(px.gap_kinds().contains(&"central_outage".to_string()));

    h.server_up().await;
    let (rep, _tx) = spawn_reporter(&h.fetcher, &px.gaps, &px.central);
    let gid = open.gap_id.clone();
    eventually("server holds the open outage gap", || {
        h.server_gaps().iter().any(|g| g["gap_id"] == gid.as_str())
    })
    .await;
    let original = h
        .server_gaps()
        .into_iter()
        .find(|g| g["gap_id"] == gid.as_str())
        .unwrap();
    assert_eq!(original["kind"], "central_outage");
    assert!(original["ended_at"].is_null(), "open: {original}");
    eventually("open gap acknowledged", || px.gaps.pending_ids().is_empty()).await;

    // The server answers the next ingest: the outage closes.
    px.fx.set_paused(false);
    eventually("2 acked after the restart", || px.fx.acked_count() == 2).await;
    eventually("server holds the closed gap", || {
        h.server_gaps()
            .iter()
            .any(|g| g["gap_id"] == gid.as_str() && g["ended_at"].is_string())
    })
    .await;
    eventually("closing gap acknowledged", || {
        px.gaps.pending_ids().is_empty()
    })
    .await;
    rep.stop().await;
    run.stop().await;
    let closed = h
        .server_gaps()
        .into_iter()
        .find(|g| g["gap_id"] == gid.as_str())
        .unwrap();
    let strip = |v: &Value| {
        let mut v = v.clone();
        v.as_object_mut().unwrap().remove("ended_at");
        v
    };
    assert_eq!(strip(&closed), strip(&original), "only ended_at differs");
    assert!(px.gaps.open_outage().is_none());
    // Events survived the restart on the same files.
    assert!(h.stored(1) && h.stored(2));
}

/// A disabled proxy gets 403 `disabled`; nothing is stored; the source keeps the
/// events.
#[tokio::test]
async fn disabled_proxy_is_refused_and_nothing_is_stored() {
    let Some(h) = H::new(|_| {}).await else {
        return;
    };
    let (st, _) = h
        .mgmt_call("POST", &format!("/v1/proxies/{PROXY}/disable"), T_CFG, None)
        .await;
    assert_eq!(st, 200, "disable");
    let px = Proxy::new(&h);
    px.fx.push([ping(1), ping(2)]);
    let mut client = px.client();
    let mut src = px.fx.clone();
    let step = client
        .send_once(&*px.tap, &mut src, tokio::time::Instant::now())
        .await;
    assert_eq!(step.outcome, Some(IngestOutcome::Rejected));
    assert!(!step.progressed);
    let posts = px.tap.posts();
    assert_eq!(posts.len(), 1);
    assert_eq!(posts[0].status, Some(403));
    let v: Value = serde_json::from_slice(&posts[0].body).unwrap();
    assert_eq!(v["error"]["code"], "disabled");
    assert!(!h.stored(1) && !h.stored(2));
    assert_eq!(h.ctx().ledger.usage(PROXY).unwrap().event_rows, 0);
    assert_eq!(px.fx.acked_count(), 0);
    assert_eq!(px.fx.unsent_count(), 2, "the source keeps its events");
    assert!(px.fx.quarantined().is_empty() && px.gap_kinds().is_empty());
    assert_eq!(px.central.consecutive_failures(), 0);
    assert!(px.gaps.open_outage().is_none());
}
