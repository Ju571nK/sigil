#![cfg(unix)]
//! T-13c (#312): the inventory on the PRODUCTION path.
//!
//! The proxy is the real `lifecycle::run_tuned` (registry opened next to the
//! spool, relay observation sink, registry client with the real mTLS transport,
//! status probe), in front of a fake MCP upstream that pages `tools/list`, and
//! talking over loopback rustls mTLS to the real `sigil-server` proxy routes. A
//! complete `tools/list` through the relay must become a baseline snapshot on the
//! server's read view; a changed listing must become drift; the status report
//! must carry the registry's real counts. A last test starts the REAL
//! `sigil-proxy` binary (built without `test-util`).
//!
//! Requirements: PX-005, PX-006, PX-010; acceptance AC-02, AC-05.
//! Real-time polling with tuned short intervals; no paused clock.
//! The PKI/server helpers are copied from `spool_ingest_e2e.rs` (sharing them is
//! tracked in #284). Missing openssl, or no proxy binary, FAILS under `CI`.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use sigil_proxy::bootstrap::Bootstrap;
use sigil_proxy::ingest_client::IngestParams;
use sigil_proxy::lifecycle::{run_tuned, RunTuning};
use sigil_proxy::registry_client::RegistryParams;
use sigil_proxy::route::TableHandle;
use sigil_proxy_api::verifier::verifier_for;
use sigil_server::app::{build_router_with_proxy, AppState};
use sigil_server::auth::ReadToken;
use sigil_server::config::{ProxyConfig, ServerConfig};
use sigil_server::fleet_index::FleetIndex;
use sigil_server::persist::HighWater;
use sigil_server::proxy::identity::proxy_san;
use sigil_server::proxy::verifiers::{Scope, VerifierEntry};
use sigil_server::proxy::ProxyContext;
use sigil_server::tls_accept::PeerCertAcceptor;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const T_ID: &str = "tok-identity-inv";
const T_CFG: &str = "tok-config-inv";
const READ_BEARER: &str = "read-bearer";
const PROXY: &str = "px-inv";
const CLIENT_TOKEN: &str = "client-tok";
const WAIT: Duration = Duration::from_secs(30);

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
    pki.ca("hostca", "inv-host-ca", "1");
    pki.ca("proxyca", "inv-proxy-ca", "2");
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

// ------------------------------------------------------------ fake MCP upstream

/// Names are canaries: they must never reach the server's views.
const NAMES: [&str; 4] = [
    "alphatoolcanary1",
    "betatoolcanary2",
    "gammatoolcanary3",
    "deltatoolcanary4",
];

struct UpState {
    /// `(name, description)` in listing order.
    tools: Vec<(String, String)>,
    page_size: usize,
    calls: usize,
}

struct Upstream {
    port: u16,
    state: Arc<Mutex<UpState>>,
}

impl Upstream {
    fn set_tools(&self, tools: &[(&str, &str)]) {
        self.state.lock().unwrap().tools = owned(tools);
    }
}

fn owned(tools: &[(&str, &str)]) -> Vec<(String, String)> {
    tools
        .iter()
        .map(|(n, d)| (n.to_string(), d.to_string()))
        .collect()
}

fn answer(state: &Mutex<UpState>, body: &[u8]) -> Vec<u8> {
    let v: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
    let id = v["id"].clone();
    let result = if v["method"] == "initialize" {
        json!({"protocolVersion":"2025-11-25", "capabilities":{"tools":{}}, "serverInfo":{"name":"fixture","version":"1"}})
    } else if v["method"] == "tools/call" {
        state.lock().unwrap().calls += 1;
        json!({"content":[{"type":"text","text":"private-result-canary"}]})
    } else if v["method"] == "tools/list" {
        let s = state.lock().unwrap();
        let offset: usize = v["params"]["cursor"]
            .as_str()
            .and_then(|c| c.strip_prefix('o'))
            .and_then(|n| n.parse().ok())
            .unwrap_or(0);
        let end = (offset + s.page_size).min(s.tools.len());
        let tools: Vec<Value> = s.tools[offset.min(end)..end]
            .iter()
            .map(|(n, d)| json!({"name": n, "description": d, "inputSchema": {"type": "object"}}))
            .collect();
        let mut r = json!({ "tools": tools });
        if end < s.tools.len() {
            r["nextCursor"] = json!(format!("o{end}"));
        }
        r
    } else {
        json!({})
    };
    serde_json::to_vec(&json!({"jsonrpc": "2.0", "id": id, "result": result})).unwrap()
}

async fn upstream(tools: &[(&str, &str)], page_size: usize) -> Upstream {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let state = Arc::new(Mutex::new(UpState {
        tools: owned(tools),
        page_size,
        calls: 0,
    }));
    let st = state.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else {
                return;
            };
            let st = st.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut tmp = [0u8; 4096];
                let (head_end, want) = loop {
                    let n = s.read(&mut tmp).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                    if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&buf[..i]).to_ascii_lowercase();
                        let want = head
                            .lines()
                            .find_map(|l| l.strip_prefix("content-length:"))
                            .and_then(|v| v.trim().parse::<usize>().ok())
                            .unwrap_or(0);
                        if buf.len() >= i + 4 + want {
                            break (i + 4, want);
                        }
                    }
                };
                let request = &buf[head_end..head_end + want];
                let v: Value = serde_json::from_slice(request).unwrap_or(Value::Null);
                let body = answer(&st, request);
                if v["params"]["wait"] == true {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
                let head = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    body.len()
                );
                let _ = s.write_all(head.as_bytes()).await;
                let _ = s.write_all(&body).await;
                let _ = s.shutdown().await;
            });
        }
    });
    Upstream { port, state }
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

fn spec(up_port: u16) -> Value {
    json!({
        "schema_version": 1,
        "proxy_id": PROXY,
        "allowed_origins": ["https://app.example.com"],
        "routes": [{
            "route_id": "r1",
            "upstream_id": "up1",
            "upstream_url": format!("http://127.0.0.1:{up_port}/mcp"),
            "upstream_protocol": "2025-11-25",
            "credential_ref": "gh",
        }],
        "principals": [{
            "principal_id": "claude",
            "verifiers": [{"key_id": "k1", "verifier": verifier_for(CLIENT_TOKEN)}],
            "routes": ["r1"],
        }],
    })
}

struct H {
    pki: Pki,
    proxy_cert: (PathBuf, PathBuf),
    srv: Server,
    host: reqwest::Client,
    up: Upstream,
}

async fn mgmt_call(
    c: &reqwest::Client,
    port: u16,
    method: &str,
    path: &str,
    bearer: &str,
    body: Value,
) -> (u16, String) {
    let r = c
        .request(
            reqwest::Method::from_bytes(method.as_bytes()).unwrap(),
            format!("https://127.0.0.1:{port}{path}"),
        )
        .bearer_auth(bearer)
        .json(&body)
        .send()
        .await
        .unwrap();
    (r.status().as_u16(), r.text().await.unwrap())
}

impl H {
    async fn new(tools: &[(&str, &str)], page_size: usize) -> Option<H> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let pki = pki()?;
        let up = upstream(tools, page_size).await;
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
        // The read API takes a host certificate (not the management caller's).
        let host_cert = pki.leaf(
            "hostca",
            "host",
            "host-1",
            "subjectAltName=DNS:host-1\nextendedKeyUsage=clientAuth\nbasicConstraints=CA:FALSE\n",
        );
        let host = mtls_client(&pki.p("hostca.crt"), &host_cert.0, &host_cert.1);
        let tweak: Tweak = Arc::new(|_| {});
        let srv = Server::start(&pki, 0, true, &tweak).await;
        let mgmt = mtls_client(&pki.p("hostca.crt"), &mgmt_cert.0, &mgmt_cert.1);
        let (st, b) = mgmt_call(
            &mgmt,
            srv.port,
            "POST",
            "/v1/proxies",
            T_ID,
            json!({"proxy_id": PROXY, "display_name": "inv"}),
        )
        .await;
        assert_eq!(st, 201, "register: {b}");
        let (st, b) = mgmt_call(
            &mgmt,
            srv.port,
            "POST",
            &format!("/v1/proxies/{PROXY}/fingerprints"),
            T_ID,
            json!({"fingerprint": fingerprint(&proxy_cert.0)}),
        )
        .await;
        assert_eq!(st, 200, "fingerprint: {b}");
        let (st, b) = mgmt_call(
            &mgmt,
            srv.port,
            "PUT",
            &format!("/v1/proxies/{PROXY}/config"),
            T_CFG,
            json!({"expected_revision": 0, "config": spec(up.port)}),
        )
        .await;
        assert_eq!(st, 200, "config put: {b}");
        Some(H {
            pki,
            proxy_cert,
            srv,
            host,
            up,
        })
    }

    fn bootstrap_yaml(&self, listen: &str) -> String {
        let d = self.pki.dir.path();
        let secret = d.join("upstream-secret");
        std::fs::write(&secret, "UPSTREAM-SECRET-VALUE\n").unwrap();
        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600)).unwrap();
        format!(
            "proxy_id: {PROXY}\nlisten: \"{listen}\"\n\
             control_plane_url: \"https://127.0.0.1:{}\"\n\
             state_dir: {}\nclient_cert_file: {}\nclient_key_file: {}\nca_file: {}\n\
             credentials:\n  gh:\n    secret_file: {}\n    upstream_origins: [\"http://127.0.0.1:{}\"]\n",
            self.srv.port,
            self.state_dir().display(),
            self.proxy_cert.0.display(),
            self.proxy_cert.1.display(),
            self.pki.p("hostca.crt").display(),
            secret.display(),
            self.up.port,
        )
    }

    fn state_dir(&self) -> PathBuf {
        self.pki.dir.path().join("proxy-state")
    }

    /// Latest applied status snapshot the server holds.
    fn status(&self) -> Option<sigil_proxy_api::ProxyStatus> {
        self.srv.ctx.store.entry(PROXY).and_then(|e| e.status)
    }

    /// An item list of the server's read API (host mTLS + read bearer).
    async fn items(&self, path: &str) -> Vec<Value> {
        let r = self
            .host
            .get(format!("https://127.0.0.1:{}{path}", self.srv.port))
            .bearer_auth(READ_BEARER)
            .send()
            .await
            .unwrap();
        let (st, t) = (r.status().as_u16(), r.text().await.unwrap());
        assert_eq!(st, 200, "{path}: {t}");
        for n in NAMES {
            assert!(!t.contains(n), "a tool name reached the read view");
        }
        serde_json::from_str::<Value>(&t).unwrap()["items"]
            .as_array()
            .unwrap()
            .clone()
    }

    async fn snapshots(&self) -> Vec<Value> {
        self.items(&format!("/v1/proxies/{PROXY}/inventory-snapshots"))
            .await
    }

    async fn drift(&self) -> Vec<Value> {
        self.items(&format!("/v1/proxies/{PROXY}/drift")).await
    }
}

async fn eventually<F: std::future::Future<Output = bool>>(what: &str, mut f: impl FnMut() -> F) {
    let start = Instant::now();
    while start.elapsed() < WAIT {
        if f().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("timed out waiting for: {what}");
}

// ------------------------------------------------------------ proxy runner

fn tuning(listener: std::net::TcpListener, registry_poll: Duration) -> RunTuning {
    let mut t = RunTuning {
        listener: Some(listener),
        ..RunTuning::default()
    };
    t.sync.poll = Duration::from_millis(150);
    t.sync.retry = Duration::from_millis(150);
    t.report.heartbeat = Duration::from_millis(200);
    t.report.retry = Duration::from_millis(150);
    t.report.max_backoff = Duration::from_millis(500);
    t.report.min_spacing = Duration::from_millis(50);
    t.ingest = IngestParams {
        poll: Duration::from_millis(30),
        retry: Duration::from_millis(100),
        max_backoff: Duration::from_millis(400),
        min_spacing: Duration::from_millis(10),
    };
    t.registry = RegistryParams {
        poll: registry_poll,
        retry: Duration::from_millis(100),
        max_backoff: Duration::from_millis(400),
        min_spacing: Duration::from_millis(20),
    };
    t
}

struct Running {
    listen: u16,
    session: tokio::sync::Mutex<Option<String>>,
    spool: Option<sigil_proxy::spool::Spool>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<anyhow::Result<()>>>,
}

/// The proxy through `lifecycle::run_tuned`, which is the production `run_inner`.
/// The registry client idles for `registry_poll` between steps.
async fn start_proxy(h: &H, registry_poll: Duration) -> Running {
    let b = Bootstrap::from_yaml(&h.bootstrap_yaml("127.0.0.1:0"), h.pki.dir.path())
        .expect("bootstrap loads");
    let sock = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let listen = sock.local_addr().unwrap().port();
    let (stop, rx) = tokio::sync::oneshot::channel::<()>();
    let mut tune = tuning(sock, registry_poll);
    let (spool_tx, spool_rx) = tokio::sync::oneshot::channel();
    tune.spool_out = Some(spool_tx);
    let task = tokio::spawn(async move {
        run_tuned(
            &b,
            TableHandle::new(),
            async move {
                let _ = rx.await;
            },
            tune,
        )
        .await
    });
    let px = Running {
        listen,
        session: tokio::sync::Mutex::new(None),
        spool: Some(tokio::time::timeout(WAIT, spool_rx).await.unwrap().unwrap()),
        stop: Some(stop),
        task: Some(task),
    };
    eventually("the proxy forwards", || async {
        px.call(json!({"jsonrpc": "2.0", "id": 1, "method": "ping"}))
            .await
            .0
            == 200
    })
    .await;
    px
}

impl Running {
    /// One request through the relay: `(status, body)`.
    async fn call(&self, body: Value) -> (u16, Value) {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();
        let url = format!("http://127.0.0.1:{}/mcp/r1", self.listen);
        let mut session = self.session.lock().await;
        if session.is_none() {
            let r = client.post(&url).bearer_auth(CLIENT_TOKEN)
                .json(&json!({"jsonrpc":"2.0","id":"initialize","method":"initialize", "params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"fixture","version":"1"}}}))
                .send().await;
            let Ok(r) = r else { return (0, Value::Null) };
            *session = r
                .headers()
                .get("mcp-session-id")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            if session.is_none() {
                return (r.status().as_u16(), Value::Null);
            }
        }
        let sid = session.clone().unwrap();
        drop(session);
        let r = client
            .post(&url)
            .header("mcp-session-id", sid)
            .header("mcp-protocol-version", "2025-11-25")
            .bearer_auth(CLIENT_TOKEN)
            .header("content-type", "application/json")
            .body(body.to_string())
            .send()
            .await;
        match r {
            Ok(r) => {
                let st = r.status().as_u16();
                (st, r.json().await.unwrap_or(Value::Null))
            }
            Err(_) => (0, Value::Null),
        }
    }

    /// A complete `tools/list` through the relay, following `nextCursor`.
    async fn list_all(&self) -> usize {
        let (mut cursor, mut total, mut id) = (None::<String>, 0, 10);
        loop {
            id += 1;
            let mut req = json!({"jsonrpc": "2.0", "id": id, "method": "tools/list"});
            if let Some(c) = &cursor {
                req["params"] = json!({ "cursor": c });
            }
            let (st, v) = self.call(req).await;
            assert_eq!(st, 200, "tools/list: {v}");
            total += v["result"]["tools"].as_array().map_or(0, Vec::len);
            match v["result"]["nextCursor"].as_str() {
                Some(c) => cursor = Some(c.to_string()),
                None => return total,
            }
        }
    }

    async fn stop(mut self) {
        let _ = self.stop.take().expect("running").send(());
        let r = tokio::time::timeout(Duration::from_secs(20), self.task.take().expect("running"))
            .await
            .expect("proxy stops within the grace")
            .expect("proxy task joins");
        r.expect("proxy run returns Ok");
    }
}

// ------------------------------------------------------------------- tests

/// A complete, paged `tools/list` through the relay becomes a baseline snapshot
/// on the server; a changed listing becomes drift; the status report carries the
/// registry's real counts (T-13c on the production path: the sink, the engine,
/// the registry client, the probe).
#[tokio::test]
async fn a_listing_through_the_relay_becomes_a_baseline_and_then_drift() {
    let Some(h) = H::new(
        &[
            (NAMES[0], "first tool"),
            (NAMES[1], "second tool"),
            (NAMES[2], "third tool"),
        ],
        2,
    )
    .await
    else {
        return;
    };

    // Phase 1: the registry client idles for a long while, so the entries the
    // listing mints stay pending and the status report shows them.
    let px = start_proxy(&h, Duration::from_secs(120)).await;
    // Let the client's first (idle) step happen before the listing completes.
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(px.list_all().await, 3);
    eventually("status shows the three pending entries", || async {
        h.status().is_some_and(|s| {
            s.registry.pending_entries.get() == 3
                && !s.registry.sync_stalled
                && s.registry.quarantined_entries.map(|v| v.get()) == Some(0)
                && s.registry.poisoned_entries.map(|v| v.get()) == Some(0)
                && s.registry.discarded_reports.map(|v| v.get()) == Some(0)
        })
    })
    .await;
    assert!(
        h.snapshots().await.is_empty(),
        "nothing is uploaded while the client idles"
    );
    px.stop().await;

    // Phase 2: a restart. The entries and the queued report were durable.
    let px = start_proxy(&h, Duration::from_millis(50)).await;
    eventually("the baseline snapshot is on the server", || async {
        h.snapshots().await.len() == 1
    })
    .await;
    let snaps = h.snapshots().await;
    assert_eq!(snaps[0]["member_count"], 3);
    assert_eq!(snaps[0]["comparison_state"], "baseline");
    assert_eq!(snaps[0]["is_first_baseline"], true);
    eventually("nothing is pending any more", || async {
        h.status()
            .is_some_and(|s| s.registry.pending_entries.get() == 0 && !s.registry.sync_stalled)
    })
    .await;
    assert!(h.drift().await.is_empty(), "a baseline is not drift");

    // Phase 3: the upstream changes one tool and adds another.
    h.up.set_tools(&[
        (NAMES[0], "first tool"),
        (NAMES[1], "second tool CHANGED"),
        (NAMES[2], "third tool"),
        (NAMES[3], "fourth tool"),
    ]);
    assert_eq!(px.list_all().await, 4);
    eventually("drift records are on the server", || async {
        !h.drift().await.is_empty()
    })
    .await;
    let drift = h.drift().await;
    let mut kinds: Vec<&str> = drift
        .iter()
        .map(|d| d["change"].as_str().unwrap())
        .collect();
    kinds.sort_unstable();
    assert_eq!(kinds, vec!["added", "changed"], "{drift:?}");
    assert_eq!(h.snapshots().await.len(), 2);
    assert_eq!(h.snapshots().await[0]["member_count"], 4, "newest first");
    px.stop().await;
    assert!(h.srv.stop().await > 0);
}

/// A listing that never completes (the client stops after the first page) changes
/// nothing on the server and is closed as incomplete when the proxy stops.
#[tokio::test]
async fn an_unfinished_listing_never_becomes_a_snapshot() {
    let Some(h) = H::new(
        &[
            (NAMES[0], "first tool"),
            (NAMES[1], "second tool"),
            (NAMES[2], "third tool"),
        ],
        2,
    )
    .await
    else {
        return;
    };
    let px = start_proxy(&h, Duration::from_secs(120)).await;
    let (st, v) = px
        .call(json!({"jsonrpc": "2.0", "id": 21, "method": "tools/list"}))
        .await;
    assert_eq!(st, 200);
    assert!(v["result"]["nextCursor"].is_string());
    // The shutdown ends the open chain (`session_ended`) and queues a report.
    px.stop().await;
    let (store, _) =
        sigil_proxy::registry_store::RegistryStore::open(&h.state_dir(), PROXY).unwrap();
    let reports: Vec<Value> = store
        .pending_reports(100)
        .unwrap()
        .iter()
        .map(|r| serde_json::from_slice(&r.body).unwrap())
        .collect();
    assert_eq!(reports.len(), 1, "{reports:?}");
    assert_eq!(reports[0]["completeness"], "incomplete");
    assert_eq!(reports[0]["incomplete_reason"], "session_ended");
    assert!(h.snapshots().await.is_empty());
}

/// H1: the client skips ahead with a cursor the proxy never handed out. The
/// upstream answers it happily and the last page has no `nextCursor`, but the
/// relay's keyed cursor tag does not match, so the listing is NOT complete.
#[tokio::test]
async fn a_forged_cursor_never_completes_a_listing() {
    let Some(h) = H::new(
        &[
            (NAMES[0], "first tool"),
            (NAMES[1], "second tool"),
            (NAMES[2], "third tool"),
        ],
        2,
    )
    .await
    else {
        return;
    };
    let px = start_proxy(&h, Duration::from_secs(120)).await;
    let (st, v) = px
        .call(json!({"jsonrpc": "2.0", "id": 31, "method": "tools/list"}))
        .await;
    assert_eq!(st, 200);
    assert_eq!(v["result"]["nextCursor"], "o2");
    // "o1" is a valid cursor for the upstream but not the one it was handed.
    let (st, v) = px
        .call(json!({"jsonrpc": "2.0", "id": 32, "method": "tools/list",
                     "params": {"cursor": "o1"}}))
        .await;
    assert_eq!(st, 200);
    assert!(v["result"]["nextCursor"].is_null());
    px.stop().await;
    let (store, _) =
        sigil_proxy::registry_store::RegistryStore::open(&h.state_dir(), PROXY).unwrap();
    let reports: Vec<Value> = store
        .pending_reports(100)
        .unwrap()
        .iter()
        .map(|r| serde_json::from_slice(&r.body).unwrap())
        .collect();
    assert_eq!(reports.len(), 1, "{reports:?}");
    assert_eq!(reports[0]["completeness"], "incomplete");
    assert_eq!(reports[0]["incomplete_reason"], "cursor_invalid");
    assert!(h.snapshots().await.is_empty());
}

// ------------------------------------------------------- the real binary

/// Build (a no-op when current) and locate the real `sigil-proxy` binary, built
/// WITHOUT the `test-util` feature: the release code path. Failing to build or
/// find it fails under `CI`; elsewhere the test skips.
fn proxy_binary() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let profile_dir = exe.parent()?.parent()?.to_path_buf();
    let profile = profile_dir.file_name()?.to_owned();
    let target_dir = match std::env::var_os("CARGO_TARGET_DIR") {
        Some(d) => PathBuf::from(d),
        None => profile_dir.parent()?.to_path_buf(),
    };
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut c = Command::new(cargo);
    c.args(["build", "-p", "sigil-proxy", "--bin", "sigil-proxy"])
        .arg("--target-dir")
        .arg(&target_dir)
        .current_dir(env!("CARGO_MANIFEST_DIR"));
    if profile == "release" {
        c.arg("--release");
    }
    let status = c
        .status()
        .expect("cargo runs to build the real sigil-proxy binary");
    assert!(
        status.success(),
        "building the real sigil-proxy binary failed: {status}"
    );
    let bin = target_dir.join(&profile).join("sigil-proxy");
    assert!(
        bin.exists(),
        "cargo succeeded but produced no real proxy binary at {}",
        bin.display()
    );
    Some(bin)
}

/// Kills the child if the test fails before it stopped it.
struct Child(std::process::Child);

impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A REAL `sigil-proxy` process (no test knobs, default pacing) turns a complete
/// `tools/list` into a baseline snapshot on the server, and stops cleanly.
#[tokio::test]
async fn real_sigil_proxy_process_reports_a_baseline() {
    let Some(h) = H::new(&[(NAMES[0], "first tool"), (NAMES[1], "second tool")], 1).await else {
        return;
    };
    let cfg_path = h.pki.p("proxy.yaml");
    // The real binary binds its configured address: pick a free port.
    let free = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let listen = free.local_addr().unwrap().port();
    drop(free);
    std::fs::write(&cfg_path, h.bootstrap_yaml(&format!("127.0.0.1:{listen}"))).unwrap();
    let Some(bin) = proxy_binary() else {
        return;
    };
    let log = std::fs::File::create(h.pki.p("proxy.log")).unwrap();
    let child = Arc::new(Mutex::new(Child(
        Command::new(bin)
            .args(["run", "--config"])
            .arg(&cfg_path)
            .stdout(std::process::Stdio::null())
            .stderr(log)
            .spawn()
            .expect("spawns the real proxy"),
    )));
    let px = Running {
        listen,
        session: tokio::sync::Mutex::new(None),
        spool: None,
        stop: None,
        task: None,
    };
    let alive = |child: &Arc<Mutex<Child>>| {
        if let Ok(Some(st)) = child.lock().unwrap().0.try_wait() {
            panic!("the proxy exited early: {st}");
        }
    };
    eventually("the real process forwards", || async {
        alive(&child);
        px.call(json!({"jsonrpc": "2.0", "id": 1, "method": "ping"}))
            .await
            .0
            == 200
    })
    .await;
    assert_eq!(px.list_all().await, 2);
    eventually("the baseline snapshot is on the server", || async {
        alive(&child);
        h.snapshots().await.len() == 1
    })
    .await;
    let kill = Command::new("kill")
        .args(["-TERM", &child.lock().unwrap().0.id().to_string()])
        .status()
        .unwrap();
    assert!(kill.success());
    let start = Instant::now();
    let st = loop {
        if let Some(st) = child.lock().unwrap().0.try_wait().unwrap() {
            break st;
        }
        assert!(start.elapsed() < Duration::from_secs(30), "no clean stop");
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    assert!(st.success(), "clean exit, got {st}");
}

/// T-13d AC-03/05/06: actual relay events, local metadata lookup, replay,
/// duplicate acknowledgement, privacy and a full-spool dispatch oracle.
#[tokio::test]
async fn real_invocations_replay_deduplicate_and_refuse_before_dispatch() {
    use sigil_proxy::config_sync::MtlsFetcher;
    use sigil_proxy::ingest_client::{EventSource, IngestTransport};
    let Some(h) = H::new(&[(NAMES[0], "private-description-canary")], 10).await else {
        return;
    };
    let px = start_proxy(&h, Duration::from_millis(30)).await;
    let spool = px.spool.as_ref().unwrap().clone();
    eventually("initial events delivered", || async {
        spool.snapshot().unsent_events == 0
    })
    .await;
    spool.set_delivery_paused_for_test(true);
    assert_eq!(px.list_all().await, 1);
    // Inventory observation finishes off the I/O runtime; wait for the local
    // complete baseline before resolving a tool by its private name.
    eventually("local inventory complete", || async {
        h.status()
            .is_some_and(|s| s.registry.pending_entries.get() > 0)
            || !h.snapshots().await.is_empty()
    })
    .await;
    let (call, cancel) = tokio::join!(
        px.call(json!({"jsonrpc":"2.0","id":70,"method":"tools/call","params":{"name":NAMES[0],"arguments":{"private-argument-canary":"secret"},"wait":true}})),
        async {
            eventually("tool dispatched", || async {h.up.state.lock().unwrap().calls == 1}).await;
            px.call(json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":70}})).await
        }
    );
    assert_eq!(call.0, 200);
    assert_eq!(cancel.0, 200);
    eventually("all relay events spooled", || async {
        spool.snapshot().unsent_events >= 5
    })
    .await;
    let before = h.up.state.lock().unwrap().calls;
    spool.set_capacity_for_test(0, 0);
    assert_eq!(
        px.call(json!({"jsonrpc":"2.0","id":71,"method":"tools/call","params":{"name":NAMES[0]}}))
            .await
            .0,
        503
    );
    assert_eq!(
        h.up.state.lock().unwrap().calls,
        before,
        "spool refusal never dispatches"
    );
    spool.set_capacity_for_test(1 << 30, 0);
    px.stop().await;
    drop(spool);
    // Reopen durable events as a restarted process, while no delivery loop is
    // running. This also proves stop drained the invocation writer.
    let bootstrap =
        Bootstrap::from_yaml(&h.bootstrap_yaml("127.0.0.1:0"), h.pki.dir.path()).unwrap();
    let lifecycle = sigil_proxy::lifecycle::Lifecycle::start(&bootstrap).unwrap();
    let mut source = lifecycle.open_spool(&Default::default()).unwrap();
    let events = source.next_events(100, &Default::default());
    let raw = serde_json::to_string(&events).unwrap();
    for canary in [
        NAMES[0],
        "private-description-canary",
        "private-argument-canary",
        "private-result-canary",
        CLIENT_TOKEN,
        "UPSTREAM-SECRET-VALUE",
    ] {
        assert!(!raw.contains(canary), "raw content in audit spool");
    }
    let vals: Vec<Value> = events
        .iter()
        .map(|e| serde_json::to_value(e).unwrap())
        .collect();
    let started = vals
        .iter()
        .find(|e| e["event_type"] == "invocation.started" && e["payload"]["method"] == "tools/call")
        .unwrap();
    assert_eq!(started["payload"]["route_revision"], 1);
    assert_eq!(started["payload"]["upstream_id"], "up1");
    assert_eq!(started["payload"]["protocol_version"], "2025-11-25");
    assert_eq!(started["payload"]["tool"]["status"], "identified");
    let inv = started["payload"]["invocation_id"].as_str().unwrap();
    let kinds: Vec<_> = vals
        .iter()
        .filter(|e| e["payload"]["invocation_id"] == inv)
        .map(|e| e["event_type"].as_str().unwrap())
        .collect();
    assert_eq!(
        kinds,
        [
            "invocation.started",
            "invocation.cancel_requested",
            "invocation.completed"
        ]
    );
    // Simulate an ACK lost after server commit, then resend the same durable
    // batch. Production delivery is paused, so both replies are deterministic.
    let transport = MtlsFetcher::from_bootstrap(&bootstrap)
        .unwrap()
        .with_timeout(Duration::from_secs(5));
    let body = serde_json::to_vec(&json!({"events":events})).unwrap();
    for duplicate in [false, true] {
        let reply = transport.post_events(body.clone()).await.unwrap();
        assert_eq!(
            reply.status,
            200,
            "{}",
            String::from_utf8_lossy(&reply.body)
        );
        let v: Value = serde_json::from_slice(&reply.body).unwrap();
        let key = if duplicate {
            "duplicate_event_ids"
        } else {
            "accepted_event_ids"
        };
        assert_eq!(v[key].as_array().unwrap().len(), vals.len());
    }
    assert_eq!(
        source.snapshot().unsent_events,
        vals.len() as u64,
        "ACK deliberately lost locally"
    );
    source.close().await;
    drop(source);
    drop(lifecycle);
    let px = start_proxy(&h, Duration::from_millis(30)).await;
    eventually("replayed events acknowledged", || async {
        px.spool.as_ref().unwrap().snapshot().unsent_events == 0
    })
    .await;
    let items = h
        .items(&format!("/v1/proxy-invocations?proxy_id={PROXY}"))
        .await;
    let row = items.iter().find(|r| r["invocation_id"] == inv).unwrap();
    assert_eq!(row["lifecycle"], "completed");
    assert_eq!(row["outcome"], "success");
    assert_eq!(row["cancel_observed"], true);
    let query = serde_json::to_string(&items).unwrap();
    for canary in [
        NAMES[0],
        "private-argument-canary",
        "private-result-canary",
        CLIENT_TOKEN,
    ] {
        assert!(!query.contains(canary));
    }
    px.stop().await;
}
