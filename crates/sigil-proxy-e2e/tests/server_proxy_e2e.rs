#![cfg(unix)]
//! #267: the real `sigil-server` proxy control plane and the real `sigil-proxy`
//! running together on loopback, over real rustls mTLS (openssl-minted PKI).
//!
//! Both sides run in-process through their library APIs: the server through
//! `build_router_with_proxy` behind `axum_server` + `PeerCertAcceptor`, the
//! proxy through `lifecycle::run_tuned` (test-only pacing knob). The stub
//! upstream is a tiny plain-HTTP loopback listener. Real-time polling with
//! generous timeouts; no paused clock.
//!
//! Flow (issue #267): register + config + fingerprint -> proxy starts and
//! applies -> 200 / 401 -> status report visible on the server -> new revision
//! picked up -> disable (401, report refused) -> enable (forwarding resumes).

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sigil_proxy::bootstrap::Bootstrap;
use sigil_proxy::lifecycle::{read_status, run_tuned, RunTuning};
use sigil_proxy::route::TableHandle;
use sigil_proxy_api::status::ConfigState;
use sigil_proxy_api::verifier::verifier_for;
use sigil_server::app::{build_router_with_proxy, AppState};
use sigil_server::auth::ReadToken;
use sigil_server::config::ServerConfig;
use sigil_server::fleet_index::FleetIndex;
use sigil_server::persist::HighWater;
use sigil_server::proxy::identity::proxy_san;
use sigil_server::proxy::verifiers::{Scope, VerifierEntry};
use sigil_server::proxy::ProxyContext;
use sigil_server::tls_accept::PeerCertAcceptor;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const T_ID: &str = "tok-identity-e2e";
const T_CFG: &str = "tok-config-e2e";
const PROXY_ID: &str = "px-e2e";
const TOK_A: &str = "client-token-a";
const TOK_B: &str = "client-token-b";
const WAIT: Duration = Duration::from_secs(40);

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
    pki.ca("hostca", "e2e-host-ca", "1");
    pki.ca("proxyca", "e2e-proxy-ca", "2");
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

struct Server {
    port: u16,
    ctx: Arc<ProxyContext>,
    handle: axum_server::Handle,
    mgmt: reqwest::Client,
}

impl Server {
    async fn start(pki: &Pki) -> Server {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mgmt_cert = pki.leaf(
            "hostca",
            "mgmt",
            "mgmt-operator",
            "subjectAltName=DNS:mgmt-operator\nextendedKeyUsage=clientAuth\nbasicConstraints=CA:FALSE\n",
        );
        let fp = fingerprint(&mgmt_cert.0);
        let entries = [
            verifier_entry("idk", T_ID, Scope::Identity, &fp),
            verifier_entry("cfgk", T_CFG, Scope::Config, &fp),
        ];
        let vpath = pki.p("verifiers.json");
        std::fs::write(
            &vpath,
            serde_json::to_vec(&serde_json::json!({"entries": entries})).unwrap(),
        )
        .unwrap();
        std::fs::set_permissions(&vpath, std::fs::Permissions::from_mode(0o600)).unwrap();

        let d = pki.dir.path();
        let p = |f: &str| d.join(f).display().to_string();
        let y = format!(
            "bind: \"127.0.0.1:0\"\ntls_cert_path: {}\ntls_key_path: {}\nclient_ca_path: {}\n\
             events_out_dir: {}\npolicy_bundle_path: {}\n\
             proxy:\n  ca_path: {}\n  registry_path: {}\n  registry_init: true\n  management_verifiers: {}\n",
            p("server.crt"),
            p("server.key"),
            p("bundle.pem"),
            d.display(),
            p("signed-policy.json"),
            p("proxyca.crt"),
            p("proxies.json"),
            p("verifiers.json"),
        );
        let cfg: ServerConfig = serde_yaml::from_str(&y).unwrap();
        let ctx = Arc::new(ProxyContext::load(&cfg).unwrap().unwrap());
        let tls = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(tls_config(pki)));
        let app = build_router_with_proxy(app_state(d), Some(ctx.clone()));
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
        let mgmt = mtls_client(&pki.p("hostca.crt"), &mgmt_cert.0, &mgmt_cert.1);
        Server {
            port,
            ctx,
            handle,
            mgmt,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("https://127.0.0.1:{}{path}", self.port)
    }

    /// Management call: returns (status, parsed JSON body or null).
    async fn mgmt(
        &self,
        method: &str,
        path: &str,
        bearer: &str,
        body: Option<serde_json::Value>,
    ) -> (u16, serde_json::Value) {
        let mut rb = self.mgmt.request(
            reqwest::Method::from_bytes(method.as_bytes()).unwrap(),
            self.url(path),
        );
        rb = rb.bearer_auth(bearer);
        if let Some(b) = body {
            rb = rb.json(&b);
        }
        let r = rb.send().await.unwrap();
        let status = r.status().as_u16();
        let bytes = r.bytes().await.unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        )
    }
}

fn mtls_client(trust: &Path, crt: &Path, key: &Path) -> reqwest::Client {
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

// --------------------------------------------------------------- upstream

/// Plain-HTTP loopback upstream: answers every request with 200 and counts them.
struct Upstream {
    port: u16,
    hits: Arc<AtomicUsize>,
}

async fn upstream() -> Upstream {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let hits = Arc::new(AtomicUsize::new(0));
    let h2 = hits.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else {
                return;
            };
            let h3 = h2.clone();
            tokio::spawn(async move {
                // Read one request (head + Content-Length body), answer, close.
                let mut buf = Vec::new();
                let mut tmp = [0u8; 4096];
                loop {
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
                            break;
                        }
                    }
                }
                h3.fetch_add(1, Ordering::SeqCst);
                let start = buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
                let v: serde_json::Value = serde_json::from_slice(&buf[start..]).unwrap();
                let result = if v["method"] == "initialize" {
                    serde_json::json!({"protocolVersion":"2025-11-25","capabilities":{},"serverInfo":{"name":"fixture","version":"1"}})
                } else {
                    serde_json::json!({})
                };
                let body = serde_json::to_vec(
                    &serde_json::json!({"jsonrpc":"2.0","id":v["id"],"result":result}),
                )
                .unwrap();
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
    Upstream { port, hits }
}

// ------------------------------------------------------------------ proxy

fn spec(up_port: u16, tokens: &[(&str, &str)], limit_bytes: i64) -> serde_json::Value {
    let principals: Vec<_> = tokens
        .iter()
        .map(|(pid, tok)| {
            serde_json::json!({
                "principal_id": pid,
                "verifiers": [{"key_id": format!("k-{pid}"), "verifier": verifier_for(tok)}],
                "routes": ["r1"],
            })
        })
        .collect();
    serde_json::json!({
        "schema_version": 1,
        "proxy_id": PROXY_ID,
        "allowed_origins": ["https://app.example.com"],
        "routes": [{
            "route_id": "r1",
            "upstream_id": "up1",
            "upstream_url": format!("http://127.0.0.1:{up_port}/mcp"),
            "upstream_protocol": "2025-11-25",
            "credential_ref": "gh",
            "limits": {"max_request_bytes": limit_bytes},
        }],
        "principals": principals,
    })
}

struct RunningProxy {
    listen: u16,
    state_dir: PathBuf,
    stop: tokio::sync::oneshot::Sender<()>,
    task: tokio::task::JoinHandle<anyhow::Result<()>>,
    client: reqwest::Client,
}

impl RunningProxy {
    /// POST /mcp/r1 with a bearer; returns the status.
    async fn call(&self, bearer: &str) -> u16 {
        let url = format!("http://127.0.0.1:{}/mcp/r1", self.listen);
        let init = self.client.post(&url).bearer_auth(bearer)
            .json(&serde_json::json!({"jsonrpc":"2.0","id":"initialize","method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"fixture","version":"1"}}}))
            .send().await;
        let Ok(init) = init else { return 0 };
        let Some(sid) = init.headers().get("mcp-session-id").cloned() else {
            return init.status().as_u16();
        };
        self.client
            .post(&url)
            .header("mcp-session-id", sid)
            .header("mcp-protocol-version", "2025-11-25")
            .bearer_auth(bearer)
            .header("content-type", "application/json")
            .body(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#)
            .send()
            .await
            .map(|r| r.status().as_u16())
            .unwrap_or(0)
    }

    async fn shutdown(self) {
        let _ = self.stop.send(());
        let r = tokio::time::timeout(Duration::from_secs(20), self.task)
            .await
            .expect("proxy stops within the grace")
            .expect("proxy task joins");
        r.expect("proxy run returns Ok");
    }
}

/// Fast pacing so the whole flow takes seconds (test-only knob).
fn tuning(listener: std::net::TcpListener) -> RunTuning {
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
    t
}

fn start_proxy(
    pki: &Pki,
    server_port: u16,
    up_port: u16,
    proxy_cert: &(PathBuf, PathBuf),
) -> RunningProxy {
    let d = pki.dir.path();
    let state_dir = d.join("proxy-state");
    let secret = d.join("upstream-secret");
    std::fs::write(&secret, "UPSTREAM-SECRET-VALUE\n").unwrap();
    std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600)).unwrap();
    // Bound here and handed to the proxy (test-util `RunTuning::listener`), so
    // there is no bind-then-release port race. The bootstrap `listen` is unused.
    let sock = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let listen = sock.local_addr().unwrap().port();
    let yaml = format!(
        "proxy_id: {PROXY_ID}\nlisten: \"127.0.0.1:0\"\n\
         control_plane_url: \"https://127.0.0.1:{server_port}\"\n\
         state_dir: {}\nclient_cert_file: {}\nclient_key_file: {}\nca_file: {}\n\
         credentials:\n  gh:\n    secret_file: {}\n    upstream_origins: [\"http://127.0.0.1:{up_port}\"]\n",
        state_dir.display(),
        proxy_cert.0.display(),
        proxy_cert.1.display(),
        pki.p("hostca.crt").display(),
        secret.display(),
    );
    let b = Bootstrap::from_yaml(&yaml, d).expect("bootstrap loads");
    let (stop, rx) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(async move {
        run_tuned(
            &b,
            TableHandle::new(),
            async move {
                let _ = rx.await;
            },
            tuning(sock),
        )
        .await
    });
    RunningProxy {
        listen,
        state_dir,
        stop,
        task,
        client: reqwest::Client::new(),
    }
}

async fn eventually<F, Fut>(what: &str, mut f: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let start = Instant::now();
    while start.elapsed() < WAIT {
        if f().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out waiting for: {what}");
}

// ------------------------------------------------------------------- test

#[tokio::test]
async fn server_and_proxy_walk_the_whole_lifecycle() {
    let Some(pki) = pki() else { return };
    let srv = Server::start(&pki).await;
    let up = upstream().await;

    // 1. Register, fingerprint, config.
    let proxy_cert = pki.leaf(
        "proxyca",
        "proxy",
        PROXY_ID,
        &format!(
            "subjectAltName=DNS:{}\nextendedKeyUsage=clientAuth\nbasicConstraints=CA:FALSE\n",
            proxy_san(PROXY_ID)
        ),
    );
    let (st, _) = srv
        .mgmt(
            "POST",
            "/v1/proxies",
            T_ID,
            Some(serde_json::json!({"proxy_id": PROXY_ID, "display_name": "e2e"})),
        )
        .await;
    assert_eq!(st, 201, "register");
    let (st, _) = srv
        .mgmt(
            "POST",
            &format!("/v1/proxies/{PROXY_ID}/fingerprints"),
            T_ID,
            Some(serde_json::json!({"fingerprint": fingerprint(&proxy_cert.0)})),
        )
        .await;
    assert_eq!(st, 200, "fingerprint");
    let cfg_path = format!("/v1/proxies/{PROXY_ID}/config");
    let put = |expected: u64, s: serde_json::Value| serde_json::json!({"expected_revision": expected, "config": s});
    let (st, body) = srv
        .mgmt(
            "PUT",
            &cfg_path,
            T_CFG,
            Some(put(0, spec(up.port, &[("alice", TOK_A)], 65536))),
        )
        .await;
    assert_eq!(st, 200, "config put: {body}");
    assert_eq!(body["revision"], 1);
    let hash1 = body["config_hash"].as_str().unwrap().to_string();

    // 2. Proxy starts from a bootstrap that points at the server.
    let px = start_proxy(&pki, srv.port, up.port, &proxy_cert);

    // 3. Right bearer reaches the upstream (200); wrong bearer is 401.
    eventually("first config applied and forwarding", || async {
        px.call(TOK_A).await == 200
    })
    .await;
    assert!(up.hits.load(Ordering::SeqCst) >= 1);
    let before = up.hits.load(Ordering::SeqCst);
    assert_eq!(px.call("wrong-token").await, 401);
    assert_eq!(
        up.hits.load(Ordering::SeqCst),
        before,
        "a 401 never reaches the upstream"
    );
    assert_eq!(px.call(TOK_B).await, 401, "token B is not configured yet");
    // The per-route limit from the server config is enforced (65536 bytes).
    let big = px
        .client
        .post(format!("http://127.0.0.1:{}/mcp/r1", px.listen))
        .bearer_auth(TOK_A)
        .header("content-type", "application/json")
        .body(vec![b' '; 70_000])
        .send()
        .await
        .unwrap();
    assert_eq!(big.status().as_u16(), 413, "request over the route limit");

    // 4. The status report reaches the server: applied revision + config hash.
    let ctx = srv.ctx.clone();
    let h1 = hash1.clone();
    eventually("server sees applied revision 1 and its hash", || async {
        ctx.store
            .entry(PROXY_ID)
            .and_then(|e| e.status)
            .is_some_and(|s| {
                s.config.state == ConfigState::Valid
                    && s.config.applied_revision.map(|r| r.get()) == Some(1)
                    && s.config
                        .config_hash
                        .as_ref()
                        .map(|h| h.as_str().to_string())
                        == Some(h1.clone())
            })
    })
    .await;
    assert!(ctx.store.last_seen(PROXY_ID).is_some());

    // 5. A new revision (adds token B) is picked up.
    let (st, body) = srv
        .mgmt(
            "PUT",
            &cfg_path,
            T_CFG,
            Some(put(
                1,
                spec(up.port, &[("alice", TOK_A), ("bob", TOK_B)], 65536),
            )),
        )
        .await;
    assert_eq!(st, 200, "second config put: {body}");
    assert_eq!(body["revision"], 2);
    let hash2 = body["config_hash"].as_str().unwrap().to_string();
    assert_ne!(hash1, hash2);
    eventually("token B accepted after revision 2", || async {
        px.call(TOK_B).await == 200
    })
    .await;
    let (ctx, h2) = (srv.ctx.clone(), hash2.clone());
    eventually("server sees applied revision 2 and its hash", || async {
        ctx.store
            .entry(PROXY_ID)
            .and_then(|e| e.status)
            .is_some_and(|s| {
                s.config.applied_revision.map(|r| r.get()) == Some(2)
                    && s.config
                        .config_hash
                        .as_ref()
                        .map(|h| h.as_str().to_string())
                        == Some(h2.clone())
            })
    })
    .await;

    // Scope rule (control-plane.md section 1.3 / H3): disable is safe-direction and
    // needs the `config` scope; enable restores trust and needs `identity`.
    // 6. Disable: forwarding stops on the next fetch; the report is refused.
    let (st, _) = srv
        .mgmt(
            "POST",
            &format!("/v1/proxies/{PROXY_ID}/disable"),
            T_CFG,
            None,
        )
        .await;
    assert_eq!(st, 200, "disable");
    eventually("401 after disable", || async {
        px.call(TOK_A).await == 401
    })
    .await;
    assert_eq!(px.call(TOK_B).await, 401);
    let sd = px.state_dir.clone();
    eventually("proxy publishes config_state disabled", || async {
        read_status(&sd).is_some_and(|s| s.config_state == ConfigState::Disabled && !s.forwarding)
    })
    .await;
    // What this proves: (a) once its view is `disabled` the proxy sends no report
    // by design, so `last_seen` stays frozen across several heartbeats (the proxy
    // goes silent); (b) the server refuses a status POST that carries the proxy
    // certificate (403 `disabled`). It does NOT exercise the proxy's own Rejected
    // path: a proxy-sent report can only be refused in the race window between the
    // server-side disable and the proxy's next fetch, which cannot be made
    // deterministic here. The status_report unit test covers Rejected.
    let local = read_status(&px.state_dir).expect("local status file");
    assert_eq!(local.config_state, ConfigState::Disabled);
    assert!(!local.forwarding);
    assert_eq!(
        local.last_update_error, None,
        "a disabled answer is not an update error"
    );
    tokio::time::sleep(Duration::from_millis(600)).await;
    let frozen = srv.ctx.store.last_seen(PROXY_ID);
    tokio::time::sleep(Duration::from_millis(900)).await;
    assert_eq!(
        srv.ctx.store.last_seen(PROXY_ID),
        frozen,
        "the proxy sends no report while disabled"
    );
    let direct = mtls_client(&pki.p("hostca.crt"), &proxy_cert.0, &proxy_cert.1)
        .post(srv.url("/v1/proxy-status"))
        .header("content-type", "application/json")
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(direct.status().as_u16(), 403);
    let eb: serde_json::Value = direct.json().await.unwrap();
    assert_eq!(eb["error"]["code"], "disabled");
    let hits_disabled = up.hits.load(Ordering::SeqCst);

    // 7. Re-enable: forwarding resumes and reports flow again.
    let (st, _) = srv
        .mgmt(
            "POST",
            &format!("/v1/proxies/{PROXY_ID}/enable"),
            T_ID,
            None,
        )
        .await;
    assert_eq!(st, 200, "enable");
    eventually("200 again after enable", || async {
        px.call(TOK_A).await == 200
    })
    .await;
    assert!(up.hits.load(Ordering::SeqCst) > hits_disabled);
    let (ctx, before_seen) = (srv.ctx.clone(), frozen.clone());
    eventually("reports accepted again", || async {
        ctx.store.last_seen(PROXY_ID) != before_seen
    })
    .await;

    // The server exposes no per-proxy read DTO (no GET /v1/proxies/{id}); its only
    // read route for this plane is the management audit stream. Check it records
    // the lifecycle the test drove, through the HTTP route a manager would use.
    let r = srv
        .mgmt
        .get(srv.url("/v1/proxy-management-audit"))
        .bearer_auth("read-bearer")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    let audit: serde_json::Value = r.json().await.unwrap();
    let actions: Vec<&str> = audit["records"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|x| x["action"].as_str())
        .collect();
    for want in [
        "proxy.register",
        "proxy.config_put",
        "proxy.disable",
        "proxy.enable",
    ] {
        assert!(actions.contains(&want), "audit lacks {want}: {actions:?}");
    }

    px.shutdown().await;
    srv.handle.graceful_shutdown(Some(Duration::from_secs(1)));
}
