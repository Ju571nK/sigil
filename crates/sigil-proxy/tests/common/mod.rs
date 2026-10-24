//! Shared fixtures for the relay integration tests: an in-process hyper
//! upstream, the proxy under test, and a raw HTTP/1.1 client that sees the
//! exact bytes (framing, chunk boundaries) the proxy writes.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body::{Body, Frame};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::service::service_fn;
use hyper::{Response, StatusCode};
use hyper_util::rt::TokioIo;
use sigil_proxy::bootstrap::{normalize_origin, Credential};
use sigil_proxy::dest::{Resolver, SystemResolver};
use sigil_proxy::lifecycle::DrainOutcome;
use sigil_proxy::limits::Limits;
use sigil_proxy::route::{PrincipalSpec, RouteSpec, RouteTable, TableHandle};
use sigil_proxy::server::Proxy;
use sigil_proxy_api::Id;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

pub const UPSTREAM_SECRET: &str = "UPSTREAM-SECRET-9f3a";

// ------------------------------------------------------------------ upstream

#[derive(Clone, Debug)]
pub struct Seen {
    pub method: String,
    pub target: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Seen {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
    pub fn has(&self, name: &str) -> bool {
        self.headers.iter().any(|(k, _)| k == name)
    }
}

pub enum Reply {
    Full {
        status: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    },
    Stream {
        status: u16,
        headers: Vec<(String, String)>,
        rx: mpsc::Receiver<Bytes>,
    },
    /// Never answers.
    Hang,
    /// Closes the connection without a response.
    Drop,
}

pub fn full(status: u16, content_type: &str, body: &[u8]) -> Reply {
    Reply::Full {
        status,
        headers: vec![("content-type".into(), content_type.into())],
        body: body.to_vec(),
    }
}

pub fn sse_stream() -> (mpsc::Sender<Bytes>, Reply) {
    let (tx, rx) = mpsc::channel(16);
    (
        tx,
        Reply::Stream {
            status: 200,
            headers: vec![("content-type".into(), "text/event-stream".into())],
            rx,
        },
    )
}

struct ChanBody(mpsc::Receiver<Bytes>);

impl Body for ChanBody {
    type Data = Bytes;
    type Error = Infallible;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        self.0.poll_recv(cx).map(|o| o.map(|b| Ok(Frame::data(b))))
    }
}

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

type Handler = Arc<dyn Fn(&Seen) -> Reply + Send + Sync>;

/// The JSON-RPC id of an `initialize` request body, if it is one.
pub fn initialize_id(body: &[u8]) -> Option<serde_json::Value> {
    let v: serde_json::Value = serde_json::from_slice(body).ok()?;
    (v.get("method")?.as_str()? == "initialize").then(|| v.get("id").cloned())?
}

/// A supported (2025-11-25, no tasks/subscribe) `InitializeResult` for `id`.
pub fn init_result(id: &serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "jsonrpc": "2.0", "id": id,
        "result": {"protocolVersion": "2025-11-25", "capabilities": {"tools": {}},
            "serverInfo": {"name": "fixture", "version": "1"}}}))
    .unwrap()
}

/// An `initialize` request body with id `id`.
pub fn initialize_body(id: &str) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":{id},"method":"initialize","params":{{"protocolVersion":"2025-11-25","capabilities":{{}},"clientInfo":{{"name":"t","version":"1"}}}}}}"#
    )
}

async fn fixture_call(
    req: hyper::Request<hyper::body::Incoming>,
    h: Handler,
    seen: Arc<Mutex<Vec<Seen>>>,
    inits: Option<Arc<AtomicUsize>>,
) -> Result<Response<BoxBody<Bytes, BoxErr>>, BoxErr> {
    let (parts, body) = req.into_parts();
    let body = body.collect().await?.to_bytes();
    // A plain fixture answers `initialize` itself (stateless, supported) so a
    // test's handler only sees the calls it is about; they are counted apart.
    if let (Some(n), Some(id)) = (&inits, initialize_id(&body)) {
        n.fetch_add(1, Ordering::SeqCst);
        let mut r = Response::new(
            Full::new(Bytes::from(init_result(&id)))
                .map_err(|n| match n {})
                .boxed(),
        );
        r.headers_mut().insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/json"),
        );
        return Ok(r);
    }
    let s = Seen {
        method: parts.method.to_string(),
        target: parts
            .uri
            .path_and_query()
            .map(|p| p.to_string())
            .unwrap_or_default(),
        headers: parts
            .headers
            .iter()
            .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("?").into()))
            .collect(),
        body: body.to_vec(),
    };
    seen.lock().unwrap().push(s.clone());
    let (status, headers, body): (u16, Vec<(String, String)>, BoxBody<Bytes, BoxErr>) = match h(&s)
    {
        Reply::Full {
            status,
            headers,
            body,
        } => (
            status,
            headers,
            Full::new(Bytes::from(body)).map_err(|n| match n {}).boxed(),
        ),
        Reply::Stream {
            status,
            headers,
            rx,
        } => (
            status,
            headers,
            ChanBody(rx).map_err(|n| match n {}).boxed(),
        ),
        Reply::Hang => {
            std::future::pending::<()>().await;
            unreachable!()
        }
        Reply::Drop => return Err("drop".into()),
    };
    let mut r = Response::new(body);
    *r.status_mut() = StatusCode::from_u16(status).unwrap();
    for (k, v) in headers {
        r.headers_mut().append(
            http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
            http::HeaderValue::from_str(&v).unwrap(),
        );
    }
    Ok(r)
}

pub struct Up {
    pub addr: SocketAddr,
    pub seen: Arc<Mutex<Vec<Seen>>>,
    pub connections: Arc<AtomicUsize>,
    /// `initialize` calls the fixture answered itself (not in `seen`).
    pub inits: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl Drop for Up {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Up {
    /// A fixture that answers `initialize` itself and hands everything else to
    /// `handler`.
    pub async fn start(handler: impl Fn(&Seen) -> Reply + Send + Sync + 'static) -> Up {
        Self::start_inner(handler, true).await
    }

    /// A fixture whose `handler` sees every request, `initialize` included.
    pub async fn start_raw(handler: impl Fn(&Seen) -> Reply + Send + Sync + 'static) -> Up {
        Self::start_inner(handler, false).await
    }

    async fn start_inner(
        handler: impl Fn(&Seen) -> Reply + Send + Sync + 'static,
        intercept_init: bool,
    ) -> Up {
        let inits = Arc::new(AtomicUsize::new(0));
        let intercept = intercept_init.then(|| inits.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let connections = Arc::new(AtomicUsize::new(0));
        let handler: Handler = Arc::new(handler);
        let (s2, c2) = (seen.clone(), connections.clone());
        let task = tokio::spawn(async move {
            loop {
                let Ok((sock, _)) = listener.accept().await else {
                    return;
                };
                c2.fetch_add(1, Ordering::SeqCst);
                let (h, seen, i) = (handler.clone(), s2.clone(), intercept.clone());
                tokio::spawn(async move {
                    let svc = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                        fixture_call(req, h.clone(), seen.clone(), i.clone())
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(sock), svc)
                        .await;
                });
            }
        });
        Up {
            addr,
            seen,
            connections,
            inits,
            task,
        }
    }

    pub fn count(&self) -> usize {
        self.seen.lock().unwrap().len()
    }
    pub fn conns(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }
    pub fn last(&self) -> Seen {
        self.seen
            .lock()
            .unwrap()
            .last()
            .cloned()
            .expect("upstream saw a request")
    }
    pub fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.addr.port())
    }
}

/// Echo-ish default upstream: 200 JSON with a fixed body.
pub async fn ok_upstream() -> Up {
    Up::start(|_| full(200, "application/json", b"{\"ok\":true}")).await
}

// --------------------------------------------------------------- route table

pub struct R<'a> {
    pub id: &'a str,
    pub upstream: String,
    /// (principal id, token)
    pub principals: Vec<(&'a str, &'a str)>,
    pub origins: Vec<&'a str>,
    pub allow_private: bool,
}

impl<'a> R<'a> {
    pub fn new(id: &'a str, upstream: String, principals: &[(&'a str, &'a str)]) -> R<'a> {
        R {
            id,
            upstream,
            principals: principals.to_vec(),
            origins: vec![],
            allow_private: false,
        }
    }
    pub fn origins(mut self, o: &[&'a str]) -> Self {
        self.origins = o.to_vec();
        self
    }
}

fn write_secret(dir: &Path) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let p = dir.join("secret");
    std::fs::write(&p, format!("{UPSTREAM_SECRET}\n")).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
    p
}

pub fn try_table(rs: &[R], limits: &Limits) -> Result<RouteTable, sigil_proxy::route::RouteError> {
    let dir = tempfile::tempdir().unwrap();
    let secret = write_secret(dir.path());
    let origins: Vec<String> = rs
        .iter()
        .map(|r| {
            let (scheme, rest) = r.upstream.split_once("://").unwrap();
            let auth = rest.split('/').next().unwrap();
            normalize_origin(&format!("{scheme}://{auth}")).unwrap()
        })
        .collect();
    let creds = BTreeMap::from([(
        "up".to_string(),
        Credential {
            secret_file: secret,
            upstream_origins: origins,
        },
    )]);
    let specs: Vec<RouteSpec> = rs
        .iter()
        .map(|r| RouteSpec {
            route_id: Id::new(r.id).unwrap(),
            upstream_url: r.upstream.clone(),
            credential_ref: "up".into(),
            principals: r
                .principals
                .iter()
                .map(|(p, t)| {
                    PrincipalSpec::new(
                        Id::new(*p).unwrap(),
                        vec![sigil_proxy_api::verifier_for(t).into()],
                    )
                })
                .collect(),
            allowed_origins: r.origins.iter().map(|s| s.to_string()).collect(),
            allow_private_destination: r.allow_private,
            limits: Default::default(),
            scope: None,
        })
        .collect();
    RouteTable::build(&specs, &creds, limits)
}

pub fn table(rs: &[R], limits: &Limits) -> RouteTable {
    try_table(rs, limits).unwrap()
}

// -------------------------------------------------------------------- proxy

pub struct StaticResolver(pub Mutex<Vec<Vec<IpAddr>>>);

impl StaticResolver {
    /// Answers the given lists in order, repeating the last one.
    pub fn sequence(answers: Vec<Vec<IpAddr>>) -> Arc<StaticResolver> {
        Arc::new(StaticResolver(Mutex::new(answers)))
    }
}

impl Resolver for StaticResolver {
    fn resolve<'a>(
        &'a self,
        _host: &'a str,
        _port: u16,
    ) -> Pin<Box<dyn std::future::Future<Output = std::io::Result<Vec<IpAddr>>> + Send + 'a>> {
        Box::pin(async move {
            let mut g = self.0.lock().unwrap();
            if g.len() > 1 {
                Ok(g.remove(0))
            } else {
                Ok(g[0].clone())
            }
        })
    }
}

pub struct Px {
    pub addr: SocketAddr,
    pub handle: TableHandle,
    /// Proxy session per (path, token), established on first use (T-12b2).
    sessions: Mutex<std::collections::HashMap<(String, String), String>>,
    stop: Option<oneshot::Sender<()>>,
    join: Option<JoinHandle<std::io::Result<DrainOutcome>>>,
}

impl Px {
    pub async fn start(table: Option<RouteTable>, limits: Limits) -> Px {
        Self::start_with(table, limits, Arc::new(SystemResolver)).await
    }

    pub async fn start_with(
        table: Option<RouteTable>,
        limits: Limits,
        resolver: Arc<dyn Resolver>,
    ) -> Px {
        Self::start_full(table, limits, resolver, None).await
    }

    pub async fn start_full(
        table: Option<RouteTable>,
        limits: Limits,
        resolver: Arc<dyn Resolver>,
        header_read_timeout: Option<Duration>,
    ) -> Px {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = TableHandle::new();
        handle.set(table);
        let (stop, rx) = oneshot::channel::<()>();
        let mut proxy = Proxy::new(limits, handle.clone(), resolver);
        if let Some(d) = header_read_timeout {
            proxy = proxy.with_header_read_timeout(d);
        }
        let join = tokio::spawn(async move {
            proxy
                .serve(listener, None, async {
                    let _ = rx.await;
                })
                .await
        });
        Px {
            addr,
            handle,
            sessions: Mutex::new(Default::default()),
            stop: Some(stop),
            join: Some(join),
        }
    }

    pub async fn stop(&mut self) -> DrainOutcome {
        let _ = self.stop.take().unwrap().send(());
        self.join.take().unwrap().await.unwrap().unwrap()
    }

    /// Raw request text with `Host` set to the proxy and `Connection: close`.
    /// A POST with a token carries the cached session of `(path, token)`.
    pub fn request(
        &self,
        method: &str,
        path: &str,
        token: Option<&str>,
        extra: &[(&str, &str)],
        body: &[u8],
    ) -> Vec<u8> {
        let mut r = format!(
            "{method} {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n",
            self.addr
        );
        if let Some(t) = token {
            r += &format!("Authorization: Bearer {t}\r\n");
            // Inside the session of (path, token) when one was established
            // (`session`), as a real client would be after initialize.
            let has = |n: &str| extra.iter().any(|(k, _)| k.eq_ignore_ascii_case(n));
            let cached = self
                .sessions
                .lock()
                .unwrap()
                .get(&(path.to_string(), t.to_string()))
                .cloned();
            if let Some(sid) = cached {
                if method == "POST" && initialize_id(body).is_none() && !has("mcp-session-id") {
                    r += &format!("Mcp-Session-Id: {sid}\r\n");
                    if !has("mcp-protocol-version") {
                        r += "MCP-Protocol-Version: 2025-11-25\r\n";
                    }
                }
            }
        }
        for (k, v) in extra {
            r += &format!("{k}: {v}\r\n");
        }
        if method == "POST" || !body.is_empty() {
            r += &format!("Content-Length: {}\r\n", body.len());
        }
        r += "\r\n";
        let mut out = r.into_bytes();
        out.extend_from_slice(body);
        out
    }

    pub async fn send(&self, req: &[u8]) -> Raw {
        send_raw(self.addr, req).await
    }

    /// POST with the session headers a real client sends after initialize
    /// (T-12b2): the proxy session of `(path, token)`, established on first use
    /// with an `initialize`, and `MCP-Protocol-Version: 2025-11-25`. An
    /// `initialize` body, a request without a token or one that names its own
    /// `Mcp-Session-Id` is sent as it is; a header given in `extra` wins.
    pub async fn post(
        &self,
        path: &str,
        token: Option<&str>,
        extra: &[(&str, &str)],
        body: &[u8],
    ) -> Raw {
        let has = |n: &str| extra.iter().any(|(k, _)| k.eq_ignore_ascii_case(n));
        if let Some(t) = token {
            if initialize_id(body).is_none() && !has("mcp-session-id") {
                // Establish (and cache) the session; `request` then uses it.
                let _ = self.session(path, t).await;
            }
        }
        self.send(&self.request("POST", path, token, extra, body))
            .await
    }

    /// POST exactly as given: no session, no version header.
    pub async fn post_bare(
        &self,
        path: &str,
        token: Option<&str>,
        extra: &[(&str, &str)],
        body: &[u8],
    ) -> Raw {
        let mut r = format!(
            "POST {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n",
            self.addr
        );
        if let Some(t) = token {
            r += &format!("Authorization: Bearer {t}\r\n");
        }
        for (k, v) in extra {
            r += &format!("{k}: {v}\r\n");
        }
        r += &format!("Content-Length: {}\r\n\r\n", body.len());
        let mut out = r.into_bytes();
        out.extend_from_slice(body);
        self.send(&out).await
    }

    /// The proxy session of `(path, token)`: initialize once, then reuse.
    /// `None` if the initialize got no session (route refused, upstream down).
    pub async fn session(&self, path: &str, token: &str) -> Option<String> {
        let key = (path.to_string(), token.to_string());
        if let Some(s) = self.sessions.lock().unwrap().get(&key) {
            return Some(s.clone());
        }
        let r = self
            .post_bare(path, Some(token), &[], initialize_body("0").as_bytes())
            .await;
        let s = r.header("mcp-session-id")?.to_string();
        self.sessions.lock().unwrap().insert(key, s.clone());
        Some(s)
    }

    /// Header lines (CRLF-terminated) a raw request needs inside the session
    /// of `(path, token)`.
    pub async fn session_lines(&self, path: &str, token: &str) -> String {
        let sid = self.session(path, token).await.expect("a session");
        format!("Mcp-Session-Id: {sid}\r\nMCP-Protocol-Version: 2025-11-25\r\n")
    }

    /// Forget the cached sessions (after the proxy ended them).
    pub fn forget_sessions(&self) {
        self.sessions.lock().unwrap().clear();
    }
}

impl Drop for Px {
    fn drop(&mut self) {
        if let Some(j) = &self.join {
            j.abort();
        }
    }
}

// ---------------------------------------------------------------- raw client

#[derive(Debug)]
pub struct Raw {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    /// Bytes after the header block, exactly as received.
    pub wire_body: Vec<u8>,
    pub all: Vec<u8>,
}

impl Raw {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
    pub fn has(&self, name: &str) -> bool {
        self.header(name).is_some()
    }
    pub fn chunked(&self) -> bool {
        self.header("transfer-encoding")
            .is_some_and(|v| v.eq_ignore_ascii_case("chunked"))
    }
    /// Decoded chunks and whether the terminating chunk was seen.
    pub fn chunks(&self) -> (Vec<Vec<u8>>, bool) {
        dechunk(&self.wire_body)
    }
    /// Decoded body (de-chunked when chunked).
    pub fn body(&self) -> Vec<u8> {
        if self.chunked() {
            self.chunks().0.concat()
        } else {
            self.wire_body.clone()
        }
    }
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body()).into_owned()
    }
}

pub fn dechunk(mut b: &[u8]) -> (Vec<Vec<u8>>, bool) {
    let mut out = Vec::new();
    loop {
        let Some(i) = b.windows(2).position(|w| w == b"\r\n") else {
            return (out, false);
        };
        let Ok(n) = usize::from_str_radix(std::str::from_utf8(&b[..i]).unwrap_or("x").trim(), 16)
        else {
            return (out, false);
        };
        b = &b[i + 2..];
        if n == 0 {
            return (out, true);
        }
        if b.len() < n + 2 {
            return (out, false);
        }
        out.push(b[..n].to_vec());
        b = &b[n + 2..];
    }
}

pub fn parse_response(mut all: Vec<u8>) -> Raw {
    // Skip interim `100 Continue` blocks (answered for `Expect: 100-continue`).
    while all.starts_with(b"HTTP/1.1 100") {
        let e = all.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
        all.drain(..e + 4);
    }
    let end = all
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or_else(|| panic!("no header block in {:?}", String::from_utf8_lossy(&all)));
    let head = String::from_utf8_lossy(&all[..end]).into_owned();
    let mut lines = head.split("\r\n");
    let status: u16 = lines
        .next()
        .unwrap()
        .split(' ')
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let headers = lines
        .map(|l| {
            let (k, v) = l.split_once(':').unwrap();
            (k.trim().to_string(), v.trim().to_string())
        })
        .collect();
    let wire_body = all[end + 4..].to_vec();
    Raw {
        status,
        headers,
        wire_body,
        all,
    }
}

/// Send raw bytes, read until EOF (or a reset), parse the response.
pub async fn send_raw(addr: SocketAddr, req: &[u8]) -> Raw {
    let mut s = TcpStream::connect(addr).await.unwrap();
    let _ = s.write_all(req).await;
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(20), async {
        let mut tmp = [0u8; 8192];
        loop {
            match s.read(&mut tmp).await {
                Ok(0) | Err(_) => break,
                Ok(n) => buf.extend_from_slice(&tmp[..n]),
            }
        }
    })
    .await;
    let r = parse_response(buf);
    // The upstream credential must never reach the client in any response.
    assert!(
        !String::from_utf8_lossy(&r.all).contains(UPSTREAM_SECRET),
        "upstream secret leaked to the client"
    );
    r
}

/// Read from `s` into `buf` until `pat` appears or `d` elapses.
pub async fn read_until(s: &mut TcpStream, buf: &mut Vec<u8>, pat: &[u8], d: Duration) -> bool {
    tokio::time::timeout(d, async {
        let mut tmp = [0u8; 4096];
        while !buf.windows(pat.len()).any(|w| w == pat) {
            match s.read(&mut tmp).await {
                Ok(0) | Err(_) => return false,
                Ok(n) => buf.extend_from_slice(&tmp[..n]),
            }
        }
        true
    })
    .await
    .unwrap_or(false)
}

pub fn limits() -> Limits {
    Limits::default()
}

/// One route `a` with principal `pa`/`tok-a` on `up`, plus a limits value.
pub async fn simple(up: &Up, limits: Limits) -> Px {
    let t = table(&[R::new("a", up.url("/up"), &[("pa", "tok-a")])], &limits);
    Px::start(Some(t), limits).await
}

/// A resolver that never answers.
pub struct HangResolver;

impl Resolver for HangResolver {
    fn resolve<'a>(
        &'a self,
        _host: &'a str,
        _port: u16,
    ) -> Pin<Box<dyn std::future::Future<Output = std::io::Result<Vec<IpAddr>>> + Send + 'a>> {
        Box::pin(std::future::pending())
    }
}
