#![cfg(unix)]
//! T-12b1: MCP classification at the relay. Refusals (batch, `tasks/*`, version
//! gating, malformed), response outcome classes for JSON and SSE, cancel
//! ordering (M3), the observation seam, and "bytes are unchanged".
//!
//! PX-003/004/006/015, AC-01/03/07, support-matrix §5 oracle.

mod common;
use bytes::Bytes;
use common::*;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sigil_proxy::dest::SystemResolver;
use sigil_proxy::limits::Limits;
use sigil_proxy::mcp::cancel::CancelRegistry;
use sigil_proxy::mcp::observation::{
    CancelDisposition, Cause, Completed, Delivery, Observation, ObservationSink, Outcome,
    RefusalKind, RequestStarted, SinkFuture, StartVerdict, ToolListCapture,
};
use sigil_proxy::mcp::{Method, ToolField};
use sigil_proxy::route::TableHandle;
use sigil_proxy::server::Proxy;
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

// ------------------------------------------------------------------ recorder

#[derive(Clone, Debug)]
enum Ev {
    Started(RequestStarted),
    Obs(Observation),
}

struct Rec {
    events: Mutex<Vec<Ev>>,
    start_delay: Duration,
    verdict: StartVerdict,
}

impl Rec {
    fn new() -> Arc<Rec> {
        Arc::new(Rec {
            events: Mutex::new(vec![]),
            start_delay: Duration::ZERO,
            verdict: StartVerdict::Proceed,
        })
    }
    fn delayed(d: Duration) -> Arc<Rec> {
        Arc::new(Rec {
            events: Mutex::new(vec![]),
            start_delay: d,
            verdict: StartVerdict::Proceed,
        })
    }
    fn refusing() -> Arc<Rec> {
        Arc::new(Rec {
            events: Mutex::new(vec![]),
            start_delay: Duration::ZERO,
            verdict: StartVerdict::Refuse,
        })
    }
    fn all(&self) -> Vec<Ev> {
        self.events.lock().unwrap().clone()
    }
    fn completed(&self) -> Vec<Completed> {
        self.all()
            .into_iter()
            .filter_map(|e| match e {
                Ev::Obs(Observation::Completed(c)) => Some(c),
                _ => None,
            })
            .collect()
    }
    /// The single completion, waiting for it (aborted streams complete a moment
    /// after the client sees the failure).
    async fn the_completion(&self) -> Completed {
        for _ in 0..200 {
            let c = self.completed();
            if c.len() == 1 {
                return c.into_iter().next().unwrap();
            }
            assert!(c.len() <= 1, "more than one completion: {c:?}");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("no completion: {:?}", self.all());
    }
    fn debug(&self) -> String {
        format!("{:?}", self.all())
    }
}

/// The harness's own `initialize` (session setup, id 0) is not what these
/// tests observe; it is left out of the record.
fn is_setup(m: Method, id: &sigil_proxy::mcp::RequestId) -> bool {
    m == Method::Initialize && id.raw() == "0"
}

impl ObservationSink for Rec {
    fn request_started<'a>(&'a self, s: &'a RequestStarted) -> SinkFuture<'a, StartVerdict> {
        Box::pin(async move {
            if is_setup(s.method, &s.request_id) {
                return StartVerdict::Proceed;
            }
            self.events.lock().unwrap().push(Ev::Started(s.clone()));
            if !self.start_delay.is_zero() {
                tokio::time::sleep(self.start_delay).await;
            }
            self.verdict
        })
    }
    fn observe(&self, o: Observation) {
        if matches!(&o, Observation::Completed(c) if is_setup(c.method, &c.request_id)) {
            return;
        }
        self.events.lock().unwrap().push(Ev::Obs(o));
    }
}

// --------------------------------------------------------------------- proxy

struct Sx {
    addr: SocketAddr,
    registry: Arc<CancelRegistry>,
    /// The proxy session of `tok-a` on `/mcp/a` (T-12b2), when the upstream
    /// accepted the harness's initialize.
    sid: Option<String>,
    stop: Option<oneshot::Sender<()>>,
    join: Option<JoinHandle<()>>,
}

impl Drop for Sx {
    fn drop(&mut self) {
        if let Some(s) = self.stop.take() {
            let _ = s.send(());
        }
        if let Some(j) = &self.join {
            j.abort();
        }
    }
}

async fn start(up: &Up, limits: Limits, sink: Option<Arc<dyn ObservationSink>>) -> Sx {
    let t = table(&[R::new("a", up.url("/up"), &[("pa", "tok-a")])], &limits);
    start_table(t, limits, sink).await
}

async fn start_table(
    t: sigil_proxy::route::RouteTable,
    limits: Limits,
    sink: Option<Arc<dyn ObservationSink>>,
) -> Sx {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = TableHandle::new();
    handle.set(Some(t));
    let mut proxy = Proxy::new(limits, handle, Arc::new(SystemResolver));
    if let Some(s) = sink {
        proxy = proxy.with_sink(s, sigil_proxy::inventory::CursorHasher::new().unwrap());
    }
    let registry = proxy.cancel_registry();
    let (stop, rx) = oneshot::channel::<()>();
    let join = tokio::spawn(async move {
        let _ = proxy
            .serve(listener, None, async {
                let _ = rx.await;
            })
            .await;
    });
    let init = send_raw(
        addr,
        &request_bytes(addr, Some("tok-a"), &[], initialize_body("0").as_bytes()),
    )
    .await;
    Sx {
        addr,
        registry,
        sid: init.header("mcp-session-id").map(str::to_string),
        stop: Some(stop),
        join: Some(join),
    }
}

fn request_bytes(
    addr: SocketAddr,
    token: Option<&str>,
    extra: &[(&str, &str)],
    body: &[u8],
) -> Vec<u8> {
    let mut r = format!("POST /mcp/a HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n");
    if let Some(t) = token {
        r += &format!("Authorization: Bearer {t}\r\n");
    }
    r += "Content-Type: application/json\r\nAccept: application/json, text/event-stream\r\n";
    for (k, v) in extra {
        r += &format!("{k}: {v}\r\n");
    }
    r += &format!("Content-Length: {}\r\n\r\n", body.len());
    let mut out = r.into_bytes();
    out.extend_from_slice(body);
    out
}

impl Sx {
    /// `extra` plus this harness's session, unless `extra` names its own or
    /// `body` is an initialize (which never carries one).
    fn with_session<'a>(
        &'a self,
        extra: &[(&'a str, &'a str)],
        body: &str,
    ) -> Vec<(&'a str, &'a str)> {
        let mut v = extra.to_vec();
        if let Some(sid) = &self.sid {
            if initialize_id(body.as_bytes()).is_none()
                && !extra
                    .iter()
                    .any(|(k, _)| k.eq_ignore_ascii_case("mcp-session-id"))
            {
                v.push(("Mcp-Session-Id", sid));
            }
        }
        v
    }

    async fn post_with(&self, extra: &[(&str, &str)], body: &str) -> Raw {
        send_raw(
            self.addr,
            &request_bytes(
                self.addr,
                Some("tok-a"),
                &self.with_session(extra, body),
                body.as_bytes(),
            ),
        )
        .await
    }
    async fn post(&self, body: &str) -> Raw {
        self.post_with(&[("MCP-Protocol-Version", "2025-11-25")], body)
            .await
    }
    /// Start a POST without waiting for the response.
    fn spawn_post(&self, body: &str) -> JoinHandle<Raw> {
        let (addr, bytes) = (
            self.addr,
            request_bytes(
                self.addr,
                Some("tok-a"),
                &self.with_session(&[("MCP-Protocol-Version", "2025-11-25")], body),
                body.as_bytes(),
            ),
        );
        tokio::spawn(async move { send_raw(addr, &bytes).await })
    }
}

fn call(id: &str, name: &str, args: &str) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"{name}","arguments":{args}}}}}"#
    )
}

fn ping(id: &str) -> String {
    format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"ping"}}"#)
}

fn cancel(target: &str) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","method":"notifications/cancelled","params":{{"requestId":{target},"reason":"CANARY-REASON"}}}}"#
    )
}

fn is_cancel(s: &Seen) -> bool {
    String::from_utf8_lossy(&s.body).contains("notifications/cancelled")
}

fn rpc(b: &[u8]) -> serde_json::Value {
    serde_json::from_slice(b).unwrap_or_else(|e| panic!("{e}: {}", String::from_utf8_lossy(b)))
}

// ------------------------------------------------------------ refusals (§5)

/// Support-matrix §5 oracle rows that the relay answers itself. Upstream is
/// never contacted, and the observation says why.
#[tokio::test]
async fn refusals_do_not_reach_upstream() {
    let up = ok_upstream().await;
    let rec = Rec::new();
    let px = start(&up, limits(), Some(rec.clone())).await;

    // JSON-RPC batch (removed in 2025-11-25)
    let r = px
        .post(r#"[{"jsonrpc":"2.0","id":1,"method":"ping"}]"#)
        .await;
    assert_eq!(r.status, 400);
    assert_eq!(r.header("content-type"), Some("application/json"));
    let v = rpc(&r.body());
    assert_eq!(v["error"]["code"], -32600);
    assert!(v["id"].is_null());
    assert!(v["error"].get("data").is_none());

    // not JSON / not JSON-RPC
    let r = px.post("not json").await;
    assert_eq!(
        (r.status, rpc(&r.body())["error"]["code"].clone()),
        (400, (-32700).into())
    );
    let r = px.post("{}").await;
    assert_eq!(
        (r.status, rpc(&r.body())["error"]["code"].clone()),
        (400, (-32600).into())
    );

    // tasks/*
    for m in ["tasks/get", "tasks/result", "tasks/list", "tasks/cancel"] {
        let r = px
            .post(&format!(r#"{{"jsonrpc":"2.0","id":"t1","method":"{m}"}}"#))
            .await;
        assert_eq!(r.status, 200, "{m}");
        let v = rpc(&r.body());
        assert_eq!(v["error"]["code"], -32601);
        assert_eq!(v["error"]["message"], "Method not found");
        assert_eq!(v["id"], "t1");
        assert_eq!(v.as_object().unwrap().len(), 3);
    }

    // resources/subscribe, unsubscribe
    let r = px
        .post(r#"{"jsonrpc":"2.0","id":4,"method":"resources/subscribe","params":{"uri":"x"}}"#)
        .await;
    assert_eq!(
        (r.status, rpc(&r.body())["error"]["code"].clone()),
        (200, (-32601).into())
    );

    // tools/call with no usable name
    let r = px
        .post(r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"arguments":{}}}"#)
        .await;
    let v = rpc(&r.body());
    assert_eq!(
        (r.status, v["error"]["code"].clone(), v["id"].clone()),
        (200, (-32602).into(), 5.into())
    );
    assert_eq!(v["error"]["message"], "Invalid params");

    // modern-era requests: 400 with an EMPTY body
    for (extra, body) in [
        (vec![], r#"{"jsonrpc":"2.0","id":1,"method":"server/discover"}"#.to_string()),
        (
            vec![],
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}"#.to_string(),
        ),
        (vec![("MCP-Protocol-Version", "2026-07-28")], ping("1")),
        (vec![("MCP-Protocol-Version", "bogus")], "garbage that is not even JSON".to_string()),
        // known legacy value after initialize
        (vec![("MCP-Protocol-Version", "2025-06-18")], ping("1")),
        (vec![("MCP-Protocol-Version", "2025-03-26")], call("2", "x", "{}")),
    ] {
        let r = px.post_with(&extra, &body).await;
        assert_eq!(r.status, 400, "{extra:?} {body}");
        assert!(r.body().is_empty(), "{extra:?} {body}");
    }

    assert_eq!(up.count(), 0, "nothing reached upstream");

    // the observations: one Refused per refusal, never a Started or Completed
    let all = rec.all();
    assert!(
        all.iter()
            .all(|e| matches!(e, Ev::Obs(Observation::Refused(_)))),
        "{all:?}"
    );
    let kinds: Vec<RefusalKind> = all
        .iter()
        .filter_map(|e| match e {
            Ev::Obs(Observation::Refused(r)) => Some(r.reason),
            _ => None,
        })
        .collect();
    use RefusalKind::*;
    assert_eq!(
        kinds,
        vec![
            Batch,
            Parse,
            InvalidRequest,
            TasksMethod,
            TasksMethod,
            TasksMethod,
            TasksMethod,
            ResourcesSubscription,
            ToolNameMalformed,
            ModernRequest,
            ModernRequest,
            ModernRequest,
            ModernRequest,
            VersionHeader,
            VersionHeader
        ]
    );
    // method/tool facets: the audit vocabulary only
    let by_kind = |k: RefusalKind| {
        all.iter()
            .find_map(|e| match e {
                Ev::Obs(Observation::Refused(r)) if r.reason == k => Some(r.clone()),
                _ => None,
            })
            .unwrap()
    };
    let t = by_kind(ToolNameMalformed);
    assert_eq!(
        (t.method, t.tool),
        (Method::ToolsCall, ToolField::Malformed)
    );
    assert_eq!(t.request_id.unwrap().raw(), "5");
    assert_eq!(t.http_status, 200);
    assert_eq!(by_kind(TasksMethod).method, Method::Unknown);
    assert_eq!(by_kind(ModernRequest).method, Method::Unknown);
    assert_eq!(by_kind(Batch).http_status, 400);
}

/// A client JSON-RPC notification that must be refused has nobody to answer by
/// id: HTTP 400 with a null-id error.
#[tokio::test]
async fn refused_notifications_get_a_null_id_error() {
    let up = ok_upstream().await;
    let px = start(&up, limits(), None).await;
    let r = px.post(r#"{"jsonrpc":"2.0","method":"tasks/get"}"#).await;
    assert_eq!(r.status, 400);
    assert!(rpc(&r.body())["id"].is_null());
    assert_eq!(up.count(), 0);
}

/// Authentication comes first: an unauthenticated modern request is a plain 401.
#[tokio::test]
async fn unauthenticated_modern_request_is_401() {
    let up = ok_upstream().await;
    let rec = Rec::new();
    let px = start(&up, limits(), Some(rec.clone())).await;
    let r = send_raw(
        px.addr,
        &request_bytes(
            px.addr,
            None,
            &[("MCP-Protocol-Version", "2026-07-28")],
            br#"{"jsonrpc":"2.0","id":1,"method":"server/discover"}"#,
        ),
    )
    .await;
    assert_eq!(r.status, 401);
    assert!(
        rec.all().is_empty(),
        "no event for an unauthenticated request"
    );
    assert_eq!(up.count(), 0);
}

/// Support-matrix §1: a client initialize that PROPOSES 2025-06-18 is forwarded
/// as is (the version is judged on the upstream's answer), with or without a
/// version header; a legacy header on initialize is tolerated.
#[tokio::test]
async fn initialize_proposing_a_legacy_version_is_forwarded() {
    let init = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"c","version":"1"}}}"#;
    // The handler sees every initialize (the harness's own, id 0, first).
    let up = Up::start_raw(|s: &Seen| {
        full(
            200,
            "application/json",
            &init_result(&initialize_id(&s.body).expect("an initialize")),
        )
    })
    .await;
    let rec = Rec::new();
    let px = start(&up, limits(), Some(rec.clone())).await;
    for extra in [vec![], vec![("MCP-Protocol-Version", "2025-06-18")]] {
        let r = px.post_with(&extra, init).await;
        assert_eq!(r.status, 200, "{extra:?}");
        assert_eq!(up.last().body, init.as_bytes());
        assert!(
            r.has("mcp-session-id"),
            "a supported answer opens a session"
        );
    }
    assert_eq!(up.count(), 3);
    let c = rec.completed();
    assert_eq!(c.len(), 2);
    assert!(c
        .iter()
        .all(|c| c.method == Method::Initialize && c.outcome == Outcome::Success));
}

/// Things the relay forwards untouched and does not observe as calls.
#[tokio::test]
async fn notifications_and_client_responses_are_relayed_without_events() {
    let up = Up::start(|_| full(202, "application/json", b"")).await;
    let rec = Rec::new();
    let px = start(&up, limits(), Some(rec.clone())).await;
    for body in [
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        r#"{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":1,"progress":2}}"#,
        // client answers to sampling / elicitation / roots
        r#"{"jsonrpc":"2.0","id":"srv-1","result":{"role":"assistant","content":{"type":"text","text":"hi"}}}"#,
        r#"{"jsonrpc":"2.0","id":3,"error":{"code":-1,"message":"declined"}}"#,
    ] {
        let r = px.post(body).await;
        assert_eq!(r.status, 202, "{body}");
        assert_eq!(up.last().body, body.as_bytes());
    }
    assert_eq!(up.count(), 4);
    assert!(rec.all().is_empty(), "{:?}", rec.all());
}

// ------------------------------------------------------- bytes are unchanged

fn awkward_call() -> Vec<u8> {
    br#"{ "jsonrpc" : "2.0","id":"x-1" ,"method":"tools/call","params":{"name":"echo","arguments":{"k":"v","k":2,"nested":[[[1]]]},"_meta":{"progressToken":"t"},"future":{"a":null}},"zzz_unknown":[1,2,3]}"#.to_vec()
}

/// Forwarded request bytes and relayed response bytes are identical whether no
/// sink is installed or a recording sink observes the call (D-01 relay-first).
#[tokio::test]
async fn bytes_are_unchanged_with_and_without_a_sink() {
    let resp = br#"{"jsonrpc":"2.0","id":"x-1","result":{"content":[{"type":"text","text":"h"}],"isError":false,"future_field":{"a":null}}}  "#.to_vec();
    let req = awkward_call();
    for with_sink in [false, true] {
        let r2 = resp.clone();
        let up = Up::start(move |_| full(200, "application/json", &r2)).await;
        let rec = Rec::new();
        let px = start(
            &up,
            limits(),
            with_sink.then(|| rec.clone() as Arc<dyn ObservationSink>),
        )
        .await;
        let r = px
            .post_with(
                &[("MCP-Protocol-Version", "2025-11-25")],
                std::str::from_utf8(&req).unwrap(),
            )
            .await;
        assert_eq!(r.status, 200);
        assert_eq!(up.last().body, req, "request bytes, sink={with_sink}");
        assert_eq!(r.body(), resp, "response bytes, sink={with_sink}");
        if with_sink {
            let c = rec.the_completion().await;
            assert_eq!(c.outcome, Outcome::Success);
            assert_eq!(c.response_bytes, resp.len() as u64);
        }
    }
}

/// SSE: chunk boundaries and bytes survive while the tracker watches, and the
/// first event is flushed before the stream ends.
#[tokio::test]
async fn sse_bytes_and_boundaries_survive_observation() {
    let (tx, reply) = sse_stream();
    let slot = Mutex::new(Some(reply));
    let up = Up::start(move |_| slot.lock().unwrap().take().expect("one call")).await;
    let rec = Rec::new();
    let px = start(&up, limits(), Some(rec.clone())).await;

    let mut s = TcpStream::connect(px.addr).await.unwrap();
    use tokio::io::AsyncWriteExt;
    let body = call("9", "slow", "{}");
    s.write_all(&request_bytes(
        px.addr,
        Some("tok-a"),
        &px.with_session(&[("MCP-Protocol-Version", "2025-11-25")], &body),
        body.as_bytes(),
    ))
    .await
    .unwrap();
    let chunks: Vec<&[u8]> = vec![
        b"event: message\r\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"progress\":1}}\r\n\r\n",
        b"data: {\"jsonrpc\":\"2.0\",\"id\":9,\"res",
        b"ult\":{\"content\":[],\"isError\":false}}\n\n",
    ];
    let mut buf = Vec::new();
    tx.send(Bytes::from_static(chunks[0])).await.unwrap();
    assert!(
        read_until(
            &mut s,
            &mut buf,
            b"\"progress\":1}}\r\n\r\n",
            Duration::from_secs(5)
        )
        .await
    );
    assert!(
        rec.completed().is_empty(),
        "not complete while the stream is open"
    );
    for c in &chunks[1..] {
        tx.send(Bytes::from_static(c)).await.unwrap();
        tokio::time::sleep(Duration::from_millis(60)).await;
    }
    drop(tx);
    assert!(read_until(&mut s, &mut buf, b"0\r\n\r\n", Duration::from_secs(5)).await);
    let r = parse_response(buf);
    let (got, complete) = r.chunks();
    assert!(complete);
    assert_eq!(got, chunks.iter().map(|c| c.to_vec()).collect::<Vec<_>>());
    let c = rec.the_completion().await;
    assert_eq!((c.outcome, c.delivery), (Outcome::Success, Delivery::Sent));
}

// ------------------------------------------------------------ outcome classes

async fn outcome_for(
    up_reply: impl Fn(&Seen) -> Reply + Send + Sync + 'static,
    body: String,
) -> (Raw, Completed) {
    let up = Up::start(up_reply).await;
    let rec = Rec::new();
    let px = start(&up, limits(), Some(rec.clone())).await;
    let r = px.post(&body).await;
    let c = rec.the_completion().await;
    (r, c)
}

#[tokio::test]
async fn json_outcomes() {
    // success
    let (r, c) = outcome_for(
        |_| {
            full(
                200,
                "application/json",
                br#"{"jsonrpc":"2.0","id":1,"result":{"content":[],"isError":false}}"#,
            )
        },
        call("1", "t", "{}"),
    )
    .await;
    assert_eq!(r.status, 200);
    assert_eq!(
        (c.outcome, c.delivery, c.cause, c.http_status),
        (Outcome::Success, Delivery::Sent, Cause::None, Some(200))
    );
    assert_eq!(c.method, Method::ToolsCall);
    assert_eq!(c.call.route_id, "a");
    assert_eq!(c.call.principal_id, "pa");
    assert!(!c.cancel_requested);

    // tool error
    let (_, c) = outcome_for(
        |_| full(200, "application/json", br#"{"jsonrpc":"2.0","id":1,"result":{"isError":true,"content":[{"type":"text","text":"CANARY-RESULT"}]}}"#),
        call("1", "t", "{}"),
    )
    .await;
    assert_eq!(c.outcome, Outcome::ToolError);

    // JSON-RPC error
    let (_, c) = outcome_for(
        |_| {
            full(
                200,
                "application/json",
                br#"{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"CANARY-ERR"}}"#,
            )
        },
        call("1", "t", "{}"),
    )
    .await;
    assert_eq!(
        (c.outcome, c.delivery),
        (Outcome::JsonRpcError, Delivery::Sent)
    );

    // HTTP failure without a JSON-RPC body
    let (r, c) = outcome_for(|_| full(500, "text/plain", b"boom"), call("1", "t", "{}")).await;
    assert_eq!(r.status, 500, "status still passes through");
    assert_eq!(
        (c.outcome, c.cause),
        (Outcome::TransportFailure, Cause::UpstreamStatus(500))
    );

    // accepted, nothing came back (202, empty): unknown, never success
    let (_, c) = outcome_for(|_| full(202, "application/json", b""), call("1", "t", "{}")).await;
    assert_eq!(
        (c.outcome, c.delivery, c.cause),
        (
            Outcome::Unknown,
            Delivery::Sent,
            Cause::StreamClosedWithoutResponse
        )
    );

    // upstream 401: mapped to the fixed error, audited unknown/sent
    let (r, c) = outcome_for(|_| full(401, "text/plain", b"no"), call("1", "t", "{}")).await;
    assert_eq!(r.status, 200);
    assert_eq!(
        (c.outcome, c.delivery, c.cause),
        (
            Outcome::Unknown,
            Delivery::Sent,
            Cause::UpstreamAuthRejected
        )
    );

    // redirect
    let (r, c) = outcome_for(
        |_| Reply::Full {
            status: 302,
            headers: vec![("location".into(), "http://elsewhere/".into())],
            body: vec![],
        },
        call("1", "t", "{}"),
    )
    .await;
    assert_eq!(r.status, 502);
    assert_eq!(c.cause, Cause::UpstreamRedirect);

    // content-encoded: relayed, never decoded, unobservable
    let gz = b"\x1f\x8b\x08\x00 not really gzip {\"id\":1,\"result\":{}}".to_vec();
    let g2 = gz.clone();
    let (r, c) = outcome_for(
        move |_| Reply::Full {
            status: 200,
            headers: vec![
                ("content-type".into(), "application/json".into()),
                ("content-encoding".into(), "gzip".into()),
            ],
            body: g2.clone(),
        },
        call("1", "t", "{}"),
    )
    .await;
    assert_eq!(r.body(), gz);
    assert_eq!(
        (c.outcome, c.cause),
        (Outcome::Unknown, Cause::Unobservable)
    );
}

/// PX-015: the connection is lost after the request went out. Unknown, sent or
/// unknown delivery, never retried.
#[tokio::test]
async fn lost_response_is_unknown_and_not_retried() {
    let up = Up::start(|_| Reply::Drop).await;
    let rec = Rec::new();
    let px = start(&up, limits(), Some(rec.clone())).await;
    let r = px.post(&call("1", "t", "{}")).await;
    assert_eq!(r.status, 502);
    let c = rec.the_completion().await;
    assert_eq!(
        (c.outcome, c.delivery, c.cause),
        (Outcome::Unknown, Delivery::Unknown, Cause::SendFailed)
    );
    assert_eq!(up.count(), 1);
    // one connection for the harness's initialize, one for the call
    assert_eq!(up.conns(), 2);
}

/// Upstream unreachable: nothing was sent.
#[tokio::test]
async fn unreachable_upstream_is_not_sent() {
    let up = ok_upstream().await;
    let l = limits();
    let t = table(&[R::new("a", up.url("/up"), &[("pa", "tok-a")])], &l);
    drop(up); // the port now refuses connections
    tokio::time::sleep(Duration::from_millis(100)).await;
    let rec = Rec::new();
    let px = start_table(t, l, Some(rec.clone())).await;
    // No session can exist; an initialize reaches the connect step on its own.
    let r = px.post(&initialize_body("1")).await;
    assert_eq!(r.status, 502);
    let c = rec.the_completion().await;
    assert_eq!(
        (c.method, c.outcome, c.delivery, c.cause),
        (
            Method::Initialize,
            Outcome::TransportFailure,
            Delivery::NotSent,
            Cause::ConnectFailed
        )
    );
}

#[tokio::test]
async fn sse_outcomes() {
    let events = |last: &'static str| {
        move |_: &Seen| {
            let body = format!(
                "data: {{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{{}}}}\n\ndata: {{\"jsonrpc\":\"2.0\",\"id\":\"sampling-1\",\"method\":\"sampling/createMessage\",\"params\":{{}}}}\n\n{last}"
            );
            Reply::Full {
                status: 200,
                headers: vec![("content-type".into(), "text/event-stream".into())],
                body: body.into_bytes(),
            }
        }
    };
    for (last, outcome, cause) in [
        (
            "data: {\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{}}\n\n",
            Outcome::Success,
            Cause::None,
        ),
        (
            "data: {\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"isError\":true}}\n\n",
            Outcome::ToolError,
            Cause::None,
        ),
        (
            "data: {\"jsonrpc\":\"2.0\",\"id\":7,\"error\":{\"code\":-1,\"message\":\"m\"}}\n\n",
            Outcome::JsonRpcError,
            Cause::None,
        ),
        // upstream closes without the response event
        ("", Outcome::Unknown, Cause::StreamClosedWithoutResponse),
        // a response for some other id does not count
        (
            "data: {\"jsonrpc\":\"2.0\",\"id\":8,\"result\":{}}\n\n",
            Outcome::Unknown,
            Cause::ResponseIdMismatch,
        ),
        // response event cut off before its blank line
        (
            "data: {\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{}}\n",
            Outcome::Unknown,
            Cause::StreamClosedWithoutResponse,
        ),
    ] {
        let (r, c) = outcome_for(events(last), call("7", "t", "{}")).await;
        assert_eq!(r.status, 200);
        assert!(
            r.text().contains("notifications/progress"),
            "stream relayed"
        );
        assert_eq!(
            (c.outcome, c.cause, c.delivery),
            (outcome, cause, Delivery::Sent),
            "{last:?}"
        );
    }
}

/// An upstream stream that dies mid-event: the client sees a truncated
/// response; the call is unknown, not failed and not successful.
#[tokio::test]
async fn aborted_sse_is_unknown() {
    let (tx, reply) = sse_stream();
    let slot = Mutex::new(Some(reply));
    let up = Up::start(move |_| slot.lock().unwrap().take().unwrap()).await;
    let rec = Rec::new();
    let px = start(&up, limits(), Some(rec.clone())).await;
    let h = px.spawn_post(&call("3", "t", "{}"));
    tx.send(Bytes::from_static(
        b"data: {\"jsonrpc\":\"2.0\",\"id\":3,\"res",
    ))
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    drop(tx); // upstream ends the stream with a partial event
    let _ = h.await;
    let c = rec.the_completion().await;
    assert_eq!((c.outcome, c.delivery), (Outcome::Unknown, Delivery::Sent));
}

#[tokio::test]
async fn oversized_request_is_refused_with_an_observation() {
    let up = ok_upstream().await;
    let mut l = limits();
    l.max_request_body_bytes = 256;
    let rec = Rec::new();
    let px = start(&up, l, Some(rec.clone())).await;
    let r = px
        .post(&call("1", "t", &format!("\"{}\"", "x".repeat(400))))
        .await;
    assert_eq!(r.status, 413);
    assert_eq!(up.count(), 0);
    match rec.all().as_slice() {
        [Ev::Obs(Observation::Refused(x))] => {
            assert_eq!(
                (x.reason, x.http_status),
                (RefusalKind::RequestTooLarge, 413)
            );
        }
        o => panic!("{o:?}"),
    }
}

// --------------------------------------------------- the observation contents

/// Nothing from arguments, results, errors, headers, tokens, cursors or cancel
/// reasons is in any observation; `Debug` prints no tool name or definition.
#[tokio::test]
async fn observations_carry_no_content() {
    let up = Up::start(|s: &Seen| {
        let b = String::from_utf8_lossy(&s.body);
        if b.contains("tools/list") {
            full(
                200,
                "application/json",
                br#"{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"echo","description":"CANARY-DESC","inputSchema":{"type":"object"}}],"nextCursor":"CANARY-NEXT"}}"#,
            )
        } else if b.contains("fails") {
            full(200, "application/json", br#"{"jsonrpc":"2.0","id":3,"error":{"code":-32000,"message":"CANARY-ERRMSG","data":"CANARY-ERRDATA"}}"#)
        } else {
            full(200, "application/json", br#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"CANARY-RESULT"}],"isError":false}}"#)
        }
    })
    .await;
    let rec = Rec::new();
    let px = start(&up, limits(), Some(rec.clone())).await;
    let extra = [
        ("MCP-Protocol-Version", "2025-11-25"),
        ("Cookie", "sid=CANARY-COOKIE"),
        ("X-Custom", "CANARY-HEADER"),
        ("Origin-Secret", "CANARY-ORIGIN"),
    ];
    let r = px
        .post_with(
            &extra,
            &call("1", "echo", r#"{"secret":"CANARY-ARG","n":[1,2]}"#),
        )
        .await;
    assert_eq!(r.status, 200);
    let r = px
        .post_with(
            &extra,
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{"cursor":"CANARY-CURSOR","_meta":{"k":"CANARY-META"}}}"#,
        )
        .await;
    assert_eq!(r.status, 200);
    let r = px
        .post_with(&extra, &call("3", "fails", r#"{"x":"CANARY-ARG2"}"#))
        .await;
    assert_eq!(r.status, 200);
    // a cancel for an unknown request (reason must not appear anywhere)
    let r = px.post_with(&extra, &cancel("99")).await;
    assert_eq!(r.status, 202);
    // a refusal carrying content
    px.post_with(
        &extra,
        r#"{"jsonrpc":"2.0","id":4,"method":"tasks/get","params":{"taskId":"CANARY-TASK"}}"#,
    )
    .await;
    // a malformed tool name carrying content
    px.post_with(&extra, r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":7,"arguments":{"a":"CANARY-ARG3"}}}"#).await;
    // a body with canaries that is not JSON at all
    px.post_with(&extra, "CANARY-GARBAGE").await;
    // an unknown method must not be echoed
    px.post_with(
        &extra,
        r#"{"jsonrpc":"2.0","id":6,"method":"vendor/CANARY-METHOD"}"#,
    )
    .await;

    // wait for all completions (4 forwarded requests: echo, list, fails, vendor)
    for _ in 0..100 {
        if rec.completed().len() == 4 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(rec.completed().len(), 4);

    let dump = rec.debug();
    assert!(dump.len() > 500, "the dump is non-trivial: {dump}");
    for canary in [
        "CANARY",
        "tok-a",
        "Bearer",
        "sid=",
        "UPSTREAM-SECRET",
        "echo",
        "fails",
        "description",
        "inputSchema",
    ] {
        assert!(
            !dump.contains(canary),
            "{canary} leaked into observations:\n{dump}"
        );
    }

    // The explicit data path the producer uses is intact:
    let started: Vec<_> = rec
        .all()
        .into_iter()
        .filter_map(|e| match e {
            Ev::Started(s) => Some(s),
            _ => None,
        })
        .collect();
    assert_eq!(started.len(), 4);
    match &started[0].tool {
        ToolField::Name(n) => assert_eq!(n.as_str(), "echo"),
        o => panic!("{o:?}"),
    }
    assert!(started[1].list_cursor.is_some() && started[1].method == Method::ToolsList);
    assert_eq!(started[3].method, Method::Unknown);
    let list = rec
        .completed()
        .into_iter()
        .find(|c| c.method == Method::ToolsList)
        .unwrap();
    match list.tool_list.unwrap() {
        ToolListCapture::Page(p) => {
            assert_eq!(p.tools[0].name.as_str(), "echo");
            assert!(
                p.tools[0].definition.contains("CANARY-DESC"),
                "T-13 gets the definition"
            );
            assert_eq!(p.next_cursor.unwrap().as_str(), "CANARY-NEXT");
        }
        o => panic!("{o:?}"),
    }
    // the cancel matched nothing: a counter, not an event
    assert!(!rec
        .all()
        .iter()
        .any(|e| matches!(e, Ev::Obs(Observation::Cancel(_)))));
}

/// The ordering contract of the seam: start, (cancel), completion.
#[tokio::test]
async fn started_precedes_completion() {
    let up = ok_upstream().await;
    let rec = Rec::new();
    let px = start(&up, limits(), Some(rec.clone())).await;
    px.post(&ping("1")).await;
    rec.the_completion().await;
    let all = rec.all();
    assert!(matches!(all[0], Ev::Started(_)));
    assert!(matches!(all[1], Ev::Obs(Observation::Completed(_))));
    assert_eq!(all.len(), 2);
}

/// `StartVerdict::Refuse` (spool full): fixed 503, upstream untouched, no
/// completion for the call.
#[tokio::test]
async fn start_refusal_blocks_dispatch() {
    let up = ok_upstream().await;
    let rec = Rec::refusing();
    let px = start(&up, limits(), Some(rec.clone())).await;
    let r = px.post(&call("1", "t", "{}")).await;
    assert_eq!(r.status, 503);
    assert_eq!(r.text(), "{\"error\":\"audit_unavailable\"}");
    assert_eq!(up.count(), 0);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(rec.completed().is_empty());
}

// -------------------------------------------------------- tools/list capture

#[tokio::test]
async fn tools_list_pages_are_exposed_to_the_seam() {
    let up = Up::start(|s: &Seen| {
        let b = String::from_utf8_lossy(&s.body);
        if b.contains("p2") {
            full(200, "application/json", br#"{"jsonrpc":"2.0","id":"p2","result":{"tools":[{"name":"c"}]}}"#)
        } else {
            full(200, "application/json", br#"{"jsonrpc":"2.0","id":"p1","result":{"tools":[{"name":"a","inputSchema":{}},{"name":"b"}],"nextCursor":"2"}}"#)
        }
    })
    .await;
    let rec = Rec::new();
    let px = start(&up, limits(), Some(rec.clone())).await;
    px.post(r#"{"jsonrpc":"2.0","id":"p1","method":"tools/list"}"#)
        .await;
    px.post(r#"{"jsonrpc":"2.0","id":"p2","method":"tools/list","params":{"cursor":"2"}}"#)
        .await;
    let c = rec.completed();
    assert_eq!(c.len(), 2);
    let pages: Vec<_> = c
        .iter()
        .map(|c| match c.tool_list.clone().unwrap() {
            ToolListCapture::Page(p) => p,
            o => panic!("{o:?}"),
        })
        .collect();
    assert_eq!(pages[0].tools.len(), 2);
    assert!(pages[0].next_cursor.is_some());
    assert_eq!(pages[1].tools.len(), 1);
    assert!(pages[1].next_cursor.is_none(), "last page");
    let started: Vec<_> = rec
        .all()
        .into_iter()
        .filter_map(|e| match e {
            Ev::Started(s) => Some(s.list_cursor.is_some()),
            _ => None,
        })
        .collect();
    assert_eq!(started, vec![false, true]);
}

// ------------------------------------------------------- cancel ordering (M3)

/// An upstream for one long call: the first non-cancel request gets a stream the
/// test controls; cancel notifications get an immediate 202.
async fn holding() -> (Up, tokio::sync::mpsc::Sender<Bytes>) {
    let (tx, reply) = sse_stream();
    let slot = Mutex::new(Some(reply));
    let up = Up::start(move |s: &Seen| {
        if is_cancel(s) {
            full(202, "application/json", b"")
        } else {
            slot.lock().unwrap().take().expect("one held call")
        }
    })
    .await;
    (up, tx)
}

/// After dispatch the cancel is forwarded; a response that still arrives decides
/// the outcome; `cancel_requested` is set.
#[tokio::test]
async fn cancel_after_dispatch_is_forwarded() {
    let (up, tx) = holding().await;
    let rec = Rec::new();
    let px = start(&up, limits(), Some(rec.clone())).await;
    let call_h = px.spawn_post(&call("5", "slow", "{}"));
    for _ in 0..100 {
        if up.count() == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(up.count(), 1, "dispatched");

    let r = px.post(&cancel("5")).await;
    assert_eq!(r.status, 202);
    assert_eq!(up.count(), 2, "the cancel reached upstream");
    assert!(is_cancel(&up.last()));
    assert!(
        String::from_utf8_lossy(&up.last().body).contains("\"requestId\":5"),
        "forwarded unchanged"
    );

    // upstream answers the cancelled request with an error: that outcome stands
    tx.send(Bytes::from_static(b"data: {\"jsonrpc\":\"2.0\",\"id\":5,\"error\":{\"code\":-32800,\"message\":\"cancelled\"}}\n\n")).await.unwrap();
    drop(tx);
    let r = call_h.await.unwrap();
    assert_eq!(r.status, 200);
    let c = rec.the_completion().await;
    assert_eq!(
        (c.outcome, c.cancel_requested),
        (Outcome::JsonRpcError, true)
    );

    let cancels: Vec<_> = rec
        .all()
        .into_iter()
        .filter_map(|e| match e {
            Ev::Obs(Observation::Cancel(c)) => Some(c),
            _ => None,
        })
        .collect();
    assert_eq!(cancels.len(), 1);
    assert_eq!(cancels[0].disposition, CancelDisposition::AfterDispatch);
    assert_eq!(cancels[0].target_id.raw(), "5");
    assert_eq!(cancels[0].target, c.call, "names the target call");
    // order: started, cancel, completed
    let kinds: Vec<&str> = rec
        .all()
        .iter()
        .map(|e| match e {
            Ev::Started(_) => "started",
            Ev::Obs(Observation::Cancel(_)) => "cancel",
            Ev::Obs(Observation::Completed(_)) => "completed",
            Ev::Obs(Observation::Refused(_)) => "refused",
        })
        .collect();
    assert_eq!(kinds, vec!["started", "cancel", "completed"]);
}

/// A forwarded cancel that gets no answer ends as unknown/cancel_no_response
/// after the grace, never as a timeout, and the call is not retried.
#[tokio::test]
async fn cancel_without_a_response_ends_as_cancel_no_response() {
    let (up, _tx) = holding().await; // _tx kept open: upstream never answers
    let rec = Rec::new();
    let px = start(&up, limits(), Some(rec.clone())).await;
    let call_h = px.spawn_post(&call("5", "slow", "{}"));
    for _ in 0..100 {
        if up.count() == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    px.post(&cancel("5")).await;
    let t0 = std::time::Instant::now();
    let c = rec.the_completion().await;
    assert_eq!(
        (c.outcome, c.delivery, c.cause, c.cancel_requested),
        (
            Outcome::Unknown,
            Delivery::Sent,
            Cause::CancelNoResponse,
            true
        )
    );
    assert!(t0.elapsed() < Duration::from_secs(10));
    let _ = call_h.await;
    assert_eq!(up.count(), 2, "no retry: one call, one cancel");
}

/// A cancel that arrives before the request: held for a short window, not
/// forwarded; the request, when it comes, is never dispatched.
#[tokio::test]
async fn cancel_before_the_request_arrives_prevents_dispatch() {
    let up = ok_upstream().await;
    let rec = Rec::new();
    let px = start(&up, limits(), Some(rec.clone())).await;

    let r = px.post(&cancel("5")).await;
    assert_eq!(r.status, 202);
    assert_eq!(up.count(), 0, "a held cancel is not forwarded");

    let r = px.post(&call("5", "t", "{}")).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.header("content-type"), Some("text/event-stream"));
    assert!(
        r.body().is_empty(),
        "an event-less stream, no JSON-RPC response"
    );
    assert_eq!(up.count(), 0, "never dispatched");

    let c = rec.the_completion().await;
    assert_eq!(
        (c.outcome, c.delivery, c.cause),
        (
            Outcome::Unknown,
            Delivery::NotSent,
            Cause::CancelledBeforeDispatch
        )
    );
    let kinds: Vec<&str> = rec
        .all()
        .iter()
        .map(|e| match e {
            Ev::Started(_) => "started",
            Ev::Obs(Observation::Cancel(c)) => {
                assert_eq!(c.disposition, CancelDisposition::BeforeDispatch);
                "cancel"
            }
            Ev::Obs(Observation::Completed(_)) => "completed",
            Ev::Obs(Observation::Refused(_)) => "refused",
        })
        .collect();
    assert_eq!(kinds, vec!["started", "cancel", "completed"]);
}

/// The race: the cancel lands while the start observation is still pending (the
/// request is registered but not dispatched). One winner: no dispatch.
#[tokio::test]
async fn cancel_during_start_observation_wins() {
    let up = ok_upstream().await;
    let rec = Rec::delayed(Duration::from_millis(600));
    let px = start(&up, limits(), Some(rec.clone())).await;
    let h = px.spawn_post(&call("8", "t", "{}"));
    tokio::time::sleep(Duration::from_millis(200)).await; // inside the delay
    let r = px.post(&cancel("8")).await;
    assert_eq!(r.status, 202);
    let r = h.await.unwrap();
    assert_eq!(r.header("content-type"), Some("text/event-stream"));
    assert_eq!(up.count(), 0, "not dispatched, cancel not forwarded");
    let c = rec.the_completion().await;
    assert_eq!(c.cause, Cause::CancelledBeforeDispatch);
}

/// Exact JSON equality, principal/route scoping: a cancel for another id (type
/// or value) leaves the request alone.
#[tokio::test]
async fn cancel_matches_exact_ids_only() {
    let up = Up::start(|_| {
        full(
            200,
            "application/json",
            br#"{"jsonrpc":"2.0","id":5,"result":{}}"#,
        )
    })
    .await;
    let rec = Rec::new();
    let px = start(&up, limits(), Some(rec.clone())).await;
    // "5" (string) and 5.0 and 6 are not 5
    for t in ["\"5\"", "5.0", "6"] {
        assert_eq!(px.post(&cancel(t)).await.status, 202);
    }
    let r = px.post(&call("5", "t", "{}")).await;
    assert_eq!(r.header("content-type"), Some("application/json"));
    assert_eq!(up.count(), 1, "dispatched");
    let c = rec.the_completion().await;
    assert_eq!(c.outcome, Outcome::Success);
}

/// A cancel older than the window does not affect a later request with the same
/// id; it is only counted.
#[tokio::test]
async fn expired_held_cancels_are_counted_not_applied() {
    let up = ok_upstream().await;
    let px = start(&up, limits(), None).await;
    px.post(&cancel("5")).await;
    // pretend the window passed
    let later = tokio::time::Instant::now() + Duration::from_secs(60);
    assert_eq!(px.registry.unmatched_total_at(later), 1);
    let r = px.post(&call("5", "t", "{}")).await;
    assert_eq!(r.header("content-type"), Some("application/json"));
    assert_eq!(up.count(), 1);
}

/// A malformed cancel is a client error, not a hold.
#[tokio::test]
async fn malformed_cancel_is_refused() {
    let up = ok_upstream().await;
    let px = start(&up, limits(), None).await;
    let r = px
        .post(r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{}}"#)
        .await;
    assert_eq!(r.status, 400);
    assert_eq!(up.count(), 0);
}

/// M1 over HTTP: an id-less `tools/call` is refused, not relayed unobserved.
#[tokio::test]
async fn id_less_tools_call_is_refused_over_http() {
    let up = ok_upstream().await;
    let rec = Rec::new();
    let px = start(&up, limits(), Some(rec.clone())).await;
    let r = px
        .post(r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"x"}}"#)
        .await;
    assert_eq!(r.status, 400);
    let v = rpc(&r.body());
    assert_eq!(v["error"]["code"], -32600);
    assert!(v["id"].is_null());
    assert_eq!(up.count(), 0);
    assert!(matches!(
        rec.all().as_slice(),
        [Ev::Obs(Observation::Refused(r))] if r.reason == RefusalKind::InvalidRequest
    ));
}

/// M2 over HTTP: a duplicate `_meta` hiding the modern marker is refused.
#[tokio::test]
async fn duplicate_meta_cannot_hide_a_modern_request() {
    let up = ok_upstream().await;
    let px = start(&up, limits(), None).await;
    let r = px
        .post(r#"{"jsonrpc":"2.0","id":1,"method":"ping","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"x"},"_meta":{}}}"#)
        .await;
    assert_eq!(r.status, 400);
    assert_eq!(up.count(), 0);
}

/// L2: a second request with an id that is still in flight (same principal and
/// route) is refused; the first call is untouched.
#[tokio::test]
async fn duplicate_in_flight_id_is_refused() {
    let (up, tx) = holding().await;
    let rec = Rec::new();
    let px = start(&up, limits(), Some(rec.clone())).await;
    let first = px.spawn_post(&call("5", "slow", "{}"));
    for _ in 0..100 {
        if up.count() == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let r = px.post(&call("5", "other", "{}")).await;
    assert_eq!(r.status, 400);
    let v = rpc(&r.body());
    assert_eq!(v["error"]["code"], -32600);
    assert_eq!(v["id"], 5);
    assert_eq!(up.count(), 1, "the duplicate never reached upstream");
    tx.send(Bytes::from_static(
        b"data: {\"jsonrpc\":\"2.0\",\"id\":5,\"result\":{}}\n\n",
    ))
    .await
    .unwrap();
    drop(tx);
    assert_eq!(first.await.unwrap().status, 200);
    let c = rec.the_completion().await;
    assert_eq!(c.outcome, Outcome::Success);
    let refused = rec
        .all()
        .into_iter()
        .filter(|e| matches!(e, Ev::Obs(Observation::Refused(r)) if r.reason == RefusalKind::InvalidRequest))
        .count();
    assert_eq!(refused, 1);
}

/// L4: with the default no-op sink nothing is scanned or captured, bytes are
/// identical, and cancel ordering (behaviour, not observation) still applies.
#[tokio::test]
async fn noop_sink_keeps_bytes_and_cancel_ordering() {
    let body =
        br#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"a"}],"nextCursor":"n"}}"#.to_vec();
    let b2 = body.clone();
    let up = Up::start(move |_| full(200, "application/json", &b2)).await;
    let px = start(&up, limits(), None).await;
    let r = px
        .post(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#)
        .await;
    assert_eq!(r.body(), body);

    assert_eq!(px.post(&cancel("9")).await.status, 202);
    let r = px.post(&call("9", "t", "{}")).await;
    assert_eq!(r.header("content-type"), Some("text/event-stream"));
    assert_eq!(up.count(), 1, "the cancelled call was never dispatched");
}
