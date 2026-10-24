#![cfg(unix)]
//! T-12b2 / AC-07,08,15: production session gate over actual HTTP.
mod common;
use common::*;
use sigil_proxy::limits::Limits;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const PING: &[u8] = br#"{"jsonrpc":"2.0","id":7,"method":"ping"}"#;
const UP_SID: &str = "private-upstream-session-canary";
fn limits() -> Limits {
    Limits {
        response_idle_timeout_secs: 1,
        call_timeout_secs: 3,
        ..Limits::default()
    }
}
async fn proxy(up: &Up, l: Limits) -> Px {
    Px::start(
        Some(table(
            &[
                R::new("a", up.url("/mcp"), &[("p", "t"), ("q", "u")]),
                R::new("b", up.url("/mcp"), &[("p", "t")]),
            ],
            &l,
        )),
        l,
    )
    .await
}
fn stateful(body: Vec<u8>, ct: &str) -> Reply {
    Reply::Full {
        status: 200,
        headers: vec![
            ("content-type".into(), ct.into()),
            ("mcp-session-id".into(), UP_SID.into()),
        ],
        body,
    }
}
async fn init(px: &Px) -> Raw {
    px.post_bare("/mcp/a", Some("t"), &[], initialize_body("1").as_bytes())
        .await
}
async fn bound(px: &Px, sid: &str, token: &str, path: &str) -> Raw {
    px.post_bare(
        path,
        Some(token),
        &[
            ("mcp-session-id", sid),
            ("mcp-protocol-version", "2025-11-25"),
        ],
        PING,
    )
    .await
}
async fn delete(px: &Px, sid: &str) -> Raw {
    px.send(&px.request(
        "DELETE",
        "/mcp/a",
        Some("t"),
        &[("mcp-session-id", sid)],
        b"",
    ))
    .await
}
async fn cleanup(up: &Up) {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if up.seen.lock().unwrap().iter().any(|s| s.method == "DELETE") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("bounded cleanup sent");
    assert_eq!(up.last().header("mcp-session-id"), Some(UP_SID));
}

#[tokio::test]
async fn proxy_session_is_private_bound_and_protocol_is_checked_after_auth() {
    let up = Up::start_raw(|s| match initialize_id(&s.body) {
        Some(id) => stateful(init_result(&id), "application/json"),
        None => full(
            200,
            "application/json",
            br#"{"jsonrpc":"2.0","id":7,"result":{}}"#,
        ),
    })
    .await;
    let px = proxy(&up, limits()).await;
    let r = init(&px).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.body(), init_result(&serde_json::json!(1)));
    let sid = r.header("mcp-session-id").unwrap();
    assert_ne!(sid, UP_SID);
    assert!(sid.len() >= 32);
    assert_eq!(bound(&px, sid, "t", "/mcp/a").await.status, 200);
    assert_eq!(up.last().header("mcp-session-id"), Some(UP_SID));
    assert!(!up.last().headers.iter().any(|(_, v)| v == sid));
    let before = up.count();
    for (token, path, presented) in [
        ("u", "/mcp/a", sid),
        ("t", "/mcp/b", sid),
        ("t", "/mcp/a", "unknown"),
    ] {
        let r = bound(&px, presented, token, path).await;
        assert_eq!(r.status, 404);
        assert!(r.body().is_empty());
    }
    assert_eq!(
        px.post_bare("/mcp/a", Some("t"), &[], PING).await.status,
        400
    );
    for headers in [
        vec![("mcp-session-id", sid)],
        vec![
            ("mcp-session-id", sid),
            ("mcp-protocol-version", "2025-06-18"),
        ],
        vec![
            ("mcp-session-id", sid),
            ("mcp-protocol-version", "2025-11-25"),
            ("mcp-protocol-version", "2025-11-25"),
        ],
    ] {
        let r = px.post_bare("/mcp/a", Some("t"), &headers, PING).await;
        assert_eq!(r.status, 400);
        assert!(r.body().is_empty());
        assert_eq!(
            px.post_bare("/mcp/a", Some("bad"), &headers, PING)
                .await
                .status,
            401
        );
    }
    for presented in [sid, "foreign", UP_SID] {
        assert_eq!(
            px.post_bare(
                "/mcp/a",
                Some("t"),
                &[("mcp-session-id", presented)],
                initialize_body("8").as_bytes()
            )
            .await
            .status,
            400
        );
    }
    assert_eq!(
        px.send(&px.request(
            "GET",
            "/mcp/a",
            Some("t"),
            &[("last-event-id", "canary")],
            b""
        ))
        .await
        .status,
        405
    );
    assert_eq!(up.count(), before);
    assert_eq!(bound(&px, sid, "t", "/mcp/a").await.status, 200);
}

#[tokio::test]
async fn stateful_delete_preserves_on_errors_then_ends_once() {
    let status = Arc::new(AtomicU16::new(405));
    let s2 = status.clone();
    let up = Up::start_raw(move |s| {
        if let Some(id) = initialize_id(&s.body) {
            stateful(init_result(&id), "application/json")
        } else if s.method == "DELETE" {
            full(s2.load(Ordering::SeqCst), "application/json", b"")
        } else {
            full(200, "application/json", b"{}")
        }
    })
    .await;
    let px = proxy(&up, limits()).await;
    let r = init(&px).await;
    let sid = r.header("mcp-session-id").unwrap();
    for code in [405, 500] {
        status.store(code, Ordering::SeqCst);
        assert_eq!(delete(&px, sid).await.status, code);
        assert_eq!(bound(&px, sid, "t", "/mcp/a").await.status, 200);
    }
    status.store(204, Ordering::SeqCst);
    let (a, b) = tokio::join!(delete(&px, sid), delete(&px, sid));
    assert!([a.status, b.status].contains(&204));
    assert!([a.status, b.status].contains(&404));
    let n = up.count();
    assert_eq!(bound(&px, sid, "t", "/mcp/a").await.status, 404);
    assert_eq!(delete(&px, sid).await.status, 404);
    assert_eq!(up.count(), n);
    assert_eq!(
        up.seen
            .lock()
            .unwrap()
            .iter()
            .filter(|s| s.method == "DELETE")
            .count(),
        3
    );
}

#[tokio::test]
async fn stateless_delete_is_local_and_post404_ends_binding() {
    let status = Arc::new(AtomicU16::new(200));
    let s2 = status.clone();
    let up = Up::start(move |_| {
        full(
            s2.load(Ordering::SeqCst),
            "application/json",
            b"untrusted404canary",
        )
    })
    .await;
    let px = proxy(&up, limits()).await;
    let r = init(&px).await;
    let sid = r.header("mcp-session-id").unwrap();
    assert_eq!(delete(&px, sid).await.status, 204);
    assert_eq!(up.count(), 0);
    let r = init(&px).await;
    let sid = r.header("mcp-session-id").unwrap();
    status.store(404, Ordering::SeqCst);
    let r = bound(&px, sid, "t", "/mcp/a").await;
    assert_eq!(r.status, 404);
    assert!(r.body().is_empty());
    let n = up.count();
    assert_eq!(bound(&px, sid, "t", "/mcp/a").await.status, 404);
    assert_eq!(up.count(), n);
}

#[tokio::test]
async fn unsupported_initialize_and_unreadable_answers_cleanup_without_a_session() {
    for result in [
        serde_json::json!({"protocolVersion":"2025-06-18","capabilities":{}}),
        serde_json::json!({"protocolVersion":"2025-11-25","capabilities":{"tasks":{}}}),
        serde_json::json!({"protocolVersion":"2025-11-25","capabilities":{"resources":{"subscribe":true}}}),
        serde_json::json!({}),
    ] {
        let up = Up::start_raw(move |s| {
            if s.method == "DELETE" {
                full(204, "application/json", b"")
            } else {
                stateful(
                    serde_json::to_vec(
                        &serde_json::json!({"jsonrpc":"2.0","id":1,"result":result}),
                    )
                    .unwrap(),
                    "application/json",
                )
            }
        })
        .await;
        let px = proxy(&up, limits()).await;
        let r = init(&px).await;
        assert_eq!(r.status, 200);
        assert!(!r.has("mcp-session-id"));
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&r.body()).unwrap(),
            serde_json::json!({"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":"Internal error"}})
        );
        cleanup(&up).await;
    }
}

#[tokio::test]
async fn sse_initialize_keeps_prefix_and_remainder_in_order() {
    let data=format!("event: message\ndata: {{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{{}}}}\n\nevent: message\ndata: {}\n\n: remainder-canary\n\n",String::from_utf8(init_result(&serde_json::json!(1))).unwrap());
    let expected = data.clone();
    let up = Up::start_raw(move |_| stateful(data.as_bytes().to_vec(), "text/event-stream")).await;
    let px = proxy(&up, limits()).await;
    let r = init(&px).await;
    assert_eq!(r.status, 200);
    assert!(r.has("mcp-session-id"));
    assert_eq!(r.body(), expected.as_bytes());
}

#[tokio::test]
async fn sse_timeout_captures_upstream_session_for_cleanup() {
    let (tx, rx) = tokio::sync::mpsc::channel(2);
    let slot = Mutex::new(Some(rx));
    let up = Up::start_raw(move |s| {
        if s.method == "DELETE" {
            full(204, "application/json", b"")
        } else {
            Reply::Stream {
                status: 200,
                headers: vec![
                    ("content-type".into(), "text/event-stream".into()),
                    ("mcp-session-id".into(), UP_SID.into()),
                ],
                rx: slot.lock().unwrap().take().unwrap(),
            }
        }
    })
    .await;
    tx.send(bytes::Bytes::from_static(b": awaiting response\n\n"))
        .await
        .unwrap();
    let px = proxy(&up, limits()).await;
    let r = init(&px).await;
    assert_eq!(r.status, 200);
    assert!(!r.has("mcp-session-id"));
    assert!(r.text().contains("-32603"));
    cleanup(&up).await;
    drop(tx);
}

#[tokio::test]
async fn session_capacity_counts_pending_initializes_and_expiry_releases_slots() {
    let up = Up::start(|_| full(200, "application/json", b"{}")).await;
    let mut l = limits();
    l.max_sessions = 1;
    l.max_sessions_per_principal = 1;
    l.session_idle_secs = 1;
    let px = proxy(&up, l).await;
    let r = init(&px).await;
    let sid = r.header("mcp-session-id").unwrap();
    let r = init(&px).await;
    assert_eq!(r.status, 429);
    assert_eq!(r.text(), r#"{"error":"too_many_sessions"}"#);
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert_eq!(bound(&px, sid, "t", "/mcp/a").await.status, 404);
    assert!(init(&px).await.has("mcp-session-id"));
}

#[tokio::test]
async fn repoint_never_sends_old_session_to_new_upstream_and_post_resume_is_stripped() {
    let up = Up::start_raw(|s| {
        if let Some(id) = initialize_id(&s.body) {
            stateful(init_result(&id), "application/json")
        } else {
            full(200, "application/json", b"{}")
        }
    })
    .await;
    let other = Up::start(|_| full(200, "application/json", b"{}")).await;
    let px = proxy(&up, limits()).await;
    let r = init(&px).await;
    let sid = r.header("mcp-session-id").unwrap();
    assert_eq!(
        px.post_bare(
            "/mcp/a",
            Some("t"),
            &[
                ("mcp-session-id", sid),
                ("mcp-protocol-version", "2025-11-25"),
                ("last-event-id", "resume-canary")
            ],
            PING
        )
        .await
        .status,
        200
    );
    assert!(!up.last().has("last-event-id"));
    px.handle.set(Some(table(
        &[R::new("a", other.url("/mcp"), &[("p", "t")])],
        &limits(),
    )));
    assert_eq!(bound(&px, sid, "t", "/mcp/a").await.status, 404);
    assert_eq!(other.conns(), 0);
}

#[tokio::test]
async fn declared_oversize_initialize_is_fixed_refusal_and_cleans_up() {
    let up = Up::start_raw(|s| {
        if s.method == "DELETE" {
            full(204, "application/json", b"")
        } else {
            stateful(vec![b' '; 4096], "application/json")
        }
    })
    .await;
    let mut l = limits();
    l.max_json_response_bytes = 1024;
    let px = proxy(&up, l).await;
    let r = init(&px).await;
    assert_eq!(r.status, 200);
    assert!(!r.has("mcp-session-id"));
    assert!(r.text().contains("-32603"));
    cleanup(&up).await;
}

#[tokio::test]
async fn pending_initialize_reserves_capacity_before_an_answer() {
    let (tx, rx) = tokio::sync::mpsc::channel(2);
    let slot = Mutex::new(Some(rx));
    let up = Up::start_raw(move |_| Reply::Stream {
        status: 200,
        headers: vec![("content-type".into(), "text/event-stream".into())],
        rx: slot.lock().unwrap().take().unwrap(),
    })
    .await;
    let mut l = limits();
    l.max_sessions = 1;
    l.max_sessions_per_principal = 1;
    let px = proxy(&up, l).await;
    let first = init(&px);
    let second = async {
        tokio::time::timeout(Duration::from_secs(2), async {
            while up.count() == 0 {
                tokio::time::sleep(Duration::from_millis(5)).await
            }
        })
        .await
        .unwrap();
        assert_eq!(init(&px).await.status, 429);
        assert_eq!(up.count(), 1);
        tx.send(bytes::Bytes::from(format!(
            "data: {}\n\n",
            String::from_utf8(init_result(&serde_json::json!(1))).unwrap()
        )))
        .await
        .unwrap();
        drop(tx);
    };
    let (r, ()) = tokio::join!(first, second);
    assert!(r.has("mcp-session-id"));
}

#[tokio::test]
async fn two_sessions_same_request_id_can_each_be_cancelled_and_active_is_not_idle() {
    let (tx1, rx1) = tokio::sync::mpsc::channel(2);
    let (tx2, rx2) = tokio::sync::mpsc::channel(2);
    let streams = Mutex::new(std::collections::VecDeque::from([rx1, rx2]));
    let up = Up::start_raw(move |s| {
        if let Some(id) = initialize_id(&s.body) {
            return stateful(init_result(&id), "application/json");
        }
        let v: serde_json::Value = serde_json::from_slice(&s.body).unwrap();
        if v["method"] == "notifications/cancelled" {
            return full(202, "application/json", b"");
        }
        Reply::Stream {
            status: 200,
            headers: vec![("content-type".into(), "text/event-stream".into())],
            rx: streams.lock().unwrap().pop_front().unwrap(),
        }
    })
    .await;
    let mut l = limits();
    l.session_idle_secs = 1;
    l.response_idle_timeout_secs = 4;
    l.call_timeout_secs = 6;
    let px = proxy(&up, l).await;
    let a = init(&px).await;
    let b = init(&px).await;
    let a = a.header("mcp-session-id").unwrap();
    let b = b.header("mcp-session-id").unwrap();
    assert_ne!(a, b);
    let calls = async { tokio::join!(bound(&px, a, "t", "/mcp/a"), bound(&px, b, "t", "/mcp/a")) };
    let cancel = async {
        tokio::time::timeout(Duration::from_secs(2), async {
            while up.count() < 4 {
                tokio::time::sleep(Duration::from_millis(5)).await
            }
        })
        .await
        .unwrap();
        // Both streams stay active past the session idle limit.
        tokio::time::sleep(Duration::from_millis(1100)).await;
        for sid in [a, b] {
            let r=px.post_bare("/mcp/a",Some("t"),&[("mcp-session-id",sid),("mcp-protocol-version","2025-11-25")],br#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":7}}"#).await;
            assert_eq!(r.status, 202);
        }
        assert_eq!(
            up.seen
                .lock()
                .unwrap()
                .iter()
                .filter(|s| s.body.windows(23).any(|w| w == b"notifications/cancelled"))
                .count(),
            2
        );
        for tx in [tx1, tx2] {
            tx.send(bytes::Bytes::from_static(
                b"data: {\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{}}\n\n",
            ))
            .await
            .unwrap();
        }
    };
    let ((ra, rb), ()) = tokio::join!(calls, cancel);
    assert_eq!((ra.status, rb.status), (200, 200));
}

#[tokio::test]
async fn an_open_sse_initialize_holds_its_session_active_past_idle_expiry() {
    let (tx, rx) = tokio::sync::mpsc::channel(8);
    let stream = Mutex::new(Some(rx));
    let up = Up::start_raw(move |s| {
        if s.method == "DELETE" {
            return full(204, "application/json", b"");
        }
        if initialize_id(&s.body).is_none() {
            return full(
                200,
                "application/json",
                br#"{"jsonrpc":"2.0","id":7,"result":{}}"#,
            );
        }
        Reply::Stream {
            status: 200,
            headers: vec![
                ("content-type".into(), "text/event-stream".into()),
                ("mcp-session-id".into(), UP_SID.into()),
            ],
            rx: stream.lock().unwrap().take().unwrap(),
        }
    })
    .await;
    let mut l = limits();
    l.session_idle_secs = 1;
    l.call_timeout_secs = 5;
    l.response_idle_timeout_secs = 4;
    let px = proxy(&up, l).await;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut init = tokio::net::TcpStream::connect(px.addr).await.unwrap();
    let body = initialize_body("1");
    init.write_all(format!("POST /mcp/a HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer t\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n{}",px.addr,body.len(),body).as_bytes()).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while up.count() == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await
        }
    })
    .await
    .unwrap();
    let event = format!(
        "data: {}\n\n",
        String::from_utf8(init_result(&serde_json::json!(1))).unwrap()
    );
    tx.send(bytes::Bytes::from(event)).await.unwrap();
    let mut head = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), async {
        let mut b = [0u8; 1024];
        loop {
            let n = init.read(&mut b).await.unwrap();
            assert!(n > 0);
            head.extend_from_slice(&b[..n]);
            if head.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
    })
    .await
    .unwrap();
    let headers = String::from_utf8_lossy(&head);
    assert!(headers.starts_with("HTTP/1.1 200"));
    let sid = headers
        .lines()
        .find_map(|l| {
            l.to_ascii_lowercase()
                .strip_prefix("mcp-session-id:")
                .map(str::trim)
                .map(str::to_string)
        })
        .unwrap();
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let ping = px
        .post_bare(
            "/mcp/a",
            Some("t"),
            &[
                ("mcp-session-id", &sid),
                ("mcp-protocol-version", "2025-11-25"),
            ],
            PING,
        )
        .await;
    assert_eq!(ping.status, 200);
    drop(init);
    drop(tx);
}

#[derive(Default)]
struct ShutdownSink {
    entered: tokio::sync::Notify,
    admitted: std::sync::atomic::AtomicUsize,
    completed: Mutex<Vec<sigil_proxy::mcp::observation::Completed>>,
    delay_ping: bool,
}
impl sigil_proxy::mcp::observation::ObservationSink for ShutdownSink {
    fn request_started<'a>(
        &'a self,
        s: &'a sigil_proxy::mcp::observation::RequestStarted,
    ) -> sigil_proxy::mcp::observation::SinkFuture<'a, sigil_proxy::mcp::observation::StartVerdict>
    {
        Box::pin(async move {
            if self.delay_ping && s.method == sigil_proxy::mcp::observation::Method::Ping {
                self.entered.notify_one();
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
            self.admitted.fetch_add(1, Ordering::SeqCst);
            sigil_proxy::mcp::observation::StartVerdict::Proceed
        })
    }
    fn observe(&self, event: sigil_proxy::mcp::observation::Observation) {
        if let sigil_proxy::mcp::observation::Observation::Completed(c) = event {
            self.completed.lock().unwrap().push(c);
        }
    }
}
async fn serve_with_sink(
    up: &Up,
    sink: Arc<ShutdownSink>,
) -> (
    std::net::SocketAddr,
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<std::io::Result<sigil_proxy::lifecycle::DrainOutcome>>,
) {
    use sigil_proxy::dest::SystemResolver;
    use sigil_proxy::route::TableHandle;
    use sigil_proxy::server::Proxy;
    let mut l = limits();
    l.shutdown_grace_secs = 1;
    l.response_idle_timeout_secs = 6;
    l.call_timeout_secs = 8;
    let table = table(&[R::new("a", up.url("/mcp"), &[("p", "t")])], &l);
    let handle = TableHandle::new();
    handle.set(Some(table));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let proxy = Proxy::new(l, handle, Arc::new(SystemResolver))
        .with_sink(sink, sigil_proxy::inventory::CursorHasher::new().unwrap());
    let (stop, rx) = tokio::sync::oneshot::channel();
    let join = tokio::spawn(proxy.serve(listener, None, async {
        let _ = rx.await;
    }));
    (addr, stop, join)
}
fn raw_post(
    addr: std::net::SocketAddr,
    path: &str,
    token: &str,
    extra: &[(&str, &str)],
    body: &[u8],
) -> Vec<u8> {
    let mut s=format!("POST {path} HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer {token}\r\nConnection: close\r\nContent-Length: {}\r\n",body.len());
    for (k, v) in extra {
        s += &format!("{k}: {v}\r\n");
    }
    s += "\r\n";
    let mut b = s.into_bytes();
    b.extend_from_slice(body);
    b
}
#[tokio::test]
async fn shutdown_grace_aborts_a_delayed_start_before_any_upstream_dispatch() {
    let up = Up::start(|_| full(200, "application/json", b"{}")).await;
    let sink = Arc::new(ShutdownSink {
        delay_ping: true,
        ..Default::default()
    });
    let (addr, stop, join) = serve_with_sink(&up, sink.clone()).await;
    let init = send_raw(
        addr,
        &raw_post(addr, "/mcp/a", "t", &[], initialize_body("1").as_bytes()),
    )
    .await;
    let sid = init.header("mcp-session-id").unwrap().to_string();
    let req = raw_post(
        addr,
        "/mcp/a",
        "t",
        &[
            ("mcp-session-id", &sid),
            ("mcp-protocol-version", "2025-11-25"),
        ],
        PING,
    );
    let call = tokio::spawn(async move { send_raw(addr, &req).await });
    tokio::time::timeout(Duration::from_secs(2), sink.entered.notified())
        .await
        .unwrap();
    let _ = stop.send(());
    let outcome = tokio::time::timeout(Duration::from_secs(2), join)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(outcome, sigil_proxy::lifecycle::DrainOutcome::GraceExpired);
    assert_eq!(up.count(), 0);
    let completed = sink.completed.lock().unwrap();
    assert_eq!(
        completed
            .iter()
            .filter(|c| c.method == sigil_proxy::mcp::observation::Method::Ping)
            .count(),
        1
    );
    assert_eq!(
        completed
            .iter()
            .find(|c| c.method == sigil_proxy::mcp::observation::Method::Ping)
            .unwrap()
            .delivery,
        sigil_proxy::mcp::observation::Delivery::NotSent
    );
    drop(call);
}
#[tokio::test]
async fn shutdown_grace_aborts_a_live_upstream_wait_and_closes_observation() {
    let up = Up::start(|_| Reply::Hang).await;
    let sink = Arc::new(ShutdownSink::default());
    let (addr, stop, join) = serve_with_sink(&up, sink.clone()).await;
    let init = send_raw(
        addr,
        &raw_post(addr, "/mcp/a", "t", &[], initialize_body("1").as_bytes()),
    )
    .await;
    let sid = init.header("mcp-session-id").unwrap().to_string();
    let req = raw_post(
        addr,
        "/mcp/a",
        "t",
        &[
            ("mcp-session-id", &sid),
            ("mcp-protocol-version", "2025-11-25"),
        ],
        PING,
    );
    let call = tokio::spawn(async move { send_raw(addr, &req).await });
    tokio::time::timeout(Duration::from_secs(2), async {
        while up.count() == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await
        }
    })
    .await
    .unwrap();
    let _ = stop.send(());
    let outcome = tokio::time::timeout(Duration::from_secs(2), join)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(outcome, sigil_proxy::lifecycle::DrainOutcome::GraceExpired);
    let completed = sink.completed.lock().unwrap();
    assert_eq!(
        completed
            .iter()
            .filter(|c| c.method == sigil_proxy::mcp::observation::Method::Ping)
            .count(),
        1
    );
    assert_eq!(
        completed
            .iter()
            .find(|c| c.method == sigil_proxy::mcp::observation::Method::Ping)
            .unwrap()
            .delivery,
        sigil_proxy::mcp::observation::Delivery::Unknown
    );
    drop(call);
}
