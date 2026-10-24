#![cfg(unix)]
//! Byte relay (D-01 relay-first) and the M3 header rules, with an in-process
//! hyper upstream. AC-01 (relay), AC-07 (SSE semantics preserved), AC-04/AC-08
//! (header rows), PX-009 (credential injection and secrecy).

mod common;

/// A valid JSON-RPC request (T-12b1 refuses bodies that are not).
const PING: &[u8] = br#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#;
use bytes::Bytes;
use common::*;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

/// A request body with unknown fields, odd whitespace, escapes, a duplicate key
/// and trailing whitespace: nothing may be normalised on the way. It is still
/// valid JSON-RPC (T-12b1 refuses anything else before dispatch).
fn awkward_request() -> Vec<u8> {
    let mut b = br#"{ "jsonrpc" : "2.0","id":7 ,"method":"tools/call","params":{"name":"x","arguments":{"k":"UESC00e9\\n","k":2},"_meta":{"progressToken":"t"}},"zzz_unknown":[1,2,3]}"#.to_vec();
    b = String::from_utf8(b)
        .unwrap()
        .replace("UESC", "\\u")
        .into_bytes();
    b.extend_from_slice(b"\n\n");
    b
}

fn awkward_response() -> Vec<u8> {
    let mut b = br#"{"jsonrpc":"2.0","id":7,"result":{"content":[{"type":"text","text":"hUESC00e9llo"}],"isError":false,"future_field":{"a":null}}}"#.to_vec();
    b = String::from_utf8(b)
        .unwrap()
        .replace("UESC", "\\u")
        .into_bytes();
    b.extend_from_slice(b"  \r\n\xff\xfe");
    b
}

/// AC-01 / D-01: JSON request and response bytes are identical end to end.
#[tokio::test]
async fn json_round_trip_is_byte_identical() {
    let resp = awkward_response();
    let r2 = resp.clone();
    let up = Up::start(move |_| full(200, "application/json", &r2)).await;
    let px = simple(&up, limits()).await;
    let req = awkward_request();
    let r = px
        .post(
            "/mcp/a",
            Some("tok-a"),
            &[
                ("Content-Type", "application/json"),
                ("Accept", "application/json, text/event-stream"),
            ],
            &req,
        )
        .await;
    assert_eq!(r.status, 200);
    assert_eq!(
        up.last().body,
        req,
        "request bytes reached upstream unchanged"
    );
    assert_eq!(
        r.body(),
        resp,
        "response bytes reached the client unchanged"
    );
    assert_eq!(r.header("content-type"), Some("application/json"));
    assert_eq!(up.last().header("content-type"), Some("application/json"));
    assert_eq!(
        up.last().header("accept"),
        Some("application/json, text/event-stream")
    );
}

/// AC-01: a chunked request is forwarded with the same body bytes.
#[tokio::test]
async fn chunked_request_body_is_identical() {
    let up = ok_upstream().await;
    let px = simple(&up, limits()).await;
    let body = awkward_request();
    let lines = px.session_lines("/mcp/a", "tok-a").await;
    let mut raw = format!(
        "POST /mcp/a HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nAuthorization: Bearer tok-a\r\n{lines}Transfer-Encoding: chunked\r\n\r\n",
        px.addr
    )
    .into_bytes();
    for part in body.chunks(17) {
        raw.extend_from_slice(format!("{:x}\r\n", part.len()).as_bytes());
        raw.extend_from_slice(part);
        raw.extend_from_slice(b"\r\n");
    }
    raw.extend_from_slice(b"0\r\n\r\n");
    let r = px.send(&raw).await;
    assert_eq!(r.status, 200);
    assert_eq!(up.last().body, body);
    assert!(!up.last().has("transfer-encoding") || up.last().header("content-length").is_none());
}

/// Statuses other than auth, redirects and session-ending 404 preserve bodies.
#[tokio::test]
async fn upstream_statuses_pass_through() {
    for (status, body) in [
        (202u16, &b""[..]),
        (400, b"{\"e\":1}"),
        (404, b"x"),
        (500, b"boom"),
        (503, b""),
    ] {
        let b = body.to_vec();
        let up = Up::start(move |_| full(status, "application/json", &b)).await;
        let px = simple(&up, limits()).await;
        let r = px.post("/mcp/a", Some("tok-a"), &[], PING).await;
        assert_eq!(r.status, status);
        assert_eq!(r.body(), if status == 404 { &b""[..] } else { body });
    }
}

/// AC-07: SSE is forwarded incrementally with chunk boundaries preserved. The
/// first event must reach the client while upstream is still holding the stream
/// open, which a buffering proxy cannot do.
#[tokio::test]
async fn sse_is_flushed_incrementally_and_boundaries_survive() {
    let (tx, reply) = sse_stream();
    let slot = std::sync::Mutex::new(Some(reply));
    let up = Up::start(move |_| slot.lock().unwrap().take().expect("one call")).await;
    let px = simple(&up, limits()).await;
    let sid = px.session("/mcp/a", "tok-a").await.unwrap();

    let mut s = TcpStream::connect(px.addr).await.unwrap();
    s.write_all(&px.request(
        "POST",
        "/mcp/a",
        Some("tok-a"),
        &[
            ("Accept", "application/json, text/event-stream"),
            ("Mcp-Session-Id", &sid),
            ("MCP-Protocol-Version", "2025-11-25"),
        ],
        PING,
    ))
    .await
    .unwrap();
    let mut buf = Vec::new();

    let chunks: Vec<&[u8]> = vec![
        b"id: 1\r\nevent: message\r\ndata: {\"n\":1}\r\n\r\n",
        b"data: {\"n\":2,\"split\":\"par",
        b"t\"}\n\n",
        b": comment\n\ndata: [3]\r\r",
    ];
    // event 1 arrives while upstream is open and has not sent anything else
    tx.send(Bytes::from_static(chunks[0])).await.unwrap();
    assert!(
        read_until(
            &mut s,
            &mut buf,
            b"{\"n\":1}\r\n\r\n",
            Duration::from_secs(5)
        )
        .await,
        "first event was not forwarded while the stream was still open"
    );
    for c in &chunks[1..] {
        tx.send(Bytes::from_static(c)).await.unwrap();
        tokio::time::sleep(Duration::from_millis(80)).await;
    }
    drop(tx);
    assert!(read_until(&mut s, &mut buf, b"0\r\n\r\n", Duration::from_secs(5)).await);

    let r = parse_response(buf);
    assert_eq!(r.status, 200);
    assert_eq!(r.header("content-type"), Some("text/event-stream"));
    let (got, complete) = r.chunks();
    assert!(complete);
    assert_eq!(got.concat(), chunks.concat(), "stream bytes identical");
    assert_eq!(
        got,
        chunks.iter().map(|c| c.to_vec()).collect::<Vec<_>>(),
        "chunk boundaries preserved"
    );
}

/// PX-015: upstream closing without a response is a fixed 502 and the proxy
/// sends the request exactly once (no retry).
#[tokio::test]
async fn failed_exchange_is_not_retried() {
    let up = Up::start(|_| Reply::Drop).await;
    let px = simple(&up, limits()).await;
    let r = px.post("/mcp/a", Some("tok-a"), &[], PING).await;
    assert_eq!(r.status, 502);
    assert_eq!(r.text(), "{\"error\":\"upstream_unavailable\"}");
    assert_eq!(up.count(), 1);
    // one connection for the initialize, one for the call: never a second try
    assert_eq!(up.conns(), 2);
}

// ------------------------------------------------------------ M3: request rows

/// Send `headers` downstream and return what the upstream saw.
async fn seen_with(headers: &[(&str, &str)]) -> Seen {
    let up = ok_upstream().await;
    let px = simple(&up, limits()).await;
    let r = px.post("/mcp/a", Some("tok-a"), headers, PING).await;
    assert_eq!(r.status, 200);
    up.last()
}

macro_rules! stripped {
    ($name:ident, $header:expr) => {
        /// M3 request row (PX-008/009/014, AC-04/AC-08): not forwarded upstream.
        #[tokio::test]
        async fn $name() {
            let s = seen_with(&[($header, "downstream-value")]).await;
            assert!(
                !s.has(&$header.to_ascii_lowercase()),
                "{} leaked: {:?}",
                $header,
                s.headers
            );
        }
    };
}
stripped!(request_cookie_is_stripped, "Cookie");
stripped!(
    request_proxy_authorization_is_stripped,
    "Proxy-Authorization"
);
stripped!(
    request_proxy_auth_header_x_sigil_is_stripped,
    "X-Sigil-Auth"
);
stripped!(request_forwarded_is_stripped, "Forwarded");
stripped!(request_x_forwarded_for_is_stripped, "X-Forwarded-For");
stripped!(request_x_forwarded_proto_is_stripped, "X-Forwarded-Proto");
stripped!(request_x_real_ip_is_stripped, "X-Real-IP");
stripped!(request_via_is_stripped, "Via");
stripped!(request_keep_alive_is_stripped, "Keep-Alive");
stripped!(request_te_is_stripped, "TE");
stripped!(request_upgrade_is_stripped, "Upgrade");
stripped!(request_last_event_id_is_stripped, "Last-Event-ID");

/// T-12b2 / M3: the proxy's own session id (a valid one) never reaches a
/// stateless upstream, and no upstream id is invented for it.
#[tokio::test]
async fn request_mcp_session_id_is_stripped() {
    let up = ok_upstream().await;
    let px = simple(&up, limits()).await;
    let sid = px.session("/mcp/a", "tok-a").await.unwrap();
    let r = px.post("/mcp/a", Some("tok-a"), &[], PING).await;
    assert_eq!(r.status, 200);
    let s = up.last();
    assert!(!s.has("mcp-session-id"));
    assert!(!s.headers.iter().any(|(_, v)| v.contains(&sid)));
}

/// M3 request row: the downstream Authorization is replaced by the route's
/// upstream credential, exactly one Authorization header, never the downstream
/// token (PX-009).
#[tokio::test]
async fn request_authorization_is_replaced_by_the_route_credential() {
    let s = seen_with(&[]).await;
    let auths: Vec<_> = s
        .headers
        .iter()
        .filter(|(k, _)| k == "authorization")
        .collect();
    assert_eq!(auths.len(), 1);
    assert_eq!(auths[0].1, format!("Bearer {UPSTREAM_SECRET}"));
    assert!(!s.headers.iter().any(|(_, v)| v.contains("tok-a")));
}

/// M3 request row: Origin is checked, not forwarded.
#[tokio::test]
async fn request_origin_is_not_forwarded() {
    let up = ok_upstream().await;
    let l = limits();
    let t = table(
        &[R::new("a", up.url("/up"), &[("pa", "tok-a")]).origins(&["https://app.example.com"])],
        &l,
    );
    let px = Px::start(Some(t), l).await;
    let r = px
        .post(
            "/mcp/a",
            Some("tok-a"),
            &[("Origin", "https://app.example.com")],
            PING,
        )
        .await;
    assert_eq!(r.status, 200);
    assert!(!up.last().has("origin"));
}

/// M3 request row: User-Agent is replaced by a fixed proxy value.
#[tokio::test]
async fn request_user_agent_is_fixed() {
    let s = seen_with(&[("User-Agent", "claude-code/9.9 (secret-build)")]).await;
    let ua = s.header("user-agent").unwrap();
    assert!(ua.starts_with("sigil-proxy/"), "{ua}");
    assert!(!ua.contains("claude"));
    let s = seen_with(&[]).await;
    assert!(s.header("user-agent").unwrap().starts_with("sigil-proxy/"));
}

/// M3 request row: hop-by-hop headers, including those named by Connection.
#[tokio::test]
async fn request_connection_named_headers_are_stripped() {
    let s = seen_with(&[
        ("Connection", "x-hop-secret, keep-alive"),
        ("X-Hop-Secret", "1"),
        ("X-Keep", "1"),
    ])
    .await;
    assert!(!s.has("x-hop-secret"));
    assert!(s.has("x-keep"));
}

/// M3 request row: Host is the upstream authority, never the proxy's.
#[tokio::test]
async fn request_host_is_the_upstream_authority() {
    let up = ok_upstream().await;
    let px = simple(&up, limits()).await;
    px.post("/mcp/a", Some("tok-a"), &[], PING).await;
    assert_eq!(
        up.last().header("host"),
        Some(format!("127.0.0.1:{}", up.addr.port()).as_str())
    );
}

/// Protocol headers the proxy has no business changing are passed through.
#[tokio::test]
async fn request_protocol_headers_pass_through() {
    let s = seen_with(&[
        ("MCP-Protocol-Version", "2025-11-25"),
        ("Content-Type", "application/json"),
        ("X-Custom", "keep"),
    ])
    .await;
    assert_eq!(s.header("mcp-protocol-version"), Some("2025-11-25"));
    assert_eq!(s.header("content-type"), Some("application/json"));
    assert_eq!(s.header("x-custom"), Some("keep"));
}

// ----------------------------------------------------------- M3: response rows

async fn response_with(h: (&str, &str)) -> Raw {
    let (k, v) = (h.0.to_string(), h.1.to_string());
    let up = Up::start(move |_| Reply::Full {
        status: 200,
        headers: vec![
            ("content-type".into(), "application/json".into()),
            (k.clone(), v.clone()),
        ],
        body: b"{}".to_vec(),
    })
    .await;
    let px = simple(&up, limits()).await;
    px.post("/mcp/a", Some("tok-a"), &[], PING).await
}

macro_rules! dropped {
    ($name:ident, $header:expr, $value:expr) => {
        /// M3 response row (M-4 allowlist): not forwarded downstream.
        #[tokio::test]
        async fn $name() {
            let r = response_with(($header, $value)).await;
            assert_eq!(r.status, 200);
            assert!(!r.has($header), "{} leaked: {:?}", $header, r.headers);
        }
    };
}
dropped!(
    response_www_authenticate_is_dropped,
    "WWW-Authenticate",
    "Bearer realm=\"up\""
);
dropped!(response_set_cookie_is_dropped, "Set-Cookie", "sid=1");
dropped!(response_set_cookie2_is_dropped, "Set-Cookie2", "sid=1");
dropped!(
    response_proxy_authenticate_is_dropped,
    "Proxy-Authenticate",
    "Basic"
);
dropped!(
    response_access_control_is_dropped,
    "Access-Control-Allow-Origin",
    "*"
);
dropped!(
    response_content_location_is_dropped,
    "Content-Location",
    "/x"
);
dropped!(response_refresh_is_dropped, "Refresh", "0;url=http://evil/");
dropped!(response_alt_svc_is_dropped, "Alt-Svc", "h3=\":443\"");
dropped!(response_link_is_dropped, "Link", "</x>; rel=preload");
dropped!(
    response_mcp_session_id_is_dropped,
    "Mcp-Session-Id",
    "upstream-sid"
);
dropped!(
    response_hsts_is_dropped,
    "Strict-Transport-Security",
    "max-age=1"
);
dropped!(
    response_unlisted_header_is_dropped,
    "X-Upstream-Internal",
    "10.0.0.7"
);
dropped!(response_server_header_is_dropped, "Server", "internal/1.2");

macro_rules! kept {
    ($name:ident, $header:expr, $value:expr) => {
        /// M3 response row (M-4 allowlist): forwarded unchanged.
        #[tokio::test]
        async fn $name() {
            let r = response_with(($header, $value)).await;
            assert_eq!(r.header($header), Some($value), "{:?}", r.headers);
        }
    };
}
kept!(
    response_content_encoding_is_kept,
    "Content-Encoding",
    "identity"
);
kept!(response_vary_is_kept, "Vary", "Accept-Encoding");
kept!(response_cache_control_is_kept, "Cache-Control", "no-store");

/// M3: the proxy sets its own security header on relayed and fixed responses.
#[tokio::test]
async fn proxy_sets_nosniff() {
    let r = response_with(("X-Whatever", "1")).await;
    assert_eq!(r.header("x-content-type-options"), Some("nosniff"));
}

/// M3 / control-plane 5.4: an upstream 401 or 403 becomes HTTP 200 with a
/// fixed JSON-RPC -32603 error that echoes only the request id. Nothing from
/// upstream (status, headers, body) reaches the client, and never a 401.
#[tokio::test]
async fn upstream_401_403_map_to_a_fixed_error() {
    for status in [401u16, 403] {
        let up = Up::start(move |_| Reply::Full {
            status,
            headers: vec![
                (
                    "www-authenticate".into(),
                    "Bearer realm=\"up\", error=\"invalid_token\"".into(),
                ),
                ("set-cookie".into(), "a=b".into()),
                ("content-type".into(), "text/plain".into()),
            ],
            body: b"upstream says: your key sk-123 is bad".to_vec(),
        })
        .await;
        let px = simple(&up, limits()).await;
        for id in ["7", "\"abc\""] {
            let body = format!(
                r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"t","arguments":{{"canary":"CANARY-XYZ"}}}}}}"#
            );
            let r = px.post("/mcp/a", Some("tok-a"), &[], body.as_bytes()).await;
            assert_eq!(r.status, 200, "upstream {status}");
            assert_eq!(r.header("content-type"), Some("application/json"));
            assert!(!r.has("www-authenticate") && !r.has("set-cookie"));
            let v: serde_json::Value = serde_json::from_slice(&r.body()).unwrap();
            assert_eq!(v["jsonrpc"], "2.0");
            assert_eq!(
                v["id"],
                serde_json::from_str::<serde_json::Value>(id).unwrap()
            );
            assert_eq!(v["error"]["code"], -32603);
            assert_eq!(
                v["error"]["message"],
                sigil_proxy::server::UPSTREAM_REJECTED_MESSAGE
            );
            assert!(v["error"].get("data").is_none());
            assert_eq!(v.as_object().unwrap().len(), 3, "{v}");
            let text = r.text();
            assert!(!text.contains("sk-123") && !text.contains("CANARY"));
        }
        // a notification has no id to answer: fixed 502, still nothing from upstream
        let r = px
            .post(
                "/mcp/a",
                Some("tok-a"),
                &[],
                br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            )
            .await;
        assert_eq!(r.status, 502);
        assert_eq!(r.text(), "{\"error\":\"upstream_rejected\"}");
        assert!(!r.has("www-authenticate"));
    }
}

/// PX-014 / control-plane 5.3: a redirect is neither followed nor relayed, and
/// the credential is therefore never sent to the Location.
#[tokio::test]
async fn redirects_are_not_followed_or_relayed() {
    let target = ok_upstream().await;
    let loc = target.url("/stolen");
    for status in [301u16, 302, 303, 307, 308] {
        let loc = loc.clone();
        let up = Up::start(move |_| Reply::Full {
            status,
            headers: vec![("location".into(), loc.clone())],
            body: vec![],
        })
        .await;
        let px = simple(&up, limits()).await;
        let r = px.post("/mcp/a", Some("tok-a"), &[], PING).await;
        assert_eq!(r.status, 502, "{status}");
        assert!(!r.has("location"));
        assert_eq!(up.count(), 1);
    }
    assert_eq!(target.conns(), 0, "the Location target was never contacted");
}

/// L5: the JSON-RPC id is echoed exactly as written (large integers, floats,
/// escapes), not re-serialised through a number type.
#[tokio::test]
async fn upstream_rejection_echoes_the_id_verbatim() {
    let up = Up::start(|_| full(401, "text/plain", b"no")).await;
    let px = simple(&up, limits()).await;
    for id in [
        "12345678901234567890123456789",
        "-9223372036854775809",
        "1.0e5",
        "0",
        r#""a\u00e9\n/b""#,
        r#""""#,
    ] {
        let body = format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/list"}}"#);
        let r = px.post("/mcp/a", Some("tok-a"), &[], body.as_bytes()).await;
        assert_eq!(r.status, 200, "{id}");
        assert!(
            r.text().contains(&format!(r#""id":{id},"error""#)),
            "{id} not echoed verbatim: {}",
            r.text()
        );
    }
    // not string/number, duplicate key, batch, not JSON: since T-12b1 the proxy
    // refuses these itself with a 400 before dispatch, so upstream is never asked
    // (and its 401 cannot be mapped).
    let before = up.count();
    for body in [
        r#"{"jsonrpc":"2.0","id":null,"method":"x"}"#,
        r#"{"jsonrpc":"2.0","id":{"a":1},"method":"x"}"#,
        r#"{"jsonrpc":"2.0","id":1,"id":2,"method":"x"}"#,
        r#"[{"jsonrpc":"2.0","id":1,"method":"x"}]"#,
        "not json",
    ] {
        let r = px.post("/mcp/a", Some("tok-a"), &[], body.as_bytes()).await;
        assert_eq!(r.status, 400, "{body}");
    }
    assert_eq!(up.count(), before);
}

/// L5: `Expect` is not forwarded (the proxy buffers the body and answers the
/// client's 100-continue itself) and the call still succeeds.
#[tokio::test]
async fn request_expect_is_stripped() {
    let up = ok_upstream().await;
    let px = simple(&up, limits()).await;
    let r = px
        .post("/mcp/a", Some("tok-a"), &[("Expect", "100-continue")], PING)
        .await;
    assert_eq!(r.status, 200);
    assert!(!up.last().has("expect"), "{:?}", up.last().headers);
    assert_eq!(up.last().body, PING);
}
