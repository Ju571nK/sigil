#![cfg(unix)]
//! Downstream auth, routing, Origin and method tests (T-12 slice A).
//! AC coverage is noted per test: AC-04 (isolation, no oracle), AC-08 (Origin,
//! fixed upstream), AC-01 (the happy path relays).

mod common;
use common::*;

const BODY: &[u8] = br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;
const UNAUTH: &str = "{\"error\":\"unauthorized\"}";

fn assert_unauthorized(r: &Raw) {
    assert_eq!(r.status, 401, "{r:?}");
    // bare scheme only: no realm / error / error_description
    assert_eq!(r.header("www-authenticate"), Some("Bearer"));
    assert_eq!(r.text(), UNAUTH);
}

/// PX-008 / AC-04: with no applied table every request is 401 and upstream is
/// never contacted, for known-looking, unknown and malformed paths alike.
#[tokio::test]
async fn no_table_is_401_for_everything() {
    let up = ok_upstream().await;
    let px = Px::start(None, limits()).await;
    for path in ["/mcp/a", "/mcp/zzz"] {
        assert_unauthorized(&px.post(path, Some("tok-a"), &[], BODY).await);
    }
    // a path outside the route shape cannot name a route; it is 404 either way
    assert_eq!(px.post("/", Some("tok-a"), &[], BODY).await.status, 404);
    assert_eq!(up.conns(), 0);
}

/// PX-008 / AC-04: a table with no principal (or principals without any
/// verifier) answers 401 to everything, including unknown routes.
#[tokio::test]
async fn table_without_verifiers_is_401() {
    let up = ok_upstream().await;
    let l = limits();
    let t = table(&[R::new("a", up.url("/up"), &[])], &l);
    assert!(!t.has_verifier());
    let px = Px::start(Some(t), l).await;
    assert_unauthorized(&px.post("/mcp/a", Some("tok-a"), &[], BODY).await);
    assert_unauthorized(&px.post("/mcp/nope", Some("tok-a"), &[], BODY).await);
    assert_eq!(up.conns(), 0);
}

/// PX-008 / AC-04: every malformed or wrong credential is the same 401 with a
/// fixed body, and nothing reaches upstream.
#[tokio::test]
async fn bad_credentials_are_401() {
    let up = ok_upstream().await;
    let px = simple(&up, limits()).await;
    // A live session, so the right token reaches upstream.
    let sid = px.session("/mcp/a", "tok-a").await.unwrap();
    let base = up.conns();
    let mk = |auth: &[&str]| {
        let mut extra = vec![
            ("Mcp-Session-Id", sid.as_str()),
            ("MCP-Protocol-Version", "2025-11-25"),
        ];
        for a in auth {
            extra.push(("Authorization", *a));
        }
        px.request("POST", "/mcp/a", None, &extra, BODY)
    };
    for case in [
        vec![],
        vec!["Bearer wrong"],
        vec!["Bearer"],
        vec!["Bearer "],
        vec!["Basic dG9rLWE6"],
        vec!["tok-a"],
        vec!["Bearer tok-a extra"],
        vec!["Bearer tok-a", "Bearer tok-a"],
        vec!["Bearer TOK-A"],
    ] {
        assert_unauthorized(&px.send(&mk(&case)).await);
    }
    assert_eq!(up.conns(), base);
    // the right token relays (scheme is case-insensitive)
    for ok in ["Bearer tok-a", "bearer tok-a", "BEARER tok-a"] {
        let r = px.send(&mk(&[ok])).await;
        assert_eq!(r.status, 200, "{ok}");
    }
    assert_eq!(up.count(), 3);
}

/// AC-04 / PX-008: a token is valid only on the routes of its own principal.
/// Route A's token on route B is 401 and route B's upstream is never contacted.
#[tokio::test]
async fn principals_cannot_cross_routes() {
    let (ua, ub) = (ok_upstream().await, ok_upstream().await);
    let l = limits();
    let t = table(
        &[
            R::new("a", ua.url("/up"), &[("pa", "tok-a")]),
            R::new("b", ub.url("/up"), &[("pb", "tok-b")]),
        ],
        &l,
    );
    let px = Px::start(Some(t), l).await;
    assert_eq!(
        px.post("/mcp/a", Some("tok-a"), &[], BODY).await.status,
        200
    );
    assert_eq!(
        px.post("/mcp/b", Some("tok-b"), &[], BODY).await.status,
        200
    );
    assert_unauthorized(&px.post("/mcp/b", Some("tok-a"), &[], BODY).await);
    assert_unauthorized(&px.post("/mcp/a", Some("tok-b"), &[], BODY).await);
    assert_eq!((ua.count(), ub.count()), (1, 1));
}

/// PX-008: several principals on one route each authenticate with their own
/// token, and a second verifier (overlap rotation) works too.
#[tokio::test]
async fn several_principals_on_one_route() {
    let up = ok_upstream().await;
    let l = limits();
    let t = table(
        &[R::new(
            "a",
            up.url("/up"),
            &[("p1", "tok-1"), ("p2", "tok-2")],
        )],
        &l,
    );
    let px = Px::start(Some(t), l).await;
    assert_eq!(
        px.post("/mcp/a", Some("tok-1"), &[], BODY).await.status,
        200
    );
    assert_eq!(
        px.post("/mcp/a", Some("tok-2"), &[], BODY).await.status,
        200
    );
    assert_unauthorized(&px.post("/mcp/a", Some("tok-3"), &[], BODY).await);
}

/// PX-002: a path that is not shaped `/mcp/{id}` is a fixed 404.
#[tokio::test]
async fn paths_outside_the_route_shape_are_404() {
    let up = ok_upstream().await;
    let px = simple(&up, limits()).await;
    for path in [
        "/mcp/",
        "/mcp",
        "/mcp/a/extra",
        "/mcp/a%2fb",
        "/other",
        "/",
        "/MCP/a",
    ] {
        let r = px.post(path, Some("tok-a"), &[], BODY).await;
        assert_eq!(r.status, 404, "{path}");
        assert_eq!(r.text(), "{\"error\":\"not_found\"}", "{path}");
    }
    assert_eq!(up.conns(), 0);
}

/// L1 / AC-04 (no oracle): an unknown route id answers exactly like a failed
/// authentication on a known route: same status, headers (except Date) and body.
#[tokio::test]
async fn unknown_route_is_indistinguishable_from_auth_failure() {
    let up = ok_upstream().await;
    let px = simple(&up, limits()).await;
    let norm = |r: &Raw| {
        let mut h: Vec<_> = r
            .headers
            .iter()
            .filter(|(k, _)| !k.eq_ignore_ascii_case("date"))
            .cloned()
            .collect();
        h.sort();
        (r.status, h, r.body())
    };
    let known_bad = norm(&px.post("/mcp/a", Some("wrong"), &[], BODY).await);
    assert_eq!(known_bad.0, 401);
    for token in [Some("tok-a"), Some("wrong"), None] {
        let r = px.post("/mcp/zzz", token, &[], BODY).await;
        assert_unauthorized(&r);
        assert_eq!(norm(&r), known_bad, "token {token:?}");
    }
    let known_missing = norm(&px.post("/mcp/a", None, &[], BODY).await);
    assert_eq!(
        norm(&px.post("/mcp/zzz", None, &[], BODY).await),
        known_missing
    );
    assert_eq!(up.conns(), 0);
}

/// PX-014 / AC-08: Origin present and not allowed is 403 with no upstream
/// contact; allowed (after normalization) relays and the Origin is not
/// forwarded; absent is allowed.
#[tokio::test]
async fn origin_check() {
    let up = ok_upstream().await;
    let l = limits();
    let t = table(
        &[R::new("a", up.url("/up"), &[("pa", "tok-a")])
            .origins(&["https://app.example.com", "http://localhost:3000"])],
        &l,
    );
    let px = Px::start(Some(t), l).await;
    // allowed, in different spellings that normalize to the same origin
    for o in [
        "https://app.example.com",
        "HTTPS://APP.example.com:443",
        "http://localhost:3000",
    ] {
        let r = px
            .post("/mcp/a", Some("tok-a"), &[("Origin", o)], BODY)
            .await;
        assert_eq!(r.status, 200, "{o}");
    }
    assert!(!up.last().has("origin"), "Origin must not be forwarded");
    // absent: allowed for non-browser bearer clients
    assert_eq!(
        px.post("/mcp/a", Some("tok-a"), &[], BODY).await.status,
        200
    );
    let before = up.count();
    for o in [
        "https://evil.example.com",
        "http://app.example.com",
        "https://app.example.com.evil.com",
        "https://app.example.com:8443",
        "null",
        "",
        "not a url",
        "https://app.example.com/path",
        "http://localhost:3001",
    ] {
        let r = px
            .post("/mcp/a", Some("tok-a"), &[("Origin", o)], BODY)
            .await;
        assert_eq!(r.status, 403, "{o:?}");
        assert_eq!(r.text(), "{\"error\":\"forbidden\"}");
    }
    // two Origin headers are refused
    let r = px
        .post(
            "/mcp/a",
            Some("tok-a"),
            &[
                ("Origin", "https://app.example.com"),
                ("Origin", "https://app.example.com"),
            ],
            BODY,
        )
        .await;
    assert_eq!(r.status, 403);
    assert_eq!(up.count(), before, "upstream untouched by refused origins");
}

/// PX-014: a route with an empty allowlist rejects every present Origin.
#[tokio::test]
async fn empty_origin_list_rejects_any_origin() {
    let up = ok_upstream().await;
    let px = simple(&up, limits()).await;
    let r = px
        .post_bare(
            "/mcp/a",
            Some("tok-a"),
            &[("Origin", "https://app.example.com")],
            BODY,
        )
        .await;
    assert_eq!(r.status, 403);
    assert_eq!(up.conns(), 0);
}

/// Authentication comes before the Origin check: a bad token with a bad Origin
/// is 401 (the allowlist is not an oracle for unauthenticated callers).
#[tokio::test]
async fn auth_is_checked_before_origin() {
    let up = ok_upstream().await;
    let px = simple(&up, limits()).await;
    let r = px
        .post(
            "/mcp/a",
            Some("nope"),
            &[("Origin", "https://evil.example.com")],
            BODY,
        )
        .await;
    assert_unauthorized(&r);
}

/// Host check on a loopback listener (DNS rebinding): a foreign Host is 403.
#[tokio::test]
async fn foreign_host_is_rejected_on_loopback() {
    let up = ok_upstream().await;
    let px = simple(&up, limits()).await;
    let port = px.addr.port();
    for host in [
        "evil.example.com",
        "evil.example.com:80",
        &format!("evil.example.com:{port}"),
        &format!("127.0.0.1:{}", port + 1),
    ] {
        let req = format!(
            "POST /mcp/a HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nAuthorization: Bearer tok-a\r\nContent-Length: 40\r\n\r\n{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}}"
        );
        let r = px.send(req.as_bytes()).await;
        assert_eq!(r.status, 403, "{host}");
    }
    let lines = px.session_lines("/mcp/a", "tok-a").await;
    for host in [
        format!("localhost:{port}"),
        format!("127.0.0.1:{port}"),
        format!("[::1]:{port}"),
    ] {
        let req = format!(
            "POST /mcp/a HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nAuthorization: Bearer tok-a\r\n{lines}Content-Length: 40\r\n\r\n{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}}"
        );
        assert_eq!(px.send(req.as_bytes()).await.status, 200, "{host}");
    }
    assert_eq!(up.count(), 3);
}

/// PX-002 / decisions "GET SSE": after auth GET (and every method but POST and
/// DELETE) is a fixed 405 with no upstream contact, `Last-Event-ID` or not;
/// unauthenticated is still 401. A DELETE without a session is 400.
#[tokio::test]
async fn non_post_methods_are_405_after_auth() {
    let up = ok_upstream().await;
    let px = simple(&up, limits()).await;
    let r = px
        .send(&px.request("DELETE", "/mcp/a", Some("tok-a"), &[], b""))
        .await;
    assert_eq!((r.status, r.body().len()), (400, 0));
    assert_eq!(
        px.send(&px.request("DELETE", "/mcp/a", None, &[], b""))
            .await
            .status,
        401
    );
    for (m, extra) in [
        ("GET", vec![("Accept", "text/event-stream")]),
        (
            "GET",
            vec![("Accept", "text/event-stream"), ("Last-Event-ID", "1")],
        ),
        ("PUT", vec![]),
        ("PATCH", vec![]),
        ("HEAD", vec![]),
        ("OPTIONS", vec![]),
    ] {
        let r = px
            .send(&px.request(m, "/mcp/a", Some("tok-a"), &extra, b""))
            .await;
        assert_eq!(r.status, 405, "{m}");
        assert_eq!(r.header("allow"), Some("POST, DELETE"), "{m}");
        if m != "HEAD" {
            assert_eq!(r.text(), "{\"error\":\"method_not_allowed\"}", "{m}");
        }
        // without a credential the method is not even looked at
        let r = px.send(&px.request(m, "/mcp/a", None, &[], b"")).await;
        assert_eq!(r.status, 401, "{m} unauthenticated");
    }
    assert_eq!(up.conns(), 0);
}

/// AC-08: the request cannot choose the upstream. The path, query, absolute-form
/// URI and `Host`/`X-*` headers are all ignored; upstream sees only the route's
/// configured path.
#[tokio::test]
async fn request_cannot_name_the_upstream() {
    let up = ok_upstream().await;
    let other = ok_upstream().await;
    let px = simple(&up, limits()).await;
    let r = px
        .post(
            "/mcp/a?target=http://evil.example.com/&upstream=127.0.0.1",
            Some("tok-a"),
            &[
                ("X-Upstream", &other.url("/x")),
                ("X-Forwarded-Host", "evil.example.com"),
            ],
            BODY,
        )
        .await;
    assert_eq!(r.status, 200);
    assert_eq!(up.last().target, "/up", "query dropped, route path used");
    assert_eq!(
        up.last().header("host"),
        Some(format!("127.0.0.1:{}", up.addr.port()).as_str())
    );
    // absolute-form request target naming another authority
    let lines = px.session_lines("/mcp/a", "tok-a").await;
    let req = format!(
        "POST http://{}/mcp/a HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nAuthorization: Bearer tok-a\r\n{lines}Content-Length: 40\r\n\r\n{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}}",
        other.addr, px.addr
    );
    assert_eq!(px.send(req.as_bytes()).await.status, 200);
    assert_eq!(
        other.conns(),
        0,
        "a request-supplied authority is never contacted"
    );
    assert_eq!(up.count(), 2);
}

/// PX-013: shutdown stops accepting and returns `Drained` when idle.
#[tokio::test]
async fn idle_shutdown_drains() {
    let up = ok_upstream().await;
    let mut px = simple(&up, limits()).await;
    assert_eq!(
        px.post("/mcp/a", Some("tok-a"), &[], BODY).await.status,
        200
    );
    assert_eq!(
        px.stop().await,
        sigil_proxy::lifecycle::DrainOutcome::Drained
    );
}

/// Table swap: installing a table after start makes routes live; clearing it
/// returns to 401 (the seam for the config-apply slice).
#[tokio::test]
async fn table_handle_swaps_atomically() {
    let up = ok_upstream().await;
    let l = limits();
    let px = Px::start(None, l.clone()).await;
    assert_unauthorized(&px.post("/mcp/a", Some("tok-a"), &[], BODY).await);
    px.handle.set(Some(table(
        &[R::new("a", up.url("/up"), &[("pa", "tok-a")])],
        &l,
    )));
    assert_eq!(
        px.post("/mcp/a", Some("tok-a"), &[], BODY).await.status,
        200
    );
    px.handle.set(None);
    assert_unauthorized(&px.post("/mcp/a", Some("tok-a"), &[], BODY).await);
}
