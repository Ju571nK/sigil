#![cfg(unix)]
//! Destination protection (PX-014, AC-08): the RESOLVED address is checked,
//! the connection goes to a checked address, DNS is resolved once per request.

mod common;

/// A valid JSON-RPC request (T-12b1 refuses bodies that are not).
const PING: &[u8] = br#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#;
/// An `initialize`: the one POST that needs no session, so it reaches the
/// destination step on its own (T-12b2).
const INIT: &[u8] = br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}"#;
use common::*;
use std::net::IpAddr;

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

/// A route whose upstream NAME is `localhost:<port>` (a loopback host name, so
/// the http origin is valid at table build) served at `up`.
async fn named_route(up: &Up, answers: Vec<Vec<IpAddr>>) -> Px {
    let l = limits();
    let t = table(
        &[R::new(
            "a",
            format!("http://localhost:{}/up", up.addr.port()),
            &[("pa", "tok-a")],
        )],
        &l,
    );
    Px::start_with(Some(t), l, StaticResolver::sequence(answers)).await
}

/// AC-08: a name that resolves to loopback relays (and the connection really
/// goes to the resolved address).
#[tokio::test]
async fn name_resolving_to_loopback_relays() {
    let up = ok_upstream().await;
    let px = named_route(&up, vec![vec![ip("127.0.0.1")]]).await;
    let r = px.post("/mcp/a", Some("tok-a"), &[], PING).await;
    assert_eq!(r.status, 200);
    assert_eq!(up.count(), 1);
    assert_eq!(
        up.last().header("host"),
        Some(format!("localhost:{}", up.addr.port()).as_str())
    );
}

/// AC-08: an http upstream whose name resolves to a non-loopback address is
/// refused before any connection (the fixture listens on loopback, so a leaked
/// connect would be visible as `conns() == 1` if the policy were bypassed).
#[tokio::test]
async fn http_name_resolving_to_non_loopback_is_refused() {
    let up = ok_upstream().await;
    for bad in [
        "10.0.0.5",
        "192.0.2.1",
        "169.254.169.254",
        "fd00:ec2::254",
        "fe80::1",
        "0.0.0.0",
        "::ffff:10.0.0.5",
    ] {
        let px = named_route(&up, vec![vec![ip(bad)]]).await;
        let r = px.post_bare("/mcp/a", Some("tok-a"), &[], INIT).await;
        assert_eq!(r.status, 502, "{bad}");
        assert_eq!(r.text(), "{\"error\":\"destination_refused\"}", "{bad}");
        // the refusal reason (address class) is not disclosed to the client
        assert!(!r.text().contains("169") && !r.text().contains("link"));
    }
    // one bad address in an otherwise loopback answer refuses the whole answer
    let px = named_route(&up, vec![vec![ip("127.0.0.1"), ip("10.0.0.5")]]).await;
    assert_eq!(
        px.post_bare("/mcp/a", Some("tok-a"), &[], INIT)
            .await
            .status,
        502
    );
    assert_eq!(up.conns(), 0, "no connection was attempted");
}

/// AC-08 (DNS rebinding): the answer is checked on every request and the
/// connection uses the checked answer. A name that flips from loopback to
/// private between two requests is allowed once and refused after; and with a
/// first answer of {private} then {loopback}, the first request is refused
/// (the later, benign answer cannot rescue it, and is not used for it).
#[tokio::test]
async fn rebinding_is_checked_per_request() {
    let up = ok_upstream().await;
    let px = named_route(&up, vec![vec![ip("127.0.0.1")], vec![ip("10.0.0.5")]]).await;
    assert_eq!(
        px.post_bare("/mcp/a", Some("tok-a"), &[], INIT)
            .await
            .status,
        200
    );
    assert_eq!(
        px.post_bare("/mcp/a", Some("tok-a"), &[], INIT)
            .await
            .status,
        502
    );
    assert_eq!(up.conns(), 1);

    let up = ok_upstream().await;
    let px = named_route(&up, vec![vec![ip("10.0.0.5")], vec![ip("127.0.0.1")]]).await;
    assert_eq!(
        px.post_bare("/mcp/a", Some("tok-a"), &[], INIT)
            .await
            .status,
        502
    );
    assert_eq!(up.conns(), 0);
    assert_eq!(
        px.post_bare("/mcp/a", Some("tok-a"), &[], INIT)
            .await
            .status,
        200
    );
}

/// A name that does not resolve is a fixed 502, no connection.
#[tokio::test]
async fn unresolvable_name_is_502() {
    let up = ok_upstream().await;
    let px = named_route(&up, vec![vec![]]).await;
    let r = px.post_bare("/mcp/a", Some("tok-a"), &[], INIT).await;
    assert_eq!(r.status, 502);
    assert_eq!(r.text(), "{\"error\":\"upstream_unresolved\"}");
    assert_eq!(up.conns(), 0);
}

/// PX-014 / control-plane 5.5 N-1: the credential binds to its origin at table
/// build; a route on another origin cannot be paired with it.
#[test]
fn credential_origin_mismatch_fails_the_build() {
    let dir = tempfile::tempdir().unwrap();
    use std::os::unix::fs::PermissionsExt;
    let secret = dir.path().join("s");
    std::fs::write(&secret, "S\n").unwrap();
    std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600)).unwrap();
    let creds = std::collections::BTreeMap::from([(
        "up".to_string(),
        sigil_proxy::bootstrap::Credential {
            secret_file: secret,
            upstream_origins: vec!["http://127.0.0.1:9000".into()],
        },
    )]);
    let mk = |url: &str| sigil_proxy::route::RouteSpec {
        route_id: sigil_proxy_api::Id::new("a").unwrap(),
        upstream_url: url.into(),
        credential_ref: "up".into(),
        principals: vec![],
        allowed_origins: vec![],
        allow_private_destination: false,
        limits: Default::default(),
        scope: None,
    };
    let l = limits();
    assert!(
        sigil_proxy::route::RouteTable::build(&[mk("http://127.0.0.1:9000/x")], &creds, &l).is_ok()
    );
    for bad in [
        "http://127.0.0.1:9001/x",
        "http://localhost:9000/x",
        "http://127.0.0.2:9000/x",
    ] {
        let e = sigil_proxy::route::RouteTable::build(&[mk(bad)], &creds, &l).unwrap_err();
        assert!(
            matches!(e, sigil_proxy::route::RouteError::CredentialOrigin { .. }),
            "{bad}: {e}"
        );
    }
    // plain http to a non-loopback host is not a valid origin at all
    let e = sigil_proxy::route::RouteTable::build(&[mk("http://10.0.0.5:9000/x")], &creds, &l)
        .unwrap_err();
    assert!(
        matches!(e, sigil_proxy::route::RouteError::UpstreamUrl { .. }),
        "{e}"
    );
}

/// A loopback literal upstream needs no resolver (an IP literal skips DNS).
#[tokio::test]
async fn ip_literal_skips_dns() {
    let up = ok_upstream().await;
    let l = limits();
    let t = table(&[R::new("a", up.url("/up"), &[("pa", "tok-a")])], &l);
    // a resolver that would refuse everything proves it is not consulted
    let px = Px::start_with(
        Some(t),
        l,
        StaticResolver::sequence(vec![vec![ip("10.0.0.5")]]),
    )
    .await;
    assert_eq!(
        px.post("/mcp/a", Some("tok-a"), &[], PING).await.status,
        200
    );
}

/// M2: a resolver that never answers is bounded by the connect timeout: fixed
/// 504, no upstream contact.
#[tokio::test]
async fn hanging_resolver_is_a_504() {
    let up = ok_upstream().await;
    let mut l = limits();
    l.connect_timeout_secs = 1;
    let t = table(
        &[R::new(
            "a",
            format!("http://localhost:{}/up", up.addr.port()),
            &[("pa", "tok-a")],
        )],
        &l,
    );
    let px = Px::start_with(Some(t), l, std::sync::Arc::new(HangResolver)).await;
    let start = std::time::Instant::now();
    let r = px.post_bare("/mcp/a", Some("tok-a"), &[], INIT).await;
    assert_eq!(r.status, 504);
    assert_eq!(r.text(), "{\"error\":\"upstream_timeout\"}");
    assert!(start.elapsed() < std::time::Duration::from_secs(5));
    assert_eq!(up.conns(), 0);
}
