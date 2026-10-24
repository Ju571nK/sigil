//! M3 header policy (control-plane.md §5.3, decisions.md D-01 follow-up "M3
//! header 정책"). Request direction is a strip list; response direction is an
//! ALLOWLIST (M-4). Both are pure functions so each row has its own test.

use http::header::{self, HeaderMap, HeaderName, HeaderValue};

/// Fixed `User-Agent` sent upstream.
pub fn proxy_user_agent() -> HeaderValue {
    HeaderValue::from_str(&format!("sigil-proxy/{}", env!("CARGO_PKG_VERSION")))
        .expect("static user agent")
}

/// Hop-by-hop headers (RFC 9110 7.6.1) that are never forwarded.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Exact request headers dropped before forwarding.
const REQUEST_STRIP: &[&str] = &[
    // downstream credentials (verified, then removed)
    "authorization",
    "cookie",
    "proxy-authorization",
    "proxy-authenticate",
    // Origin is checked, not forwarded (PX-014)
    "origin",
    // rewritten to the upstream authority
    "host",
    // the proxy answers the client's 100-continue itself and buffers the body
    "expect",
    // length is recomputed from the buffered body
    "content-length",
    // proxy-added forwarding metadata is not synthesised and inbound is removed
    "forwarded",
    "x-real-ip",
    "via",
    "user-agent", // replaced by a fixed value
    // Session ids are issued by the proxy and bound 1:1 to (principal, route,
    // upstream session) (T-12b2): the downstream id never crosses over; the
    // bound upstream id is set by [`set_upstream_session`].
    "mcp-session-id",
    // P1 has no stream resumption (GET is 405): never let an upstream replay
    // across proxy-bound sessions.
    "last-event-id",
];

/// Response headers forwarded from upstream (control-plane.md §5.3 M-4).
/// `Content-Length` is forwarded; chunked framing is set by hyper.
const RESPONSE_ALLOW: &[&str] = &[
    "content-type",
    "content-encoding",
    "vary",
    "content-length",
    "cache-control",
    "date",
];

fn is_proxy_header(name: &str) -> bool {
    // Any proxy-defined auth header (`x-sigil-*`) and `x-forwarded-*`.
    name.starts_with("x-sigil-") || name.starts_with("x-forwarded-")
}

/// Build the header map sent upstream.
///
/// `upstream_authorization` is the route's injected credential; `host` is the
/// upstream authority. Headers named by the downstream `Connection` header are
/// removed as well.
pub fn upstream_request_headers(
    src: &HeaderMap,
    upstream_authorization: &HeaderValue,
    host: &str,
) -> Result<HeaderMap, header::InvalidHeaderValue> {
    let mut named_by_connection: Vec<HeaderName> = Vec::new();
    for v in src.get_all(header::CONNECTION) {
        if let Ok(s) = v.to_str() {
            for tok in s.split(',') {
                if let Ok(n) = HeaderName::from_bytes(tok.trim().as_bytes()) {
                    named_by_connection.push(n);
                }
            }
        }
    }
    let mut out = HeaderMap::new();
    for (k, v) in src {
        let n = k.as_str();
        if HOP_BY_HOP.contains(&n)
            || REQUEST_STRIP.contains(&n)
            || is_proxy_header(n)
            || named_by_connection.contains(k)
        {
            continue;
        }
        out.append(k.clone(), v.clone());
    }
    out.insert(header::USER_AGENT, proxy_user_agent());
    out.insert(header::HOST, HeaderValue::from_str(host)?);
    out.insert(header::AUTHORIZATION, upstream_authorization.clone());
    Ok(out)
}

/// Put the bound upstream session id (if the upstream issued one) on a request
/// built by [`upstream_request_headers`]. Only the proxy's stored value is ever
/// sent; the client's own `Mcp-Session-Id` was stripped.
pub fn set_upstream_session(h: &mut HeaderMap, upstream: Option<&HeaderValue>) {
    h.remove("mcp-session-id");
    if let Some(v) = upstream {
        h.insert(HeaderName::from_static("mcp-session-id"), v.clone());
    }
}

/// Keep only the allowlisted upstream response headers, then add the proxy's
/// own security header.
pub fn downstream_response_headers(src: &HeaderMap) -> HeaderMap {
    let mut out = HeaderMap::new();
    for (k, v) in src {
        if RESPONSE_ALLOW.contains(&k.as_str()) {
            out.append(k.clone(), v.clone());
        }
    }
    out.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth() -> HeaderValue {
        HeaderValue::from_static("Bearer UP")
    }

    fn hm(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut m = HeaderMap::new();
        for (k, v) in pairs {
            m.append(
                HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        m
    }

    /// T-12b2: the client's session id never reaches upstream; only the bound
    /// upstream id does, and a stateless upstream gets none.
    #[test]
    fn upstream_session_replaces_the_client_one() {
        let src = hm(&[("mcp-session-id", "PROXY-ID"), ("last-event-id", "7")]);
        let mut out = upstream_request_headers(&src, &auth(), "h").unwrap();
        set_upstream_session(&mut out, Some(&HeaderValue::from_static("UP-ID")));
        assert_eq!(out.get_all("mcp-session-id").iter().count(), 1);
        assert_eq!(out["mcp-session-id"], "UP-ID");
        assert!(!out.contains_key("last-event-id"));
        let mut out = upstream_request_headers(&src, &auth(), "h").unwrap();
        set_upstream_session(&mut out, None);
        assert!(!out.contains_key("mcp-session-id"));
    }

    /// M3 request rows: each stripped header, one assertion per row.
    #[test]
    fn request_strip_rows() {
        for name in [
            "cookie",
            "expect",
            "proxy-authorization",
            "proxy-authenticate",
            "origin",
            "forwarded",
            "x-forwarded-for",
            "x-forwarded-host",
            "x-forwarded-proto",
            "x-real-ip",
            "via",
            "x-sigil-auth",
            "mcp-session-id",
            "last-event-id",
            "keep-alive",
            "te",
            "trailer",
            "upgrade",
            "proxy-connection",
            "transfer-encoding",
        ] {
            let out =
                upstream_request_headers(&hm(&[(name, "downstream")]), &auth(), "up:1").unwrap();
            assert!(!out.contains_key(name), "{name} must not be forwarded");
        }
    }

    #[test]
    fn request_downstream_authorization_is_replaced() {
        let out =
            upstream_request_headers(&hm(&[("authorization", "Bearer D")]), &auth(), "h").unwrap();
        assert_eq!(out.get_all("authorization").iter().count(), 1);
        assert_eq!(out["authorization"], "Bearer UP");
    }

    #[test]
    fn request_injects_credential_host_and_user_agent() {
        let out = upstream_request_headers(
            &hm(&[
                ("authorization", "Bearer DOWNSTREAM"),
                ("user-agent", "claude-code/9"),
                ("host", "proxy.local:8480"),
            ]),
            &auth(),
            "up.example:8443",
        )
        .unwrap();
        assert_eq!(out.get_all("authorization").iter().count(), 1);
        assert_eq!(out["authorization"], "Bearer UP");
        assert_eq!(out["host"], "up.example:8443");
        assert_eq!(out["user-agent"], proxy_user_agent());
    }

    #[test]
    fn request_connection_listed_headers_are_removed() {
        let out = upstream_request_headers(
            &hm(&[
                ("connection", "x-hop, close"),
                ("x-hop", "1"),
                ("x-keep", "1"),
            ]),
            &auth(),
            "h",
        )
        .unwrap();
        assert!(!out.contains_key("x-hop") && !out.contains_key("connection"));
        assert!(out.contains_key("x-keep"));
    }

    #[test]
    fn request_passes_protocol_headers_unchanged() {
        let out = upstream_request_headers(
            &hm(&[
                ("content-type", "application/json"),
                ("accept", "application/json, text/event-stream"),
                ("mcp-protocol-version", "2025-11-25"),
                ("accept-encoding", "gzip"),
            ]),
            &auth(),
            "h",
        )
        .unwrap();
        assert_eq!(out["content-type"], "application/json");
        assert_eq!(out["accept"], "application/json, text/event-stream");
        assert_eq!(out["mcp-protocol-version"], "2025-11-25");
        assert_eq!(out["accept-encoding"], "gzip");
    }

    /// M-4: response allowlist. Everything named in the contract's drop list
    /// plus an unlisted custom header is removed.
    #[test]
    fn response_is_an_allowlist() {
        let src = hm(&[
            ("content-type", "text/event-stream"),
            ("content-encoding", "gzip"),
            ("vary", "Accept-Encoding"),
            ("content-length", "12"),
            ("cache-control", "no-cache"),
            ("date", "Sun, 11 Oct 2026 00:00:00 GMT"),
            ("www-authenticate", "Bearer realm=up"),
            ("set-cookie", "a=b"),
            ("set-cookie2", "a=b"),
            ("proxy-authenticate", "x"),
            ("access-control-allow-origin", "*"),
            ("content-location", "/x"),
            ("location", "http://elsewhere/"),
            ("refresh", "0;url=/"),
            ("alt-svc", "h3=\":443\""),
            ("link", "</x>; rel=preload"),
            ("mcp-session-id", "upstream-sid"),
            ("strict-transport-security", "max-age=1"),
            ("x-custom", "1"),
            ("server", "upstream/1"),
        ]);
        let out = downstream_response_headers(&src);
        for kept in [
            "content-type",
            "content-encoding",
            "vary",
            "content-length",
            "cache-control",
            "date",
        ] {
            assert!(out.contains_key(kept), "{kept} must be kept");
        }
        for dropped in [
            "www-authenticate",
            "set-cookie",
            "set-cookie2",
            "proxy-authenticate",
            "access-control-allow-origin",
            "content-location",
            "location",
            "refresh",
            "alt-svc",
            "link",
            "mcp-session-id",
            "strict-transport-security",
            "x-custom",
            "server",
        ] {
            assert!(!out.contains_key(dropped), "{dropped} must be dropped");
        }
        assert_eq!(out["x-content-type-options"], "nosniff");
    }
}
