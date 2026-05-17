//! Bearer token authentication. The token is loaded once at server start from
//! the `SIGIL_SERVER_READ_TOKEN` env var; an unset/empty value disables every
//! read route (handler returns 404 instead of 401 to avoid leaking that read
//! routes exist).

use axum::body::Body;
use axum::http::{header, HeaderMap, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

/// Configured token. `None` ⇒ read API disabled (every protected route 404s).
#[derive(Clone, Debug)]
pub struct ReadToken(pub Option<String>);

impl ReadToken {
    /// Load from `SIGIL_SERVER_READ_TOKEN`. Trims whitespace; empty ⇒ None.
    pub fn from_env() -> Self {
        match std::env::var("SIGIL_SERVER_READ_TOKEN") {
            Ok(s) => {
                let t = s.trim().to_string();
                if t.is_empty() {
                    ReadToken(None)
                } else {
                    ReadToken(Some(t))
                }
            }
            Err(_) => ReadToken(None),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.0.is_some()
    }
}

/// Constant-time byte compare to dodge timing side channels on token equality.
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Extract the bearer token from an `Authorization: Bearer ...` header.
pub(crate) fn extract_bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(str::trim)
}

/// Middleware. Mount on every read route EXCEPT `/v1/healthz`.
/// - Token unset on server ⇒ 404 (hide read API existence).
/// - Header missing / wrong scheme / wrong token ⇒ 401.
/// - OK ⇒ pass through.
pub async fn require_bearer(
    axum::extract::State(token): axum::extract::State<ReadToken>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let configured = match &token.0 {
        Some(t) => t.as_bytes(),
        None => return not_found_response(),
    };
    let presented = match extract_bearer(req.headers()) {
        Some(t) => t.as_bytes(),
        None => return unauthorized_response(),
    };
    if ct_eq(configured, presented) {
        next.run(req).await
    } else {
        unauthorized_response()
    }
}

fn unauthorized_response() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({"error": {"code": "unauthorized", "message": "missing or invalid bearer token"}})),
    )
        .into_response()
}

fn not_found_response() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(json!({"error": {"code": "not_found", "message": "endpoint not found"}})),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn ct_eq_basic() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"abcd"));
        assert!(ct_eq(b"", b""));
    }

    #[test]
    fn read_token_from_env_unset_is_none() {
        std::env::remove_var("SIGIL_SERVER_READ_TOKEN");
        let t = ReadToken::from_env();
        assert!(!t.is_enabled());
    }

    #[test]
    fn read_token_from_env_trims_and_rejects_empty() {
        std::env::set_var("SIGIL_SERVER_READ_TOKEN", "   ");
        let t = ReadToken::from_env();
        assert!(!t.is_enabled());
        std::env::set_var("SIGIL_SERVER_READ_TOKEN", "  abc  ");
        let t = ReadToken::from_env();
        assert_eq!(t.0.as_deref(), Some("abc"));
        std::env::remove_var("SIGIL_SERVER_READ_TOKEN");
    }

    #[test]
    fn extract_bearer_basic() {
        let mut h = HeaderMap::new();
        h.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer hello"),
        );
        assert_eq!(extract_bearer(&h), Some("hello"));
        h.insert(header::AUTHORIZATION, HeaderValue::from_static("Basic xxx"));
        assert_eq!(extract_bearer(&h), None);
    }
}
