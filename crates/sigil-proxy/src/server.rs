//! Downstream listener and byte relay (T-12 slice A, #258).
//!
//! Request order (first failing step answers; nothing reaches upstream before
//! the last step):
//!
//! 1. path `/mcp/{route_id}` shape            -> 404
//! 2. `Host` check on loopback listeners      -> 403 (DNS rebinding)
//! 3. no applied table / no verifier at all   -> 401
//! 4. unknown route                           -> 404
//! 5. bearer verification on that route       -> 401
//! 6. `Origin` check                          -> 403
//! 7. method: POST relays, DELETE ends a session (below), anything else
//!    (GET included: no stream, no resumption) -> 405
//! 8. `Mcp-Session-Id` (T-12b2): duplicate     -> 400 empty;
//!    unknown, foreign principal/route, ended, rebound -> the same 404 empty
//! 9. admission (total, route, principal)     -> 429 (queue depth 0)
//! 10. bounded request body                   -> 413
//! 11. classify the JSON-RPC message (`mcp`). B1 modern markers are refused
//!     first (400 empty, audited) with or without a session. Then:
//!     - `initialize` carrying a session id -> 400 empty, no invocation;
//!     - a full session table -> 429, no invocation;
//!     - anything else without a session -> 400 empty, no invocation;
//!     - in a session, `MCP-Protocol-Version` absent or a known legacy value
//!       -> 400 empty (audited, m5);
//!     - other refusals -> 400 / 200 fixed, audited;
//!     - 202 for a held or pre-dispatch cancel
//! 12. start observation: LOCAL durable start -> 503 if the sink refuses
//! 13. resolve + destination check, connect   -> 502 / 504
//! 14. cancel check, then dispatch (the bound upstream session id, never the
//!     client's, goes upstream)
//! 15. relay; response streamed through the metered body, which classifies
//!     the outcome for the observation seam. An `initialize` answer is held
//!     (bounded) and judged first (README N12): only a supported one creates
//!     a session and gets the proxy's `Mcp-Session-Id`. An upstream 404 for a
//!     bound upstream session ends the proxy session (empty 404).
//!
//! DELETE: steps 1-8, then the session's upstream DELETE is sent once (no
//! retry): 2xx/404 end the session, anything else keeps it and the status is
//! passed on. A session of a stateless upstream ends locally with 204. No
//! invocation is recorded for session handling.
//!
//! The forwarded request body and the response bytes are never re-encoded
//! (D-01 relay-first). No MCP SDK type is on this path.

use std::convert::Infallible;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use http::header::{self, HeaderValue};
use http::{Method, Request, Response, StatusCode};
use http_body::Body as _;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::server::graceful::GracefulShutdown;
use sigil_proxy_api::Id;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::Instant;

use crate::body::{BodyMode, MeteredBody, Permits};
use crate::bootstrap::{is_loopback, is_loopback_host, normalize_origin};
use crate::dest::{resolve_checked, DestError, Resolver};
use crate::headers::{downstream_response_headers, set_upstream_session, upstream_request_headers};
use crate::inventory::CursorHasher;
use crate::lifecycle::{drain, DrainOutcome};
use crate::limits::Limits;
use crate::mcp::cancel::{CancelKey, CancelOutcome, CancelRegistry, CancelScope};
use crate::mcp::classify::{self, HeaderVersion, Message, NotificationInfo, Refusal, RefusalKind};
use crate::mcp::initialize::{InitGate, InitVerdict};
use crate::mcp::observation::{
    AuditContext, CallRef, CancelDisposition, CancelObserved, Cause, Delivery, Method as McpMethod,
    NoopSink, Observation, ObservationSink, Outcome, RequestRefused, RequestStarted, StartVerdict,
    ToolField,
};
use crate::mcp::response::{CallCtx, CaptureLimits, Resolution, ResponseTracker};
use crate::route::{Route, RouteTable, TableHandle};
use crate::route_health::{Mark, RouteHealth};
use crate::session::{
    ActiveCall, Presented, Reservation, SessionLimits, SessionTable, UpstreamSessionId,
};
use crate::tls;
use sigil_proxy_api::status::{RouteReason, RouteState};

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub type RespBody = BoxBody<Bytes, BoxError>;

/// JSON-RPC message for an upstream 401/403 (control-plane.md §5.4).
// OPEN: the fixed text is not defined anywhere in the contract (control-plane
// open question 3). This wording is a placeholder.
pub const UPSTREAM_REJECTED_MESSAGE: &str = "upstream request failed";

/// Default idle limit for a client that has connected but not finished its
/// headers (slowloris). Also bounds a TLS handshake.
// OPEN: not in the D-04 table; a fixed value so a stalled client cannot hold a
// connection open forever.
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Open connections allowed per unit of `max_concurrent_calls`. A connection
/// (including one still in its TLS handshake) holds a slot, so idle or
/// handshaking sockets cannot exhaust file descriptors.
// OPEN: the factor 4 is a review-chosen value, not a D-04 number.
const CONNECTIONS_PER_CALL: usize = 4;

// OPEN: D-04 per-call (4 MiB/s) and process (32 MiB/s) response bandwidth are
// NOT enforced in this slice; no backpressure shaping exists yet.

/// Never matches a real token; only used to spend the same hashing work as a
/// real verification when the route is unknown.
const DUMMY_VERIFIER: &str = "0000000000000000000000000000000000000000000000000000000000000000";

// OPEN: the route path shape `/mcp/{route_id}` is a candidate (task T-12a).
const ROUTE_PREFIX: &str = "/mcp/";

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

#[derive(Clone, Copy)]
enum HostPolicy {
    /// Loopback listener: `Host` must be a loopback name or literal with this
    /// port. A `Host` without a port is read as port 80, so it matches only a
    /// listener bound to 80.
    // OPEN: caveat: behind a port mapping (container `-p 9000:8480`, SSH or
    // reverse-proxy forwarding) the client's `Host` port differs from the bound
    // port and is refused with 403. Use a matching port or a non-loopback
    // listener (TLS) for such setups.
    Loopback {
        port: u16,
    },
    // OPEN: for a non-loopback listener the bootstrap holds no host names, so
    // no Host check is made (control-plane.md §5.3 "Host ... recommended").
    Any,
}

struct Shared {
    limits: Limits,
    table: TableHandle,
    resolver: Arc<dyn Resolver>,
    total: Arc<Semaphore>,
    host: HostPolicy,
    header_read_timeout: Duration,
    sink: Arc<dyn ObservationSink>,
    cursor_hasher: CursorHasher,
    cancel: Arc<CancelRegistry>,
    sessions: Arc<SessionTable>,
    health: RouteHealth,
    /// Relay-local call numbers (not invocation ids).
    seq: AtomicU64,
    #[cfg(unix)]
    upstream_tls: tls::Connector,
}

pub struct Proxy {
    limits: Limits,
    table: TableHandle,
    resolver: Arc<dyn Resolver>,
    header_read_timeout: Duration,
    sink: Arc<dyn ObservationSink>,
    cursor_hasher: CursorHasher,
    cancel: Arc<CancelRegistry>,
    sessions: Arc<SessionTable>,
    health: RouteHealth,
}

impl Proxy {
    pub fn new(limits: Limits, table: TableHandle, resolver: Arc<dyn Resolver>) -> Proxy {
        Proxy {
            header_read_timeout: HEADER_READ_TIMEOUT,
            // No producer until T-13: nothing is observed and behaviour is
            // exactly the plain relay.
            sink: Arc::new(NoopSink),
            // Only used when a sink observes; a producer installs the process's
            // own hasher with `with_cursor_hasher`.
            cursor_hasher: CursorHasher::new().unwrap_or_else(|_| CursorHasher::from_key([0; 32])),
            cancel: Arc::new(CancelRegistry::default()),
            sessions: Arc::new(SessionTable::new(SessionLimits::from_limits(&limits))),
            health: RouteHealth::new(table.clone()),
            limits,
            table,
            resolver,
        }
    }

    /// The proxy's session table (its size, for status and tests).
    pub fn session_table(&self) -> Arc<SessionTable> {
        self.sessions.clone()
    }

    /// The runtime route health the relay marks; the status report reads it.
    pub fn route_health(&self) -> RouteHealth {
        self.health.clone()
    }

    /// Use `health` (shared with the status report) instead of a private one.
    pub fn with_route_health(mut self, health: RouteHealth) -> Proxy {
        self.health = health;
        self
    }

    /// Install the consumer of observations (T-13) together with the hasher that
    /// tags `tools/list` request cursors for it. The hasher must be the one the
    /// sink uses for a page's `nextCursor` (clone the producer's), or a
    /// continuation can never be matched; taking both here means a sink cannot
    /// be installed with a mismatched or default hasher. The default observes
    /// nothing.
    pub fn with_sink(mut self, sink: Arc<dyn ObservationSink>, hasher: CursorHasher) -> Proxy {
        self.sink = sink;
        self.cursor_hasher = hasher;
        self
    }

    /// The cancel registry, for its counters (`unmatched_total`).
    pub fn cancel_registry(&self) -> Arc<CancelRegistry> {
        self.cancel.clone()
    }

    /// Override the header-read (and TLS handshake) timeout; used by tests.
    pub fn with_header_read_timeout(mut self, d: Duration) -> Proxy {
        self.header_read_timeout = d;
        self
    }

    /// Accept until shutdown, then join every connection task within the grace
    /// and abort and join any that remain before stopping observation producers.
    pub async fn serve(
        self,
        listener: TcpListener,
        acceptor: Option<tls::Acceptor>,
        shutdown: impl Future<Output = ()>,
    ) -> io::Result<DrainOutcome> {
        let local = listener.local_addr()?;
        let grace = Duration::from_secs(self.limits.shutdown_grace_secs);
        // A session's end closes its inventory chains and drops its held cancels.
        {
            let (sink, cancel) = (self.sink.clone(), self.cancel.clone());
            self.sessions.set_end_hook(Arc::new(move |n| {
                sink.session_ended(n);
                cancel.drop_session(n);
            }));
        }
        let sessions = self.sessions.clone();
        let shared = Arc::new(Shared {
            total: Arc::new(Semaphore::new(self.limits.max_concurrent_calls as usize)),
            host: if is_loopback(local.ip()) {
                HostPolicy::Loopback { port: local.port() }
            } else {
                HostPolicy::Any
            },
            header_read_timeout: self.header_read_timeout,
            sink: self.sink,
            cursor_hasher: self.cursor_hasher,
            cancel: self.cancel,
            sessions: self.sessions,
            health: self.health,
            seq: AtomicU64::new(1),
            limits: self.limits,
            table: self.table,
            resolver: self.resolver,
            #[cfg(unix)]
            upstream_tls: tls::upstream_connector(),
        });
        let graceful = GracefulShutdown::new();
        let mut connections = tokio::task::JoinSet::new();
        let conn_slots = Arc::new(Semaphore::new(
            (shared.limits.max_concurrent_calls as usize).saturating_mul(CONNECTIONS_PER_CALL),
        ));
        let acceptor = acceptor.map(Arc::new);
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                _ = &mut shutdown => break,
                Some(_) = connections.join_next(), if !connections.is_empty() => {},
                accepted = listener.accept() => {
                    let (sock, _) = match accepted {
                        Ok(a) => a,
                        Err(e) => {
                            tracing::warn!(error = %e, "accept failed");
                            tokio::time::sleep(Duration::from_millis(50)).await;
                            continue;
                        }
                    };
                    // Connection cap: refuse at accept, before any bytes are read.
                    let Ok(slot) = conn_slots.clone().try_acquire_owned() else {
                        drop(sock);
                        continue;
                    };
                    let _ = sock.set_nodelay(true);
                    let shared = shared.clone();
                    match &acceptor {
                        None => {
                            let conn = graceful.watcher().watch(connection(sock, shared));
                            connections.spawn(async move {
                                let _ = conn.await;
                                drop(slot);
                            });
                        }
                        Some(a) => {
                            let a = a.clone();
                            // The handshake runs inside the tracked task so a slow
                            // TLS client cannot stall the accept loop and is joined
                            // or aborted with established connections.
                            let watch = graceful.watcher();
                            connections.spawn(async move {
                                handshake_and_serve(a, sock, shared, watch).await;
                                drop(slot);
                            });
                        }
                    }
                }
            }
        }
        drop(listener);
        let outcome = drain(grace, async {
            let _ = graceful.shutdown().await;
            while connections.join_next().await.is_some() {}
        })
        .await;
        if outcome == DrainOutcome::GraceExpired {
            connections.abort_all();
        }
        while connections.join_next().await.is_some() {}
        // Sessions do not outlive the relay (their inventory chains end now).
        sessions.end_all();
        Ok(outcome)
    }
}

type Watcher = hyper_util::server::graceful::Watcher;

async fn handshake_and_serve(
    a: Arc<tls::Acceptor>,
    sock: TcpStream,
    shared: Arc<Shared>,
    watch: Watcher,
) {
    #[cfg(unix)]
    {
        match tokio::time::timeout(shared.header_read_timeout, a.accept(sock)).await {
            Ok(Ok(tls_stream)) => {
                let conn = connection(tls_stream, shared);
                let _ = watch.watch(conn).await;
            }
            _ => tracing::debug!("tls handshake failed"),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (a, sock, shared, watch);
    }
}

fn connection<I>(
    io: I,
    shared: Arc<Shared>,
) -> impl hyper_util::server::graceful::GracefulConnection
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let max_buf = (shared.limits.max_header_bytes as usize).max(8192);
    let timeout = shared.header_read_timeout;
    let svc = service_fn(move |req| handle(req, shared.clone()));
    hyper::server::conn::http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(timeout)
        .max_buf_size(max_buf)
        .serve_connection(TokioIo::new(io), svc)
}

// ---------------------------------------------------------------- responses

fn fixed(status: StatusCode, code: &'static str) -> Response<RespBody> {
    let body = format!("{{\"error\":\"{code}\"}}");
    let mut r = Response::new(boxed_full(Bytes::from(body)));
    *r.status_mut() = status;
    let h = r.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    r
}

fn boxed_full(b: Bytes) -> RespBody {
    Full::new(b).map_err(|never| match never {}).boxed()
}

fn unauthorized() -> Response<RespBody> {
    let mut r = fixed(StatusCode::UNAUTHORIZED, "unauthorized");
    // Bare scheme only: no realm, error or error_description (control-plane §5.1).
    r.headers_mut()
        .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    r
}

// ------------------------------------------------------------------ helpers

fn route_id_from_path(path: &str) -> Option<&str> {
    let id = path.strip_prefix(ROUTE_PREFIX)?;
    Id::new(id).ok()?;
    Some(id)
}

fn host_allowed(policy: HostPolicy, req: &http::request::Parts) -> bool {
    let HostPolicy::Loopback { port } = policy else {
        return true;
    };
    let mut hosts = req.headers.get_all(header::HOST).iter();
    let (Some(h), None) = (hosts.next(), hosts.next()) else {
        return false;
    };
    let Ok(h) = h.to_str() else { return false };
    let Ok((host, p)) = crate::bootstrap::split_host_port(&h.to_ascii_lowercase()) else {
        return false;
    };
    let p = p.unwrap_or(80);
    p == port && is_loopback_host(&host)
}

fn bearer_token(h: &http::HeaderMap) -> Option<&str> {
    let mut it = h.get_all(header::AUTHORIZATION).iter();
    let (Some(v), None) = (it.next(), it.next()) else {
        return None;
    };
    let s = v.to_str().ok()?;
    let (scheme, token) = s.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer")
        || token.is_empty()
        || token.len() > 4096
        || token.bytes().any(|b| b <= b' ')
    {
        return None;
    }
    Some(token)
}

fn origin_ok(route: &Route, h: &http::HeaderMap) -> bool {
    let mut it = h.get_all(header::ORIGIN).iter();
    let Some(v) = it.next() else {
        // Absent is allowed: non-browser bearer clients send none
        // (control-plane.md §5.3, "absent-allowed recommended").
        return true;
    };
    if it.next().is_some() {
        return false;
    }
    v.to_str()
        .ok()
        .and_then(|s| normalize_origin(s).ok())
        .is_some_and(|o| route.origin_allowed(&o))
}

fn content_length(h: &http::HeaderMap) -> Option<u64> {
    h.get(header::CONTENT_LENGTH)?.to_str().ok()?.parse().ok()
}

fn is_sse(h: &http::HeaderMap) -> bool {
    h.get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            v.trim_start()
                .get(..17)
                .is_some_and(|p| p.eq_ignore_ascii_case("text/event-stream"))
        })
}

/// The request's JSON-RPC `id` exactly as written (string or number), from the
/// parse COPY only. Kept as raw JSON so large integers and escapes are echoed
/// verbatim. A duplicate `id` key, a non-object body (batch) or any other type
/// gives `None`.
fn request_id(body: &[u8]) -> Option<Box<serde_json::value::RawValue>> {
    #[derive(serde::Deserialize)]
    struct Probe {
        id: Option<Box<serde_json::value::RawValue>>,
    }
    let id = serde_json::from_slice::<Probe>(body).ok()?.id?;
    match id.get().as_bytes().first()? {
        b'"' | b'-' | b'0'..=b'9' => Some(id),
        _ => None,
    }
}

/// control-plane.md §5.4: HTTP 200 JSON-RPC -32603, fixed message, no data,
/// nothing echoed but the request id. Without an id (a notification or an
/// unparsable body) a JSON-RPC reply is not possible, so a fixed 502 is sent.
// OPEN: the no-id case is not specified by the contract.
fn upstream_auth_rejected(request_body: &[u8]) -> Response<RespBody> {
    match request_id(request_body) {
        Some(id) => {
            // `id` is validated JSON; the message is a constant without quotes.
            let v = format!(
                "{{\"jsonrpc\":\"2.0\",\"id\":{},\"error\":{{\"code\":-32603,\"message\":\"{}\"}}}}",
                id.get(),
                UPSTREAM_REJECTED_MESSAGE
            );
            let mut r = Response::new(boxed_full(Bytes::from(v)));
            r.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            r.headers_mut().insert(
                header::X_CONTENT_TYPE_OPTIONS,
                HeaderValue::from_static("nosniff"),
            );
            r
        }
        None => fixed(StatusCode::BAD_GATEWAY, "upstream_rejected"),
    }
}

// ------------------------------------------------------------------ handler

async fn handle(
    req: Request<Incoming>,
    shared: Arc<Shared>,
) -> Result<Response<RespBody>, Infallible> {
    Ok(handle_inner(req, &shared).await)
}

async fn handle_inner(req: Request<Incoming>, sh: &Arc<Shared>) -> Response<RespBody> {
    let (parts, body) = req.into_parts();

    // hyper's buffer cap bounds reads but a single large read can exceed it, so
    // the header block is measured here as well (D-04: 32 KiB -> 431).
    let header_bytes: usize = parts.uri.to_string().len()
        + parts
            .headers
            .iter()
            .map(|(k, v)| k.as_str().len() + v.len() + 4)
            .sum::<usize>();
    if header_bytes as u64 > sh.limits.max_header_bytes {
        return fixed(
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            "headers_too_large",
        );
    }

    let Some(route_id) = route_id_from_path(parts.uri.path()) else {
        return fixed(StatusCode::NOT_FOUND, "not_found");
    };
    if !host_allowed(sh.host, &parts) {
        return fixed(StatusCode::FORBIDDEN, "forbidden");
    }
    // Until an applied config has at least one verifier everything is 401, so
    // an unconfigured proxy answers the same to every probe.
    let table = match sh.table.current() {
        Some(t) if t.has_verifier() => t,
        _ => return unauthorized(),
    };
    // An unknown route answers exactly like a failed authentication on a known
    // route (same status, body and headers), after the same kind of hashing
    // work, so route ids are not an oracle. Only a path that is not shaped
    // `/mcp/{id}` at all is a 404.
    let Some(route) = table.route(route_id) else {
        let _ = std::hint::black_box(sigil_proxy_api::verify(
            bearer_token(&parts.headers).unwrap_or(""),
            DUMMY_VERIFIER,
        ));
        return unauthorized();
    };
    let principal = bearer_token(&parts.headers).and_then(|t| route.authenticate(t));
    // `authenticate("")` is never a match, so a missing header needs no
    // separate timing-equalising pass.
    let Some(principal) = principal else {
        return unauthorized();
    };
    if !origin_ok(route, &parts.headers) {
        return fixed(StatusCode::FORBIDDEN, "forbidden");
    }
    let is_delete = parts.method == Method::DELETE;
    if parts.method != Method::POST && !is_delete {
        // GET SSE is a fixed 405 after auth with no upstream contact and no
        // resumption (decisions.md "P1 기능 범위"). Every other method is 405
        // as well.
        let mut r = fixed(StatusCode::METHOD_NOT_ALLOWED, "method_not_allowed");
        r.headers_mut()
            .insert(header::ALLOW, HeaderValue::from_static("POST, DELETE"));
        return r;
    }

    // Step 8: the shape of the proxy session header. It is looked up only once
    // the message is known: an initialize carrying any id is refused without a
    // lookup (the same 400 for an own, foreign or unknown id).
    let presented = Presented::from_request(&parts.headers);
    if presented == Presented::Duplicate {
        return empty(StatusCode::BAD_REQUEST);
    }
    let lookup = |wire: &[u8]| {
        sh.sessions.lookup(
            wire,
            principal.id.as_str(),
            route.id.as_str(),
            route.binding(),
            Instant::now(),
        )
    };
    if is_delete {
        return match presented {
            // One answer for every session the caller cannot use.
            Presented::One(wire) => match lookup(wire) {
                Ok(active) => delete_session(sh, &table, route, &parts, active).await,
                Err(_) => empty(StatusCode::NOT_FOUND),
            },
            // DELETE needs a session to end.
            _ => empty(StatusCode::BAD_REQUEST),
        };
    }

    // Admission: queue depth is 0, so saturation is an immediate rejection. The
    // permits live until the response body ends (an open SSE stream counts).
    let sems = match (
        sh.total.clone().try_acquire_owned(),
        route.sem.clone().try_acquire_owned(),
        principal.sem.clone().try_acquire_owned(),
    ) {
        (Ok(a), Ok(b), Ok(c)) => vec![a, b, c],
        _ => return fixed(StatusCode::TOO_MANY_REQUESTS, "too_many_requests"),
    };

    // Effective per-route limits: min(local, remote) (#260).
    let lim = route.limits();
    let call_deadline = Instant::now() + Duration::from_secs(lim.call_timeout_secs);
    let received_at = SystemTime::now();
    let t0 = std::time::Instant::now();
    // Provenance comes from this very table (README: fixed at call start).
    let audit = match (table.revision(), route.scope()) {
        (Some(rev), Some(scope)) => sigil_proxy_api::Id::new(scope.upstream_id.as_str())
            .ok()
            .map(|upstream_id| {
                Arc::new(AuditContext {
                    route_revision: rev,
                    upstream_id,
                    actor: principal.actor.clone(),
                })
            }),
        _ => None,
    };
    let mut call = CallRef {
        seq: sh.seq.fetch_add(1, Ordering::Relaxed),
        route_id: route.id.as_str().to_string(),
        principal_id: principal.id.as_str().to_string(),
        scope: route.scope.clone(),
        audit,
        // Set once the session is looked up (below).
        session: None,
    };

    // The request body is read in full under the request limit BEFORE any
    // upstream contact: an oversized body is a 413 with upstream untouched, and
    // the copy used for parsing is the very bytes forwarded.
    // OPEN: bounded buffering (<= max_request_body_bytes) instead of a pure
    // stream; the upstream sees a Content-Length body, not the client's framing.
    let max_body = lim.max_request_body_bytes;
    if content_length(&parts.headers).is_some_and(|n| n > max_body) {
        return refuse_too_large(sh, call, received_at);
    }
    let collected = tokio::time::timeout_at(
        call_deadline,
        Limited::new(body, max_body as usize).collect(),
    )
    .await;
    let request_body: Bytes = match collected {
        Err(_) => return fixed(StatusCode::REQUEST_TIMEOUT, "request_timeout"),
        Ok(Err(e)) if e.downcast_ref::<LengthLimitError>().is_some() => {
            return refuse_too_large(sh, call, received_at)
        }
        Ok(Err(_)) => return fixed(StatusCode::BAD_REQUEST, "bad_request"),
        Ok(Ok(c)) => c.to_bytes(),
    };

    // Classify a parse COPY of the body (T-12b1). The bytes forwarded below are
    // `request_body` itself, untouched. The version header is judged here only
    // for B1 (an unknown value is modern); the m5 rule below needs the session.
    let header_version = HeaderVersion::from_headers(&parts.headers);
    let mut message = classify::classify(
        &request_body,
        if header_version == HeaderVersion::Modern {
            HeaderVersion::Modern
        } else {
            HeaderVersion::Current
        },
    );
    let modern = matches!(&message, Message::Refused(r) if r.kind == RefusalKind::ModernRequest);
    let is_initialize =
        matches!(&message, Message::Request(i) if i.method == McpMethod::Initialize);
    // Session rules (t13d-t12b2.md). B1 keeps its audit with or without one.
    let mut reservation: Option<Reservation> = None;
    let mut active: Option<ActiveCall> = None;
    if !modern {
        match (is_initialize, presented) {
            // An initialize never joins an existing session.
            (true, Presented::One(_)) => return empty(StatusCode::BAD_REQUEST),
            (true, _) => match sh.sessions.reserve(principal.id.as_str(), Instant::now()) {
                Ok(r) => reservation = Some(r),
                Err(_) => return fixed(StatusCode::TOO_MANY_REQUESTS, "too_many_sessions"),
            },
            (false, Presented::One(wire)) => {
                let Ok(a) = lookup(wire) else {
                    return empty(StatusCode::NOT_FOUND);
                };
                call.session = Some(a.session().no());
                // m5: after initialize the header is required and must be the
                // negotiated revision (unknown values were B1 above).
                if matches!(
                    header_version,
                    HeaderVersion::Absent | HeaderVersion::Legacy
                ) {
                    message = Message::Refused(version_header_refusal(message));
                }
                active = Some(a);
            }
            (false, _) => return empty(StatusCode::BAD_REQUEST),
        }
    }
    let session_no = call.session;
    let upstream_session = active
        .as_ref()
        .and_then(|a| a.session().upstream().cloned());

    // `Some` for a client request that is observed (start, completion, cancel).
    let mut ctx: Option<CallCtx> = None;
    let mut init_id: Option<classify::RequestId> = None;
    match message {
        Message::Refused(r) => {
            return refuse(sh, call, r, request_body.len() as u64, received_at);
        }
        // Client answers to server requests and other notifications are relayed
        // as they are; no events.
        Message::ClientResponse | Message::Notification(NotificationInfo::Other) => {}
        Message::Notification(NotificationInfo::Cancelled { target }) => {
            let key = CancelKey {
                route: call.route_id.clone(),
                principal: call.principal_id.clone(),
                session: CancelScope::Session(session_no.unwrap_or_default()),
                id: target.clone(),
            };
            match sh.cancel.cancel(&key, Instant::now()) {
                CancelOutcome::AfterDispatch(seq) => {
                    // The target is in flight: the cancel goes upstream (below).
                    sh.sink.observe(Observation::Cancel(CancelObserved {
                        target: CallRef {
                            seq,
                            ..call.clone()
                        },
                        target_id: target,
                        disposition: CancelDisposition::AfterDispatch,
                        at: SystemTime::now(),
                    }));
                }
                // Not dispatched yet (the target's handler records it), already
                // cancelled, or held for a request that has not arrived: never
                // forwarded (M3, no hold-and-forward).
                CancelOutcome::BeforeDispatch
                | CancelOutcome::AlreadyCancelled
                | CancelOutcome::Held => return empty(StatusCode::ACCEPTED),
            }
        }
        Message::Request(info) => {
            let key = CancelKey {
                route: call.route_id.clone(),
                principal: call.principal_id.clone(),
                // An initialize has no session yet: a key no cancel can name.
                session: match session_no {
                    Some(n) if !is_initialize => CancelScope::Session(n),
                    _ => CancelScope::Initialize(call.seq),
                },
                id: info.id.clone(),
            };
            // Two in-flight requests of one session may not share an id: a
            // cancel could not tell them apart. The second is refused.
            let Some(registration) = sh.cancel.register(key, call.seq, Instant::now()) else {
                return refuse(
                    sh,
                    call,
                    Refusal {
                        kind: RefusalKind::InvalidRequest,
                        id: Some(info.id),
                        method: info.method,
                        tool: info.tool,
                    },
                    request_body.len() as u64,
                    received_at,
                );
            };
            if is_initialize {
                init_id = Some(info.id.clone());
            }
            let mut c = CallCtx::new(
                sh.sink.clone(),
                call.clone(),
                info.method,
                info.id,
                t0,
                registration,
            );
            if info.method == McpMethod::ToolsCall {
                // N10 ii: a task handle marks the route degraded.
                let (health, rid, binding) = (
                    sh.health.clone(),
                    route.id.as_str().to_string(),
                    route.binding().clone(),
                );
                let upstream_id = route.scope().map(|s| s.upstream_id.clone());
                c.on_task_handle(Box::new(move || {
                    if let Some(u) = upstream_id {
                        health.mark(
                            &rid,
                            &binding,
                            &u,
                            Mark {
                                state: RouteState::Degraded,
                                reason: RouteReason::TaskAugmentationUnsupported,
                            },
                        );
                    }
                }));
            }
            // The sink may defer dispatch (local spool commit of the start). The
            // no-op sink has nothing to wait for or record.
            if sh.sink.wants_observations() {
                let started = RequestStarted {
                    call: call.clone(),
                    method: info.method,
                    request_id: c.request_id().clone(),
                    tool: info.tool.clone(),
                    list_cursor: info
                        .list_cursor
                        .as_ref()
                        .map(|c| sh.cursor_hasher.tag_list_cursor(c)),
                    task_augmented: info.task_augmented,
                    request_bytes: request_body.len() as u64,
                    received_at,
                };
                if sh.sink.request_started(&started).await == StartVerdict::Refuse {
                    c.abandon();
                    return fixed(StatusCode::SERVICE_UNAVAILABLE, "audit_unavailable");
                }
            }
            if c.registration().is_cancelled() {
                return cancelled_before_dispatch(sh, c);
            }
            if is_initialize && sh.health.is_unsupported(route.id.as_str(), route.binding()) {
                // Already judged unsupported under this binding: refused
                // before the upstream, same answer as the first refusal.
                let id = c.request_id().clone();
                c.complete(Resolution::not_sent(
                    Outcome::ProtocolError,
                    Cause::RouteUnsupported,
                ));
                return init_refused(&id);
            }
            ctx = Some(c);
        }
    }

    // Fail the observed call (if any) and answer.
    macro_rules! bail {
        ($resp:expr, $res:expr) => {{
            let resp = $resp;
            if let Some(c) = ctx.as_mut() {
                c.complete($res);
            }
            return resp;
        }};
    }

    // Destination: resolve once, check every address, connect to a checked one.
    // Resolution is bounded by the connect timeout (a hanging resolver is a 504).
    let resolved = tokio::time::timeout(
        Duration::from_secs(lim.connect_timeout_secs),
        resolve_checked(&*sh.resolver, &route.upstream, route.allow_private),
    )
    .await;
    let addrs = match resolved {
        Err(_) => bail!(
            fixed(StatusCode::GATEWAY_TIMEOUT, "upstream_timeout"),
            Resolution::not_sent(Outcome::TransportFailure, Cause::ConnectTimeout)
        ),
        Ok(Ok(a)) => a,
        Ok(Err(DestError::Unresolved)) => bail!(
            fixed(StatusCode::BAD_GATEWAY, "upstream_unresolved"),
            Resolution::not_sent(Outcome::TransportFailure, Cause::Unresolved)
        ),
        Ok(Err(DestError::Refused(why))) => {
            tracing::warn!(
                route = route.id.as_str(),
                class = why,
                "destination refused"
            );
            bail!(
                fixed(StatusCode::BAD_GATEWAY, "destination_refused"),
                Resolution::not_sent(Outcome::TransportFailure, Cause::DestinationRefused)
            )
        }
    };

    let Ok(mut headers) = upstream_request_headers(
        &parts.headers,
        &route.upstream_authorization,
        &route.upstream.host_header,
    ) else {
        bail!(
            fixed(StatusCode::BAD_GATEWAY, "upstream_unavailable"),
            Resolution::not_sent(Outcome::TransportFailure, Cause::UpstreamRequestBuild)
        )
    };
    set_upstream_session(
        &mut headers,
        upstream_session
            .as_ref()
            .map(UpstreamSessionId::header_value),
    );
    let Ok(uri) = route.upstream.path.parse::<http::Uri>() else {
        bail!(
            fixed(StatusCode::BAD_GATEWAY, "upstream_unavailable"),
            Resolution::not_sent(Outcome::TransportFailure, Cause::UpstreamRequestBuild)
        )
    };
    let mut up_req = Request::new(Full::new(request_body.clone()));
    *up_req.method_mut() = Method::POST;
    *up_req.uri_mut() = uri;
    *up_req.headers_mut() = headers;

    let connect_for = Duration::from_secs(lim.connect_timeout_secs);
    let io = match connect(sh, route, &addrs, connect_for).await {
        Ok(io) => io,
        Err(ConnectError::Timeout) => bail!(
            fixed(StatusCode::GATEWAY_TIMEOUT, "upstream_timeout"),
            Resolution::not_sent(Outcome::TransportFailure, Cause::ConnectTimeout)
        ),
        Err(ConnectError::Io) => bail!(
            fixed(StatusCode::BAD_GATEWAY, "upstream_unavailable"),
            Resolution::not_sent(Outcome::TransportFailure, Cause::ConnectFailed)
        ),
    };
    let (mut sender, conn) = match hyper::client::conn::http1::handshake(TokioIo::new(io)).await {
        Ok(p) => p,
        Err(_) => bail!(
            fixed(StatusCode::BAD_GATEWAY, "upstream_unavailable"),
            Resolution::not_sent(Outcome::TransportFailure, Cause::ConnectFailed)
        ),
    };
    tokio::spawn(async move {
        let _ = conn.await;
    });

    // M3: the dispatch decision. A cancel that got here first wins and the
    // request is never written; otherwise the request is dispatched and any
    // later cancel is forwarded instead.
    if let Some(c) = ctx.as_mut() {
        if c.registration().try_dispatch().is_err() {
            let c = ctx.take().expect("checked above");
            return cancelled_before_dispatch(sh, c);
        }
        c.mark_dispatched();
    }

    // One fresh connection per exchange and one send: a failed exchange is never
    // retried (PX-015). First byte = response headers, bounded by the idle limit
    // and the call deadline.
    let first_byte =
        (Instant::now() + Duration::from_secs(lim.response_idle_timeout_secs)).min(call_deadline);
    let resp = match tokio::time::timeout_at(first_byte, sender.send_request(up_req)).await {
        Err(_) => bail!(
            fixed(StatusCode::GATEWAY_TIMEOUT, "upstream_timeout"),
            Resolution::after_dispatch(
                Outcome::Timeout,
                Delivery::Unknown,
                Cause::FirstByteTimeout,
                None
            )
        ),
        Ok(Err(_)) => bail!(
            fixed(StatusCode::BAD_GATEWAY, "upstream_unavailable"),
            Resolution::after_dispatch(
                Outcome::Unknown,
                Delivery::Unknown,
                Cause::SendFailed,
                None
            )
        ),
        Ok(Ok(r)) => r,
    };

    let (rparts, rbody) = resp.into_parts();
    let status = rparts.status;
    let sent = |cause| {
        Resolution::after_dispatch(
            Outcome::Unknown,
            Delivery::Sent,
            cause,
            Some(status.as_u16()),
        )
    };
    if status.is_redirection() {
        // Redirects are neither followed nor relayed (PX-014).
        bail!(
            fixed(StatusCode::BAD_GATEWAY, "upstream_redirect_refused"),
            sent(Cause::UpstreamRedirect)
        )
    }
    if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
        // decisions.md D-02 #7: unknown/sent, no reason.
        bail!(
            upstream_auth_rejected(&request_body),
            sent(Cause::UpstreamAuthRejected)
        )
    }
    if status == StatusCode::NOT_FOUND {
        if let Some(a) = &active {
            // A 404 for a call in a proxy session (stateful or stateless
            // upstream) ends that session; the client re-initializes after the
            // empty 404 (t13d-t12b2.md).
            sh.sessions.invalidate(a.session());
            bail!(
                empty(StatusCode::NOT_FOUND),
                sent(Cause::UpstreamSessionEnded)
            )
        }
    }

    let sse = is_sse(&rparts.headers);
    // A content-encoded stream is opaque to the proxy: the event tracker cannot
    // see event boundaries in compressed bytes, so only the call cap applies. It
    // is never decoded, and the call's outcome is reported as unobservable.
    let encoded = rparts
        .headers
        .get(header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            let v = v.trim();
            !v.is_empty() && !v.eq_ignore_ascii_case("identity")
        });
    let mode = match (sse, encoded) {
        (true, false) => BodyMode::Sse,
        (true, true) => BodyMode::Opaque,
        (false, _) => BodyMode::Json,
    };
    // The limits above treat an encoded plain body like JSON (as before); the
    // outcome tracker cannot read it.
    let track_mode = if encoded { BodyMode::Opaque } else { mode };
    // A declared length over the limit is refused while the status line can
    // still be replaced.
    let declared_cap = if mode == BodyMode::Json {
        lim.max_json_response_bytes.min(lim.max_call_response_bytes)
    } else {
        lim.max_call_response_bytes
    };
    if init_id.is_none() && content_length(&rparts.headers).is_some_and(|n| n > declared_cap) {
        bail!(
            fixed(StatusCode::BAD_GATEWAY, "upstream_response_too_large"),
            sent(Cause::ResponseTooLarge)
        )
    }

    // initialize (README N12): hold and judge the answer before anything of it
    // reaches the client. Only a 2xx answer can carry an InitializeResult.
    let mut prefix = Bytes::new();
    let mut new_session: Option<HeaderValue> = None;
    let mut rbody = rbody;
    if let (Some(id), Some(reservation)) = (init_id.as_ref(), reservation.take()) {
        if status.is_success() {
            // Captured before buffering, so a refusal can still end it upstream.
            let upstream_sid = UpstreamSessionId::from_response(&rparts.headers);
            let mut gate = InitGate::new(
                track_mode,
                id.clone(),
                lim.max_json_response_bytes.min(lim.max_call_response_bytes) as usize,
                lim.max_sse_event_bytes as usize,
            );
            let (verdict, read, rest) = hold_initialize(
                &mut gate,
                &mut rbody,
                Duration::from_secs(lim.response_idle_timeout_secs),
                call_deadline,
            )
            .await;
            let verdict = match (&upstream_sid, verdict) {
                // An upstream session id the proxy cannot carry back cannot be
                // bound: the answer is unusable.
                (Err(_), _) => InitVerdict::Unreadable,
                (_, v) => v,
            };
            let upstream_sid = upstream_sid.ok().flatten();
            let refusal = match verdict {
                InitVerdict::Supported => None,
                InitVerdict::UpstreamError => {
                    // Relayed unchanged without a session; the upstream's own
                    // session (if any) is ended.
                    if let Some(u) = upstream_sid.clone() {
                        spawn_cleanup(sh, &table, route, u);
                    }
                    None
                }
                InitVerdict::VersionUnsupported => Some((
                    Cause::UpstreamVersionUnsupported,
                    RouteReason::UpstreamVersionUnsupported,
                )),
                InitVerdict::CapabilityUnsupported => Some((
                    Cause::UpstreamCapabilityUnsupported,
                    RouteReason::UpstreamCapabilityUnsupported,
                )),
                InitVerdict::Unreadable => Some((
                    Cause::UpstreamInitializeUnreadable,
                    RouteReason::UpstreamInitializeUnreadable,
                )),
            };
            if let Some((cause, reason)) = refusal {
                // Nothing of the answer is relayed and no session exists.
                drop(reservation);
                if let Some(u) = upstream_sid {
                    spawn_cleanup(sh, &table, route, u);
                }
                if let Some(scope) = route.scope() {
                    sh.health.mark(
                        route.id.as_str(),
                        route.binding(),
                        &scope.upstream_id,
                        Mark {
                            state: RouteState::Unsupported,
                            reason,
                        },
                    );
                }
                let mut r = Resolution::after_dispatch(
                    Outcome::ProtocolError,
                    Delivery::Sent,
                    cause,
                    Some(status.as_u16()),
                );
                r.response_bytes = read;
                bail!(init_refused(id), r)
            }
            let mut held = gate.take_held().to_vec();
            held.extend_from_slice(&rest);
            prefix = Bytes::from(held);
            if verdict == InitVerdict::Supported {
                match reservation.establish_with_lease(
                    route.id.as_str(),
                    route.binding(),
                    upstream_sid.clone(),
                    Instant::now(),
                    true,
                ) {
                    Some((wire, _, lease)) => {
                        new_session = Some(wire);
                        active = lease;
                    }
                    None => {
                        // No randomness for an id: no session; end the upstream's.
                        if let Some(u) = upstream_sid {
                            spawn_cleanup(sh, &table, route, u);
                        }
                        bail!(
                            fixed(StatusCode::SERVICE_UNAVAILABLE, "session_unavailable"),
                            sent(Cause::None)
                        )
                    }
                }
            }
        }
    }

    // From here the tracker owns the call and reports its completion when the
    // body ends, fails or is dropped.
    let page_cap = if mode == BodyMode::Json {
        lim.max_json_response_bytes
    } else {
        lim.max_sse_event_bytes
    }
    .min(lim.inventory_max_bytes);
    let tracker = ctx.take().map(|c| {
        ResponseTracker::new(
            c,
            track_mode,
            status.as_u16(),
            CaptureLimits {
                max_bytes: page_cap as usize,
                max_tools: lim.inventory_max_tools as usize,
            },
        )
    });
    let metered = MeteredBody::with_prefix(
        rbody,
        crate::body::Limits {
            mode,
            max_json_bytes: lim.max_json_response_bytes,
            max_sse_event_bytes: lim.max_sse_event_bytes,
            max_call_bytes: lim.max_call_response_bytes,
            idle: Duration::from_secs(lim.response_idle_timeout_secs),
            call_deadline,
        },
        Permits(sems, active),
        tracker,
        prefix,
    );
    let mut out = Response::new(metered.boxed());
    *out.status_mut() = status;
    *out.headers_mut() = downstream_response_headers(&rparts.headers);
    if let Some(wire) = new_session {
        // Generated by the proxy, never copied from upstream.
        out.headers_mut()
            .insert(http::HeaderName::from_static("mcp-session-id"), wire);
    }
    out
}

/// Read the upstream `initialize` answer into `gate` until it decides, the
/// stream ends, an idle/call deadline passes or the stream fails. Returns the
/// verdict, the body bytes read and the undecided remainder of the deciding
/// chunk (relayed after the held bytes on a relayable verdict).
async fn hold_initialize(
    gate: &mut InitGate,
    body: &mut Incoming,
    idle: Duration,
    call_deadline: Instant,
) -> (InitVerdict, u64, Bytes) {
    let mut read = 0u64;
    loop {
        let until = (Instant::now() + idle).min(call_deadline);
        match tokio::time::timeout_at(until, body.frame()).await {
            Err(_) | Ok(Some(Err(_))) => return (InitVerdict::Unreadable, read, Bytes::new()),
            Ok(None) => return (gate.finish(), read, Bytes::new()),
            Ok(Some(Ok(f))) => {
                let Ok(d) = f.into_data() else { continue };
                read += d.len() as u64;
                if let Some(v) = gate.feed(&d) {
                    let rest = d.slice(gate.last_consumed().min(d.len())..);
                    return (v, read, rest);
                }
                if body.is_end_stream() {
                    return (gate.finish(), read, Bytes::new());
                }
            }
        }
    }
}

/// The fixed answer to a refused upstream `initialize` (README "런타임 route
/// 거절의 client 응답", t13d-t12b2.md): HTTP 200 JSON, -32603, no data.
fn init_refused(id: &classify::RequestId) -> Response<RespBody> {
    jsonrpc_error(Some(id), -32603, "Internal error", StatusCode::OK)
}

/// Turn a classified message into the m5 refusal (header absent or a known
/// legacy revision after initialize). Keeps its id, method and tool so the
/// audit pair is complete; the client sees 400 with an empty body.
fn version_header_refusal(m: Message) -> Refusal {
    let (id, method, tool) = match m {
        Message::Request(i) => (Some(i.id), i.method, i.tool),
        Message::Refused(r) => (r.id, r.method, r.tool),
        Message::Notification(_) | Message::ClientResponse => {
            (None, McpMethod::Unknown, ToolField::NotApplicable)
        }
    };
    Refusal {
        kind: RefusalKind::VersionHeader,
        id,
        method,
        tool,
    }
}

// --------------------------------------------------------- session DELETE

/// DELETE of a live session (`active`, already checked against the caller's
/// principal, route and binding).
async fn delete_session(
    sh: &Arc<Shared>,
    table: &Arc<RouteTable>,
    route: &Route,
    parts: &http::request::Parts,
    active: ActiveCall,
) -> Response<RespBody> {
    let session = active.session().clone();
    // One DELETE at a time per session; a second one sees the outcome.
    let _one = session.delete_lock.lock().await;
    if session.is_ended() {
        return empty(StatusCode::NOT_FOUND);
    }
    let Some(upstream) = session.upstream().cloned() else {
        // Stateless upstream: nothing to end there.
        sh.sessions.invalidate(&session);
        return empty(StatusCode::NO_CONTENT);
    };
    let Ok(mut headers) = upstream_request_headers(
        &parts.headers,
        &route.upstream_authorization,
        &route.upstream.host_header,
    ) else {
        return fixed(StatusCode::BAD_GATEWAY, "upstream_unavailable");
    };
    set_upstream_session(&mut headers, Some(upstream.header_value()));
    // DELETE carries no body to the upstream.
    headers.remove(header::CONTENT_TYPE);
    match upstream_delete(sh, table, route, headers).await {
        Ok(status) if status.is_success() || status == StatusCode::NOT_FOUND => {
            sh.sessions.invalidate(&session);
            empty(status)
        }
        Ok(status) if status.is_redirection() => {
            fixed(StatusCode::BAD_GATEWAY, "upstream_redirect_refused")
        }
        Ok(StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) => {
            fixed(StatusCode::BAD_GATEWAY, "upstream_rejected")
        }
        // 405 (the upstream keeps its sessions) and other errors: passed on,
        // the session stays.
        Ok(status) => empty(status),
        Err(ConnectError::Timeout) => fixed(StatusCode::GATEWAY_TIMEOUT, "upstream_timeout"),
        Err(ConnectError::Io) => fixed(StatusCode::BAD_GATEWAY, "upstream_unavailable"),
    }
}

/// Send one DELETE to the route's upstream: destination checked as for any
/// call, bounded by the connect and response idle limits, never retried. The
/// status only; the body is not read.
async fn upstream_delete(
    sh: &Shared,
    _table: &Arc<RouteTable>,
    route: &Route,
    headers: http::HeaderMap,
) -> Result<StatusCode, ConnectError> {
    let lim = route.limits();
    let connect_for = Duration::from_secs(lim.connect_timeout_secs);
    let addrs = match tokio::time::timeout(
        connect_for,
        resolve_checked(&*sh.resolver, &route.upstream, route.allow_private),
    )
    .await
    {
        Err(_) => return Err(ConnectError::Timeout),
        Ok(Err(_)) => return Err(ConnectError::Io),
        Ok(Ok(a)) => a,
    };
    let uri = route
        .upstream
        .path
        .parse::<http::Uri>()
        .map_err(|_| ConnectError::Io)?;
    let io = connect(sh, route, &addrs, connect_for).await?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io))
        .await
        .map_err(|_| ConnectError::Io)?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let mut req = Request::new(Full::new(Bytes::new()));
    *req.method_mut() = Method::DELETE;
    *req.uri_mut() = uri;
    *req.headers_mut() = headers;
    let wait = Duration::from_secs(lim.response_idle_timeout_secs);
    match tokio::time::timeout(wait, sender.send_request(req)).await {
        Err(_) => Err(ConnectError::Timeout),
        Ok(Err(_)) => Err(ConnectError::Io),
        Ok(Ok(r)) => Ok(r.status()),
    }
}

/// Best-effort, bounded, single DELETE of an upstream session the proxy will
/// not use (a refused `initialize`). In the background: the client's answer
/// does not wait for it. Never retried; never a tool call.
fn spawn_cleanup(
    sh: &Arc<Shared>,
    table: &Arc<RouteTable>,
    route: &Route,
    upstream: UpstreamSessionId,
) {
    let Ok(mut headers) = upstream_request_headers(
        &http::HeaderMap::new(),
        &route.upstream_authorization,
        &route.upstream.host_header,
    ) else {
        return;
    };
    set_upstream_session(&mut headers, Some(upstream.header_value()));
    let (sh, table, route_id) = (sh.clone(), table.clone(), route.id.as_str().to_string());
    tokio::spawn(async move {
        // The table snapshot that routed the call, so a later repoint cannot
        // send the id elsewhere.
        if let Some(route) = table.route(&route_id) {
            if upstream_delete(&sh, &table, route, headers).await.is_err() {
                tracing::debug!("upstream session cleanup failed");
            }
        }
    });
}

// ------------------------------------------------------- MCP-level answers

fn empty(status: StatusCode) -> Response<RespBody> {
    let mut r = Response::new(boxed_full(Bytes::new()));
    *r.status_mut() = status;
    r.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    r
}

/// A fixed JSON-RPC error: constant message, no `data`, nothing echoed but the
/// request id (contracts/README.md "Client-visible errors for pre-dispatch
/// refusals"). Without an id the reply carries `"id":null`.
fn jsonrpc_error(
    id: Option<&classify::RequestId>,
    code: i32,
    message: &'static str,
    status: StatusCode,
) -> Response<RespBody> {
    // `id.raw()` is validated JSON (a string or number); the message is a
    // constant without quotes.
    let body = format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":{},\"error\":{{\"code\":{code},\"message\":\"{message}\"}}}}",
        id.map(|i| i.raw()).unwrap_or("null")
    );
    let mut r = Response::new(boxed_full(Bytes::from(body)));
    *r.status_mut() = status;
    let h = r.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    r
}

/// The client-visible answer to a refusal. Upstream is never contacted.
///
/// - modern-era request, legacy version header: HTTP 400, empty body (B1).
/// - `tasks/*`, `resources/(un)subscribe`: JSON-RPC `-32601`, HTTP 200.
/// - unparseable tool name: JSON-RPC `-32602`, HTTP 200.
/// - batch, malformed JSON-RPC, a method-less notification refusal: HTTP 400
///   with a JSON-RPC `-32700`/`-32600` error and `"id":null`.
// OPEN: the batch/malformed shape is not fixed by the contract ("batch 거절의
// client 응답 형태는 [OPEN]"); this is the JSON-RPC 2.0 Invalid Request shape
// over HTTP 400.
fn refusal_response(r: &Refusal) -> Response<RespBody> {
    let bad = StatusCode::BAD_REQUEST;
    match r.kind {
        RefusalKind::ModernRequest | RefusalKind::VersionHeader => empty(bad),
        RefusalKind::Parse => jsonrpc_error(None, -32700, "Parse error", bad),
        // The id is echoed when one was read (batches and unparseable bodies
        // have none).
        RefusalKind::InvalidRequest | RefusalKind::Batch => {
            jsonrpc_error(r.id.as_ref(), -32600, "Invalid Request", bad)
        }
        RefusalKind::TasksMethod | RefusalKind::ResourcesSubscription => match &r.id {
            Some(id) => jsonrpc_error(Some(id), -32601, "Method not found", StatusCode::OK),
            // a notification: there is nobody to answer by id
            None => jsonrpc_error(None, -32600, "Invalid Request", bad),
        },
        RefusalKind::ToolNameMalformed => {
            jsonrpc_error(r.id.as_ref(), -32602, "Invalid params", StatusCode::OK)
        }
        RefusalKind::RequestTooLarge => fixed(StatusCode::PAYLOAD_TOO_LARGE, "request_too_large"),
    }
}

fn refuse(
    sh: &Shared,
    call: CallRef,
    r: Refusal,
    request_bytes: u64,
    received_at: SystemTime,
) -> Response<RespBody> {
    let resp = refusal_response(&r);
    sh.sink.observe(Observation::Refused(RequestRefused {
        call,
        reason: r.kind,
        method: r.method,
        request_id: r.id,
        tool: r.tool,
        http_status: resp.status().as_u16(),
        request_bytes,
        received_at,
    }));
    resp
}

fn refuse_too_large(sh: &Shared, call: CallRef, received_at: SystemTime) -> Response<RespBody> {
    refuse(
        sh,
        call,
        Refusal {
            kind: RefusalKind::RequestTooLarge,
            id: None,
            method: McpMethod::Unknown,
            tool: ToolField::NotApplicable,
        },
        0,
        received_at,
    )
}

/// M3: a cancel won against dispatch. Nothing was written upstream and no
/// JSON-RPC response is sent; the open POST gets an event-less 200 event stream
/// (README "취소 순서(M3)", N13).
// OPEN: P1 verification: if Claude/Codex retry on this, close the connection
// without an HTTP response instead (decisions.md "취소 전 dispatch의 HTTP 종료").
fn cancelled_before_dispatch(sh: &Shared, mut ctx: CallCtx) -> Response<RespBody> {
    sh.sink.observe(Observation::Cancel(CancelObserved {
        target: ctx.call().clone(),
        target_id: ctx.request_id().clone(),
        disposition: CancelDisposition::BeforeDispatch,
        at: SystemTime::now(),
    }));
    ctx.complete(Resolution::not_sent(
        Outcome::Unknown,
        Cause::CancelledBeforeDispatch,
    ));
    let mut r = empty(StatusCode::OK);
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/event-stream"),
    );
    r
}

// ------------------------------------------------------------------ connect

/// Connect to one of the CHECKED addresses (in order, never re-resolving), and
/// complete the TLS handshake for https. The whole step is bounded by `limit`.
async fn connect(
    sh: &Shared,
    route: &Route,
    addrs: &[SocketAddr],
    limit: Duration,
) -> Result<Box<dyn Io>, ConnectError> {
    let attempt = async {
        let mut last = io::Error::from(io::ErrorKind::NotFound);
        for a in addrs {
            match TcpStream::connect(a).await {
                Ok(tcp) => {
                    let _ = tcp.set_nodelay(true);
                    return wrap_tls(sh, route, tcp).await;
                }
                Err(e) => last = e,
            }
        }
        Err(last)
    };
    match tokio::time::timeout(limit, attempt).await {
        Err(_) => Err(ConnectError::Timeout),
        Ok(Ok(io)) => Ok(io),
        Ok(Err(_)) => Err(ConnectError::Io),
    }
}

enum ConnectError {
    Timeout,
    Io,
}

#[cfg(unix)]
async fn wrap_tls(sh: &Shared, route: &Route, tcp: TcpStream) -> io::Result<Box<dyn Io>> {
    if !route.upstream.https {
        return Ok(Box::new(tcp));
    }
    let name = tls::server_name(&route.upstream.host)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid server name"))?;
    Ok(Box::new(sh.upstream_tls.connect(name, tcp).await?))
}

#[cfg(not(unix))]
async fn wrap_tls(_: &Shared, route: &Route, tcp: TcpStream) -> io::Result<Box<dyn Io>> {
    if route.upstream.https {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "https upstream is not supported on this platform",
        ));
    }
    Ok(Box::new(tcp))
}
