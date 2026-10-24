//! Response outcome classification (T-12b1; PX-006/015).
//!
//! [`ResponseTracker`] watches the response body bytes as they stream to the
//! client and reports exactly one [`Completed`] per call. It never changes the
//! bytes and keeps no result content: a constant-size scanner finds the JSON-RPC
//! response (matching the request id) in a JSON body or in the SSE events of a
//! stream. The one exception is a `tools/list` page, captured within a bound
//! because the inventory needs it (see `observation::ToolListCapture`).
//!
//! Outcome rules (the response head was received unless noted):
//!
//! - a JSON-RPC message with the request's id decides: `result` is `Success`
//!   (`ToolError` when `tools/call` has `result.isError == true`), `error` is
//!   `JsonRpcError`. A `tools/call` result carrying a task handle
//!   (`result.task`, N10 ii) is relayed unchanged and is `ProtocolError` /
//!   `TaskHandle`, never a success. In SSE the first such message wins; server requests and
//!   notifications in the stream (they carry a `method`) are skipped.
//! - a cancel was forwarded and no response arrived: `Unknown` /
//!   `CancelNoResponse` (never `Timeout`; README M3).
//! - HTTP status >= 400 with no JSON-RPC message: `TransportFailure`.
//! - proxy idle/call deadline: `Timeout`.
//! - everything else without a response (closed, aborted, over a limit, not
//!   JSON-RPC, content-encoded): `Unknown`. A lost response is never inferred
//!   to be a failure or a success.

use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Instant, SystemTime};

use serde::Deserialize;
use serde_json::value::RawValue;

use super::cancel::{Registration, CANCEL_RESPONSE_GRACE};
use super::classify::{Method, RequestId, ToolName};
use super::observation::{
    CallRef, Cause, Completed, Delivery, NextCursor, Observation, ObservationSink, Outcome,
    PageUnavailable, ToolDescriptor, ToolListCapture, ToolListPage, MAX_DEFINITION_BYTES,
};
use super::scan::{Facts, IdFact, MsgScanner, SseEv, SseParser};
use crate::body::{BodyLimit, BodyMode};

/// How a call ended, as the tracker or the relay reports it.
pub struct Resolution {
    pub outcome: Outcome,
    pub delivery: Delivery,
    pub cause: Cause,
    pub http_status: Option<u16>,
    pub response_bytes: u64,
    pub tool_list: Option<ToolListCapture>,
}

impl Resolution {
    /// The request was (or may have been) written to upstream.
    pub fn after_dispatch(
        outcome: Outcome,
        delivery: Delivery,
        cause: Cause,
        http_status: Option<u16>,
    ) -> Resolution {
        Resolution {
            outcome,
            delivery,
            cause,
            http_status,
            response_bytes: 0,
            tool_list: None,
        }
    }

    /// The request never reached upstream.
    pub fn not_sent(outcome: Outcome, cause: Cause) -> Resolution {
        Resolution {
            outcome,
            delivery: Delivery::NotSent,
            cause,
            http_status: None,
            response_bytes: 0,
            tool_list: None,
        }
    }
}

/// One forwarded call: the identity, the clock, the cancel registration and the
/// exactly-once completion. If it is dropped without being completed (the
/// client disconnected, the task was cancelled) it reports `Unknown`.
pub struct CallCtx {
    sink: Arc<dyn ObservationSink>,
    call: CallRef,
    method: Method,
    request_id: RequestId,
    started: Instant,
    registration: Registration,
    dispatched: bool,
    done: bool,
    /// The sink wants observations; otherwise `complete` reports nothing.
    wants: bool,
    /// Runs once if the response turns out to be a task handle (route health).
    on_task_handle: Option<Box<dyn FnOnce() + Send + Sync>>,
}

impl CallCtx {
    pub fn new(
        sink: Arc<dyn ObservationSink>,
        call: CallRef,
        method: Method,
        request_id: RequestId,
        started: Instant,
        registration: Registration,
    ) -> CallCtx {
        CallCtx {
            wants: sink.wants_observations(),
            sink,
            call,
            method,
            request_id,
            started,
            registration,
            dispatched: false,
            done: false,
            on_task_handle: None,
        }
    }

    /// Run `f` once if this call's response is a task handle.
    pub fn on_task_handle(&mut self, f: Box<dyn FnOnce() + Send + Sync>) {
        self.on_task_handle = Some(f);
    }

    pub fn registration(&self) -> &Registration {
        &self.registration
    }

    pub fn call(&self) -> &CallRef {
        &self.call
    }

    pub fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    /// The request is being written to upstream. Call right after a
    /// successful `Registration::try_dispatch`.
    pub fn mark_dispatched(&mut self) {
        self.dispatched = true;
    }

    pub fn is_tools_list(&self) -> bool {
        self.method == Method::ToolsList
    }

    pub fn is_tools_call(&self) -> bool {
        self.method == Method::ToolsCall
    }

    /// Report nothing for this call (the sink refused its start).
    pub fn abandon(&mut self) {
        self.done = true;
    }

    pub fn complete(&mut self, r: Resolution) {
        if std::mem::replace(&mut self.done, true) {
            return;
        }
        if r.cause == Cause::TaskHandle {
            if let Some(f) = self.on_task_handle.take() {
                f();
            }
        }
        if !self.wants {
            return;
        }
        self.sink.observe(Observation::Completed(Completed {
            call: self.call.clone(),
            method: self.method,
            request_id: self.request_id.clone(),
            outcome: r.outcome,
            delivery: r.delivery,
            cause: r.cause,
            http_status: r.http_status,
            response_bytes: r.response_bytes,
            duration: self.started.elapsed(),
            completed_at: SystemTime::now(),
            cancel_requested: self.registration.cancel_requested(),
            tool_list: r.tool_list,
        }));
    }
}

impl Drop for CallCtx {
    fn drop(&mut self) {
        if !self.done {
            let delivery = if self.dispatched {
                Delivery::Unknown
            } else {
                Delivery::NotSent
            };
            let outcome = if self.dispatched {
                Outcome::Unknown
            } else {
                Outcome::TransportFailure
            };
            self.complete(Resolution {
                outcome,
                delivery,
                cause: Cause::ClientGone,
                http_status: None,
                response_bytes: 0,
                tool_list: None,
            });
        }
    }
}

// ------------------------------------------------------------------ tracker

/// How the response body ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum End {
    Eof,
    Limit(BodyLimit),
    /// The upstream body errored.
    Upstream,
    /// The body was dropped before it ended (client disconnect).
    Dropped,
}

/// Bounds for capturing a `tools/list` page.
#[derive(Debug, Clone, Copy)]
pub struct CaptureLimits {
    /// Largest page (JSON body or one SSE event) that is captured.
    pub max_bytes: usize,
    pub max_tools: usize,
}

struct Capture {
    buf: Vec<u8>,
    max: usize,
    over: bool,
}

impl Capture {
    fn push(&mut self, data: &[u8]) {
        if self.over {
            return;
        }
        if self.buf.len() + data.len() > self.max {
            self.over = true;
            self.buf = Vec::new();
        } else {
            self.buf.extend_from_slice(data);
        }
    }
    fn take(&mut self) -> (Vec<u8>, bool) {
        let over = std::mem::replace(&mut self.over, false);
        (std::mem::take(&mut self.buf), over)
    }
}

enum Found {
    Result { tool_error: bool, task: bool },
    Error,
}

pub struct ResponseTracker {
    ctx: CallCtx,
    mode: BodyMode,
    status: u16,
    scanner: MsgScanner,
    sse: SseParser,
    capture: Option<Capture>,
    caplimits: CaptureLimits,
    found: Option<(Found, Vec<u8>, bool)>,
    saw_mismatch: bool,
    saw_message: bool,
    total: u64,
    grace: Option<std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + Sync>>>,
    finished: bool,
}

impl ResponseTracker {
    pub fn new(
        ctx: CallCtx,
        mode: BodyMode,
        status: u16,
        caplimits: CaptureLimits,
    ) -> ResponseTracker {
        let capture =
            (ctx.wants && ctx.is_tools_list() && mode != BodyMode::Opaque).then(|| Capture {
                buf: Vec::new(),
                max: caplimits.max_bytes,
                over: false,
            });
        // Without a consumer the response is not scanned, so there is nothing to
        // tell the grace that an answer arrived: it is not armed.
        let grace = ctx
            .wants
            .then(|| ctx.registration().grace_expired(CANCEL_RESPONSE_GRACE));
        ResponseTracker {
            ctx,
            mode,
            status,
            scanner: MsgScanner::new(),
            sse: SseParser::default(),
            capture,
            caplimits,
            found: None,
            saw_mismatch: false,
            saw_message: false,
            total: 0,
            grace,
            finished: false,
        }
    }

    /// Poll the cancel grace: `Ready` once a forwarded cancel has gone
    /// unanswered for the grace period. Never ready once a response was seen.
    pub fn poll_cancel_grace(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        if self.found.is_some() || self.finished {
            return Poll::Pending;
        }
        match self.grace.as_mut() {
            Some(g) => g.as_mut().poll(cx),
            None => Poll::Pending,
        }
    }

    /// Feed relayed bytes. Never retains them (except the bounded `tools/list`
    /// page).
    pub fn feed(&mut self, data: &[u8]) {
        self.total += data.len() as u64;
        if !self.ctx.wants {
            return;
        }
        match self.mode {
            BodyMode::Opaque => {}
            BodyMode::Json => {
                if self.found.is_none() {
                    if let Some(c) = &mut self.capture {
                        c.push(data);
                    }
                    self.scanner.feed(data);
                }
            }
            BodyMode::Sse => {
                if self.found.is_some() {
                    return;
                }
                let mut ended: Vec<(Facts, Vec<u8>, bool)> = Vec::new();
                {
                    let Self {
                        sse,
                        scanner,
                        capture,
                        ..
                    } = self;
                    sse.feed(data, |ev| match ev {
                        SseEv::Data(b) => {
                            scanner.feed(&[b]);
                            if let Some(c) = capture {
                                c.push(&[b]);
                            }
                        }
                        SseEv::DataBreak => {
                            scanner.feed(b"\n");
                            if let Some(c) = capture {
                                c.push(b"\n");
                            }
                        }
                        SseEv::EventEnd => {
                            let facts = scanner.take();
                            let (bytes, over) =
                                capture.as_mut().map(Capture::take).unwrap_or_default();
                            ended.push((facts, bytes, over));
                        }
                    });
                }
                for (facts, bytes, over) in ended {
                    self.message(facts, bytes, over);
                    if self.found.is_some() {
                        break;
                    }
                }
            }
        }
    }

    fn message(&mut self, facts: Facts, bytes: Vec<u8>, over: bool) {
        if !facts.complete {
            return;
        }
        self.saw_message = true;
        // Server requests, server notifications and client-style messages are
        // not the response.
        if facts.has_method || !(facts.has_result || facts.has_error) {
            return;
        }
        let ours = match &facts.id {
            IdFact::Value(v) => v == self.ctx.request_id(),
            // JSON-RPC allows an id-less error (e.g. an upstream parse error).
            IdFact::Null | IdFact::Missing => facts.has_error,
            IdFact::Invalid => false,
        };
        if !ours {
            self.saw_mismatch = true;
            return;
        }
        let f = if facts.has_error {
            Found::Error
        } else {
            Found::Result {
                tool_error: self.ctx.is_tools_call() && facts.is_error,
                task: self.ctx.is_tools_call() && facts.has_task,
            }
        };
        self.found = Some((f, bytes, over));
        self.grace = None;
    }

    /// Report the call's end. Idempotent.
    pub fn finish(&mut self, end: End) {
        if self.finished {
            return;
        }
        self.finished = true;
        if self.mode == BodyMode::Json && self.found.is_none() && end == End::Eof {
            let facts = self.scanner.take();
            let (bytes, over) = self.capture.as_mut().map(Capture::take).unwrap_or_default();
            self.message(facts, bytes, over);
        }
        let r = self.resolve(end);
        self.ctx.complete(r);
    }

    fn resolve(&mut self, end: End) -> Resolution {
        let status = Some(self.status);
        let sent = |outcome, cause| Resolution {
            outcome,
            delivery: Delivery::Sent,
            cause,
            http_status: status,
            response_bytes: self.total,
            tool_list: None,
        };
        let is_list = self.ctx.is_tools_list();
        let mut res = if let Some((found, bytes, over)) = self.found.take() {
            match found {
                Found::Error => {
                    let mut r = sent(Outcome::JsonRpcError, Cause::None);
                    if is_list {
                        r.tool_list =
                            Some(ToolListCapture::Unavailable(PageUnavailable::NoSuccess));
                    }
                    r
                }
                Found::Result { task: true, .. } => sent(Outcome::ProtocolError, Cause::TaskHandle),
                Found::Result { tool_error, .. } => {
                    let mut r = sent(
                        if tool_error {
                            Outcome::ToolError
                        } else {
                            Outcome::Success
                        },
                        Cause::None,
                    );
                    if is_list {
                        r.tool_list = Some(if over {
                            ToolListCapture::Unavailable(PageUnavailable::TooLarge)
                        } else {
                            parse_list_page(&bytes, self.caplimits.max_tools)
                        });
                    }
                    r
                }
            }
        } else if self.ctx.registration().cancel_requested() {
            sent(Outcome::Unknown, Cause::CancelNoResponse)
        } else if end == End::Eof && self.status >= 400 {
            sent(
                Outcome::TransportFailure,
                Cause::UpstreamStatus(self.status),
            )
        } else if self.mode == BodyMode::Opaque && end == End::Eof {
            sent(Outcome::Unknown, Cause::Unobservable)
        } else {
            match end {
                End::Eof => sent(
                    Outcome::Unknown,
                    if self.saw_mismatch {
                        Cause::ResponseIdMismatch
                    } else if self.total > 0 && !self.saw_message {
                        Cause::ResponseUnparseable
                    } else {
                        Cause::StreamClosedWithoutResponse
                    },
                ),
                End::Limit(BodyLimit::IdleTimeout) => sent(Outcome::Timeout, Cause::IdleTimeout),
                End::Limit(BodyLimit::CallTimeout) => sent(Outcome::Timeout, Cause::CallTimeout),
                End::Limit(BodyLimit::CancelNoResponse) => {
                    sent(Outcome::Unknown, Cause::CancelNoResponse)
                }
                End::Limit(_) => sent(Outcome::Unknown, Cause::ResponseTooLarge),
                End::Upstream => sent(Outcome::Unknown, Cause::StreamError),
                End::Dropped => sent(Outcome::Unknown, Cause::ClientGone),
            }
        };
        if is_list && res.tool_list.is_none() {
            res.tool_list = Some(ToolListCapture::Unavailable(
                if self.mode == BodyMode::Opaque {
                    PageUnavailable::Unobservable
                } else {
                    PageUnavailable::NoSuccess
                },
            ));
        }
        res
    }
}

impl Drop for ResponseTracker {
    fn drop(&mut self) {
        self.finish(End::Dropped);
    }
}

// ------------------------------------------------------------ tools/list page

#[derive(Deserialize)]
struct ListEnvelope<'a> {
    #[serde(borrow)]
    result: ListResult<'a>,
}

#[derive(Deserialize)]
struct ListResult<'a> {
    #[serde(borrow)]
    tools: Vec<&'a RawValue>,
    #[serde(rename = "nextCursor", default, borrow)]
    next_cursor: Option<&'a RawValue>,
}

#[derive(Deserialize)]
struct ToolName_<'a> {
    #[serde(borrow)]
    name: std::borrow::Cow<'a, str>,
}

/// Parse a captured `tools/list` response body into a bounded page.
pub fn parse_list_page(bytes: &[u8], max_tools: usize) -> ToolListCapture {
    let unavailable = ToolListCapture::Unavailable;
    let env: ListEnvelope = match serde_json::from_slice(bytes) {
        Ok(e) => e,
        Err(_) => return unavailable(PageUnavailable::Unparseable),
    };
    if env.result.tools.len() > max_tools {
        return unavailable(PageUnavailable::TooManyTools);
    }
    // `nextCursor` must be a string within the bound (a null counts as absent).
    let next_cursor = match env.result.next_cursor {
        None => None,
        Some(raw) => {
            let c = serde_json::from_str::<String>(raw.get())
                .ok()
                .and_then(|s| NextCursor::new(&s));
            match c {
                Some(c) => Some(c),
                None => return unavailable(PageUnavailable::CursorInvalid),
            }
        }
    };
    let mut tools = Vec::with_capacity(env.result.tools.len());
    for raw in env.result.tools {
        if raw.get().len() > MAX_DEFINITION_BYTES {
            return unavailable(PageUnavailable::TooLarge);
        }
        let Ok(t) = serde_json::from_str::<ToolName_>(raw.get()) else {
            return unavailable(PageUnavailable::Unparseable);
        };
        let Some(name) = ToolName::parse(&t.name) else {
            return unavailable(PageUnavailable::Unparseable);
        };
        tools.push(ToolDescriptor {
            name,
            definition: raw.get().into(),
        });
    }
    ToolListCapture::Page(ToolListPage { tools, next_cursor })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::cancel::{CancelKey, CancelRegistry};
    use std::sync::Mutex;
    use std::time::Duration;

    #[derive(Default)]
    struct Rec(Mutex<Vec<Observation>>);
    impl ObservationSink for Rec {
        fn observe(&self, o: Observation) {
            self.0.lock().unwrap().push(o);
        }
    }

    struct Fixture {
        rec: Arc<Rec>,
        reg: Arc<CancelRegistry>,
    }

    fn tracker(
        method: Method,
        id: &str,
        mode: BodyMode,
        status: u16,
    ) -> (ResponseTracker, Fixture) {
        let rec = Arc::new(Rec::default());
        let reg = Arc::new(CancelRegistry::default());
        let key = CancelKey {
            route: "r".into(),
            principal: "p".into(),
            session: crate::mcp::cancel::CancelScope::Session(1),
            id: RequestId::from_raw(id).unwrap(),
        };
        let registration = reg.register(key, 1, tokio::time::Instant::now()).unwrap();
        registration.try_dispatch().unwrap();
        let ctx = CallCtx::new(
            rec.clone(),
            CallRef {
                seq: 1,
                route_id: "r".into(),
                principal_id: "p".into(),
                scope: None,
                audit: None,
                session: None,
            },
            method,
            RequestId::from_raw(id).unwrap(),
            Instant::now(),
            registration,
        );
        let t = ResponseTracker::new(
            ctx,
            mode,
            status,
            CaptureLimits {
                max_bytes: 1 << 20,
                max_tools: 100,
            },
        );
        (t, Fixture { rec, reg })
    }

    fn done(f: &Fixture) -> Completed {
        let g = f.rec.0.lock().unwrap();
        assert_eq!(g.len(), 1, "exactly one completion: {g:?}");
        match &g[0] {
            Observation::Completed(c) => c.clone(),
            o => panic!("{o:?}"),
        }
    }

    fn json(method: Method, id: &str, status: u16, body: &str) -> Completed {
        let (mut t, f) = tracker(method, id, BodyMode::Json, status);
        // two chunks at an arbitrary point
        let b = body.as_bytes();
        t.feed(&b[..b.len() / 2]);
        t.feed(&b[b.len() / 2..]);
        t.finish(End::Eof);
        done(&f)
    }

    fn sse(method: Method, id: &str, chunks: &[&str], end: End) -> Completed {
        let (mut t, f) = tracker(method, id, BodyMode::Sse, 200);
        for c in chunks {
            t.feed(c.as_bytes());
        }
        t.finish(end);
        done(&f)
    }

    #[test]
    fn json_success_tool_error_and_rpc_error() {
        let c = json(
            Method::ToolsCall,
            "1",
            200,
            r#"{"jsonrpc":"2.0","id":1,"result":{"content":[],"isError":false}}"#,
        );
        assert_eq!(
            (c.outcome, c.delivery, c.cause),
            (Outcome::Success, Delivery::Sent, Cause::None)
        );
        assert_eq!(c.http_status, Some(200));

        let c = json(
            Method::ToolsCall,
            "1",
            200,
            r#"{"jsonrpc":"2.0","id":1,"result":{"isError":true,"content":[{"type":"text","text":"CANARY"}]}}"#,
        );
        assert_eq!(c.outcome, Outcome::ToolError);

        // isError only means something for tools/call
        let c = json(
            Method::Ping,
            "1",
            200,
            r#"{"id":1,"result":{"isError":true}}"#,
        );
        assert_eq!(c.outcome, Outcome::Success);

        let c = json(
            Method::ToolsCall,
            "\"a\"",
            200,
            r#"{"jsonrpc":"2.0","id":"a","error":{"code":-32602,"message":"CANARY"}}"#,
        );
        assert_eq!(
            (c.outcome, c.delivery),
            (Outcome::JsonRpcError, Delivery::Sent)
        );
    }

    #[test]
    fn json_failures_are_unknown_or_transport() {
        // 2xx with no body: upstream accepted, nothing came back
        let c = json(Method::ToolsCall, "1", 202, "");
        assert_eq!(
            (c.outcome, c.cause),
            (Outcome::Unknown, Cause::StreamClosedWithoutResponse)
        );
        // not JSON
        let c = json(Method::ToolsCall, "1", 200, "<html>oops</html>");
        assert_eq!(
            (c.outcome, c.cause),
            (Outcome::Unknown, Cause::ResponseUnparseable)
        );
        // a response for another id
        let c = json(
            Method::ToolsCall,
            "1",
            200,
            r#"{"jsonrpc":"2.0","id":2,"result":{}}"#,
        );
        assert_eq!(
            (c.outcome, c.cause),
            (Outcome::Unknown, Cause::ResponseIdMismatch)
        );
        // string vs number id
        let c = json(
            Method::ToolsCall,
            "1",
            200,
            r#"{"jsonrpc":"2.0","id":"1","result":{}}"#,
        );
        assert_eq!(c.cause, Cause::ResponseIdMismatch);
        // HTTP failure with a non-JSON-RPC body
        let c = json(Method::ToolsCall, "1", 500, "boom");
        assert_eq!(
            (c.outcome, c.delivery, c.cause),
            (
                Outcome::TransportFailure,
                Delivery::Sent,
                Cause::UpstreamStatus(500)
            )
        );
        // HTTP 400 carrying a JSON-RPC error is still a JSON-RPC error
        let c = json(
            Method::ToolsCall,
            "1",
            400,
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"x"}}"#,
        );
        assert_eq!(c.outcome, Outcome::JsonRpcError);
        // an id-less JSON-RPC error answers the request
        let c = json(
            Method::ToolsCall,
            "1",
            400,
            r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"x"}}"#,
        );
        assert_eq!(c.outcome, Outcome::JsonRpcError);
        // a batch from upstream is not a response
        let c = json(
            Method::ToolsCall,
            "1",
            200,
            r#"[{"jsonrpc":"2.0","id":1,"result":{}}]"#,
        );
        assert_eq!(c.outcome, Outcome::Unknown);
        // truncated body
        let (mut t, f) = tracker(Method::ToolsCall, "1", BodyMode::Json, 200);
        t.feed(br#"{"jsonrpc":"2.0","id":1,"result":{"content":["#);
        t.finish(End::Upstream);
        let c = done(&f);
        assert_eq!((c.outcome, c.cause), (Outcome::Unknown, Cause::StreamError));
    }

    #[test]
    fn sse_picks_the_response_among_server_messages() {
        let c = sse(
            Method::ToolsCall,
            "5",
            &[
                "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"progress\":1}}\n\n",
                "data: {\"jsonrpc\":\"2.0\",\"id\":\"srv1\",\"method\":\"sampling/createMessage\",\"params\":{}}\n\n",
                "data: {\"jsonrpc\":\"2.0\",\"id\":9,\"result\":{}}\r\n\r\n",
                "id: 3\ndata: {\"jsonrpc\":\"2.0\",\"id\":5,\"res",
                "ult\":{\"isError\":true}}\n\n",
                "data: {\"jsonrpc\":\"2.0\",\"id\":5,\"error\":{}}\n\n",
            ],
            End::Eof,
        );
        // the first matching message wins; the later duplicate is ignored
        assert_eq!((c.outcome, c.cause), (Outcome::ToolError, Cause::None));
    }

    #[test]
    fn sse_multiline_data_and_crlf() {
        let c = sse(
            Method::ToolsCall,
            "1",
            &["data: {\"jsonrpc\":\"2.0\",\r\ndata: \"id\":1,\r\ndata: \"result\":{}}\r\n\r\n"],
            End::Eof,
        );
        assert_eq!(c.outcome, Outcome::Success);
    }

    #[test]
    fn sse_closed_without_a_response_is_unknown() {
        // events but no response, clean end
        let c = sse(
            Method::ToolsCall,
            "1",
            &["data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\n"],
            End::Eof,
        );
        assert_eq!(
            (c.outcome, c.delivery, c.cause),
            (
                Outcome::Unknown,
                Delivery::Sent,
                Cause::StreamClosedWithoutResponse
            )
        );
        // an empty stream (the cancelled-before-dispatch shape from upstream)
        let c = sse(Method::ToolsCall, "1", &[], End::Eof);
        assert_eq!(c.outcome, Outcome::Unknown);
        // response event not terminated by a blank line is discarded, as a client would
        let c = sse(
            Method::ToolsCall,
            "1",
            &["data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n"],
            End::Eof,
        );
        assert_eq!(c.outcome, Outcome::Unknown);
        // aborted
        let c = sse(
            Method::ToolsCall,
            "1",
            &["data: {\"jsonrpc\":\"2.0\",\"meth"],
            End::Upstream,
        );
        assert_eq!((c.outcome, c.cause), (Outcome::Unknown, Cause::StreamError));
        // a response seen before the abort stands
        let c = sse(
            Method::ToolsCall,
            "1",
            &["data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\ndata: {\"par"],
            End::Upstream,
        );
        assert_eq!(c.outcome, Outcome::Success);
    }

    #[test]
    fn limits_and_timeouts() {
        for (end, outcome, cause) in [
            (
                End::Limit(BodyLimit::IdleTimeout),
                Outcome::Timeout,
                Cause::IdleTimeout,
            ),
            (
                End::Limit(BodyLimit::CallTimeout),
                Outcome::Timeout,
                Cause::CallTimeout,
            ),
            (
                End::Limit(BodyLimit::ResponseTooLarge),
                Outcome::Unknown,
                Cause::ResponseTooLarge,
            ),
            (
                End::Limit(BodyLimit::SseEventTooLarge),
                Outcome::Unknown,
                Cause::ResponseTooLarge,
            ),
            (
                End::Limit(BodyLimit::CallTooLarge),
                Outcome::Unknown,
                Cause::ResponseTooLarge,
            ),
            (End::Dropped, Outcome::Unknown, Cause::ClientGone),
        ] {
            let c = sse(Method::ToolsCall, "1", &[], end);
            assert_eq!((c.outcome, c.cause), (outcome, cause), "{end:?}");
            assert_eq!(c.delivery, Delivery::Sent);
        }
    }

    #[test]
    fn encoded_bodies_are_unobservable() {
        let (mut t, f) = tracker(Method::ToolsCall, "1", BodyMode::Opaque, 200);
        t.feed(b"\x1f\x8b\x08 gzip bytes {\"id\":1,\"result\":{}}");
        t.finish(End::Eof);
        let c = done(&f);
        assert_eq!(
            (c.outcome, c.cause),
            (Outcome::Unknown, Cause::Unobservable)
        );
        assert_eq!(c.response_bytes, 35, "bytes are still counted");
    }

    #[test]
    fn cancel_without_a_response_is_never_a_timeout() {
        for end in [
            End::Eof,
            End::Limit(BodyLimit::IdleTimeout),
            End::Limit(BodyLimit::CallTimeout),
            End::Limit(BodyLimit::CancelNoResponse),
            End::Dropped,
        ] {
            let (mut t, f) = tracker(Method::ToolsCall, "7", BodyMode::Sse, 200);
            f.reg.cancel(
                &CancelKey {
                    route: "r".into(),
                    principal: "p".into(),
                    session: crate::mcp::cancel::CancelScope::Session(1),
                    id: RequestId::from_raw("7").unwrap(),
                },
                tokio::time::Instant::now(),
            );
            t.finish(end);
            let c = done(&f);
            assert_eq!(
                (c.outcome, c.cause, c.delivery, c.cancel_requested),
                (
                    Outcome::Unknown,
                    Cause::CancelNoResponse,
                    Delivery::Sent,
                    true
                ),
                "{end:?}"
            );
        }
        // but a response that arrives after the cancel decides
        let (mut t, f) = tracker(Method::ToolsCall, "7", BodyMode::Sse, 200);
        f.reg.cancel(
            &CancelKey {
                route: "r".into(),
                principal: "p".into(),
                session: crate::mcp::cancel::CancelScope::Session(1),
                id: RequestId::from_raw("7").unwrap(),
            },
            tokio::time::Instant::now(),
        );
        t.feed(b"data: {\"jsonrpc\":\"2.0\",\"id\":7,\"error\":{\"code\":-32800,\"message\":\"cancelled\"}}\n\n");
        t.finish(End::Eof);
        let c = done(&f);
        assert_eq!(
            (c.outcome, c.cancel_requested),
            (Outcome::JsonRpcError, true)
        );
    }

    #[test]
    fn completion_is_reported_exactly_once() {
        let (mut t, f) = tracker(Method::Ping, "1", BodyMode::Json, 200);
        t.feed(br#"{"id":1,"result":{}}"#);
        t.finish(End::Eof);
        t.finish(End::Dropped);
        drop(t);
        assert_eq!(done(&f).outcome, Outcome::Success);
    }

    #[test]
    fn a_dropped_tracker_reports_client_gone() {
        let (t, f) = tracker(Method::ToolsCall, "1", BodyMode::Sse, 200);
        drop(t);
        let c = done(&f);
        assert_eq!((c.outcome, c.cause), (Outcome::Unknown, Cause::ClientGone));
    }

    #[test]
    fn a_dropped_ctx_before_dispatch_is_not_sent() {
        let rec = Arc::new(Rec::default());
        let reg = Arc::new(CancelRegistry::default());
        let key = CancelKey {
            route: "r".into(),
            principal: "p".into(),
            session: crate::mcp::cancel::CancelScope::Session(1),
            id: RequestId::from_raw("1").unwrap(),
        };
        let ctx = CallCtx::new(
            rec.clone(),
            CallRef {
                seq: 1,
                route_id: "r".into(),
                principal_id: "p".into(),
                scope: None,
                audit: None,
                session: None,
            },
            Method::ToolsCall,
            RequestId::from_raw("1").unwrap(),
            Instant::now(),
            reg.register(key, 1, tokio::time::Instant::now()).unwrap(),
        );
        drop(ctx);
        let g = rec.0.lock().unwrap();
        match &g[0] {
            Observation::Completed(c) => assert_eq!(c.delivery, Delivery::NotSent),
            o => panic!("{o:?}"),
        }
    }

    // ------------------------------------------------------------- tools/list

    fn list_body(tools: &str, extra: &str) -> String {
        format!(r#"{{"jsonrpc":"2.0","id":1,"result":{{"tools":[{tools}]{extra}}}}}"#)
    }

    fn page(c: &Completed) -> &ToolListPage {
        match c.tool_list.as_ref().unwrap() {
            ToolListCapture::Page(p) => p,
            o => panic!("{o:?}"),
        }
    }

    #[test]
    fn tools_list_page_is_exposed_with_cursor() {
        let body = list_body(
            r#"{"name":"a","description":"d","inputSchema":{"type":"object"}},{"name":"b"}"#,
            r#","nextCursor":"CUR""#,
        );
        for mode in [BodyMode::Json, BodyMode::Sse] {
            let (mut t, f) = tracker(Method::ToolsList, "1", mode, 200);
            if mode == BodyMode::Json {
                t.feed(body.as_bytes());
            } else {
                t.feed(format!("data: {body}\n\n").as_bytes());
            }
            t.finish(End::Eof);
            let c = done(&f);
            assert_eq!(c.outcome, Outcome::Success);
            let p = page(&c);
            assert_eq!(p.tools.len(), 2);
            assert_eq!(p.tools[0].name.as_str(), "a");
            assert_eq!(
                &*p.tools[0].definition,
                r#"{"name":"a","description":"d","inputSchema":{"type":"object"}}"#
            );
            assert_eq!(p.next_cursor.as_ref().unwrap().as_str(), "CUR");
            // nothing readable in Debug
            let d = format!("{c:?}");
            assert!(
                !d.contains("CUR") && !d.contains("description") && !d.contains("\"a\""),
                "{d}"
            );
        }
        // last page: no cursor; empty page is valid
        let (mut t, f) = tracker(Method::ToolsList, "1", BodyMode::Json, 200);
        t.feed(list_body("", "").as_bytes());
        t.finish(End::Eof);
        let c = done(&f);
        assert!(page(&c).tools.is_empty() && page(&c).next_cursor.is_none());
    }

    #[test]
    fn tools_list_page_unavailable_cases() {
        let run = |body: &str, status: u16, mode: BodyMode, caplim: CaptureLimits| {
            let (mut t, f) = tracker(Method::ToolsList, "1", mode, status);
            t.caplimits = caplim;
            if let Some(c) = t.capture.as_mut() {
                c.max = caplim.max_bytes;
            }
            t.feed(body.as_bytes());
            t.finish(End::Eof);
            let c = done(&f);
            match c.tool_list.clone().unwrap() {
                ToolListCapture::Unavailable(u) => (c.outcome, u),
                o => panic!("{o:?}"),
            }
        };
        let big = CaptureLimits {
            max_bytes: 1 << 20,
            max_tools: 100,
        };
        for (body, want) in [
            (
                list_body(r#"{"name":"a"},{"nameless":1}"#, ""),
                PageUnavailable::Unparseable,
            ),
            (list_body(r#"{"name":5}"#, ""), PageUnavailable::Unparseable),
            (
                list_body(r#"{"name":""}"#, ""),
                PageUnavailable::Unparseable,
            ),
            (list_body(r#"1"#, ""), PageUnavailable::Unparseable),
            (
                list_body(r#"{"name":"a"}"#, r#","nextCursor":5"#),
                PageUnavailable::CursorInvalid,
            ),
            (
                list_body(
                    r#"{"name":"a"}"#,
                    &format!(r#","nextCursor":"{}""#, "c".repeat(5000)),
                ),
                PageUnavailable::CursorInvalid,
            ),
            (
                r#"{"jsonrpc":"2.0","id":1,"result":{}}"#.to_string(),
                PageUnavailable::Unparseable,
            ),
        ] {
            let (o, u) = run(&body, 200, BodyMode::Json, big);
            assert_eq!((o, u), (Outcome::Success, want), "{body}");
        }
        // tool limit
        let (o, u) = run(
            &list_body(r#"{"name":"a"},{"name":"b"},{"name":"c"}"#, ""),
            200,
            BodyMode::Json,
            CaptureLimits {
                max_bytes: 1 << 20,
                max_tools: 2,
            },
        );
        assert_eq!((o, u), (Outcome::Success, PageUnavailable::TooManyTools));
        // capture bound
        let (o, u) = run(
            &list_body(
                &format!(r#"{{"name":"a","description":"{}"}}"#, "d".repeat(500)),
                "",
            ),
            200,
            BodyMode::Json,
            CaptureLimits {
                max_bytes: 100,
                max_tools: 100,
            },
        );
        assert_eq!((o, u), (Outcome::Success, PageUnavailable::TooLarge));
        // an oversized event in SSE
        let (o, u) = run(
            &format!(
                "data: {}\n\n",
                list_body(&format!(r#"{{"name":"a","d":"{}"}}"#, "d".repeat(500)), "")
            ),
            200,
            BodyMode::Sse,
            CaptureLimits {
                max_bytes: 100,
                max_tools: 100,
            },
        );
        assert_eq!((o, u), (Outcome::Success, PageUnavailable::TooLarge));
        // errors and failures
        let (o, u) = run(
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"m"}}"#,
            200,
            BodyMode::Json,
            big,
        );
        assert_eq!((o, u), (Outcome::JsonRpcError, PageUnavailable::NoSuccess));
        let (o, u) = run("down", 503, BodyMode::Json, big);
        assert_eq!(
            (o, u),
            (Outcome::TransportFailure, PageUnavailable::NoSuccess)
        );
    }

    #[test]
    fn tools_list_encoded_is_unobservable() {
        let (mut t, f) = tracker(Method::ToolsList, "1", BodyMode::Opaque, 200);
        t.feed(b"zzz");
        t.finish(End::Eof);
        let c = done(&f);
        assert!(matches!(
            c.tool_list,
            Some(ToolListCapture::Unavailable(PageUnavailable::Unobservable))
        ));
    }

    #[test]
    fn non_list_calls_carry_no_tool_list() {
        let c = json(
            Method::ToolsCall,
            "1",
            200,
            r#"{"id":1,"result":{"tools":[{"name":"x"}]}}"#,
        );
        assert!(c.tool_list.is_none());
    }

    #[test]
    fn duration_and_sizes_are_recorded() {
        let (mut t, f) = tracker(Method::ToolsCall, "1", BodyMode::Json, 200);
        let body = br#"{"id":1,"result":{}}"#;
        t.feed(body);
        std::thread::sleep(Duration::from_millis(2));
        t.finish(End::Eof);
        let c = done(&f);
        assert_eq!(c.response_bytes, body.len() as u64);
        assert!(c.duration >= Duration::from_millis(2));
    }
}
