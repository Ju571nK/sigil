//! The observation seam (T-12b1). The relay reports what it classified and
//! what happened; a producer (T-13 lifecycle, T-14 spool) consumes it. This
//! module has no I/O and no event schema: mapping onto
//! `proxy-event.schema.json` is the consumer's job.
//!
//! Observations carry CLASSIFICATION only: audit method, request ids, the
//! tool name (for local inventory lookup), outcome and delivery classes,
//! sizes and timings, and the provenance of the applied config that routed the
//! call ([`AuditContext`]). They never carry argument values, results, error
//! messages, session ids (a session is a process-local number), headers,
//! tokens, cursors or cancel reasons. The only
//! untrusted content that crosses the seam is the `tools/list` page
//! ([`ToolListPage`]), which T-13 needs for the inventory and registry; its
//! types print nothing of their content in `Debug`.

use crate::inventory::CursorTag;
use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, SystemTime};

pub use super::classify::{Method, RefusalKind, RequestId, ToolField, ToolName};

/// Identifies one call inside the relay. `seq` is a process-local counter, NOT
/// an invocation id (the producer allocates those).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallRef {
    pub seq: u64,
    pub route_id: String,
    pub principal_id: String,
    /// The scope of the route in the very table that routed this call (T-13c).
    /// `None`: the route has no scope (no applied config).
    pub scope: Option<std::sync::Arc<crate::route::RouteScope>>,
    /// Audit provenance from the same table snapshot (T-13d). `None`: the table
    /// has no applied revision or scope, so the call cannot be audited.
    pub audit: Option<std::sync::Arc<AuditContext>>,
    /// The proxy session the call belongs to (T-12b2): a process-local number,
    /// never the wire id. `None` for `initialize` and for calls refused before
    /// a session was established.
    pub session: Option<u64>,
}

/// Where a call's audit identity comes from: the applied route/credential
/// configuration that routed it, fixed when the call was accepted (README
/// "upstream_id/route_revision은 호출 시작 당시 값으로 고정", N3). Nothing here
/// comes from client input.
#[derive(Clone, Debug, PartialEq)]
pub struct AuditContext {
    pub route_revision: sigil_proxy_api::PositiveI64,
    pub upstream_id: sigil_proxy_api::Id,
    pub actor: sigil_proxy_api::event::Actor,
}

impl Eq for AuditContext {}

/// A client request that passed classification and is about to be dispatched.
/// Delivered through [`ObservationSink::request_started`], which may defer
/// dispatch (the LOCAL spool commit of the start event, README "Traffic").
#[derive(Clone, Debug)]
pub struct RequestStarted {
    pub call: CallRef,
    pub method: Method,
    pub request_id: RequestId,
    pub tool: ToolField,
    /// `tools/list`: the keyed tag of the cursor the request carried (`None`:
    /// no cursor). The value itself is never kept; the tag is made by the
    /// process's `CursorHasher`, the same one that tags a page's `nextCursor`,
    /// so a continuation can be matched to the page that handed it out.
    pub list_cursor: Option<CursorTag>,
    /// `tools/call`: `params.task` was present (forwarded unchanged).
    pub task_augmented: bool,
    pub request_bytes: u64,
    pub received_at: SystemTime,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartVerdict {
    /// Dispatch the request.
    Proceed,
    /// Do not dispatch; the client gets a fixed 503. No completion is
    /// reported for this call. (P1: spool full, `allow-with-gap` is later.)
    Refuse,
}

/// A request the proxy answered itself or refused before dispatch because of
/// its classification. Upstream was not contacted (`delivery = not_sent`,
/// outcome `protocol_error`). `method`/`tool` support emitting the start and
/// completion pair for the same call.
#[derive(Clone, Debug)]
pub struct RequestRefused {
    pub call: CallRef,
    pub reason: RefusalKind,
    pub method: Method,
    pub request_id: Option<RequestId>,
    pub tool: ToolField,
    /// The HTTP status the client was sent.
    pub http_status: u16,
    pub request_bytes: u64,
    pub received_at: SystemTime,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CancelDisposition {
    /// The target had not been dispatched; it never will be. Not forwarded.
    /// (Followed by a `Completed` with `Cause::CancelledBeforeDispatch`.)
    BeforeDispatch,
    /// The target was dispatched; the cancel was forwarded.
    AfterDispatch,
}

/// `invocation.cancel_requested` material for a cancel that matched a request.
/// Cancels that match nothing are counted, not reported
/// ([`super::cancel::CancelRegistry::unmatched_total`]).
#[derive(Clone, Debug)]
pub struct CancelObserved {
    pub target: CallRef,
    pub target_id: RequestId,
    pub disposition: CancelDisposition,
    pub at: SystemTime,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// A JSON-RPC result (for `tools/call`, `isError` is not true).
    Success,
    /// `tools/call` result with `isError: true`.
    ToolError,
    /// A JSON-RPC error response.
    JsonRpcError,
    /// The proxy refused the upstream's answer for a protocol reason (see the
    /// `Upstream*`/`TaskHandle` causes). Never a success.
    ProtocolError,
    /// Upstream could not be used or answered with a non-JSON-RPC failure
    /// status; see [`Cause`].
    TransportFailure,
    /// The proxy-enforced deadline passed.
    Timeout,
    /// Upstream accepted the request and no response was observed (closed,
    /// aborted, unparseable, unobservable). Never inferred as failure or
    /// success (PX-015).
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Delivery {
    NotSent,
    Sent,
    Unknown,
}

/// The detail behind an outcome. A closed vocabulary; contains no content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cause {
    /// The response was classified from a JSON-RPC message.
    None,
    // before dispatch
    Unresolved,
    DestinationRefused,
    ConnectFailed,
    ConnectTimeout,
    UpstreamRequestBuild,
    CancelledBeforeDispatch,
    // after dispatch, no usable response
    SendFailed,
    FirstByteTimeout,
    IdleTimeout,
    CallTimeout,
    ResponseTooLarge,
    StreamError,
    /// Upstream answered 2xx and the stream ended with no response message.
    StreamClosedWithoutResponse,
    /// 2xx, but the body was not a JSON-RPC message.
    ResponseUnparseable,
    /// A response message was seen, for a different id.
    ResponseIdMismatch,
    /// The body is content-encoded; the proxy does not decode it.
    Unobservable,
    UpstreamStatus(u16),
    /// Upstream 401/403, mapped to the fixed error.
    UpstreamAuthRejected,
    UpstreamRedirect,
    /// The client went away before the response ended.
    ClientGone,
    /// A cancel was forwarded and no response arrived within the grace.
    CancelNoResponse,
    /// `initialize` answered with a revision outside the allowlist.
    UpstreamVersionUnsupported,
    /// `initialize` answered with `capabilities.tasks` or
    /// `capabilities.resources.subscribe = true`.
    UpstreamCapabilityUnsupported,
    /// `initialize` answer not readable within the bound or timeout.
    UpstreamInitializeUnreadable,
    /// `tools/call` answered with a task handle (N10 ii), relayed unchanged.
    TaskHandle,
    /// Upstream answered 404 for a call in a proxy session: the session ended.
    UpstreamSessionEnded,
    /// `initialize` refused locally: the route's binding is already marked
    /// `unsupported` (no reason on the completion).
    RouteUnsupported,
}

/// One tool of a `tools/list` page, exactly as upstream sent it.
#[derive(Clone)]
pub struct ToolDescriptor {
    /// Validated, bounded name (untrusted content).
    pub name: ToolName,
    /// The tool object's JSON text, unchanged (untrusted content, at most
    /// [`MAX_DEFINITION_BYTES`]). T-13 canonicalises and fingerprints it.
    pub definition: Box<str>,
}

impl std::fmt::Debug for ToolDescriptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ToolDescriptor({} bytes)", self.definition.len())
    }
}

/// Per-entry bound, the registry upload limit (registry.md R2).
pub const MAX_DEFINITION_BYTES: usize = 256 * 1024;

/// Longest `nextCursor` kept. A longer one makes the page unusable.
/// // OPEN: not in D-04.
pub const MAX_NEXT_CURSOR_BYTES: usize = 4096;

#[derive(Clone, Debug)]
pub struct ToolListPage {
    pub tools: Vec<ToolDescriptor>,
    /// Present iff upstream sent a `nextCursor` (opaque, bounded). Kept only so
    /// the producer can tell a last page (`None`) from a middle page.
    pub next_cursor: Option<NextCursor>,
}

/// An opaque pagination cursor. Never printed.
#[derive(Clone, PartialEq, Eq)]
pub struct NextCursor(String);

impl NextCursor {
    pub fn new(s: &str) -> Option<NextCursor> {
        (s.len() <= MAX_NEXT_CURSOR_BYTES).then(|| NextCursor(s.to_string()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for NextCursor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NextCursor(<opaque>)")
    }
}

/// Why a page cannot be used for an inventory (maps to the registry.md
/// `incomplete_reason` values: `page_error`, `size_limit_exceeded`,
/// `tool_limit_exceeded`, `canonicalization_failed`, `cursor_invalid`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageUnavailable {
    /// The response was a JSON-RPC error, a non-success outcome or had no
    /// response message.
    NoSuccess,
    /// Content-encoded response.
    Unobservable,
    /// The page exceeded the capture bound.
    TooLarge,
    /// More tools than `inventory_max_tools` on one page.
    TooManyTools,
    /// `result.tools` missing, not an array, or a tool without a valid name.
    Unparseable,
    /// `nextCursor` over the bound or not a string.
    CursorInvalid,
}

/// What T-13's inventory needs from a `tools/list` response.
#[derive(Clone, Debug)]
pub enum ToolListCapture {
    Page(ToolListPage),
    Unavailable(PageUnavailable),
}

/// The end of a forwarded call.
#[derive(Clone, Debug)]
pub struct Completed {
    pub call: CallRef,
    pub method: Method,
    pub request_id: RequestId,
    pub outcome: Outcome,
    pub delivery: Delivery,
    pub cause: Cause,
    /// Upstream HTTP status when a response head was received.
    pub http_status: Option<u16>,
    /// Response body bytes relayed.
    pub response_bytes: u64,
    /// Request received to completion.
    pub duration: Duration,
    pub completed_at: SystemTime,
    /// A cancel was forwarded for this request.
    pub cancel_requested: bool,
    /// `tools/list` calls only.
    pub tool_list: Option<ToolListCapture>,
}

#[derive(Clone, Debug)]
pub enum Observation {
    Refused(RequestRefused),
    Cancel(CancelObserved),
    Completed(Completed),
}

pub type SinkFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The consumer of observations. Called from relay tasks: implementations must
/// not block (use a bounded queue); a slow `request_started` delays dispatch of
/// that call only.
pub trait ObservationSink: Send + Sync + 'static {
    /// Called once per forwarded client request, before it is dispatched.
    /// Dispatch waits for the returned future. Default: proceed at once.
    fn request_started<'a>(&'a self, _: &'a RequestStarted) -> SinkFuture<'a, StartVerdict> {
        Box::pin(std::future::ready(StartVerdict::Proceed))
    }

    /// Everything else. Default: ignore.
    fn observe(&self, _: Observation) {}

    /// The proxy session `session` ended (DELETE, upstream 404, expiry, config
    /// change, shutdown). Default: ignore.
    fn session_ended(&self, _session: u64) {}

    /// False means every call to this sink would be a no-op, so the relay skips
    /// the response scanning, `tools/list` capture and observation building.
    /// Forwarded bytes and cancel ordering are the same either way.
    fn wants_observations(&self) -> bool {
        true
    }
}

/// Production default until a producer is wired in: observes nothing.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopSink;

impl ObservationSink for NoopSink {
    fn wants_observations(&self) -> bool {
        false
    }
}
