//! MCP request and response classification (T-12b1).
//!
//! The relay (`server.rs`) forwards raw bytes (D-01 relay-first). This module
//! reads a COPY of those bytes to decide, per message:
//!
//! - [`classify`]: method, id, tool name, cancel target; refusals for batches,
//!   `tasks/*`, subscriptions, modern-era requests and malformed input.
//! - [`cancel`]: M3 cancel ordering.
//! - [`response`] / [`scan`]: outcome of the upstream response (JSON or SSE)
//!   without buffering it.
//! - [`observation`]: the typed seam a producer (T-13) plugs into.
//!
//! No MCP SDK type is used anywhere on this path.

pub mod cancel;
pub mod classify;
pub mod initialize;
pub mod observation;
pub mod response;
pub mod scan;

pub use classify::{
    classify, HeaderVersion, ListCursor, Message, Method, NotificationInfo, Refusal, RefusalKind,
    RequestId, RequestInfo, ToolField, ToolName,
};
pub use observation::{
    CallRef, CancelDisposition, CancelObserved, Cause, Completed, Delivery, NoopSink, Observation,
    ObservationSink, Outcome, PageUnavailable, RequestRefused, RequestStarted, StartVerdict,
    ToolDescriptor, ToolListCapture, ToolListPage,
};
