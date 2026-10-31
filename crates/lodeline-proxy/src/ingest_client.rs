//! Event ingest client (T-11 S4 slice C, #275): `POST /v1/proxy-events` over the
//! shared mTLS exchange, with the answer rules of the contracts README and the
//! gap rules of ledger-and-query.md L4/L6b.
//!
//! * [`EventSource`] is the seam to the event producer. In production it is the
//!   durable spool ([`crate::spool::Spool`], T-14b); tests feed it in memory.
//! * [`classify_ingest`] reduces the server's answer to an [`IngestOutcome`]; it
//!   is pure.
//! * [`IngestClient`] builds batches (at most [`MAX_BATCH_EVENTS`] events and
//!   [`MAX_BATCH_BYTES`] serialized, split before sending), sends them and
//!   applies the outcome to the source and to the [`GapQueue`].
//! * [`run_ingest`] is the paced loop.
//!
//! Answer rules, all fail closed:
//!
//! | answer | effect |
//! |---|---|
//! | 200 | `accepted` and `duplicate` ids are durable: acknowledged to the source |
//! | 409 `conflict`, `sequence_conflict`, `invocation_owner_conflict` by item | those events are quarantined unchanged, a `event_quarantined` gap is queued, the rest is resent |
//! | 422 `semantic_invalid` by index | same, code `semantic_invalid`, under the limit below |
//! | 409/422 naming nothing usable | batch of one: quarantined under the limit below; larger batch: send singles until the failing event is found, then back to batches (F2) |
//! | 424 `metadata_ref_pending` | the named events are held and retried later with growing, bounded delay; nothing is quarantined |
//! | 413 | halve the batch; a single event is quarantined (`semantic_invalid`) under the limit below |
//! | 429 | backoff |
//! | 503 `storage_limit` | backoff; the server is up, so this is NOT a central outage |
//! | other 5xx, no answer | backoff; counts toward a `central_outage` gap |
//! | 403 `disabled`/`retired` | long backoff, nothing changes locally (the config fetch is the authority) |
//! | anything else (404, 401, unreadable 200, ...) | backoff |
//!
//! [`MAX_CONSECUTIVE_SINGLE_QUARANTINES`] is the limit: past it, these answers
//! quarantine nothing and back off, and only a 200 clears the count.
//!
//! An event is never rewritten and never given a new id: the bytes sent for an
//! event are those it serialized to from the source, on every retry.
//!
//! Nothing here logs a body, an event, an id or an address.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use lodeline_proxy_api::status::QuarantineCode;
use lodeline_proxy_api::{ErrorCode, GapReport, ProxyEvent};
use serde_json::json;
use tokio::time::Instant;

use crate::state_dir::OpenOutage;
use crate::status_report::{
    rfc3339, CentralHealth, GapQueue, PostFuture, StatusReply, MAX_ISOLATE_SENDS,
};

/// Events per request (`POST /v1/proxy-events`).
pub const MAX_BATCH_EVENTS: usize = 100;
/// Serialized bytes per request.
pub const MAX_BATCH_BYTES: usize = lodeline_proxy_api::parse::MAX_EVENT_BATCH_BYTES;
/// Largest answer read from the server. A 200 lists at most 200 ids; an error
/// lists at most 100 items.
pub const MAX_INGEST_RESPONSE_BYTES: usize = 64 * 1024;
/// Failed attempts in a row (no answer, or a 5xx other than `storage_limit`)
/// before a `central_outage` gap is opened.
pub const OUTAGE_THRESHOLD: u32 = 3;
/// Events held for a pending metadata ref. Beyond it an event is not held and is
/// simply retried with the normal backoff.
pub const MAX_HELD_EVENTS: usize = 1024;
/// Holds in a row after which the registry sync counts as stalled.
pub const STALL_ATTEMPTS: u32 = 5;
/// Answers that quarantine on the server's say-so (422 by index, unattributed
/// 422/409 or 413 on a single event) without a 200 in between. Past it,
/// quarantining stops and the client backs off: a server that rejects everything
/// must not drain the queue into quarantine. One answer counts once, however
/// many events it names. A 409 by item neither counts nor clears the count: the
/// server parsed that batch, so it is not this failure, and it is not a success.
pub const MAX_CONSECUTIVE_SINGLE_QUARANTINES: u32 = 8;
/// `{"events":[` and `]}`.
const BATCH_OVERHEAD: usize = 13;

/// Where events come from. The producer (the spool, T-13/T-14) implements this;
/// until then only tests do.
pub trait EventSource: Send {
    /// The oldest unsent events, oldest first, at most `max`, none of `skip`.
    /// Events handed out stay unsent until [`EventSource::acknowledged`] or
    /// [`EventSource::quarantined`].
    fn next_events(&mut self, max: usize, skip: &HashSet<String>) -> Vec<ProxyEvent>;
    /// The server durably holds these events (accepted or duplicate).
    fn acknowledged(&mut self, event_ids: &[String]);
    /// These events are rejected for good. Keep them unchanged in a local
    /// quarantine; never send them again, never rewrite them.
    fn quarantined(&mut self, event_ids: &[String], code: QuarantineCode);

    // Async variants, which the ingest loop calls (M2). The defaults run the
    // synchronous method inline, which is right for an in-memory source. A
    // source that waits on I/O (the spool: an fsync behind a writer thread)
    // overrides them so no tokio worker blocks.
    fn next_events_async<'a>(
        &'a mut self,
        max: usize,
        skip: &'a HashSet<String>,
    ) -> SourceFuture<'a, Vec<ProxyEvent>> {
        Box::pin(async move { self.next_events(max, skip) })
    }
    fn acknowledged_async<'a>(&'a mut self, event_ids: &'a [String]) -> SourceFuture<'a, ()> {
        Box::pin(async move { self.acknowledged(event_ids) })
    }
    fn quarantined_async<'a>(
        &'a mut self,
        event_ids: &'a [String],
        code: QuarantineCode,
    ) -> SourceFuture<'a, ()> {
        Box::pin(async move { self.quarantined(event_ids, code) })
    }
}

/// Boxed future returned by the async [`EventSource`] methods.
pub type SourceFuture<'a, T> = std::pin::Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// How batches are sent. `None` means no answer (transport error, timeout, bad
/// TLS material).
pub trait IngestTransport: Send + Sync {
    fn post_events(&self, body: Vec<u8>) -> PostFuture<'_>;
}

// ------------------------------------------------------------------ outcomes

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IngestOutcome {
    /// 200: these (sent) ids are durable.
    Done { ids: Vec<String> },
    /// 409 or 422 that names events: quarantine exactly these.
    Quarantine {
        items: Vec<(String, QuarantineCode)>,
    },
    /// 409 or 422 that names nothing usable.
    Unattributed { status: u16 },
    /// 424: these events wait for a metadata ref to be registered.
    Pending { ids: Vec<String> },
    /// 413.
    TooLarge,
    /// 404 (`proxy_unknown`): the server does not know this identity. Backed off
    /// like a failure, but it is not an outage and not a healthy answer.
    Unregistered,
    /// 429.
    RateLimited,
    /// 503 `storage_limit`: server storage, not an outage.
    StorageLimit,
    /// 403 `disabled` or `retired`.
    Rejected,
    /// No answer at all.
    Unreachable,
    /// 5xx that is not `storage_limit`.
    Unavailable,
    /// Any other answer (404, 401, an unreadable 200, ...).
    Retry,
}

impl IngestOutcome {
    /// Whether this answer counts toward a `central_outage` gap. A refusal for
    /// server storage or load does not: the server is up and answering.
    pub fn signals_central_outage(&self) -> bool {
        matches!(
            self,
            IngestOutcome::Unreachable | IngestOutcome::Unavailable
        )
    }
}

fn quarantine_code(c: &ErrorCode) -> QuarantineCode {
    match c {
        ErrorCode::SequenceConflict => QuarantineCode::SequenceConflict,
        ErrorCode::SemanticInvalid => QuarantineCode::SemanticInvalid,
        // `invocation_owner_conflict` has no code of its own in the gap schema
        // (L4: conflict, sequence_conflict, semantic_invalid).
        _ => QuarantineCode::Conflict,
    }
}

/// Reduce an answer to an outcome. `sent` are the event ids in the request, in
/// order (the `index` of a 422 item refers to this order). Pure.
pub fn classify_ingest(reply: Option<&StatusReply>, sent: &[String]) -> IngestOutcome {
    let Some(r) = reply else {
        return IngestOutcome::Unreachable;
    };
    let in_sent = |id: &str| sent.iter().any(|s| s == id);
    let err = || lodeline_proxy_api::parse_api_error(&r.body).ok();
    let dedup = |v: &mut Vec<String>| {
        let mut seen = HashSet::new();
        v.retain(|i| seen.insert(i.clone()));
    };
    match r.status {
        200 => match lodeline_proxy_api::parse_ingest_response(&r.body) {
            Ok(ok) => {
                let mut ids: Vec<String> = ok
                    .accepted_event_ids
                    .iter()
                    .chain(ok.duplicate_event_ids.iter())
                    .map(|u| u.as_str().to_string())
                    .filter(|i| in_sent(i))
                    .collect();
                dedup(&mut ids);
                if ids.is_empty() {
                    IngestOutcome::Retry
                } else {
                    IngestOutcome::Done { ids }
                }
            }
            Err(_) => IngestOutcome::Retry,
        },
        403 => match err().map(|e| e.error.code) {
            Some(ErrorCode::Disabled | ErrorCode::Retired) => IngestOutcome::Rejected,
            _ => IngestOutcome::Retry,
        },
        409 => {
            let items = err().and_then(|e| e.error.items).unwrap_or_default();
            let mut out: Vec<(String, QuarantineCode)> = Vec::new();
            for it in &items {
                if let Some(id) = it.event_id.as_ref().map(|u| u.as_str()) {
                    if in_sent(id) && !out.iter().any(|(o, _)| o == id) {
                        out.push((id.to_string(), quarantine_code(&it.code)));
                    }
                }
            }
            if out.is_empty() {
                IngestOutcome::Unattributed { status: 409 }
            } else {
                IngestOutcome::Quarantine { items: out }
            }
        }
        422 => {
            let items = err().and_then(|e| e.error.items).unwrap_or_default();
            let mut out: Vec<(String, QuarantineCode)> = Vec::new();
            for it in &items {
                if let Some(id) = sent.get(it.index as usize) {
                    if !out.iter().any(|(o, _)| o == id) {
                        out.push((id.clone(), QuarantineCode::SemanticInvalid));
                    }
                }
            }
            if out.is_empty() {
                IngestOutcome::Unattributed { status: 422 }
            } else {
                IngestOutcome::Quarantine { items: out }
            }
        }
        424 => match err() {
            Some(e) if e.error.code == ErrorCode::MetadataRefPending => {
                let mut ids: Vec<String> = e
                    .error
                    .items
                    .unwrap_or_default()
                    .iter()
                    .filter_map(|i| i.event_id.as_ref().map(|u| u.as_str().to_string()))
                    .filter(|i| in_sent(i))
                    .collect();
                dedup(&mut ids);
                // The whole request was refused; naming nothing means every
                // event in it waits (retry later, never quarantine).
                if ids.is_empty() {
                    ids = sent.to_vec();
                }
                IngestOutcome::Pending { ids }
            }
            _ => IngestOutcome::Retry,
        },
        404 => IngestOutcome::Unregistered,
        413 => IngestOutcome::TooLarge,
        429 => IngestOutcome::RateLimited,
        503 => match err().map(|e| e.error.code) {
            Some(ErrorCode::StorageLimit) => IngestOutcome::StorageLimit,
            _ => IngestOutcome::Unavailable,
        },
        s if (500..600).contains(&s) => IngestOutcome::Unavailable,
        _ => IngestOutcome::Retry,
    }
}

// ------------------------------------------------------------------- batches

/// The events chosen for one request and their serialized form.
struct Batch {
    ids: Vec<String>,
    body: Vec<u8>,
    /// Events that can never be sent (cannot serialize, or alone exceed the
    /// byte limit): quarantined locally without a request.
    unsendable: Vec<String>,
}

/// Take a prefix of `events` that fits `max_events` and `max_bytes` serialized.
/// Pure. Events that cannot be sent even alone are listed in `unsendable` and
/// skipped; the batch is built from the rest.
fn build_batch(events: &[ProxyEvent], max_events: usize, max_bytes: usize) -> Batch {
    let mut pieces: Vec<Vec<u8>> = Vec::new();
    let mut ids = Vec::new();
    let mut unsendable = Vec::new();
    let mut total = BATCH_OVERHEAD;
    for ev in events {
        if ids.len() >= max_events {
            break;
        }
        let id = ev.event_id.as_str().to_string();
        let Ok(bytes) = serde_json::to_vec(ev) else {
            unsendable.push(id);
            continue;
        };
        if BATCH_OVERHEAD + bytes.len() > max_bytes {
            unsendable.push(id);
            continue;
        }
        let extra = bytes.len() + usize::from(!pieces.is_empty());
        if total + extra > max_bytes {
            break;
        }
        total += extra;
        pieces.push(bytes);
        ids.push(id);
    }
    let mut body = Vec::with_capacity(total);
    body.extend_from_slice(b"{\"events\":[");
    for (i, p) in pieces.iter().enumerate() {
        if i > 0 {
            body.push(b',');
        }
        body.extend_from_slice(p);
    }
    body.extend_from_slice(b"]}");
    Batch {
        ids,
        body,
        unsendable,
    }
}

// -------------------------------------------------------------------- client

#[derive(Debug, Clone, Copy)]
pub struct IngestParams {
    /// Wait when the source has nothing to send.
    pub poll: Duration,
    /// First retry delay after a failure; doubles up to `max_backoff`.
    pub retry: Duration,
    pub max_backoff: Duration,
    /// Least spacing between two requests; singles in isolation go at this pace.
    pub min_spacing: Duration,
}

impl Default for IngestParams {
    /// Proposed values (unmeasured), like the status reporter.
    fn default() -> Self {
        IngestParams {
            poll: Duration::from_secs(1),
            retry: Duration::from_secs(5),
            max_backoff: Duration::from_secs(300),
            min_spacing: Duration::from_millis(200),
        }
    }
}

/// How events are sent after an unattributed 409/422: the failing event is
/// found by sending singles, then batches resume (F2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Batch,
    Isolate,
}

struct Hold {
    attempts: u32,
    until: Instant,
}

#[derive(Default)]
struct Outage {
    streak: u32,
    first_failure_at: Option<String>,
    /// The opened gap (mirrored in the persisted queue state).
    open: Option<OpenOutage>,
    /// The open gap did not fit in the queue (counted as overflow), so there is
    /// nothing to close.
    not_queued: bool,
}

/// What one [`IngestClient::send_once`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngestStep {
    /// Events in the request that went out (0 when none did).
    pub sent: usize,
    /// The reduced answer; `None` when no request was made.
    pub outcome: Option<IngestOutcome>,
    /// Events quarantined locally before sending (oversize or unserializable).
    pub local_quarantined: usize,
    /// The request made progress (an answer that moved events on). Without it
    /// the next attempt backs off.
    pub progressed: bool,
}

pub struct IngestClient {
    gaps: GapQueue,
    central: CentralHealth,
    params: IngestParams,
    mode: Mode,
    isolate_sends: usize,
    max_events: usize,
    max_bytes: usize,
    /// Current event cap; halved by a 413, doubled back by successes.
    cap: usize,
    failures: u32,
    /// See [`MAX_CONSECUTIVE_SINGLE_QUARANTINES`].
    single_quarantines: u32,
    holds: HashMap<String, Hold>,
    outage: Outage,
    /// Mirror of [`IngestClient::registry_sync_stalled`] for the status report
    /// (the client itself moves into the ingest task).
    stalled: Arc<AtomicBool>,
}

impl IngestClient {
    pub fn new(gaps: GapQueue, central: CentralHealth, params: IngestParams) -> IngestClient {
        // An open outage left in the (reloaded) queue is closed when the server
        // next answers.
        let open = gaps.open_outage();
        IngestClient {
            gaps,
            central,
            params,
            mode: Mode::Batch,
            isolate_sends: 0,
            max_events: MAX_BATCH_EVENTS,
            max_bytes: MAX_BATCH_BYTES,
            cap: MAX_BATCH_EVENTS,
            failures: 0,
            single_quarantines: 0,
            holds: HashMap::new(),
            outage: Outage {
                open,
                ..Outage::default()
            },
            stalled: Arc::new(AtomicBool::new(false)),
        }
    }

    /// A flag that follows [`IngestClient::registry_sync_stalled`] after every
    /// request, readable while the client runs in its task.
    pub fn registry_stalled_flag(&self) -> Arc<AtomicBool> {
        self.stalled.clone()
    }

    /// Test knob: smaller batch limits.
    #[cfg(any(test, feature = "test-util"))]
    pub fn with_batch_limits(mut self, max_events: usize, max_bytes: usize) -> IngestClient {
        self.max_events = max_events.clamp(1, MAX_BATCH_EVENTS);
        self.cap = self.max_events;
        self.max_bytes = max_bytes.min(MAX_BATCH_BYTES);
        self
    }

    /// Holds make the registry sync look stalled after [`STALL_ATTEMPTS`] tries.
    pub fn registry_sync_stalled(&self) -> bool {
        self.holds.values().any(|h| h.attempts >= STALL_ATTEMPTS)
    }

    /// Events currently held for a pending metadata ref.
    pub fn held_events(&self) -> usize {
        self.holds.len()
    }

    /// F2 state, for tests and diagnostics.
    pub fn isolating(&self) -> bool {
        self.mode == Mode::Isolate
    }

    async fn quarantine(
        &mut self,
        source: &mut dyn EventSource,
        ids: &[String],
        code: QuarantineCode,
    ) {
        if ids.is_empty() {
            return;
        }
        // The gap is recorded (and persisted) before the source moves the
        // events, so a crash in between leaves a gap for events still unsent,
        // never quarantined events without a gap.
        let now = rfc3339(time::OffsetDateTime::now_utc());
        for chunk in ids.chunks(100) {
            let gap = serde_json::from_value::<GapReport>(json!({
                "kind": "event_quarantined",
                "gap_id": uuid::Uuid::new_v4().to_string(),
                "detected_at": now,
                "event_ids": chunk,
                "code": code,
            }));
            match gap {
                Ok(g) => {
                    self.gaps.record(g);
                }
                Err(_) => tracing::error!("event_quarantined gap did not build"),
            }
        }
        source.quarantined_async(ids, code).await;
        for id in ids {
            self.holds.remove(id);
        }
        tracing::warn!(count = ids.len(), "events quarantined");
    }

    fn open_outage(&mut self) {
        let started = self
            .outage
            .first_failure_at
            .clone()
            .unwrap_or_else(|| rfc3339(time::OffsetDateTime::now_utc()));
        let open = OpenOutage {
            gap_id: uuid::Uuid::new_v4().to_string(),
            started_at: started,
            detected_at: rfc3339(time::OffsetDateTime::now_utc()),
        };
        match outage_gap(&open, None) {
            Some(g) => {
                // Marker first, gap second: a crash between the two flushes
                // leaves a marker without a gap (harmless, the close is still
                // sent), never a gap without a marker.
                self.gaps.set_open_outage(Some(open.clone()));
                self.outage.not_queued = !self.gaps.record(g);
                if self.outage.not_queued {
                    // Counted as overflow: there is no gap to close.
                    self.gaps.set_open_outage(None);
                }
                self.outage.open = Some(open);
                tracing::warn!("central outage opened");
            }
            None => tracing::error!("central_outage gap did not build"),
        }
    }

    /// The server answered: end the failure streak and close an open outage gap
    /// (the same `gap_id`, with `ended_at`, resent until acknowledged).
    fn server_answered(&mut self) {
        self.central.record_answer();
        self.outage.streak = 0;
        self.outage.first_failure_at = None;
        if let Some(open) = self.outage.open.take() {
            // An outage that did not fit in the queue was counted as overflow:
            // there is no gap to close.
            if !std::mem::take(&mut self.outage.not_queued) {
                let ended = rfc3339(time::OffsetDateTime::now_utc());
                // Normally the gap is still queued; if it was acknowledged
                // already, the server holds it open, so it is sent again. Either
                // way it equals the original apart from `ended_at` (L6b).
                if !self.gaps.close_outage(&open.gap_id, &ended) {
                    if let Some(g) = outage_gap(&open, Some(&ended)) {
                        self.gaps.record(g);
                    }
                }
            }
            self.gaps.set_open_outage(None);
            tracing::info!("central outage closed");
        }
    }

    /// Build, send and settle one request. Does nothing when the source has no
    /// event that is not held.
    pub async fn send_once<T, S>(
        &mut self,
        transport: &T,
        source: &mut S,
        now: Instant,
    ) -> IngestStep
    where
        T: IngestTransport + ?Sized,
        S: EventSource,
    {
        let step = self.send_once_inner(transport, source, now).await;
        self.stalled
            .store(self.registry_sync_stalled(), Ordering::Relaxed);
        step
    }

    async fn send_once_inner<T, S>(
        &mut self,
        transport: &T,
        source: &mut S,
        now: Instant,
    ) -> IngestStep
    where
        T: IngestTransport + ?Sized,
        S: EventSource,
    {
        let skip: HashSet<String> = self
            .holds
            .iter()
            .filter(|(_, h)| h.until > now)
            .map(|(id, _)| id.clone())
            .collect();
        let want = if self.mode == Mode::Isolate {
            1
        } else {
            self.cap.min(self.max_events)
        };
        let events = source.next_events_async(want, &skip).await;
        if events.is_empty() {
            self.mode = Mode::Batch;
            return IngestStep {
                sent: 0,
                outcome: None,
                local_quarantined: 0,
                progressed: true,
            };
        }
        let batch = build_batch(&events, want, self.max_bytes);
        let local = batch.unsendable.len();
        self.quarantine(source, &batch.unsendable, QuarantineCode::SemanticInvalid)
            .await;
        if batch.ids.is_empty() {
            if local > 0 {
                self.isolated_locally();
            }
            return IngestStep {
                sent: 0,
                outcome: None,
                local_quarantined: local,
                progressed: true,
            };
        }
        // The shared parser is the contract check; a body it refuses is never
        // sent. A named bad event is quarantined; otherwise singles find it.
        if let Err(e) = lodeline_proxy_api::parse_event_batch(&batch.body) {
            match (e.index(), batch.ids.len()) {
                (Some(i), _) if i < batch.ids.len() => {
                    let id = batch.ids[i].clone();
                    self.quarantine(source, &[id], QuarantineCode::SemanticInvalid)
                        .await;
                    self.isolated_locally();
                }
                (_, 1) => {
                    let ids = batch.ids.clone();
                    self.quarantine(source, &ids, QuarantineCode::SemanticInvalid)
                        .await;
                    self.isolated_locally();
                }
                _ => {
                    self.mode = Mode::Isolate;
                    self.isolate_sends = 0;
                }
            }
            return IngestStep {
                sent: 0,
                outcome: None,
                local_quarantined: local + 1,
                progressed: true,
            };
        }

        let sent = batch.ids;
        let reply = transport.post_events(batch.body).await;
        let outcome = classify_ingest(reply.as_ref(), &sent);
        let progressed = self.apply(source, &outcome, &sent, now).await;
        tracing::info!(
            outcome = outcome_label(&outcome),
            events = sent.len(),
            "ingest"
        );
        IngestStep {
            sent: sent.len(),
            outcome: Some(outcome),
            local_quarantined: local,
            progressed,
        }
    }

    /// An event was quarantined without a request. During isolation that finds
    /// the failing event (and counts as one isolation step), so batches resume.
    fn isolated_locally(&mut self) {
        if self.mode == Mode::Isolate {
            self.mode = Mode::Batch;
            self.isolate_sends = 0;
        }
    }

    /// Quarantine events on the server's say-so, unless that has already
    /// happened [`MAX_CONSECUTIVE_SINGLE_QUARANTINES`] times without a success.
    /// Returns whether they were quarantined.
    async fn quarantine_single(
        &mut self,
        source: &mut dyn EventSource,
        ids: &[String],
        code: QuarantineCode,
    ) -> bool {
        if self.single_quarantines >= MAX_CONSECUTIVE_SINGLE_QUARANTINES {
            tracing::error!("the server keeps rejecting events: quarantine paused, backing off");
            return false;
        }
        self.single_quarantines += 1;
        self.quarantine(source, ids, code).await;
        true
    }

    /// Settle one answer. Returns whether it made progress (otherwise the caller
    /// backs off).
    async fn apply(
        &mut self,
        source: &mut dyn EventSource,
        outcome: &IngestOutcome,
        sent: &[String],
        now: Instant,
    ) -> bool {
        if outcome.signals_central_outage() {
            self.central.record_failure();
            self.outage.streak = self.outage.streak.saturating_add(1);
            if self.outage.streak == 1 {
                self.outage.first_failure_at = Some(rfc3339(time::OffsetDateTime::now_utc()));
            }
            if self.outage.streak >= OUTAGE_THRESHOLD && self.outage.open.is_none() {
                self.open_outage();
            }
        } else if !matches!(outcome, IngestOutcome::Unregistered) {
            // Any answer shows the server is up, a refusal for storage or load
            // included, and so is a rejection of this proxy's identity. A 404 is
            // neither healthy nor an outage: it changes nothing here.
            self.server_answered();
        }

        let mut progressed = true;
        match outcome {
            IngestOutcome::Done { ids } => {
                source.acknowledged_async(ids).await;
                for id in ids {
                    self.holds.remove(id);
                }
                self.central
                    .record_ingest_ack(time::OffsetDateTime::now_utc());
                self.cap = (self.cap * 2).clamp(1, self.max_events);
                self.single_quarantines = 0;
            }
            IngestOutcome::Quarantine { items } => {
                for code in [
                    QuarantineCode::Conflict,
                    QuarantineCode::SequenceConflict,
                    QuarantineCode::SemanticInvalid,
                ] {
                    let ids: Vec<String> = items
                        .iter()
                        .filter(|(_, c)| *c == code)
                        .map(|(i, _)| i.clone())
                        .collect();
                    if code != QuarantineCode::SemanticInvalid || ids.is_empty() {
                        self.quarantine(source, &ids, code).await;
                    } else if !self.quarantine_single(source, &ids, code).await {
                        progressed = false;
                    }
                }
            }
            IngestOutcome::Unattributed { status } => {
                if sent.len() > 1 {
                    // Not attributable: quarantine nothing. Singles find it.
                    self.mode = Mode::Isolate;
                    self.isolate_sends = 0;
                } else {
                    let code = if *status == 409 {
                        QuarantineCode::Conflict
                    } else {
                        QuarantineCode::SemanticInvalid
                    };
                    if !self.quarantine_single(source, sent, code).await {
                        self.mode = Mode::Batch;
                        progressed = false;
                    }
                }
            }
            IngestOutcome::Pending { ids } => {
                let mut held = false;
                for id in ids {
                    if !self.holds.contains_key(id) && self.holds.len() >= MAX_HELD_EVENTS {
                        continue;
                    }
                    held = true;
                    let h = self.holds.entry(id.clone()).or_insert(Hold {
                        attempts: 0,
                        until: now,
                    });
                    h.attempts = h.attempts.saturating_add(1);
                    let shift = (h.attempts - 1).min(16);
                    h.until = now
                        + self
                            .params
                            .retry
                            .saturating_mul(1u32 << shift)
                            .min(self.params.max_backoff)
                            .max(self.params.retry);
                }
                // Nothing held (the hold table is full): the same events would
                // go out again at once, so back off instead.
                progressed = held;
            }
            IngestOutcome::TooLarge => {
                if sent.len() > 1 {
                    self.cap = (sent.len() / 2).max(1);
                } else if !self
                    .quarantine_single(source, sent, QuarantineCode::SemanticInvalid)
                    .await
                {
                    progressed = false;
                }
            }
            IngestOutcome::RateLimited
            | IngestOutcome::StorageLimit
            | IngestOutcome::Unregistered
            | IngestOutcome::Rejected
            | IngestOutcome::Unreachable
            | IngestOutcome::Unavailable
            | IngestOutcome::Retry => progressed = false,
        }
        if progressed {
            self.failures = 0;
        }

        // F2: the failing event is found (quarantined alone, or named): batches
        // resume. A bound keeps a steady producer out of singles for good.
        if self.mode == Mode::Isolate {
            self.isolate_sends += 1;
            let found = matches!(outcome, IngestOutcome::Quarantine { .. })
                || (matches!(outcome, IngestOutcome::Unattributed { .. }) && sent.len() == 1);
            if found || self.isolate_sends > MAX_ISOLATE_SENDS {
                self.mode = Mode::Batch;
                self.isolate_sends = 0;
            }
        }
        progressed
    }

    /// Delay before the next request.
    pub fn next_delay(&mut self, step: &IngestStep) -> Duration {
        let p = self.params;
        let backoff = |f: &mut u32| {
            *f = f.saturating_add(1);
            let shift = (*f - 1).min(16);
            p.retry
                .saturating_mul(1u32 << shift)
                .min(p.max_backoff)
                .max(p.retry)
        };
        let d = match &step.outcome {
            None if step.local_quarantined > 0 => p.min_spacing,
            None => p.poll,
            Some(IngestOutcome::Rejected) => p.max_backoff,
            Some(_) if !step.progressed => backoff(&mut self.failures),
            // Progress: the rest goes out at the least spacing (singles too).
            Some(_) => p.min_spacing,
        };
        crate::config_sync::jitter(d).max(p.min_spacing)
    }
}

/// The `central_outage` gap of `open`, with `ended_at` as given. Every other
/// field is the original's.
fn outage_gap(open: &OpenOutage, ended_at: Option<&str>) -> Option<GapReport> {
    serde_json::from_value::<GapReport>(json!({
        "kind": "central_outage",
        "gap_id": open.gap_id,
        "detected_at": open.detected_at,
        "started_at": open.started_at,
        "ended_at": ended_at,
    }))
    .ok()
}

fn outcome_label(o: &IngestOutcome) -> &'static str {
    match o {
        IngestOutcome::Done { .. } => "accepted",
        IngestOutcome::Quarantine { .. } => "quarantined",
        IngestOutcome::Unattributed { .. } => "unattributed",
        IngestOutcome::Pending { .. } => "metadata_ref_pending",
        IngestOutcome::TooLarge => "payload_too_large",
        IngestOutcome::Unregistered => "unregistered",
        IngestOutcome::RateLimited => "rate_limited",
        IngestOutcome::StorageLimit => "storage_limit",
        IngestOutcome::Rejected => "rejected",
        IngestOutcome::Unreachable => "unreachable",
        IngestOutcome::Unavailable => "unavailable",
        IngestOutcome::Retry => "retry",
    }
}

/// Send events until `shutdown` completes. The production lifecycle starts it
/// with the spool as the [`EventSource`] (T-14b).
pub async fn run_ingest<T, S>(
    transport: &T,
    mut source: S,
    mut client: IngestClient,
    shutdown: impl Future<Output = ()>,
) where
    T: IngestTransport + ?Sized,
    S: EventSource,
{
    tokio::pin!(shutdown);
    loop {
        let step = tokio::select! {
            _ = &mut shutdown => return,
            s = client.send_once(transport, &mut source, Instant::now()) => s,
        };
        let delay = client.next_delay(&step);
        tokio::select! {
            _ = &mut shutdown => return,
            _ = tokio::time::sleep(delay) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    fn uid(n: u32) -> String {
        format!("00000000-0000-4000-8000-{n:012x}")
    }

    fn event(n: u32) -> ProxyEvent {
        serde_json::from_value(json!({
            "schema_version": 1, "event_id": uid(n), "proxy_id": "px-1",
            "epoch_id": uid(5000), "sequence": n.max(1),
            "occurred_at": "2026-10-14T00:00:00Z",
            "event_type": "invocation.started",
            "payload": {"invocation_id": uid(7000 + n), "upstream_id": "up-1",
                "route_revision": 1, "protocol_version": "2025-11-25", "method": "ping",
                "actor": {"actor_id": "a1", "actor_kind": "non_human",
                    "authentication_method": "bearer",
                    "evidence_source": "proxy_credential_mapping"}}
        }))
        .unwrap()
    }

    #[derive(Default)]
    struct Mem {
        unsent: Vec<ProxyEvent>,
        acked: Vec<String>,
        quarantined: Vec<(String, QuarantineCode)>,
        /// Looked at when `quarantined` is called (L4).
        probe: Option<GapQueue>,
        gaps_seen_at_quarantine: Vec<usize>,
    }

    impl Mem {
        fn with(n: std::ops::RangeInclusive<u32>) -> Mem {
            Mem {
                unsent: n.map(event).collect(),
                ..Mem::default()
            }
        }
    }

    impl EventSource for Mem {
        fn next_events(&mut self, max: usize, skip: &HashSet<String>) -> Vec<ProxyEvent> {
            self.unsent
                .iter()
                .filter(|e| !skip.contains(e.event_id.as_str()))
                .take(max)
                .cloned()
                .collect()
        }
        fn acknowledged(&mut self, ids: &[String]) {
            self.unsent
                .retain(|e| !ids.iter().any(|i| i == e.event_id.as_str()));
            self.acked.extend(ids.iter().cloned());
        }
        fn quarantined(&mut self, ids: &[String], code: QuarantineCode) {
            if let Some(q) = &self.probe {
                self.gaps_seen_at_quarantine.push(q.pending_ids().len());
            }
            self.unsent
                .retain(|e| !ids.iter().any(|i| i == e.event_id.as_str()));
            self.quarantined
                .extend(ids.iter().map(|i| (i.clone(), code)));
        }
    }

    /// Answers consumed in order; the last repeats. Records every body.
    struct Fake {
        replies: Mutex<VecDeque<Option<StatusReply>>>,
        bodies: Mutex<Vec<Vec<u8>>>,
    }

    impl Fake {
        fn new(r: Vec<Option<StatusReply>>) -> Arc<Fake> {
            Arc::new(Fake {
                replies: Mutex::new(r.into()),
                bodies: Mutex::default(),
            })
        }
        fn set(&self, r: Vec<Option<StatusReply>>) {
            *self.replies.lock().unwrap() = r.into();
        }
        fn posts(&self) -> Vec<Vec<u8>> {
            self.bodies.lock().unwrap().clone()
        }
        fn sent_ids(&self, i: usize) -> Vec<String> {
            let v: Value = serde_json::from_slice(&self.posts()[i]).unwrap();
            v["events"]
                .as_array()
                .unwrap()
                .iter()
                .map(|e| e["event_id"].as_str().unwrap().to_string())
                .collect()
        }
    }

    impl IngestTransport for Arc<Fake> {
        fn post_events(&self, body: Vec<u8>) -> PostFuture<'_> {
            self.bodies.lock().unwrap().push(body);
            let mut q = self.replies.lock().unwrap();
            let r = if q.len() > 1 {
                q.pop_front().unwrap()
            } else {
                q.front().cloned().flatten()
            };
            Box::pin(async move { r })
        }
    }

    fn reply(status: u16, body: Value) -> Option<StatusReply> {
        Some(StatusReply {
            status,
            body: serde_json::to_vec(&body).unwrap(),
        })
    }

    fn ok(acc: &[u32], dup: &[u32]) -> Option<StatusReply> {
        reply(
            200,
            json!({"accepted_event_ids": acc.iter().map(|n| uid(*n)).collect::<Vec<_>>(),
                "duplicate_event_ids": dup.iter().map(|n| uid(*n)).collect::<Vec<_>>()}),
        )
    }

    fn err(status: u16, code: &str, items: Value) -> Option<StatusReply> {
        reply(
            status,
            json!({"error": {"code": code, "message": "fixed", "items": items}}),
        )
    }

    fn params() -> IngestParams {
        IngestParams {
            poll: Duration::from_millis(10),
            retry: Duration::from_secs(5),
            max_backoff: Duration::from_secs(40),
            min_spacing: Duration::from_millis(1),
        }
    }

    fn client() -> (IngestClient, GapQueue, CentralHealth) {
        let g = GapQueue::new();
        let c = CentralHealth::new();
        (IngestClient::new(g.clone(), c.clone(), params()), g, c)
    }

    fn ids(v: &[u32]) -> Vec<String> {
        v.iter().map(|n| uid(*n)).collect()
    }

    async fn step(c: &mut IngestClient, t: &Arc<Fake>, s: &mut Mem) -> IngestStep {
        c.send_once(t, s, Instant::now()).await
    }

    fn gap_kinds(g: &GapQueue) -> Vec<Value> {
        g.pending_batch()
            .iter()
            .map(|x| serde_json::to_value(x).unwrap())
            .collect()
    }

    // ---- classify

    #[test]
    fn classify_every_answer_class() {
        let sent = ids(&[1, 2, 3]);
        let c = |r: Option<StatusReply>| classify_ingest(r.as_ref(), &sent);
        assert_eq!(
            c(ok(&[1, 99], &[2])),
            IngestOutcome::Done { ids: ids(&[1, 2]) }
        );
        assert_eq!(c(reply(200, json!({"x": 1}))), IngestOutcome::Retry);
        assert_eq!(c(ok(&[99], &[])), IngestOutcome::Retry);
        // 409 by item, all three codes
        assert_eq!(
            c(err(
                409,
                "conflict",
                json!([
                    {"index": 0, "event_id": uid(1), "code": "conflict"},
                    {"index": 1, "event_id": uid(2), "code": "sequence_conflict"},
                    {"index": 2, "event_id": uid(3), "code": "invocation_owner_conflict"},
                    {"index": 3, "event_id": uid(77), "code": "conflict"}
                ])
            )),
            IngestOutcome::Quarantine {
                items: vec![
                    (uid(1), QuarantineCode::Conflict),
                    (uid(2), QuarantineCode::SequenceConflict),
                    (uid(3), QuarantineCode::Conflict)
                ]
            }
        );
        assert_eq!(
            c(err(409, "conflict", json!([]))),
            IngestOutcome::Unattributed { status: 409 }
        );
        // 422 by index; out-of-range names nothing
        assert_eq!(
            c(err(
                422,
                "semantic_invalid",
                json!([{"index": 1, "code": "semantic_invalid"}, {"index": 1, "code": "semantic_invalid"}])
            )),
            IngestOutcome::Quarantine {
                items: vec![(uid(2), QuarantineCode::SemanticInvalid)]
            }
        );
        assert_eq!(
            c(err(
                422,
                "semantic_invalid",
                json!([{"index": 9, "code": "semantic_invalid"}])
            )),
            IngestOutcome::Unattributed { status: 422 }
        );
        // 424 names events; naming none holds all, never quarantines
        assert_eq!(
            c(reply(
                424,
                json!({"error": {"code": "metadata_ref_pending", "message": "x",
                    "items": [{"index": 1, "event_id": uid(2), "code": "metadata_ref_pending"}],
                    "pending_metadata_refs": []}})
            )),
            IngestOutcome::Pending { ids: ids(&[2]) }
        );
        assert_eq!(
            c(err(424, "metadata_ref_pending", json!([]))),
            IngestOutcome::Pending { ids: sent.clone() }
        );
        assert_eq!(c(err(424, "conflict", json!([]))), IngestOutcome::Retry);
        assert_eq!(
            c(err(413, "payload_too_large", json!([]))),
            IngestOutcome::TooLarge
        );
        assert_eq!(
            c(err(429, "rate_limited", json!([]))),
            IngestOutcome::RateLimited
        );
        let sl = c(err(503, "storage_limit", json!([])));
        assert_eq!(sl, IngestOutcome::StorageLimit);
        assert!(!sl.signals_central_outage());
        for r in [
            err(503, "storage_unavailable", json!([])),
            reply(503, json!("x")),
            reply(500, json!({})),
        ] {
            assert!(c(r).signals_central_outage());
        }
        assert!(c(None).signals_central_outage());
        // identity: disabled/retired rejected, 404 and other 403 retried
        assert_eq!(c(err(403, "disabled", json!([]))), IngestOutcome::Rejected);
        assert_eq!(c(err(403, "retired", json!([]))), IngestOutcome::Rejected);
        assert_eq!(c(err(403, "forbidden", json!([]))), IngestOutcome::Retry);
        assert_eq!(
            c(err(404, "proxy_unknown", json!([]))),
            IngestOutcome::Unregistered
        );
    }

    // ---- batches

    #[test]
    fn batch_splits_by_count() {
        let evs: Vec<_> = (1..=250).map(event).collect();
        let b = build_batch(&evs, MAX_BATCH_EVENTS, MAX_BATCH_BYTES);
        assert_eq!(b.ids.len(), 100);
        assert!(lodeline_proxy_api::parse_event_batch(&b.body).is_ok());
    }

    #[test]
    fn batch_splits_by_serialized_size() {
        let evs: Vec<_> = (1..=10).map(event).collect();
        let one = serde_json::to_vec(&evs[0]).unwrap().len();
        // room for exactly 3 events plus the envelope and two commas
        let max = BATCH_OVERHEAD + 3 * one + 2;
        let b = build_batch(&evs, 100, max);
        assert_eq!(b.ids.len(), 3);
        assert!(b.body.len() <= max);
        // one byte less fits only 2
        let b = build_batch(&evs, 100, max - 1);
        assert_eq!(b.ids.len(), 2);
        // an event that cannot fit alone is unsendable, the rest still go
        let b = build_batch(&evs, 100, BATCH_OVERHEAD + one - 1);
        assert!(b.ids.is_empty());
        assert_eq!(b.unsendable.len(), 10);
    }

    #[tokio::test]
    async fn batches_of_100_then_the_rest() {
        let (mut c, _g, central) = client();
        let t = Fake::new(vec![
            ok(&(1..=100).collect::<Vec<_>>(), &[]),
            ok(&(101..=130).collect::<Vec<_>>(), &[]),
        ]);
        let mut s = Mem::with(1..=130);
        let a = step(&mut c, &t, &mut s).await;
        assert_eq!(a.sent, 100);
        let b = step(&mut c, &t, &mut s).await;
        assert_eq!(b.sent, 30);
        assert!(s.unsent.is_empty());
        assert_eq!(s.acked.len(), 130);
        assert!(central.last_ingest_ack_at().is_some());
        assert_eq!(central.consecutive_failures(), 0);
        // nothing left: no request
        let n = t.posts().len();
        assert!(step(&mut c, &t, &mut s).await.outcome.is_none());
        assert_eq!(t.posts().len(), n);
    }

    #[tokio::test]
    async fn client_splits_a_batch_by_bytes() {
        let one = serde_json::to_vec(&event(1)).unwrap().len();
        let g = GapQueue::new();
        let mut c = IngestClient::new(g, CentralHealth::new(), params())
            .with_batch_limits(100, BATCH_OVERHEAD + 2 * one + 1);
        let t = Fake::new(vec![ok(&[1, 2], &[])]);
        let mut s = Mem::with(1..=5);
        assert_eq!(step(&mut c, &t, &mut s).await.sent, 2);
    }

    // ---- answers

    #[tokio::test]
    async fn accepted_and_duplicate_are_both_done() {
        let (mut c, _g, _) = client();
        let t = Fake::new(vec![ok(&[1], &[2])]);
        let mut s = Mem::with(1..=2);
        let st = step(&mut c, &t, &mut s).await;
        assert!(matches!(st.outcome, Some(IngestOutcome::Done { .. })));
        assert_eq!(s.acked, ids(&[1, 2]));
        assert!(s.unsent.is_empty());
    }

    #[tokio::test]
    async fn conflict_by_item_quarantines_unchanged_and_resends_the_rest() {
        let (mut c, g, _) = client();
        let t = Fake::new(vec![
            err(
                409,
                "conflict",
                json!([{"index": 1, "event_id": uid(2), "code": "sequence_conflict"}]),
            ),
            ok(&[1, 3], &[]),
        ]);
        let mut s = Mem::with(1..=3);
        step(&mut c, &t, &mut s).await;
        assert_eq!(
            s.quarantined,
            vec![(uid(2), QuarantineCode::SequenceConflict)]
        );
        let gaps = gap_kinds(&g);
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0]["kind"], "event_quarantined");
        assert_eq!(gaps[0]["code"], "sequence_conflict");
        assert_eq!(gaps[0]["event_ids"], json!([uid(2)]));
        // the rest is resent, with the same bytes for the same events
        step(&mut c, &t, &mut s).await;
        assert_eq!(t.sent_ids(1), ids(&[1, 3]));
        assert_eq!(s.acked, ids(&[1, 3]));
        let first: Value = serde_json::from_slice(&t.posts()[0]).unwrap();
        let second: Value = serde_json::from_slice(&t.posts()[1]).unwrap();
        assert_eq!(first["events"][0], second["events"][0]);
        assert_eq!(first["events"][2], second["events"][1]);
    }

    #[tokio::test]
    async fn unprocessable_by_index_quarantines_semantic_invalid() {
        let (mut c, g, _) = client();
        let t = Fake::new(vec![err(
            422,
            "semantic_invalid",
            json!([{"index": 0, "code": "semantic_invalid"}]),
        )]);
        let mut s = Mem::with(1..=2);
        step(&mut c, &t, &mut s).await;
        assert_eq!(
            s.quarantined,
            vec![(uid(1), QuarantineCode::SemanticInvalid)]
        );
        assert_eq!(gap_kinds(&g)[0]["code"], "semantic_invalid");
        assert_eq!(s.unsent.len(), 1);
    }

    /// F2 for events: an unattributed 422 sends singles until the bad event is
    /// found, then batches resume.
    #[tokio::test]
    async fn unattributed_422_isolates_then_returns_to_batches() {
        let (mut c, _g, _) = client();
        // batch of 4 -> bare 422; singles: 1 ok, 2 bad (alone: 422), then a batch.
        let bare = err(422, "semantic_invalid", json!([]));
        let t = Fake::new(vec![
            bare.clone(),
            ok(&[1], &[]),
            bare,
            ok(&[3, 4, 5, 6], &[]),
        ]);
        let mut s = Mem::with(1..=6);
        step(&mut c, &t, &mut s).await;
        assert!(c.isolating());
        assert!(
            s.quarantined.is_empty(),
            "nothing quarantined without attribution"
        );
        step(&mut c, &t, &mut s).await; // single 1 -> ok
        assert_eq!(t.sent_ids(1), ids(&[1]));
        assert!(c.isolating());
        step(&mut c, &t, &mut s).await; // single 2 -> 422 alone
        assert_eq!(t.sent_ids(2), ids(&[2]));
        assert_eq!(
            s.quarantined,
            vec![(uid(2), QuarantineCode::SemanticInvalid)]
        );
        assert!(!c.isolating(), "failing event found: batches resume");
        step(&mut c, &t, &mut s).await;
        assert_eq!(t.sent_ids(3), ids(&[3, 4, 5, 6]));
    }

    /// Singles are paced at the least spacing, not at the retry delay.
    #[tokio::test]
    async fn singles_are_paced_at_min_spacing() {
        let (mut c, _g, _) = client();
        let t = Fake::new(vec![err(422, "semantic_invalid", json!([])), ok(&[1], &[])]);
        let mut s = Mem::with(1..=3);
        let a = step(&mut c, &t, &mut s).await;
        let b = step(&mut c, &t, &mut s).await;
        assert!(c.isolating());
        for st in [&a, &b] {
            assert!(c.next_delay(st) < Duration::from_secs(1));
        }
    }

    #[tokio::test]
    async fn isolation_is_bounded() {
        let (mut c, _g, _) = client();
        let t = Fake::new(vec![err(409, "conflict", json!([]))]);
        let mut s = Mem::with(1..=400);
        step(&mut c, &t, &mut s).await;
        assert!(c.isolating());
        // every single succeeds
        t.set(vec![ok(&(1..=400).collect::<Vec<_>>(), &[])]);
        for _ in 0..=MAX_ISOLATE_SENDS {
            step(&mut c, &t, &mut s).await;
        }
        assert!(
            !c.isolating(),
            "a steady source does not keep singles forever"
        );
        step(&mut c, &t, &mut s).await;
        assert!(t.sent_ids(t.posts().len() - 1).len() > 1);
    }

    #[tokio::test]
    async fn pending_metadata_holds_with_bounded_growing_delay() {
        let (mut c, g, _) = client();
        let pend = reply(
            424,
            json!({"error": {"code": "metadata_ref_pending", "message": "x",
                "items": [{"index": 0, "event_id": uid(1), "code": "metadata_ref_pending"}],
                "pending_metadata_refs": ["00000000-0000-8000-8000-000000000900"]}}),
        );
        let t = Fake::new(vec![
            pend.clone(),
            ok(&[2], &[]),
            pend.clone(),
            ok(&[1], &[]),
        ]);
        let mut s = Mem::with(1..=2);
        let t0 = Instant::now();
        c.send_once(&t, &mut s, t0).await;
        assert_eq!(c.held_events(), 1);
        assert!(
            s.quarantined.is_empty() && g.pending_ids().is_empty(),
            "not quarantined, no gap"
        );
        // while held, event 1 is not offered; 2 goes alone
        c.send_once(&t, &mut s, t0).await;
        assert_eq!(t.sent_ids(1), ids(&[2]));
        // nothing but the held event is left: no request until the hold ends
        let n = t.posts().len();
        let idle = c.send_once(&t, &mut s, t0 + Duration::from_secs(1)).await;
        assert!(idle.outcome.is_none());
        assert_eq!(t.posts().len(), n);
        // after the delay it is retried (5 s), pending again: delay doubles (10 s)
        c.send_once(&t, &mut s, t0 + Duration::from_secs(6)).await;
        assert_eq!(t.sent_ids(2), ids(&[1]));
        let idle = c
            .send_once(&t, &mut s, t0 + Duration::from_secs(6 + 9))
            .await;
        assert!(
            idle.outcome.is_none(),
            "second hold is longer than the first"
        );
        c.send_once(&t, &mut s, t0 + Duration::from_secs(6 + 11))
            .await;
        assert_eq!(s.acked, ids(&[2, 1]));
        assert_eq!(c.held_events(), 0);
    }

    #[tokio::test]
    async fn repeated_pending_marks_the_registry_sync_stalled_without_quarantine() {
        let (mut c, _g, _) = client();
        let pend = err(424, "metadata_ref_pending", json!([]));
        let t = Fake::new(vec![pend]);
        let mut s = Mem::with(1..=1);
        let mut now = Instant::now();
        for _ in 0..STALL_ATTEMPTS {
            c.send_once(&t, &mut s, now).await;
            now += Duration::from_secs(60);
        }
        assert!(c.registry_sync_stalled());
        assert!(s.quarantined.is_empty());
        assert_eq!(s.unsent.len(), 1);
    }

    #[tokio::test]
    async fn too_large_halves_and_a_single_is_quarantined() {
        let (mut c, g, _) = client();
        let big = err(413, "payload_too_large", json!([]));
        let t = Fake::new(vec![big.clone(), big.clone(), big.clone(), big]);
        let mut s = Mem::with(1..=8);
        let st = step(&mut c, &t, &mut s).await;
        assert_eq!(st.sent, 8);
        assert_eq!(step(&mut c, &t, &mut s).await.sent, 4);
        assert_eq!(step(&mut c, &t, &mut s).await.sent, 2);
        assert_eq!(step(&mut c, &t, &mut s).await.sent, 1);
        // alone and still too large: quarantined, never resent
        assert_eq!(
            s.quarantined,
            vec![(uid(1), QuarantineCode::SemanticInvalid)]
        );
        assert_eq!(gap_kinds(&g).len(), 1);
    }

    #[tokio::test]
    async fn oversize_single_is_quarantined_without_a_request() {
        let one = serde_json::to_vec(&event(1)).unwrap().len();
        let mut c = IngestClient::new(GapQueue::new(), CentralHealth::new(), params())
            .with_batch_limits(100, BATCH_OVERHEAD + one - 1);
        let t = Fake::new(vec![ok(&[], &[])]);
        let mut s = Mem::with(1..=2);
        let st = step(&mut c, &t, &mut s).await;
        assert_eq!(st.local_quarantined, 2);
        assert!(t.posts().is_empty());
        assert_eq!(s.quarantined.len(), 2);
    }

    #[tokio::test]
    async fn rate_limit_and_storage_limit_back_off_without_an_outage() {
        let (mut c, g, central) = client();
        let t = Fake::new(vec![err(429, "rate_limited", json!([]))]);
        let mut s = Mem::with(1..=1);
        let mut delays = Vec::new();
        for _ in 0..5 {
            let st = step(&mut c, &t, &mut s).await;
            delays.push(c.next_delay(&st));
        }
        assert!(delays[3] > delays[0], "backs off: {delays:?}");
        t.set(vec![err(503, "storage_limit", json!([]))]);
        for _ in 0..10 {
            step(&mut c, &t, &mut s).await;
        }
        assert!(
            g.pending_ids().is_empty(),
            "no central_outage gap for storage_limit"
        );
        assert_eq!(central.consecutive_failures(), 0);
        assert_eq!(s.unsent.len(), 1, "the event stays unsent");
    }

    #[tokio::test]
    async fn outage_gap_opens_after_failures_and_closes_with_ended_at() {
        let (mut c, g, central) = client();
        let t = Fake::new(vec![reply(
            503,
            json!({"error": {"code": "storage_unavailable", "message": "x"}}),
        )]);
        let mut s = Mem::with(1..=1);
        for _ in 0..OUTAGE_THRESHOLD - 1 {
            step(&mut c, &t, &mut s).await;
        }
        assert!(g.pending_ids().is_empty());
        step(&mut c, &t, &mut s).await;
        let gaps = gap_kinds(&g);
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0]["kind"], "central_outage");
        assert_eq!(gaps[0]["ended_at"], Value::Null);
        assert_eq!(central.consecutive_failures(), OUTAGE_THRESHOLD as i64);
        // more failures do not open a second one
        step(&mut c, &t, &mut s).await;
        assert_eq!(g.pending_ids().len(), 1);
        // recovery: same gap id, now with ended_at; the original detected_at kept
        t.set(vec![ok(&[1], &[])]);
        step(&mut c, &t, &mut s).await;
        let after = gap_kinds(&g);
        assert_eq!(after.len(), 1);
        assert_eq!(after[0]["gap_id"], gaps[0]["gap_id"]);
        assert_ne!(after[0]["ended_at"], Value::Null);
        assert_eq!(after[0]["started_at"], gaps[0]["started_at"]);
        assert_eq!(central.consecutive_failures(), 0);
    }

    #[tokio::test]
    async fn open_outage_survives_a_reload_and_closes() {
        let (mut c, g, _) = client();
        let t = Fake::new(vec![None]);
        let mut s = Mem::with(1..=1);
        for _ in 0..OUTAGE_THRESHOLD {
            step(&mut c, &t, &mut s).await;
        }
        let id = g.open_outage().unwrap().gap_id;
        assert!(!g.pending_ids().is_empty());
        // restart: the queue is rebuilt from its persisted form
        let snap = g.pending_batch();
        let g2 = GapQueue::restore(crate::state_dir::GapQueueState {
            pending: snap,
            open_outage: g.open_outage(),
            ..Default::default()
        });
        let mut c2 = IngestClient::new(g2.clone(), CentralHealth::new(), params());
        t.set(vec![ok(&[1], &[])]);
        step(&mut c2, &t, &mut s).await;
        assert!(g2.open_outage().is_none());
        assert_eq!(gap_kinds(&g2)[0]["gap_id"], json!(id));
    }

    #[tokio::test]
    async fn identity_answers_back_off_and_keep_events() {
        let (mut c, g, central) = client();
        let mut s = Mem::with(1..=1);
        let t = Fake::new(vec![err(403, "disabled", json!([]))]);
        let st = step(&mut c, &t, &mut s).await;
        assert_eq!(st.outcome, Some(IngestOutcome::Rejected));
        assert!(c.next_delay(&st) >= Duration::from_secs(30));
        assert_eq!(
            central.consecutive_failures(),
            0,
            "an answer is not an outage"
        );
        t.set(vec![err(404, "proxy_unknown", json!([]))]);
        let st = step(&mut c, &t, &mut s).await;
        assert_eq!(st.outcome, Some(IngestOutcome::Unregistered));
        assert_eq!(s.unsent.len(), 1);
        assert!(g.pending_ids().is_empty());
    }

    #[tokio::test]
    async fn invalid_event_is_quarantined_before_sending() {
        // an event the shared parser refuses (tools/call without a tool) is
        // quarantined locally and never sent; the good one goes out
        let (mut c, g, _) = client();
        let t = Fake::new(vec![ok(&[2], &[])]);
        let mut bad = event(1);
        if let lodeline_proxy_api::event::EventPayload::Started(p) = &mut bad.payload {
            p.method = lodeline_proxy_api::event::Method::ToolsCall;
        }
        let mut s = Mem {
            unsent: vec![bad, event(2)],
            ..Mem::default()
        };
        let st = step(&mut c, &t, &mut s).await;
        assert!(t.posts().is_empty(), "the invalid batch is never sent");
        assert_eq!(st.sent, 0);
        assert_eq!(
            s.quarantined,
            vec![(uid(1), QuarantineCode::SemanticInvalid)]
        );
        assert_eq!(gap_kinds(&g).len(), 1);
        let st = step(&mut c, &t, &mut s).await;
        assert_eq!(st.sent, 1);
        assert_eq!(t.sent_ids(0), ids(&[2]));
    }

    // ---- review fixes (H1, M1-M5, L1-L4)

    fn without_ended_at(mut v: Value) -> Value {
        v["ended_at"] = Value::Null;
        v
    }

    /// H1: the closing gap equals the original except `ended_at`, also when the
    /// original was acknowledged and dropped from the queue.
    #[tokio::test]
    async fn resent_closed_outage_equals_the_original_apart_from_ended_at() {
        let (mut c, g, _) = client();
        let t = Fake::new(vec![None]);
        let mut s = Mem::with(1..=1);
        for _ in 0..OUTAGE_THRESHOLD {
            step(&mut c, &t, &mut s).await;
        }
        let original = gap_kinds(&g)[0].clone();
        // acknowledged and dropped (the open gap reached the server)
        g.settle(&crate::status_report::ReportOutcome::Accepted {
            acknowledged: vec![original["gap_id"].as_str().unwrap().to_string()],
            duplicate: vec![],
        });
        assert!(g.pending_ids().is_empty());
        t.set(vec![ok(&[1], &[])]);
        step(&mut c, &t, &mut s).await;
        let resent = gap_kinds(&g)[0].clone();
        assert_ne!(resent["ended_at"], Value::Null);
        assert_eq!(without_ended_at(resent), original);
        // and when it was still queued
        let (mut c, g, _) = client();
        let t = Fake::new(vec![None]);
        let mut s = Mem::with(1..=1);
        for _ in 0..OUTAGE_THRESHOLD {
            step(&mut c, &t, &mut s).await;
        }
        let original = gap_kinds(&g)[0].clone();
        t.set(vec![ok(&[1], &[])]);
        step(&mut c, &t, &mut s).await;
        assert_eq!(without_ended_at(gap_kinds(&g)[0].clone()), original);
    }

    /// M2: the open outage is persisted and found after a restart, so
    /// `ended_at` is still sent, equal to the original apart from it.
    #[tokio::test]
    async fn open_outage_is_persisted_and_closed_after_a_restart() {
        let snaps: Arc<Mutex<Vec<crate::state_dir::GapQueueState>>> = Arc::default();
        let s2 = snaps.clone();
        let g = GapQueue::new().with_persister(Box::new(move |st| {
            s2.lock().unwrap().push(st.clone());
            true
        }));
        let mut c = IngestClient::new(g.clone(), CentralHealth::new(), params());
        let t = Fake::new(vec![None]);
        let mut s = Mem::with(1..=1);
        for _ in 0..OUTAGE_THRESHOLD {
            step(&mut c, &t, &mut s).await;
        }
        let original = gap_kinds(&g)[0].clone();
        // the open gap is acknowledged, then the process restarts
        g.settle(&crate::status_report::ReportOutcome::Accepted {
            acknowledged: vec![original["gap_id"].as_str().unwrap().to_string()],
            duplicate: vec![],
        });
        // no flush ever holds the outage gap without its marker
        assert!(snaps
            .lock()
            .unwrap()
            .iter()
            .filter(|s| !s.pending.is_empty())
            .all(|s| s.open_outage.is_some()));
        let saved = snaps.lock().unwrap().last().cloned().unwrap();
        assert!(saved.pending.is_empty());
        assert_eq!(
            saved.open_outage.as_ref().unwrap().gap_id,
            original["gap_id"].as_str().unwrap()
        );
        let g2 = GapQueue::restore(saved);
        let mut c2 = IngestClient::new(g2.clone(), CentralHealth::new(), params());
        t.set(vec![ok(&[1], &[])]);
        step(&mut c2, &t, &mut s).await;
        let resent = gap_kinds(&g2)[0].clone();
        assert_ne!(resent["ended_at"], Value::Null);
        assert_eq!(without_ended_at(resent), original);
        assert!(g2.open_outage().is_none(), "closed outage is forgotten");
    }

    /// M3: a 424 that holds nothing new (the hold table is full) backs off
    /// instead of resending at the minimum spacing.
    #[tokio::test]
    async fn pending_that_holds_nothing_backs_off() {
        let (mut c, _g, _) = client();
        let far = Instant::now() + Duration::from_secs(3600);
        for n in 0..MAX_HELD_EVENTS {
            c.holds.insert(
                format!("held-{n}"),
                Hold {
                    attempts: 1,
                    until: far,
                },
            );
        }
        let t = Fake::new(vec![err(424, "metadata_ref_pending", json!([]))]);
        let mut s = Mem::with(1..=1);
        let st = step(&mut c, &t, &mut s).await;
        assert!(!st.progressed);
        assert!(c.next_delay(&st) >= Duration::from_secs(4));
        assert_eq!(c.held_events(), MAX_HELD_EVENTS);
        assert_eq!(s.unsent.len(), 1);
    }

    /// M5: a server that rejects everything cannot drain the queue into
    /// quarantine; after the cap the client stops quarantining and backs off.
    #[tokio::test]
    async fn consecutive_single_quarantines_are_capped() {
        let (mut c, _g, _) = client();
        let t = Fake::new(vec![err(422, "semantic_invalid", json!([]))]);
        let mut s = Mem::with(1..=40);
        let mut last = None;
        for _ in 0..60 {
            last = Some(step(&mut c, &t, &mut s).await);
        }
        assert_eq!(
            s.quarantined.len(),
            MAX_CONSECUTIVE_SINGLE_QUARANTINES as usize
        );
        assert_eq!(
            s.unsent.len(),
            40 - MAX_CONSECUTIVE_SINGLE_QUARANTINES as usize
        );
        let last = last.unwrap();
        assert!(c.next_delay(&last) >= Duration::from_secs(4) || last.sent > 1);
        // a success clears the count
        t.set(vec![ok(&(1..=40).collect::<Vec<_>>(), &[])]);
        step(&mut c, &t, &mut s).await;
        step(&mut c, &t, &mut s).await;
        assert_eq!(c.single_quarantines, 0);
        // single-event 413 is capped the same way
        let (mut c, _g, _) = client();
        let t = Fake::new(vec![err(413, "payload_too_large", json!([]))]);
        let mut s = Mem::with(1..=20);
        for _ in 0..40 {
            step(&mut c, &t, &mut s).await;
        }
        assert_eq!(
            s.quarantined.len(),
            MAX_CONSECUTIVE_SINGLE_QUARANTINES as usize
        );
    }

    /// The server's all-or-nothing answer to a batch: 200 when no event in it is
    /// bad, else 422 naming bad events and storing nothing. Its parse path names
    /// only the first bad index, SV-3..SV-5 name all of them.
    #[derive(Default)]
    struct Server {
        bad: Mutex<HashSet<String>>,
        names_all: bool,
        posts: Mutex<usize>,
    }

    impl Server {
        fn parse_path(bad: impl IntoIterator<Item = u32>) -> Arc<Server> {
            let s = Server::default();
            s.bad.lock().unwrap().extend(bad.into_iter().map(uid));
            Arc::new(s)
        }
        fn semantic_path(bad: impl IntoIterator<Item = u32>) -> Arc<Server> {
            let s = Server {
                names_all: true,
                ..Server::default()
            };
            s.bad.lock().unwrap().extend(bad.into_iter().map(uid));
            Arc::new(s)
        }
        fn upgrade(&self) {
            self.bad.lock().unwrap().clear();
        }
    }

    impl IngestTransport for Arc<Server> {
        fn post_events(&self, body: Vec<u8>) -> PostFuture<'_> {
            *self.posts.lock().unwrap() += 1;
            let v: Value = serde_json::from_slice(&body).unwrap();
            let sent: Vec<&str> = v["events"]
                .as_array()
                .unwrap()
                .iter()
                .map(|e| e["event_id"].as_str().unwrap())
                .collect();
            let bad = self.bad.lock().unwrap();
            let mut items: Vec<Value> = sent
                .iter()
                .enumerate()
                .filter(|(_, id)| bad.contains(**id))
                .map(|(i, _)| json!({"index": i, "code": "semantic_invalid"}))
                .collect();
            if !self.names_all {
                items.truncate(1);
            }
            let r = if items.is_empty() {
                reply(
                    200,
                    json!({"accepted_event_ids": sent, "duplicate_event_ids": []}),
                )
            } else {
                err(422, "semantic_invalid", Value::Array(items))
            };
            Box::pin(async move { r })
        }
    }

    const CAP: usize = MAX_CONSECUTIVE_SINGLE_QUARANTINES as usize;

    /// #339: a server that cannot parse the proxy's shape answers by index for
    /// every batch. Eight events are lost, the rest wait for the upgrade.
    #[tokio::test]
    async fn by_index_storm_stops_at_the_cap_and_resumes_after_success() {
        let (mut c, g, central) = client();
        let t = Server::parse_path(1..=40);
        let mut s = Mem::with(1..=40);
        let mut progressed = Vec::new();
        for _ in 0..30 {
            progressed.push(c.send_once(&t, &mut s, Instant::now()).await.progressed);
        }
        assert_eq!(s.quarantined.len(), CAP);
        assert_eq!(s.quarantined[0].0, uid(1));
        assert_eq!(s.quarantined[CAP - 1].0, uid(CAP as u32));
        assert_eq!(s.unsent.len(), 40 - CAP);
        assert!(s.acked.is_empty());
        assert!(progressed[..CAP].iter().all(|p| *p));
        assert!(progressed[CAP..].iter().all(|p| !p));

        // The same signals as the unattributed path: a gap per quarantine, the
        // server counts as reachable, the ack time stays old, backoff grows.
        assert_eq!(gap_kinds(&g).len(), CAP);
        assert_eq!(central.consecutive_failures(), 0);
        assert!(central.last_ingest_ack_at().is_none());
        let stopped = c.send_once(&t, &mut s, Instant::now()).await;
        c.next_delay(&stopped);
        assert_eq!(c.failures, 1);
        c.next_delay(&stopped);
        assert_eq!(c.failures, 2);

        // Upgrade: the next retry is a success that clears count and backoff.
        t.upgrade();
        let done = c.send_once(&t, &mut s, Instant::now()).await;
        assert!(done.progressed);
        assert_eq!(s.acked.len(), 40 - CAP);
        assert_eq!((c.single_quarantines, c.failures), (0, 0));

        // A later storm has the whole limit again.
        s.unsent = (41..=60).map(event).collect();
        t.bad.lock().unwrap().extend((41..=60).map(uid));
        for _ in 0..30 {
            c.send_once(&t, &mut s, Instant::now()).await;
        }
        assert_eq!(s.quarantined.len(), 2 * CAP);
    }

    /// One bad event among good ones: the good ones are accepted on the resend,
    /// and that 200 clears the count, so no run of such batches trips the limit.
    #[tokio::test]
    async fn bad_events_among_good_ones_do_not_trip_the_cap() {
        for t in [
            Server::parse_path((1..=300).filter(|n| n % 10 == 0)),
            Server::semantic_path((1..=300).filter(|n| n % 10 == 0)),
        ] {
            let (c, _g, _) = client();
            let mut c = c.with_batch_limits(5, MAX_BATCH_BYTES);
            let mut s = Mem::with(1..=300);
            while !s.unsent.is_empty() {
                let st = c.send_once(&t, &mut s, Instant::now()).await;
                assert!(st.progressed, "never stops");
            }
            assert_eq!((s.quarantined.len(), s.acked.len()), (30, 270));
        }
    }

    /// SV-3..SV-5 name every bad event of the batch in one answer. That answer
    /// counts once, so nine bad events among good ones are all quarantined.
    #[tokio::test]
    async fn one_answer_naming_nine_events_counts_once() {
        let (mut c, _g, _) = client();
        let t = Server::semantic_path(2..=10);
        let mut s = Mem::with(1..=20);
        c.send_once(&t, &mut s, Instant::now()).await;
        assert_eq!(s.quarantined.len(), 9);
        assert_eq!(c.single_quarantines, 1);
        c.send_once(&t, &mut s, Instant::now()).await;
        assert_eq!(s.acked.len(), 11);
        assert_eq!(*t.posts.lock().unwrap(), 2);
        assert_eq!(c.single_quarantines, 0);
    }

    /// The parse path names one event per answer and stores nothing, so nine
    /// such events in one batch never meet a 200. The client parses the same
    /// bytes first, so only version skew gets here: it stops and keeps the ninth
    /// event and the good ones for the upgrade.
    #[tokio::test]
    async fn nine_parse_failures_in_a_batch_stop_and_keep_the_rest() {
        let (mut c, _g, _) = client();
        let t = Server::parse_path(2..=10);
        let mut s = Mem::with(1..=20);
        for _ in 0..12 {
            c.send_once(&t, &mut s, Instant::now()).await;
        }
        assert_eq!(s.quarantined.len(), CAP);
        assert_eq!(s.unsent.len(), 20 - CAP);
        assert!(s.acked.is_empty());
        t.upgrade();
        c.send_once(&t, &mut s, Instant::now()).await;
        assert_eq!(s.acked.len(), 20 - CAP);
        assert!(s.acked.contains(&uid(10)), "the ninth event is not lost");
    }

    fn by_index() -> Option<StatusReply> {
        err(
            422,
            "semantic_invalid",
            json!([{"index": 0, "code": "semantic_invalid"}]),
        )
    }

    /// A 409 by item is not the storm and is not a success: it neither counts
    /// nor clears the count, and it is still quarantined past the limit.
    #[tokio::test]
    async fn conflict_by_item_neither_counts_nor_resets() {
        let (mut c, _g, _) = client();
        let conflict = |n: u32| {
            err(
                409,
                "conflict",
                json!([{"index": 0, "event_id": uid(n), "code": "conflict"}]),
            )
        };
        let cap = CAP as u32;
        let mut replies = vec![by_index(); CAP - 1];
        replies.push(conflict(cap));
        replies.push(by_index());
        replies.push(by_index());
        replies.push(conflict(cap + 2));
        let t = Fake::new(replies);
        let mut s = Mem::with(1..=(cap + 3));
        for _ in 0..CAP + 1 {
            assert!(step(&mut c, &t, &mut s).await.progressed);
        }
        assert_eq!(c.single_quarantines as usize, CAP);
        assert_eq!(s.quarantined.len(), CAP + 1);
        assert!(!step(&mut c, &t, &mut s).await.progressed, "limit reached");
        assert_eq!(s.quarantined.len(), CAP + 1);
        assert!(step(&mut c, &t, &mut s).await.progressed, "409 still acts");
        assert_eq!(s.quarantined.len(), CAP + 2);
        assert_eq!(c.single_quarantines as usize, CAP);
    }

    /// A 424 changes nothing about the limit: held events stay held and a
    /// stopped client stays stopped until a real success.
    #[tokio::test]
    async fn pending_neither_counts_nor_resets() {
        let (mut c, _g, _) = client();
        let next = CAP as u32 + 1;
        let mut replies = vec![by_index(); CAP];
        replies.push(err(
            424,
            "metadata_ref_pending",
            json!([{"index": 0, "event_id": uid(next), "code": "metadata_ref_pending"}]),
        ));
        replies.push(by_index());
        replies.push(ok(&[next + 1], &[]));
        let t = Fake::new(replies);
        let mut s = Mem::with(1..=(next + 1));
        for _ in 0..CAP {
            step(&mut c, &t, &mut s).await;
        }
        step(&mut c, &t, &mut s).await;
        assert_eq!(c.held_events(), 1);
        assert_eq!(c.single_quarantines as usize, CAP);
        assert!(!step(&mut c, &t, &mut s).await.progressed, "still stopped");
        assert_eq!(s.quarantined.len(), CAP);
        step(&mut c, &t, &mut s).await;
        assert_eq!(s.acked, ids(&[next + 1]));
        assert_eq!(c.single_quarantines, 0);
        assert_eq!(c.held_events(), 1, "the held event is untouched");
    }

    /// Both paths share one count, and a by-index stop during isolation goes
    /// back to batches like an unattributed stop does.
    #[tokio::test]
    async fn by_index_and_unattributed_share_the_cap() {
        let (mut c, _g, _) = client();
        let bare = err(422, "semantic_invalid", json!([]));
        let mut replies = vec![by_index(); CAP - 1];
        replies.push(bare.clone());
        replies.push(bare.clone());
        replies.push(bare);
        replies.push(by_index());
        let t = Fake::new(replies);
        let mut s = Mem::with(1..=30);
        for _ in 0..CAP - 1 {
            step(&mut c, &t, &mut s).await;
        }
        step(&mut c, &t, &mut s).await;
        assert!(c.isolating());
        step(&mut c, &t, &mut s).await;
        assert_eq!(s.quarantined.len(), CAP, "the single fills the count");
        step(&mut c, &t, &mut s).await;
        assert!(c.isolating());
        assert!(!step(&mut c, &t, &mut s).await.progressed);
        assert_eq!(s.quarantined.len(), CAP);
        assert!(!c.isolating());
    }

    /// L1: a local quarantine during isolation ends isolation.
    #[tokio::test]
    async fn local_quarantine_during_isolation_returns_to_batches() {
        let one = serde_json::to_vec(&event(1)).unwrap().len();
        let mut c = IngestClient::new(GapQueue::new(), CentralHealth::new(), params())
            .with_batch_limits(100, BATCH_OVERHEAD + one - 1);
        c.mode = Mode::Isolate;
        c.isolate_sends = 5;
        let t = Fake::new(vec![ok(&[], &[])]);
        let mut s = Mem::with(1..=2);
        step(&mut c, &t, &mut s).await;
        assert!(!c.isolating());
        assert_eq!(c.isolate_sends, 0);
    }

    /// L2: 404 backs off but neither resets the failure count nor opens or
    /// closes an outage.
    #[tokio::test]
    async fn not_found_is_not_a_healthy_answer() {
        let (mut c, g, central) = client();
        central.record_failure();
        central.record_failure();
        let t = Fake::new(vec![err(404, "proxy_unknown", json!([]))]);
        let mut s = Mem::with(1..=1);
        let st = step(&mut c, &t, &mut s).await;
        assert_eq!(st.outcome, Some(IngestOutcome::Unregistered));
        assert_eq!(central.consecutive_failures(), 2);
        assert!(!st.progressed);
        assert!(g.pending_ids().is_empty());
    }

    /// L4: the quarantine gap is queued before the source moves the events.
    #[tokio::test]
    async fn gap_is_recorded_before_the_events_are_quarantined() {
        let (mut c, g, _) = client();
        let t = Fake::new(vec![err(
            422,
            "semantic_invalid",
            json!([{"index": 0, "code": "semantic_invalid"}]),
        )]);
        let mut s = Mem::with(1..=1);
        s.probe = Some(g.clone());
        step(&mut c, &t, &mut s).await;
        assert_eq!(s.gaps_seen_at_quarantine, vec![1]);
    }
}
