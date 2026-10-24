//! The invocation audit producer (T-13d; PX-006/007/010/011/015, README
//! "Traffic와 내구성", M3, N3, R1/R2, D-05).
//!
//! [`InvocationSink`] implements [`ObservationSink`] and turns the relay's
//! observations into `proxy-event.schema.json` events in the local spool:
//!
//! * **Start.** [`ObservationSink::request_started`] builds `invocation.started`
//!   with a fresh invocation id and waits for its LOCAL durable commit
//!   ([`Admission::append`]) before the relay dispatches. A full or unusable
//!   spool, a full producer, a missing audit context or an unreadable registry
//!   refuses the call (the relay answers a fixed 503 and never contacts the
//!   upstream). The central server is never on this path.
//! * **Provenance.** `upstream_id`, `route_revision` and `actor` come from the
//!   [`AuditContext`] the relay took from the applied table that routed the
//!   call, never from client input. `protocol_version` is `2025-11-25` only for
//!   a call inside an established proxy session (its negotiation was validated);
//!   `initialize`, B1 modern requests and anything outside a session are
//!   `unknown`.
//! * **Tool.** A `tools/call` start carries the `metadata_ref` of the name in the
//!   last complete local inventory of the call's scope, or the fixed
//!   `metadata_unavailable` / `unavailable` objects. The name itself is used
//!   only for that lookup and is never stored.
//! * **Everything else** (refusal pairs, `cancel_requested`, completions) goes
//!   through ONE bounded FIFO queue to one writer task. Events of one
//!   invocation are queued under one lock, so the spool order is always start,
//!   cancel, completion; a cancel is recorded once per invocation, and a
//!   completion that saw a forwarded cancel records it first if the cancel's own
//!   observation has not yet arrived. Cancellation is never terminal.
//! * **Loss.** The relay never waits on this queue. A record that cannot be
//!   queued or appended is counted and reported as a `local_record_failed` gap
//!   (with its invocation id), handed to the gap queue off the async workers.
//!   Nothing is retried against the upstream and nothing is invented: a lost
//!   completion leaves the invocation start-only.
//!
//! Outcome mapping (the closed matrix of the schema):
//!
//! | relay | outcome / delivery / reason |
//! |---|---|
//! | `Success`, `ToolError` | `success` / `tool_error`, `sent` |
//! | `JsonRpcError` | `protocol_error`, `sent` |
//! | `ProtocolError` (`Upstream*`, `TaskHandle`) | `protocol_error`, `sent`, the matching reason |
//! | `TransportFailure` | `unknown`, its delivery (`not_sent` before dispatch) |
//! | `Timeout` | `timeout`, its delivery |
//! | `Unknown` | `unknown`, its delivery; `cancel_no_response` / `cancelled_before_dispatch` |
//! | refusal | `protocol_error` / `not_sent`; `modern_request_unsupported` (B1), `task_augmentation_unsupported` (`tasks/*`), otherwise no reason |
//!
//! Nothing here logs an event, a name, an id from the request or an error text.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use sigil_proxy_api::event::{
    CompletionReason, DeliveryState, InvocationCancelRequested, InvocationCompleted,
    InvocationStarted, MetadataUnavailableReason, Method as EventMethod, Outcome as EventOutcome,
    ProtocolVersion, Tool, ToolIdentified, ToolMetadataUnavailable, ToolUnavailable,
    UnavailableReason,
};
use sigil_proxy_api::{
    EventPayload, GapReport, Id, MetadataRef, NonNegativeI64, PositiveI64, ProxyEvent, Timestamp,
    Uuid, Validate,
};
use tokio::sync::{mpsc, Notify};

use crate::mcp::observation::{
    AuditContext, CallRef, Cause, Completed, Delivery, Method, Observation, ObservationSink,
    Outcome, RefusalKind, RequestRefused, RequestStarted, SinkFuture, StartVerdict, ToolField,
    ToolName,
};
use crate::registry_key::ScopeKey;
use crate::registry_store::{RegistryStore, ToolLookup};
use crate::spool::Admission;

/// Records queued for the writer. Beyond it a record is lost (counted, gap).
pub const QUEUE_DEPTH: usize = 1024;
/// Started invocations whose completion is still to come. A start beyond it is
/// refused (fail closed), never recorded without a way to complete it.
pub const MAX_INFLIGHT: usize = 4096;
/// Longest wait for a registry lookup before the start is refused.
// OPEN: not in D-04. The lookup is one indexed read of local SQLite.
pub const LOOKUP_TIMEOUT: Duration = Duration::from_secs(2);
/// Registry lookups running at once on the blocking pool. A lookup that timed
/// out keeps its slot until its blocking read returns, so a stuck registry
/// holds at most this many blocking threads.
pub const LOOKUP_CONCURRENCY: usize = 4;
/// Invocation ids named in one `local_record_failed` gap (schema bound).
const MAX_GAP_IDS: usize = 100;

/// Hands a gap to the durable gap queue. Called on the blocking pool; returns
/// whether the gap was taken. A false return must leave ownership here without
/// counting the same gap elsewhere: retries use `GapQueue::push`, not `record`.
pub type GapSink = Arc<dyn Fn(GapReport) -> bool + Send + Sync>;

struct Inflight {
    invocation_id: Uuid,
    cancel_recorded: bool,
    phase: Phase,
    /// The completion arrived while the start was still pending.
    completed: bool,
    commit: Option<tokio::task::AbortHandle>,
}

enum Phase {
    /// The start is being committed. Its cancel and completion wait here and
    /// are queued only after the commit; a failed commit drops them, so the
    /// spool never holds a cancel or completion without its start.
    Pending(Vec<ProxyEvent>),
    Committed,
}

type InflightMap = Arc<Mutex<HashMap<u64, Inflight>>>;

fn lock_map(
    m: &Mutex<HashMap<u64, Inflight>>,
) -> std::sync::MutexGuard<'_, HashMap<u64, Inflight>> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

enum Job {
    /// A ready event of a known invocation.
    Event(Box<ProxyEvent>),
    /// A refusal: start (its tool may still need a lookup) and completion.
    Refused(Box<RefusedJob>),
    /// Stop after everything queued before it.
    Stop,
}

/// The channel and current writer frame each own their record until settled.
/// Dropping either during cancellation accounts for uncertainty synchronously.
struct AccountedJob {
    job: Option<Job>,
    shared: Arc<Shared>,
    id: Option<Uuid>,
}

impl AccountedJob {
    fn stop(shared: Arc<Shared>) -> Self {
        Self {
            job: Some(Job::Stop),
            shared,
            id: None,
        }
    }
}

impl Drop for AccountedJob {
    fn drop(&mut self) {
        if let Some(id) = self.id.take() {
            self.shared.note_lost(&id);
        }
    }
}

struct RefusedJob {
    invocation_id: Uuid,
    started: InvocationStarted,
    name: Option<ToolName>,
    scope: Option<ScopeKey>,
    completed: InvocationCompleted,
    occurred_at: Timestamp,
}

#[derive(Default)]
struct Lost {
    count: u64,
    ids: Vec<Uuid>,
    seen: HashSet<String>,
}

impl Lost {
    fn add(&mut self, count: u64, id: &Uuid) {
        self.count = self.count.saturating_add(count);
        if self.ids.len() < MAX_GAP_IDS && self.seen.insert(id.as_str().to_string()) {
            self.ids.push(id.clone());
        }
    }
}

struct Shared {
    admission: Admission,
    proxy_id: Id,
    epoch_id: Uuid,
    registry: Option<RegistryStore>,
    gap_sink: GapSink,
    lost: Mutex<Lost>,
    lost_total: AtomicU64,
    /// Shutdown passed its grace: count the rest instead of appending it.
    abandon: AtomicBool,
    /// Shutdown began: nothing more is queued (a late record is counted).
    closed: AtomicBool,
    notify: Notify,
    lookups: Arc<tokio::sync::Semaphore>,
    gap_slot: Arc<tokio::sync::Semaphore>,
    late_flush_running: AtomicBool,
    next_gap_attempt: Mutex<std::time::Instant>,
    /// Starts refused by this producer (the relay answered 503).
    refused_starts: AtomicU64,
    /// Tests: held while a start's append waits.
    #[cfg(test)]
    append_gate: Arc<tokio::sync::RwLock<()>>,
}

/// The producer. Install with [`crate::server::Proxy::with_sink`] (wrapped in a
/// [`FanoutSink`] with the inventory when there is one).
pub struct InvocationSink {
    shared: Arc<Shared>,
    inflight: InflightMap,
    tx: mpsc::Sender<AccountedJob>,
}

impl std::fmt::Debug for InvocationSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InvocationSink").finish_non_exhaustive()
    }
}

/// Owns the writer task; [`InvocationHandle::shutdown`] drains it.
pub struct InvocationHandle {
    shared: Arc<Shared>,
    tx: mpsc::Sender<AccountedJob>,
    join: Option<tokio::task::JoinHandle<()>>,
    inflight: InflightMap,
}

fn now_ts() -> Timestamp {
    ts(SystemTime::now())
}

fn ts(t: SystemTime) -> Timestamp {
    let t = time::OffsetDateTime::from(t);
    Timestamp::new(crate::status_report::rfc3339(t)).expect("rfc3339 is a valid timestamp")
}

fn new_uuid() -> Uuid {
    Uuid::new(uuid::Uuid::new_v4().hyphenated().to_string()).expect("v4 uuid")
}

fn millis(d: Duration) -> NonNegativeI64 {
    NonNegativeI64::new(i64::try_from(d.as_millis()).unwrap_or(i64::MAX)).expect("non-negative")
}

fn bytes(n: u64) -> NonNegativeI64 {
    NonNegativeI64::new(i64::try_from(n).unwrap_or(i64::MAX)).expect("non-negative")
}

fn event_method(m: Method) -> EventMethod {
    match m {
        Method::Initialize => EventMethod::Initialize,
        Method::Ping => EventMethod::Ping,
        Method::ToolsList => EventMethod::ToolsList,
        Method::ToolsCall => EventMethod::ToolsCall,
        Method::Unknown => EventMethod::Unknown,
    }
}

/// `2025-11-25` only inside an established session, never for `initialize`.
fn protocol_of(call: &CallRef, method: Method) -> ProtocolVersion {
    if method != Method::Initialize && call.session.is_some() {
        ProtocolVersion::V2025_11_25
    } else {
        ProtocolVersion::Unknown
    }
}

fn scope_key(proxy_id: &Id, call: &CallRef) -> Option<ScopeKey> {
    let s = call.scope.as_deref()?;
    Some(ScopeKey::live(
        proxy_id.as_str(),
        &s.upstream_id,
        &s.credential_scope_id,
    ))
}

fn unavailable(reason: MetadataUnavailableReason) -> Tool {
    Tool::MetadataUnavailable(ToolMetadataUnavailable { reason })
}

/// The completion matrix (module doc).
pub fn completion_of(
    outcome: Outcome,
    delivery: Delivery,
    cause: Cause,
) -> (EventOutcome, DeliveryState, Option<CompletionReason>) {
    let d = match delivery {
        Delivery::NotSent => DeliveryState::NotSent,
        Delivery::Sent => DeliveryState::Sent,
        Delivery::Unknown => DeliveryState::Unknown,
    };
    match outcome {
        Outcome::Success => (EventOutcome::Success, DeliveryState::Sent, None),
        Outcome::ToolError => (EventOutcome::ToolError, DeliveryState::Sent, None),
        Outcome::JsonRpcError => (EventOutcome::ProtocolError, d, None),
        Outcome::ProtocolError => (
            EventOutcome::ProtocolError,
            d,
            match cause {
                Cause::UpstreamVersionUnsupported => {
                    Some(CompletionReason::UpstreamVersionUnsupported)
                }
                Cause::UpstreamCapabilityUnsupported => {
                    Some(CompletionReason::UpstreamCapabilityUnsupported)
                }
                Cause::UpstreamInitializeUnreadable => {
                    Some(CompletionReason::UpstreamInitializeUnreadable)
                }
                Cause::TaskHandle => Some(CompletionReason::TaskAugmentationUnsupported),
                _ => None,
            },
        ),
        Outcome::TransportFailure => (EventOutcome::Unknown, d, None),
        Outcome::Timeout => (EventOutcome::Timeout, d, None),
        Outcome::Unknown => (
            EventOutcome::Unknown,
            d,
            match cause {
                Cause::CancelNoResponse if d != DeliveryState::NotSent => {
                    Some(CompletionReason::CancelNoResponse)
                }
                Cause::CancelledBeforeDispatch if d == DeliveryState::NotSent => {
                    Some(CompletionReason::CancelledBeforeDispatch)
                }
                _ => None,
            },
        ),
    }
}

fn refusal_reason(k: RefusalKind) -> Option<CompletionReason> {
    match k {
        RefusalKind::ModernRequest => Some(CompletionReason::ModernRequestUnsupported),
        RefusalKind::TasksMethod => Some(CompletionReason::TaskAugmentationUnsupported),
        _ => None,
    }
}

impl Shared {
    fn envelope(&self, occurred_at: Timestamp, payload: EventPayload) -> Option<ProxyEvent> {
        let ev = ProxyEvent {
            schema_version: sigil_proxy_api::scalar::SchemaVersion,
            event_id: new_uuid(),
            proxy_id: self.proxy_id.clone(),
            epoch_id: self.epoch_id.clone(),
            // The spool assigns the real sequence in its commit.
            sequence: PositiveI64::new(1).expect("1 is positive"),
            occurred_at,
            payload,
        };
        // A producer bug, not input: fixed text only.
        if ev.validate().is_err() {
            tracing::error!("invocation event failed validation and was not recorded");
            return None;
        }
        Some(ev)
    }

    fn note_lost(self: &Arc<Self>, invocation_id: &Uuid) {
        self.lost_total.fetch_add(1, Ordering::Relaxed);
        self.lost
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .add(1, invocation_id);
        tracing::warn!("an invocation record could not be stored locally (counted as a gap)");
        if self.closed.load(Ordering::SeqCst) {
            self.start_late_flush();
        } else {
            self.notify.notify_one();
        }
    }

    /// At most one post-shutdown retry task; a failing hook never starts a
    /// new blocking job more often than the retry interval.
    fn start_late_flush(self: &Arc<Self>) {
        // The writer may be gone: hand the gap over directly.
        if let Ok(h) = tokio::runtime::Handle::try_current() {
            if !self.late_flush_running.swap(true, Ordering::SeqCst) {
                let s = self.clone();
                h.spawn(async move {
                    loop {
                        s.flush_lost().await;
                        if s.lost.lock().unwrap_or_else(|p| p.into_inner()).count == 0
                            && s.gap_slot.available_permits() == 1
                        {
                            s.late_flush_running.store(false, Ordering::SeqCst);
                            // A loss racing the flag reset must get a worker.
                            if s.lost.lock().unwrap_or_else(|p| p.into_inner()).count == 0
                                || s.late_flush_running.swap(true, Ordering::SeqCst)
                            {
                                break;
                            }
                        }
                        tokio::time::sleep(Duration::from_millis(250)).await;
                    }
                });
            }
        }
    }

    /// Queue a job, or count the invocation as lost. Callers hold the inflight
    /// lock when ordering matters. Never waits.
    fn queue(self: &Arc<Self>, tx: &mpsc::Sender<AccountedJob>, job: Job, id: &Uuid) {
        let job = AccountedJob {
            job: Some(job),
            shared: self.clone(),
            id: Some(id.clone()),
        };
        if !self.closed.load(Ordering::SeqCst) {
            // A refused send drops the guard and accounts for the record.
            let _ = tx.try_send(job);
        }
    }

    /// Hand the counted losses to the gap queue as one `local_record_failed`
    /// gap. Runs the (file-writing) gap sink on the blocking pool.
    async fn flush_lost(self: &Arc<Self>) {
        {
            let mut next = self
                .next_gap_attempt
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            let now = std::time::Instant::now();
            if now < *next || self.lost.lock().unwrap_or_else(|p| p.into_inner()).count == 0 {
                return;
            }
            *next = now + Duration::from_millis(250);
        }
        // Retain the slot inside the closure: cancellation of this future must
        // neither duplicate handovers nor lose the aggregate being handed over.
        let Ok(slot) = self.gap_slot.clone().try_acquire_owned() else {
            return;
        };
        let shared = self.clone();
        let _ = tokio::task::spawn_blocking(move || {
            let _slot = slot;
            let taken = {
                let mut l = shared.lost.lock().unwrap_or_else(|p| p.into_inner());
                if l.count == 0 {
                    return;
                }
                std::mem::take(&mut *l)
            };
            let gap = serde_json::from_value::<GapReport>(serde_json::json!({
                "kind": "local_record_failed",
                "gap_id": uuid::Uuid::new_v4().hyphenated().to_string(),
                "detected_at": now_ts(),
                "count": i64::try_from(taken.count).unwrap_or(i64::MAX).max(1),
                "invocation_ids": &taken.ids,
            }));
            let accepted = gap.ok().is_some_and(|g| {
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| (shared.gap_sink)(g)))
                    .unwrap_or(false)
            });
            if !accepted {
                let mut l = shared.lost.lock().unwrap_or_else(|p| p.into_inner());
                l.count = l.count.saturating_add(taken.count);
                for id in &taken.ids {
                    l.add(0, id);
                }
                tracing::error!("a local_record_failed gap hand-over failed; kept for retry");
            }
        })
        .await;
    }

    async fn lookup(&self, scope: Option<ScopeKey>, name: &ToolName) -> Option<Tool> {
        let Some(store) = self.registry.clone() else {
            // No registry on this platform: no inventory can ever be complete.
            return Some(unavailable(MetadataUnavailableReason::NoCompleteInventory));
        };
        let scope = scope?;
        let name = name.as_str().to_string();
        let slots = self.lookups.clone();
        let found = tokio::time::timeout(LOOKUP_TIMEOUT, async move {
            let slot = slots.try_acquire_owned().ok()?;
            tokio::task::spawn_blocking(move || {
                // Released when the read returns, not when the wait gives up.
                let _slot = slot;
                store.lookup_tool(&scope, &name)
            })
            .await
            .ok()?
            .ok()
        })
        .await
        .ok()??;
        Some(match found {
            ToolLookup::Found(r) => Tool::Identified(ToolIdentified {
                metadata_ref: MetadataRef::new(r).ok()?,
            }),
            ToolLookup::NotInInventory => unavailable(MetadataUnavailableReason::NotInInventory),
            ToolLookup::NoCompleteInventory => {
                unavailable(MetadataUnavailableReason::NoCompleteInventory)
            }
        })
    }

    async fn append(&self, ev: ProxyEvent) -> bool {
        #[cfg(test)]
        let _gate = self.append_gate.clone().read_owned().await;
        if self.abandon.load(Ordering::SeqCst) {
            return false;
        }
        self.admission.append(ev).await.is_ok()
    }
}

async fn writer(shared: Arc<Shared>, mut rx: mpsc::Receiver<AccountedJob>) {
    let mut retry = tokio::time::interval(Duration::from_millis(250));
    retry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        if shared.abandon.load(Ordering::SeqCst) {
            break;
        }
        let job = tokio::select! {
            j = rx.recv() => j,
            _ = retry.tick() => { shared.flush_lost().await; continue; },
            _ = shared.notify.notified() => {
                if rx.is_empty() { shared.flush_lost().await; }
                continue;
            }
        };
        let Some(mut owned) = job else { break };
        let job = owned.job.take().expect("queued job");
        if matches!(job, Job::Stop) {
            break;
        }
        write_job(&shared, job).await;
        owned.id = None;
        if rx.is_empty() {
            shared.flush_lost().await;
        }
    }
    // Dropping the receiver drops all queued guards, before the final flush.
    drop(rx);
    shared.flush_lost().await;
}

async fn write_job(shared: &Arc<Shared>, job: Job) {
    match job {
        Job::Stop => {}
        Job::Event(ev) => {
            let id = ev.payload.invocation_id().clone();
            if !shared.append(*ev).await {
                shared.note_lost(&id);
            }
        }
        Job::Refused(r) => {
            let RefusedJob {
                invocation_id,
                mut started,
                name,
                scope,
                completed,
                occurred_at,
            } = *r;
            if let Some(n) = &name {
                match shared.lookup(scope, n).await {
                    Some(t) => started.tool = Some(t),
                    None => {
                        shared.note_lost(&invocation_id);
                        return;
                    }
                }
            }
            let start = shared.envelope(occurred_at, EventPayload::Started(started));
            let done = shared.envelope(now_ts(), EventPayload::Completed(completed));
            match (start, done) {
                (Some(s), Some(d)) => {
                    if !shared.append(s).await || !shared.append(d).await {
                        shared.note_lost(&invocation_id);
                    }
                }
                _ => shared.note_lost(&invocation_id),
            }
        }
    }
}

impl InvocationSink {
    /// Start the writer task (needs a tokio runtime). `registry` is the local
    /// metadata registry, `None` where the platform has none.
    pub fn start(
        admission: Admission,
        proxy_id: &str,
        epoch_id: &str,
        registry: Option<RegistryStore>,
        gap_sink: GapSink,
    ) -> anyhow::Result<(Arc<InvocationSink>, InvocationHandle)> {
        let shared = Arc::new(Shared {
            admission,
            proxy_id: Id::new(proxy_id)?,
            epoch_id: Uuid::new(epoch_id)?,
            registry,
            gap_sink,
            lost: Mutex::new(Lost::default()),
            lost_total: AtomicU64::new(0),
            abandon: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            notify: Notify::new(),
            lookups: Arc::new(tokio::sync::Semaphore::new(LOOKUP_CONCURRENCY)),
            refused_starts: AtomicU64::new(0),
            gap_slot: Arc::new(tokio::sync::Semaphore::new(1)),
            late_flush_running: AtomicBool::new(false),
            next_gap_attempt: Mutex::new(std::time::Instant::now()),
            #[cfg(test)]
            append_gate: Arc::new(tokio::sync::RwLock::new(())),
        });
        let (tx, rx) = mpsc::channel(QUEUE_DEPTH);
        let join = tokio::spawn(writer(shared.clone(), rx));
        let inflight = Arc::new(Mutex::new(HashMap::new()));
        Ok((
            Arc::new(InvocationSink {
                shared: shared.clone(),
                inflight: inflight.clone(),
                tx: tx.clone(),
            }),
            InvocationHandle {
                shared,
                tx,
                join: Some(join),
                inflight,
            },
        ))
    }

    /// Records that could not be stored locally since start.
    pub fn lost_records(&self) -> u64 {
        self.shared.lost_total.load(Ordering::Relaxed)
    }

    /// Starts refused by this producer since start.
    pub fn refused_starts(&self) -> u64 {
        self.shared.refused_starts.load(Ordering::Relaxed)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<u64, Inflight>> {
        lock_map(&self.inflight)
    }

    fn queue(&self, job: Job, id: &Uuid) {
        self.shared.queue(&self.tx, job, id);
    }

    fn refuse_start(&self) -> StartVerdict {
        self.shared.refused_starts.fetch_add(1, Ordering::Relaxed);
        StartVerdict::Refuse
    }

    async fn record_start(&self, s: &RequestStarted) -> StartVerdict {
        let Some(audit) = s.call.audit.as_deref() else {
            // No applied revision or scope: nothing true to record.
            return self.refuse_start();
        };
        let seq = s.call.seq;
        let invocation_id = new_uuid();
        {
            // Reserve the in-flight slot first: the cap counts starts being
            // committed too, and a cancel or completion arriving meanwhile
            // finds the entry.
            let mut g = self.lock();
            if self.shared.closed.load(Ordering::SeqCst)
                || self.tx.capacity() == 0
                || g.len() >= MAX_INFLIGHT
                || g.contains_key(&seq)
            {
                drop(g);
                return self.refuse_start();
            }
            g.insert(
                seq,
                Inflight {
                    invocation_id: invocation_id.clone(),
                    cancel_recorded: false,
                    phase: Phase::Pending(Vec::new()),
                    completed: false,
                    commit: None,
                },
            );
        }
        // Until the append is handed to its task, a dropped request (or a
        // refusal) removes the reservation.
        let mut reserved = Reserved {
            map: &self.inflight,
            seq,
            armed: true,
        };
        let tool = match (&s.method, &s.tool) {
            (Method::ToolsCall, ToolField::Name(n)) => {
                match self
                    .shared
                    .lookup(scope_key(&self.shared.proxy_id, &s.call), n)
                    .await
                {
                    Some(t) => Some(t),
                    // A registry that cannot answer must not let a call through
                    // with an invented identity.
                    None => return self.refuse_start(),
                }
            }
            (Method::ToolsCall, _) => Some(Tool::Unavailable(ToolUnavailable {
                reason: UnavailableReason::Malformed,
            })),
            _ => None,
        };
        let Some(ev) = self.shared.envelope(
            ts(s.received_at),
            EventPayload::Started(started_of(audit, &invocation_id, &s.call, s.method, tool)),
        ) else {
            return self.refuse_start();
        };
        // The commit runs in its own task: if the request is dropped while it
        // waits, the entry is still settled (and its stashed records queued or
        // dropped) when the commit answers.
        reserved.armed = false;
        let (shared, map, tx) = (self.shared.clone(), self.inflight.clone(), self.tx.clone());
        let task = tokio::spawn(async move {
            #[cfg(test)]
            let _gate = shared.append_gate.clone().read_owned().await;
            let r = shared.admission.append(ev).await;
            settle_start(&shared, &map, &tx, seq, r.is_ok());
            r
        });
        {
            let mut g = self.lock();
            if let Some(f) = g.get_mut(&seq) {
                f.commit = Some(task.abort_handle());
            } else if self.shared.closed.load(Ordering::SeqCst) {
                task.abort();
            }
        }
        match task.await {
            Ok(Ok(_)) if !self.shared.closed.load(Ordering::SeqCst) => StartVerdict::Proceed,
            Ok(Ok(_)) => self.refuse_start(),
            Ok(Err(crate::spool::Refusal::Invalid(_))) => {
                tracing::error!("the spool refused an invocation start as inadmissible");
                self.refuse_start()
            }
            Ok(Err(_)) => self.refuse_start(),
            Err(_) => {
                lock_map(&self.inflight).remove(&seq);
                self.refuse_start()
            }
        }
    }

    fn refused(&self, r: RequestRefused) {
        let invocation_id = new_uuid();
        let Some(audit) = r.call.audit.as_deref() else {
            self.shared.note_lost(&invocation_id);
            return;
        };
        let modern = r.reason == RefusalKind::ModernRequest;
        // B1 and header refusals carry no validated revision.
        let protocol = if modern || r.reason == RefusalKind::VersionHeader {
            ProtocolVersion::Unknown
        } else {
            protocol_of(&r.call, r.method)
        };
        let method = if modern { Method::Unknown } else { r.method };
        let (tool, name) = match (method, r.tool) {
            (Method::ToolsCall, ToolField::Name(n)) => (None, Some(n)),
            // A tools/call whose name was not (or could not be) parsed.
            (Method::ToolsCall, _) => (
                Some(Tool::Unavailable(ToolUnavailable {
                    reason: UnavailableReason::Malformed,
                })),
                None,
            ),
            _ => (None, None),
        };
        let mut started = started_of(audit, &invocation_id, &r.call, method, tool);
        started.protocol_version = protocol;
        let elapsed = SystemTime::now()
            .duration_since(r.received_at)
            .unwrap_or_default();
        let completed = InvocationCompleted {
            invocation_id: invocation_id.clone(),
            outcome: EventOutcome::ProtocolError,
            delivery_state: DeliveryState::NotSent,
            reason: refusal_reason(r.reason),
            duration_ms: millis(elapsed),
            response_bytes: bytes(0),
        };
        let job = Job::Refused(Box::new(RefusedJob {
            invocation_id: invocation_id.clone(),
            started,
            name,
            scope: scope_key(&self.shared.proxy_id, &r.call),
            completed,
            occurred_at: ts(r.received_at),
        }));
        self.queue(job, &invocation_id);
    }

    fn cancel(&self, seq: u64) {
        let mut g = self.lock();
        let Some(f) = g.get_mut(&seq) else {
            return;
        };
        if f.cancel_recorded || f.completed {
            return;
        }
        f.cancel_recorded = true;
        let id = f.invocation_id.clone();
        if let Some(ev) = self.cancel_event(&id) {
            match &mut f.phase {
                Phase::Pending(stash) => stash.push(ev),
                Phase::Committed => self.queue(Job::Event(Box::new(ev)), &id),
            }
        }
    }

    fn cancel_event(&self, id: &Uuid) -> Option<ProxyEvent> {
        self.shared.envelope(
            now_ts(),
            EventPayload::CancelRequested(InvocationCancelRequested {
                invocation_id: id.clone(),
            }),
        )
    }

    fn completed(&self, c: Completed) {
        let mut g = self.lock();
        let Some(f) = g.get_mut(&c.call.seq) else {
            // The start was never recorded (refused): nothing to complete.
            return;
        };
        if f.completed {
            return;
        }
        let id = f.invocation_id.clone();
        let mut out = Vec::with_capacity(2);
        if c.cancel_requested && !f.cancel_recorded {
            f.cancel_recorded = true;
            out.extend(self.cancel_event(&id));
        }
        let (outcome, delivery_state, reason) = completion_of(c.outcome, c.delivery, c.cause);
        let ev = self.shared.envelope(
            ts(c.completed_at),
            EventPayload::Completed(InvocationCompleted {
                invocation_id: id.clone(),
                outcome,
                delivery_state,
                reason,
                duration_ms: millis(c.duration),
                response_bytes: bytes(c.response_bytes),
            }),
        );
        match ev {
            Some(ev) => out.push(ev),
            None => self.shared.note_lost(&id),
        }
        match &mut f.phase {
            Phase::Pending(stash) => {
                stash.extend(out);
                f.completed = true;
            }
            Phase::Committed => {
                g.remove(&c.call.seq);
                for ev in out {
                    self.queue(Job::Event(Box::new(ev)), &id);
                }
            }
        }
    }
}

/// Drops an in-flight reservation unless disarmed.
struct Reserved<'a> {
    map: &'a InflightMap,
    seq: u64,
    armed: bool,
}

impl Drop for Reserved<'_> {
    fn drop(&mut self) {
        if self.armed {
            lock_map(self.map).remove(&self.seq);
        }
    }
}

/// The start of `seq` committed (`ok`) or failed: queue what waited for it, or
/// drop it with the entry.
fn settle_start(
    shared: &Arc<Shared>,
    map: &InflightMap,
    tx: &mpsc::Sender<AccountedJob>,
    seq: u64,
    ok: bool,
) {
    let mut g = lock_map(map);
    if !ok {
        g.remove(&seq);
        return;
    }
    let Some(f) = g.get_mut(&seq) else {
        return;
    };
    let Phase::Pending(stash) = std::mem::replace(&mut f.phase, Phase::Committed) else {
        return;
    };
    let id = f.invocation_id.clone();
    if f.completed {
        g.remove(&seq);
    }
    for ev in stash {
        shared.queue(tx, Job::Event(Box::new(ev)), &id);
    }
}

fn started_of(
    audit: &AuditContext,
    invocation_id: &Uuid,
    call: &CallRef,
    method: Method,
    tool: Option<Tool>,
) -> InvocationStarted {
    InvocationStarted {
        invocation_id: invocation_id.clone(),
        upstream_id: audit.upstream_id.clone(),
        route_revision: audit.route_revision,
        protocol_version: protocol_of(call, method),
        method: event_method(method),
        actor: audit.actor.clone(),
        tool,
    }
}

impl ObservationSink for InvocationSink {
    fn request_started<'a>(&'a self, s: &'a RequestStarted) -> SinkFuture<'a, StartVerdict> {
        Box::pin(self.record_start(s))
    }

    fn observe(&self, o: Observation) {
        match o {
            Observation::Refused(r) => self.refused(r),
            Observation::Cancel(c) => self.cancel(c.target.seq),
            Observation::Completed(c) => self.completed(c),
        }
    }
}

impl InvocationHandle {
    /// Drain: everything queued so far is appended (at most `grace`), then the
    /// writer stops. What could not be appended in time is counted and handed
    /// to the gap queue. Returns false if handover remains incomplete after
    /// five seconds; lifecycle must preserve Stopping and report failure.
    /// Call after the relay has stopped.
    pub async fn shutdown(mut self, grace: Duration) -> bool {
        let Some(mut join) = self.join.take() else {
            return true;
        };
        let deadline = tokio::time::Instant::now() + grace;
        self.shared.closed.store(true, Ordering::SeqCst);
        // Detached start commits are bounded by the inflight map. Remove their
        // stashes under the same lock used by settle_start, then cancel them.
        // An append already sent to the spool may still commit: count it as
        // uncertain, never invent a completion or permit a late dispatch.
        {
            let mut g = lock_map(&self.inflight);
            g.retain(|_, f| {
                if let Phase::Pending(stash) = &f.phase {
                    self.shared.note_lost(&f.invocation_id);
                    for _ in stash {
                        self.shared.note_lost(&f.invocation_id);
                    }
                    if let Some(task) = &f.commit {
                        task.abort();
                    }
                    false
                } else {
                    // Keep committed ids so any late observation is counted.
                    true
                }
            });
        }
        let stop = tokio::time::timeout_at(
            deadline,
            self.tx.send(AccountedJob::stop(self.shared.clone())),
        )
        .await;
        let drained = stop.is_ok() && tokio::time::timeout_at(deadline, &mut join).await.is_ok();
        if !drained {
            self.shared.abandon.store(true, Ordering::SeqCst);
            join.abort();
            // Cancellation drops both current and queued guards before returning.
            let _ = join.await;
        }
        let finished = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                self.shared.flush_lost().await;
                if self
                    .shared
                    .lost
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .count
                    == 0
                    && self.shared.gap_slot.available_permits() == 1
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .is_ok();
        if !finished {
            self.shared.start_late_flush();
            tracing::error!(
                "invocation shutdown gap handover incomplete; durable accounting unconfirmed"
            );
        }
        finished
    }
}

impl Drop for InvocationHandle {
    fn drop(&mut self) {
        if self.join.take().is_some() {
            self.shared.closed.store(true, Ordering::SeqCst);
            self.shared.abandon.store(true, Ordering::SeqCst);
            self.shared.notify.notify_one();
            self.shared.start_late_flush();
        }
    }
}

/// Two sinks in one: the audit producer decides the start, the inventory
/// observes only calls the audit admitted. Both see every observation.
pub struct FanoutSink {
    audit: Arc<dyn ObservationSink>,
    inventory: Arc<dyn ObservationSink>,
}

impl FanoutSink {
    pub fn new(audit: Arc<dyn ObservationSink>, inventory: Arc<dyn ObservationSink>) -> FanoutSink {
        FanoutSink { audit, inventory }
    }
}

impl ObservationSink for FanoutSink {
    fn request_started<'a>(&'a self, s: &'a RequestStarted) -> SinkFuture<'a, StartVerdict> {
        Box::pin(async move {
            match self.audit.request_started(s).await {
                StartVerdict::Proceed => {
                    match self.inventory.request_started(s).await {
                        StartVerdict::Proceed => StartVerdict::Proceed,
                        StartVerdict::Refuse => {
                            // A secondary refusal prevents dispatch, but cannot
                            // erase the start already committed by the audit.
                            self.audit.observe(Observation::Completed(Completed {
                                call: s.call.clone(),
                                method: s.method,
                                request_id: s.request_id.clone(),
                                outcome: Outcome::Unknown,
                                delivery: Delivery::NotSent,
                                cause: Cause::None,
                                http_status: None,
                                response_bytes: 0,
                                duration: s.received_at.elapsed().unwrap_or_default(),
                                completed_at: SystemTime::now(),
                                cancel_requested: false,
                                tool_list: None,
                            }));
                            StartVerdict::Refuse
                        }
                    }
                }
                StartVerdict::Refuse => StartVerdict::Refuse,
            }
        })
    }

    fn observe(&self, o: Observation) {
        self.inventory.observe(o.clone());
        self.audit.observe(o);
    }

    fn session_ended(&self, session: u64) {
        self.audit.session_ended(session);
        self.inventory.session_ended(session);
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::mcp::classify::RequestId;
    use crate::spool::{Spool, SpoolConfig};
    use sigil_proxy_api::event::{Actor, ActorKind, AuthenticationMethod, EvidenceSource};

    fn spool(dir: &std::path::Path) -> Spool {
        let mut cfg = SpoolConfig::new(
            dir,
            "px-1",
            "00000000-0000-4000-8000-0000000000e1",
            true,
            &crate::limits::Limits::default(),
        );
        cfg.maintenance_interval = Duration::from_secs(3600);
        Spool::open(cfg).unwrap()
    }

    fn audit() -> Arc<AuditContext> {
        Arc::new(AuditContext {
            route_revision: PositiveI64::new(7).unwrap(),
            upstream_id: Id::new("up-1").unwrap(),
            actor: Actor {
                actor_id: Id::new("pa").unwrap(),
                actor_kind: ActorKind::NonHuman,
                authentication_method: AuthenticationMethod::Bearer,
                evidence_source: EvidenceSource::ProxyCredentialMapping,
                credential_owner_id: None,
            },
        })
    }

    fn call(seq: u64, session: Option<u64>) -> CallRef {
        CallRef {
            seq,
            route_id: "a".into(),
            principal_id: "pa".into(),
            scope: Some(Arc::new(crate::route::RouteScope {
                upstream_id: "up-1".into(),
                credential_scope_id: "cs-1".into(),
            })),
            audit: Some(audit()),
            session,
        }
    }

    fn started(seq: u64, method: Method, tool: ToolField) -> RequestStarted {
        RequestStarted {
            call: call(seq, Some(1)),
            method,
            request_id: RequestId::from_raw("1").unwrap(),
            tool,
            list_cursor: None,
            task_augmented: false,
            request_bytes: 10,
            received_at: SystemTime::now(),
        }
    }

    fn gaps() -> (GapSink, Arc<Mutex<Vec<GapReport>>>) {
        let v = Arc::new(Mutex::new(Vec::new()));
        let v2 = v.clone();
        (
            Arc::new(move |g| {
                v2.lock().unwrap().push(g);
                true
            }),
            v,
        )
    }

    /// The spool's events in sequence order (read-only, WAL readers allowed).
    fn events(dir: &std::path::Path) -> Vec<serde_json::Value> {
        let db = rusqlite::Connection::open_with_flags(
            dir.join(crate::spool::SPOOL_FILE),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let mut st = db
            .prepare("SELECT bytes FROM events ORDER BY sequence")
            .unwrap();
        let rows = st
            .query_map([], |r| r.get::<_, Vec<u8>>(0))
            .unwrap()
            .map(|b| serde_json::from_slice(&b.unwrap()).unwrap())
            .collect();
        rows
    }

    fn completed(
        seq: u64,
        outcome: Outcome,
        delivery: Delivery,
        cause: Cause,
        cancel: bool,
    ) -> Completed {
        Completed {
            call: call(seq, Some(1)),
            method: Method::Ping,
            request_id: RequestId::from_raw("1").unwrap(),
            outcome,
            delivery,
            cause,
            http_status: Some(200),
            response_bytes: 12,
            duration: Duration::from_millis(3),
            completed_at: SystemTime::now(),
            cancel_requested: cancel,
            tool_list: None,
        }
    }

    #[tokio::test]
    async fn start_is_durable_before_proceed_and_order_is_start_cancel_completion() {
        let d = tempfile::tempdir().unwrap();
        let sp = spool(d.path());
        let (g, _) = gaps();
        let (sink, h) =
            InvocationSink::start(Admission::new(sp.clone()), "px-1", sp.epoch_id(), None, g)
                .unwrap();
        let s = started(1, Method::Ping, ToolField::NotApplicable);
        assert_eq!(sink.request_started(&s).await, StartVerdict::Proceed);
        assert_eq!(sp.snapshot().unsent_events, 1, "durable before the verdict");
        // a completion that saw a forwarded cancel records the cancel first,
        // and the late cancel observation adds nothing
        sink.observe(Observation::Completed(completed(
            1,
            Outcome::Unknown,
            Delivery::Sent,
            Cause::CancelNoResponse,
            true,
        )));
        sink.cancel(1);
        h.shutdown(Duration::from_secs(5)).await;
        let ev = events(d.path());
        let kinds: Vec<&str> = ev
            .iter()
            .map(|e| e["event_type"].as_str().unwrap())
            .collect();
        assert_eq!(
            kinds,
            [
                "invocation.started",
                "invocation.cancel_requested",
                "invocation.completed"
            ]
        );
        let inv = &ev[0]["payload"]["invocation_id"];
        assert!(ev.iter().all(|e| &e["payload"]["invocation_id"] == inv));
        assert_eq!(ev[0]["payload"]["route_revision"], 7);
        assert_eq!(ev[0]["payload"]["upstream_id"], "up-1");
        assert_eq!(ev[0]["payload"]["protocol_version"], "2025-11-25");
        assert_eq!(ev[0]["payload"]["actor"]["actor_kind"], "non_human");
        assert_eq!(ev[2]["payload"]["outcome"], "unknown");
        assert_eq!(ev[2]["payload"]["reason"], "cancel_no_response");
    }

    #[tokio::test]
    async fn a_full_or_broken_spool_refuses_the_start() {
        let d = tempfile::tempdir().unwrap();
        let sp = spool(d.path());
        let (g, _) = gaps();
        let (sink, _h) =
            InvocationSink::start(Admission::new(sp.clone()), "px-1", sp.epoch_id(), None, g)
                .unwrap();
        sp.set_capacity_for_test(10, 0);
        assert_eq!(
            sink.request_started(&started(1, Method::Ping, ToolField::NotApplicable))
                .await,
            StartVerdict::Refuse
        );
        sp.set_capacity_for_test(1 << 30, 0);
        sp.inject_storage_failure(true);
        assert_eq!(
            sink.request_started(&started(2, Method::Ping, ToolField::NotApplicable))
                .await,
            StartVerdict::Refuse
        );
        sp.inject_storage_failure(false);
        // no audit context: refused, nothing invented
        let mut s = started(3, Method::Ping, ToolField::NotApplicable);
        s.call.audit = None;
        assert_eq!(sink.request_started(&s).await, StartVerdict::Refuse);
        assert_eq!(sp.snapshot().unsent_events, 0);
    }

    #[tokio::test]
    async fn lost_completions_become_a_local_record_failed_gap() {
        let d = tempfile::tempdir().unwrap();
        let sp = spool(d.path());
        let (g, got) = gaps();
        let (sink, h) =
            InvocationSink::start(Admission::new(sp.clone()), "px-1", sp.epoch_id(), None, g)
                .unwrap();
        assert_eq!(
            sink.request_started(&started(1, Method::Ping, ToolField::NotApplicable))
                .await,
            StartVerdict::Proceed
        );
        sp.inject_storage_failure(true);
        sink.observe(Observation::Completed(completed(
            1,
            Outcome::Success,
            Delivery::Sent,
            Cause::None,
            false,
        )));
        h.shutdown(Duration::from_secs(5)).await;
        assert_eq!(sink.lost_records(), 1);
        let gaps = got.lock().unwrap();
        let v = serde_json::to_value(&gaps[0]).unwrap();
        assert_eq!(v["kind"], "local_record_failed");
        assert_eq!(v["count"], 1);
        assert_eq!(v["invocation_ids"].as_array().unwrap().len(), 1);
    }

    async fn wait_for(mut f: impl FnMut() -> bool) {
        for _ in 0..500 {
            if f() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("condition not reached");
    }

    #[tokio::test]
    async fn a_request_dropped_while_its_start_commits_still_gets_cancel_and_completion() {
        let d = tempfile::tempdir().unwrap();
        let sp = spool(d.path());
        let (g, _) = gaps();
        let (sink, h) =
            InvocationSink::start(Admission::new(sp.clone()), "px-1", sp.epoch_id(), None, g)
                .unwrap();
        let gate = sink.shared.append_gate.clone().write_owned().await;
        let s2 = sink.clone();
        let req = tokio::spawn(async move {
            s2.request_started(&started(1, Method::Ping, ToolField::NotApplicable))
                .await
        });
        wait_for(|| sink.lock().contains_key(&1)).await;
        // cancel and completion arrive while the commit waits, then the
        // request goes away
        sink.cancel(1);
        sink.observe(Observation::Completed(completed(
            1,
            Outcome::Unknown,
            Delivery::Unknown,
            Cause::ClientGone,
            true,
        )));
        req.abort();
        assert_eq!(sp.snapshot().unsent_events, 0, "nothing before the start");
        drop(gate);
        wait_for(|| sink.lock().is_empty()).await;
        h.shutdown(Duration::from_secs(5)).await;
        let kinds: Vec<String> = events(d.path())
            .iter()
            .map(|e| e["event_type"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(
            kinds,
            [
                "invocation.started",
                "invocation.cancel_requested",
                "invocation.completed"
            ]
        );
        assert_eq!(sink.lost_records(), 0);
    }

    #[tokio::test]
    async fn a_failed_start_commit_drops_what_waited_for_it() {
        let d = tempfile::tempdir().unwrap();
        let sp = spool(d.path());
        let (g, _) = gaps();
        let (sink, h) =
            InvocationSink::start(Admission::new(sp.clone()), "px-1", sp.epoch_id(), None, g)
                .unwrap();
        let gate = sink.shared.append_gate.clone().write_owned().await;
        let s2 = sink.clone();
        let req = tokio::spawn(async move {
            s2.request_started(&started(1, Method::Ping, ToolField::NotApplicable))
                .await
        });
        wait_for(|| sink.lock().contains_key(&1)).await;
        sink.cancel(1);
        sink.observe(Observation::Completed(completed(
            1,
            Outcome::Unknown,
            Delivery::NotSent,
            Cause::ClientGone,
            false,
        )));
        sp.inject_storage_failure(true);
        drop(gate);
        assert_eq!(req.await.unwrap(), StartVerdict::Refuse);
        assert!(sink.lock().is_empty());
        sp.inject_storage_failure(false);
        // a late completion of the refused start adds nothing
        sink.observe(Observation::Completed(completed(
            1,
            Outcome::Unknown,
            Delivery::NotSent,
            Cause::ClientGone,
            false,
        )));
        h.shutdown(Duration::from_secs(5)).await;
        assert!(
            events(d.path()).is_empty(),
            "no orphan cancel or completion"
        );
        assert_eq!(sink.refused_starts(), 1);
    }

    #[tokio::test]
    async fn a_stuck_registry_holds_a_bounded_number_of_lookups() {
        let d = tempfile::tempdir().unwrap();
        let sp = spool(d.path());
        let rd = tempfile::tempdir().unwrap();
        std::fs::set_permissions(
            rd.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let (store, _) = RegistryStore::open(rd.path(), "px-1").unwrap();
        let (g, _) = gaps();
        let (sink, h) = InvocationSink::start(
            Admission::new(sp.clone()),
            "px-1",
            sp.epoch_id(),
            Some(store.clone()),
            g,
        )
        .unwrap();
        let (ready, ready_rx) = tokio::sync::oneshot::channel();
        let (release, release_rx) = tokio::sync::oneshot::channel();
        let held = tokio::task::spawn_blocking(move || {
            let _lock = store.lock();
            ready.send(()).unwrap();
            let _ = release_rx.blocking_recv();
        });
        ready_rx.await.unwrap();
        let n = LOOKUP_CONCURRENCY + 2;
        let mut reqs = Vec::new();
        for i in 0..n {
            let s2 = sink.clone();
            reqs.push(tokio::spawn(async move {
                let name = ToolName::parse("t").unwrap();
                s2.request_started(&started(
                    i as u64 + 1,
                    Method::ToolsCall,
                    ToolField::Name(name),
                ))
                .await
            }));
        }
        for r in reqs {
            assert_eq!(r.await.unwrap(), StartVerdict::Refuse);
        }
        assert_eq!(sink.refused_starts(), n as u64);
        // the timed-out reads still hold their slots, no more than the bound
        assert_eq!(sink.shared.lookups.available_permits(), 0);
        assert!(sink.lock().is_empty());
        // Repeated client retries and the writer's refusal path share the
        // same occupied slots and must fail immediately, without more work.
        tokio::time::timeout(Duration::from_millis(500), async {
            for seq in 100..120 {
                assert_eq!(
                    sink.request_started(&started(
                        seq,
                        Method::ToolsCall,
                        ToolField::Name(ToolName::parse("t").unwrap())
                    ))
                    .await,
                    StartVerdict::Refuse
                );
            }
            sink.observe(Observation::Refused(RequestRefused {
                call: call(200, Some(1)),
                reason: RefusalKind::VersionHeader,
                method: Method::ToolsCall,
                request_id: None,
                tool: ToolField::Name(ToolName::parse("t").unwrap()),
                http_status: 400,
                request_bytes: 0,
                received_at: SystemTime::now(),
            }));
            wait_for(|| sink.lost_records() == 1).await;
        })
        .await
        .expect("saturated lookups must refuse immediately");
        assert_eq!(sink.shared.lookups.available_permits(), 0);
        release.send(()).unwrap();
        held.await.unwrap();
        wait_for(|| sink.shared.lookups.available_permits() == LOOKUP_CONCURRENCY).await;
        h.shutdown(Duration::from_secs(5)).await;
        assert_eq!(sp.snapshot().unsent_events, 0);
    }

    #[tokio::test]
    async fn a_record_after_shutdown_is_counted_as_a_gap() {
        let d = tempfile::tempdir().unwrap();
        let sp = spool(d.path());
        let (g, got) = gaps();
        let (sink, h) =
            InvocationSink::start(Admission::new(sp.clone()), "px-1", sp.epoch_id(), None, g)
                .unwrap();
        assert_eq!(
            sink.request_started(&started(1, Method::Ping, ToolField::NotApplicable))
                .await,
            StartVerdict::Proceed
        );
        h.shutdown(Duration::from_secs(5)).await;
        // a start after shutdown is refused, a completion is counted
        assert_eq!(
            sink.request_started(&started(2, Method::Ping, ToolField::NotApplicable))
                .await,
            StartVerdict::Refuse
        );
        sink.observe(Observation::Completed(completed(
            1,
            Outcome::Success,
            Delivery::Sent,
            Cause::None,
            false,
        )));
        assert_eq!(sink.lost_records(), 1);
        wait_for(|| !got.lock().unwrap().is_empty()).await;
        let v = serde_json::to_value(&got.lock().unwrap()[0]).unwrap();
        assert_eq!(v["kind"], "local_record_failed");
    }

    #[tokio::test]
    async fn gap_false_and_panic_keep_bounded_losses_until_recovery() {
        let d = tempfile::tempdir().unwrap();
        let sp = spool(d.path());
        let attempts = Arc::new(AtomicU64::new(0));
        let recover = Arc::new(AtomicBool::new(false));
        let reports = Arc::new(Mutex::new(Vec::new()));
        let (a, r, out) = (attempts.clone(), recover.clone(), reports.clone());
        let gap: GapSink = Arc::new(move |g| {
            let n = a.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                panic!("test gap failure");
            }
            if !r.load(Ordering::SeqCst) {
                return false;
            }
            out.lock().unwrap().push(g);
            true
        });
        let (sink, h) =
            InvocationSink::start(Admission::new(sp.clone()), "px-1", sp.epoch_id(), None, gap)
                .unwrap();
        for _ in 0..150 {
            sink.shared.note_lost(&new_uuid());
        }
        wait_for(|| attempts.load(Ordering::SeqCst) >= 2).await;
        {
            let lost = sink.shared.lost.lock().unwrap();
            assert_eq!(lost.count, 150);
            assert_eq!(lost.ids.len(), MAX_GAP_IDS);
            assert_eq!(lost.seen.len(), MAX_GAP_IDS);
        }
        // Failed handovers cannot turn queued observations into a hot loop.
        let before = attempts.load(Ordering::SeqCst);
        for _ in 0..100 {
            sink.shared.flush_lost().await;
        }
        assert_eq!(attempts.load(Ordering::SeqCst), before);
        h.shutdown(Duration::from_secs(5)).await;
        recover.store(true, Ordering::SeqCst);
        wait_for(|| !reports.lock().unwrap().is_empty()).await;
        assert_eq!(sink.lost_records(), 150);
        let reports = reports.lock().unwrap();
        assert_eq!(reports.len(), 1);
        assert_eq!(serde_json::to_value(&reports[0]).unwrap()["count"], 150);
    }

    #[tokio::test]
    async fn shutdown_retains_queued_completion_past_blocked_gap_handover_timeout() {
        let d = tempfile::tempdir().unwrap();
        let sp = spool(d.path());
        let gate = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
        let entered = Arc::new(AtomicBool::new(false));
        let reports = Arc::new(Mutex::new(Vec::new()));
        let (g, e, out) = (gate.clone(), entered.clone(), reports.clone());
        let gap: GapSink = Arc::new(move |report| {
            e.store(true, Ordering::SeqCst);
            let (lock, ready) = &*g;
            let mut released = lock.lock().unwrap();
            while !*released {
                released = ready.wait(released).unwrap();
            }
            out.lock().unwrap().push(report);
            true
        });
        let (sink, h) =
            InvocationSink::start(Admission::new(sp.clone()), "px-1", sp.epoch_id(), None, gap)
                .unwrap();
        assert_eq!(
            sink.request_started(&started(1, Method::Ping, ToolField::NotApplicable))
                .await,
            StartVerdict::Proceed
        );
        let invocation_id = events(d.path())[0]["payload"]["invocation_id"].clone();
        sink.shared.note_lost(&new_uuid());
        wait_for(|| entered.load(Ordering::SeqCst)).await;
        sink.observe(Observation::Completed(completed(
            1,
            Outcome::Success,
            Delivery::Sent,
            Cause::None,
            false,
        )));
        // The blocking hook holds the writer beyond grace + the five-second
        // cleanup wait. Shutdown must return while retaining queue ownership.
        let before = tokio::time::Instant::now();
        assert!(!h.shutdown(Duration::from_millis(1)).await);
        assert_eq!(
            sink.lost_records(),
            2,
            "queued loss accounted before return"
        );
        let elapsed = before.elapsed();
        *gate.0.lock().unwrap() = true;
        gate.1.notify_all();
        assert!(elapsed >= Duration::from_secs(5));
        assert!(elapsed < Duration::from_secs(7));
        wait_for(|| sink.lost_records() == 2).await;
        wait_for(|| reports.lock().unwrap().len() == 2).await;
        let reports = reports.lock().unwrap();
        let values: Vec<_> = reports
            .iter()
            .map(|g| serde_json::to_value(g).unwrap())
            .collect();
        assert_eq!(
            values
                .iter()
                .map(|g| g["count"].as_u64().unwrap())
                .sum::<u64>(),
            2
        );
        assert!(values.iter().any(|g| g["invocation_ids"]
            .as_array()
            .unwrap()
            .contains(&invocation_id)));
        assert_eq!(events(d.path()).len(), 1);
    }

    #[test]
    fn production_full_gap_queue_survives_shutdown_and_runtime_destruction() {
        use crate::status_report::{GapQueue, MAX_QUEUED_GAPS};
        let d = tempfile::tempdir().unwrap();
        let state_path = d.path().join("gap-state");
        let state =
            crate::state_dir::StateDir::open(&state_path, &Id::new("px-1").unwrap()).unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let state_dir = state;
            let q = GapQueue::new().with_persister(Box::new(move |state| {
                state_dir.write_gap_queue(state).is_ok()
            }));
            for _ in 0..MAX_QUEUED_GAPS {
                assert!(q.record(
                    serde_json::from_value(serde_json::json!({
                        "kind": "local_record_failed", "gap_id": new_uuid(),
                        "detected_at": now_ts(), "count": 1, "invocation_ids": [],
                    }))
                    .unwrap()
                ));
            }
            let sp = spool(d.path());
            let (sink, h) = InvocationSink::start(
                Admission::new(sp.clone()),
                "px-1",
                sp.epoch_id(),
                None,
                crate::lifecycle::invocation_gap_handover(q.clone()),
            )
            .unwrap();
            assert_eq!(
                sink.request_started(&started(1, Method::Ping, ToolField::NotApplicable))
                    .await,
                StartVerdict::Proceed
            );
            assert_eq!(
                sink.request_started(&started(2, Method::Ping, ToolField::NotApplicable))
                    .await,
                StartVerdict::Proceed
            );
            // Hold one current append and leave another completion queued.

            let gate = sink.shared.append_gate.clone().write_owned().await;
            sink.observe(Observation::Completed(completed(
                1,
                Outcome::Success,
                Delivery::Sent,
                Cause::None,
                false,
            )));
            wait_for(|| sink.tx.capacity() == QUEUE_DEPTH).await;
            sink.observe(Observation::Completed(completed(
                2,
                Outcome::Success,
                Delivery::Sent,
                Cause::None,
                false,
            )));
            assert_eq!(sink.tx.capacity(), QUEUE_DEPTH - 1);
            assert!(h.shutdown(Duration::ZERO).await);
            drop(gate);
            assert_eq!(sink.lost_records(), 2);
            assert!(!q.persist_failed());
            assert_eq!(events(d.path()).len() as u64 + sink.lost_records(), 4);
            assert_eq!(q.overflow_count(), 1);
            sp.close().await;
        });
        drop(runtime);
        let reopened =
            crate::state_dir::StateDir::open(&state_path, &Id::new("px-1").unwrap()).unwrap();
        let restored = GapQueue::restore(reopened.read_gap_queue().unwrap().unwrap());
        assert_eq!(restored.pending_ids().len(), MAX_QUEUED_GAPS);
        // A saturated handover is durably counted exactly once, never retried.
        assert_eq!(restored.overflow_count(), 1);
    }

    #[tokio::test]
    async fn shutdown_accounts_blocked_start_and_its_pending_completion() {
        let d = tempfile::tempdir().unwrap();
        let sp = spool(d.path());
        let (gap, reports) = gaps();
        let (sink, h) =
            InvocationSink::start(Admission::new(sp.clone()), "px-1", sp.epoch_id(), None, gap)
                .unwrap();
        let gate = sink.shared.append_gate.clone().write_owned().await;
        let copy = sink.clone();
        let request = tokio::spawn(async move {
            copy.request_started(&started(1, Method::Ping, ToolField::NotApplicable))
                .await
        });
        wait_for(|| sink.lock().get(&1).is_some_and(|f| f.commit.is_some())).await;
        sink.observe(Observation::Completed(completed(
            1,
            Outcome::Unknown,
            Delivery::Unknown,
            Cause::ClientGone,
            false,
        )));
        assert!(h.shutdown(Duration::ZERO).await);
        assert_eq!(sink.lost_records(), 2);
        assert!(sink.lock().is_empty());
        drop(gate);
        assert_eq!(request.await.unwrap(), StartVerdict::Refuse);
        assert!(events(d.path()).is_empty());
        let total: u64 = reports
            .lock()
            .unwrap()
            .iter()
            .map(|g| serde_json::to_value(g).unwrap()["count"].as_u64().unwrap())
            .sum();
        assert_eq!(total, 2);
    }

    #[tokio::test]
    async fn real_gap_queue_retries_do_not_inflate_overflow_or_duplicate_loss() {
        use crate::status_report::{GapQueue, ReportOutcome, MAX_QUEUED_GAPS};
        let q = GapQueue::new();
        for _ in 0..MAX_QUEUED_GAPS {
            q.push(
                serde_json::from_value(serde_json::json!({
                    "kind": "local_record_failed", "gap_id": new_uuid(),
                    "detected_at": now_ts(), "count": 1, "invocation_ids": [],
                }))
                .unwrap(),
            )
            .unwrap();
        }
        let d = tempfile::tempdir().unwrap();
        let sp = spool(d.path());
        let attempts = Arc::new(AtomicU64::new(0));
        let (queue, tried) = (q.clone(), attempts.clone());
        // Generic retaining-ownership hook: retries must use push, not record.
        let gap: GapSink = Arc::new(move |g| {
            tried.fetch_add(1, Ordering::SeqCst);
            queue.push(g).is_ok()
        });
        let (sink, h) =
            InvocationSink::start(Admission::new(sp.clone()), "px-1", sp.epoch_id(), None, gap)
                .unwrap();
        let id = new_uuid();
        sink.shared.note_lost(&id);
        wait_for(|| attempts.load(Ordering::SeqCst) >= 3).await;
        assert_eq!(q.overflow_count(), 0);
        assert_eq!(sink.lost_records(), 1);
        let ids = q.pending_ids();
        q.settle(&ReportOutcome::Accepted {
            acknowledged: ids,
            duplicate: vec![],
        });
        wait_for(|| q.pending_ids().len() == 1).await;
        let gaps = q.pending_batch();
        let gap = serde_json::to_value(&gaps[0]).unwrap();
        assert_eq!(gap["count"], 1);
        assert_eq!(gap["invocation_ids"], serde_json::json!([id]));
        assert_eq!(q.overflow_count(), 0);
        h.shutdown(Duration::from_secs(1)).await;
        assert_eq!(q.pending_ids().len(), 1);
    }

    #[tokio::test]
    async fn capacity_is_reserved_before_the_start_ack_and_duplicate_seq_is_refused() {
        let d = tempfile::tempdir().unwrap();
        let sp = spool(d.path());
        let (gap, _) = gaps();
        let (sink, h) =
            InvocationSink::start(Admission::new(sp.clone()), "px-1", sp.epoch_id(), None, gap)
                .unwrap();
        // Leave one slot: two starts racing an ACK must not both reserve it.
        for seq in 2..=MAX_INFLIGHT as u64 {
            sink.lock().insert(
                seq,
                Inflight {
                    invocation_id: new_uuid(),
                    cancel_recorded: false,
                    phase: Phase::Committed,
                    completed: false,
                    commit: None,
                },
            );
        }
        let gate = sink.shared.append_gate.clone().write_owned().await;
        let copy = sink.clone();
        let req = tokio::spawn(async move {
            copy.request_started(&started(1, Method::Ping, ToolField::NotApplicable))
                .await
        });
        wait_for(|| sink.lock().contains_key(&1)).await;
        assert_eq!(sink.lock().len(), MAX_INFLIGHT);
        assert_eq!(
            sink.request_started(&started(5000, Method::Ping, ToolField::NotApplicable))
                .await,
            StartVerdict::Refuse
        );
        // Remove fixture entries, then check duplicate protection independently.
        sink.lock().retain(|seq, _| *seq == 1);
        assert_eq!(
            sink.request_started(&started(1, Method::Ping, ToolField::NotApplicable))
                .await,
            StartVerdict::Refuse
        );
        drop(gate);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), req)
                .await
                .unwrap()
                .unwrap(),
            StartVerdict::Proceed
        );
        sink.observe(Observation::Completed(completed(
            1,
            Outcome::Unknown,
            Delivery::NotSent,
            Cause::ClientGone,
            false,
        )));
        h.shutdown(Duration::from_secs(5)).await;
        assert_eq!(events(d.path()).len(), 2);
    }

    #[tokio::test]
    async fn dropped_ack_waiter_can_complete_after_commit_without_synthetic_completion() {
        let d = tempfile::tempdir().unwrap();
        let sp = spool(d.path());
        let (gap, _) = gaps();
        let (sink, h) =
            InvocationSink::start(Admission::new(sp.clone()), "px-1", sp.epoch_id(), None, gap)
                .unwrap();
        let gate = sink.shared.append_gate.clone().write_owned().await;
        let copy = sink.clone();
        let req = tokio::spawn(async move {
            copy.request_started(&started(1, Method::Ping, ToolField::NotApplicable))
                .await
        });
        wait_for(|| sink.lock().contains_key(&1)).await;
        req.abort();
        let _ = req.await;
        drop(gate);
        wait_for(|| {
            matches!(
                sink.lock().get(&1).map(|f| &f.phase),
                Some(Phase::Committed)
            )
        })
        .await;
        assert_eq!(events(d.path()).len(), 1, "no invented completion");
        sink.cancel(1);
        sink.observe(Observation::Completed(completed(
            1,
            Outcome::Unknown,
            Delivery::NotSent,
            Cause::CancelledBeforeDispatch,
            true,
        )));
        h.shutdown(Duration::from_secs(5)).await;
        let ev = events(d.path());
        assert_eq!(ev.len(), 3);
        assert_eq!(ev[1]["event_type"], "invocation.cancel_requested");
        assert_eq!(ev[2]["payload"]["delivery_state"], "not_sent");
        assert_eq!(ev[2]["payload"]["reason"], "cancelled_before_dispatch");
    }

    struct RefusingSecondary;
    impl ObservationSink for RefusingSecondary {
        fn request_started<'a>(&'a self, _: &'a RequestStarted) -> SinkFuture<'a, StartVerdict> {
            Box::pin(async { StartVerdict::Refuse })
        }
        fn observe(&self, _: Observation) {}
    }

    #[tokio::test]
    async fn secondary_refusal_completes_the_durable_start_without_dispatch() {
        let d = tempfile::tempdir().unwrap();
        let sp = spool(d.path());
        let (gap, _) = gaps();
        let (sink, h) =
            InvocationSink::start(Admission::new(sp.clone()), "px-1", sp.epoch_id(), None, gap)
                .unwrap();
        let fanout = FanoutSink::new(sink.clone(), Arc::new(RefusingSecondary));
        assert_eq!(
            fanout
                .request_started(&started(1, Method::Ping, ToolField::NotApplicable))
                .await,
            StartVerdict::Refuse
        );
        assert!(sink.lock().is_empty());
        h.shutdown(Duration::from_secs(5)).await;
        let ev = events(d.path());
        assert_eq!(ev.len(), 2);
        assert_eq!(ev[1]["payload"]["outcome"], "unknown");
        assert_eq!(ev[1]["payload"]["delivery_state"], "not_sent");
    }

    #[test]
    fn completion_matrix_is_closed() {
        use Cause as C;
        use Delivery as D;
        use Outcome as O;
        for (o, d, c) in [
            (O::Success, D::Sent, C::None),
            (O::ToolError, D::Sent, C::None),
            (O::JsonRpcError, D::Sent, C::None),
            (O::ProtocolError, D::Sent, C::UpstreamVersionUnsupported),
            (O::ProtocolError, D::Sent, C::UpstreamCapabilityUnsupported),
            (O::ProtocolError, D::Sent, C::UpstreamInitializeUnreadable),
            (O::ProtocolError, D::Sent, C::TaskHandle),
            (O::TransportFailure, D::NotSent, C::ConnectFailed),
            (O::TransportFailure, D::Sent, C::UpstreamStatus(500)),
            (O::Timeout, D::NotSent, C::ConnectTimeout),
            (O::Timeout, D::Unknown, C::FirstByteTimeout),
            (O::Unknown, D::Sent, C::CancelNoResponse),
            (O::Unknown, D::NotSent, C::CancelledBeforeDispatch),
            (O::Unknown, D::Unknown, C::ClientGone),
            (O::Unknown, D::Sent, C::UpstreamSessionEnded),
            (O::ProtocolError, D::NotSent, C::RouteUnsupported),
        ] {
            let (outcome, delivery_state, reason) = completion_of(o, d, c);
            let ev = InvocationCompleted {
                invocation_id: new_uuid(),
                outcome,
                delivery_state,
                reason,
                duration_ms: millis(Duration::ZERO),
                response_bytes: bytes(0),
            };
            assert!(ev.validate().is_ok(), "{o:?} {d:?} {c:?}");
        }
    }
}
