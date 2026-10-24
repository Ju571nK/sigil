//! Status report and heartbeat (T-12c2, control-plane.md section 6.2 "Status
//! report", ledger-and-query.md L6b).
//!
//! * [`StatusBuilder`] turns the config sync's [`ConfigView`] plus pending gaps
//!   into a `POST /v1/proxy-status` body and validates it with the shared
//!   `sigil_proxy_api::parse_status` before anything is sent.
//! * [`classify`] reduces the server's answer to a [`ReportOutcome`]; it is pure.
//! * [`GapQueue`] holds gap reports until they are acknowledged. It is durable
//!   (L6b): every change is handed to a persister (the `gap_queue.json` file of
//!   the state dir) and the queue is reloaded at start. A gap that does not fit
//!   is counted and reported later as one aggregated `local_record_failed` gap,
//!   never dropped silently. The ingest client ([`crate::ingest_client`]) is the
//!   producer.
//! * [`run_status_reporter`] sends on a jittered schedule (the heartbeat) and
//!   promptly after the config view changes. It reuses the config client
//!   ([`crate::config_sync::MtlsFetcher`]) through [`StatusTransport`].
//!
//! Response rules (#260), all fail closed:
//! * `503 storage_limit` is server storage, not a central outage: no outage gap
//!   is ever opened for it, and only the refused gap ids are resent.
//! * `422` with items quarantines exactly those gaps; `422` without usable items
//!   quarantines the whole report (every gap in it).
//! * `409` quarantines the named gaps and resends the rest.
//! * `403 disabled` or `retired` is a rejection: it is never retried hot and it
//!   does not change the local config state (the config fetch is the authority).
//! * Anything else (other 5xx, 429, 404, transport failure) is retried with
//!   backoff; no gap is dropped.
//!
//! Nothing here logs a body, a gap, a hash or an address.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};
use sigil_proxy_api::status::ConfigState;
use sigil_proxy_api::{ErrorCode, GapReport};
use tokio::sync::watch;
use tokio::time::Instant;

use crate::config_sync::ConfigView;
use crate::spool::Spool;
use crate::state_dir::{GapQueueState, OpenOutage};

/// Largest answer read from the server. A 200 body lists at most 200 ids.
pub const MAX_STATUS_RESPONSE_BYTES: usize = 64 * 1024;
/// Gaps per report (`proxy-status.schema.json`).
pub const MAX_GAPS_PER_REPORT: usize = 100;
/// Pending gaps the queue holds. A full queue refuses new gaps rather than
/// dropping an unacknowledged one.
pub const MAX_QUEUED_GAPS: usize = 1024;
/// Quarantined gaps kept locally, on top of the pending bound. The oldest
/// quarantined gap is evicted first, so quarantine can never crowd out a pending
/// gap.
pub const MAX_QUARANTINED_GAPS: usize = 256;
/// `status_sequence` values reserved ahead in state_dir (one hour of
/// milliseconds), so the file is rewritten about once an hour, not per report.
const SEQUENCE_RESERVE: i64 = 3_600_000;

/// Reachability of the central server as the proxy has observed it: the source
/// of the status report's `central` section. Cheap to clone (shared).
///
/// Any answer from the server (even a refusal such as 429 or `storage_limit`)
/// proves it is reachable and resets the failure count; only no answer or a 5xx
/// other than `storage_limit` counts as a failure
/// ([`ReportOutcome::signals_central_outage`]).
#[derive(Clone, Default)]
pub struct CentralHealth(Arc<Mutex<CentralInner>>);

#[derive(Default)]
struct CentralInner {
    last_ingest_ack_at: Option<String>,
    consecutive_failures: i64,
}

impl CentralHealth {
    pub fn new() -> CentralHealth {
        CentralHealth::default()
    }
    fn lock(&self) -> std::sync::MutexGuard<'_, CentralInner> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
    /// The server answered (any status that is not an outage signal).
    pub fn record_answer(&self) {
        self.lock().consecutive_failures = 0;
    }
    /// No answer, or a 5xx that is an outage signal.
    pub fn record_failure(&self) {
        let mut g = self.lock();
        g.consecutive_failures = g.consecutive_failures.saturating_add(1);
    }
    /// The server durably accepted events (`accepted` or `duplicate` ids).
    pub fn record_ingest_ack(&self, at: time::OffsetDateTime) {
        let mut g = self.lock();
        g.consecutive_failures = 0;
        g.last_ingest_ack_at = Some(rfc3339(at));
    }
    pub fn consecutive_failures(&self) -> i64 {
        self.lock().consecutive_failures
    }
    pub fn last_ingest_ack_at(&self) -> Option<String> {
        self.lock().last_ingest_ack_at.clone()
    }
}

/// The server's answer, reduced to what the classifier reads.
#[derive(Clone, PartialEq, Eq)]
pub struct StatusReply {
    pub status: u16,
    pub body: Vec<u8>,
}

/// The body is not printed.
impl std::fmt::Debug for StatusReply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "StatusReply({}, {} bytes)", self.status, self.body.len())
    }
}

pub type PostFuture<'a> = Pin<Box<dyn Future<Output = Option<StatusReply>> + Send + 'a>>;

/// `None` means no answer (transport error, timeout, bad TLS material).
pub trait StatusTransport: Send + Sync {
    fn post_status(&self, body: Vec<u8>) -> PostFuture<'_>;
}

// --------------------------------------------------------------------- queue

pub(crate) fn gap_id(g: &GapReport) -> &str {
    match g {
        GapReport::RegistryConflict(x) => x.gap_id.as_str(),
        GapReport::EventQuarantined(x) => x.gap_id.as_str(),
        GapReport::LocalRecordFailed(x) => x.gap_id.as_str(),
        GapReport::SpoolExpired(x) => x.gap_id.as_str(),
        GapReport::UnrecordedCalls(x) => x.gap_id.as_str(),
        GapReport::CentralOutage(x) => x.gap_id.as_str(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GapState {
    Pending,
    /// Kept locally, never resent (a 422 or 409 named it).
    Quarantined,
}

struct Entry {
    gap: GapReport,
    state: GapState,
}

/// The pending bound is reached.
///
/// [`GapQueue::record`] turns this into an aggregated gap; a producer should
/// call that, not [`GapQueue::push`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueueFull;

/// Called with the whole queue after each change. `false` means it is not
/// durable; the in-memory queue is kept (a gap is never dropped for it) and the
/// failure is logged and shown by [`GapQueue::persist_failed`].
pub type GapPersister = Box<dyn FnMut(&GapQueueState) -> bool + Send>;

#[derive(Default)]
struct Inner {
    entries: Vec<Entry>,
    /// Gaps that did not fit and are not yet in the queue as an aggregated gap.
    overflow: i64,
    persist: Option<GapPersister>,
    persist_failed: bool,
    /// The `central_outage` gap opened and not yet closed (persisted).
    open_outage: Option<OpenOutage>,
}

impl Inner {
    fn pending(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| e.state == GapState::Pending)
            .count()
    }

    /// Insert or replace by id. A replaced gap is pending again.
    fn push(&mut self, gap: GapReport) -> Result<(), QueueFull> {
        let id = gap_id(&gap).to_string();
        let pending = self.pending();
        if let Some(e) = self.entries.iter_mut().find(|e| gap_id(&e.gap) == id) {
            // A quarantined gap coming back as pending needs room like a new one.
            if e.state == GapState::Quarantined && pending >= MAX_QUEUED_GAPS {
                return Err(QueueFull);
            }
            *e = Entry {
                gap,
                state: GapState::Pending,
            };
            return Ok(());
        }
        if pending >= MAX_QUEUED_GAPS {
            return Err(QueueFull);
        }
        self.entries.push(Entry {
            gap,
            state: GapState::Pending,
        });
        Ok(())
    }

    /// Whether [`Inner::push`] would accept this gap (without changing anything).
    fn has_room_for(&self, gap: &GapReport) -> bool {
        let id = gap_id(gap);
        match self.entries.iter().find(|e| gap_id(&e.gap) == id) {
            Some(e) if e.state == GapState::Pending => true,
            _ => self.pending() < MAX_QUEUED_GAPS,
        }
    }

    /// Report the overflow tally as one `local_record_failed` gap as soon as
    /// there is room. The gap is new (its own id): a gap already sent is never
    /// changed, because the server answers a different body under the same id
    /// with 409. `invocation_ids` is empty on purpose: this gap says that
    /// `count` gap records were lost locally, it is not about invocations.
    fn materialize_overflow(&mut self) {
        if self.overflow <= 0 || self.pending() >= MAX_QUEUED_GAPS {
            return;
        }
        let gap = serde_json::from_value::<GapReport>(json!({
            "kind": "local_record_failed",
            "gap_id": uuid::Uuid::new_v4().to_string(),
            "detected_at": rfc3339(time::OffsetDateTime::now_utc()),
            "count": self.overflow,
            "invocation_ids": [],
        }));
        if let Ok(g) = gap {
            if self.push(g).is_ok() {
                self.overflow = 0;
            }
        }
    }

    fn snapshot(&self) -> GapQueueState {
        let of = |s: GapState| {
            self.entries
                .iter()
                .filter(|e| e.state == s)
                .map(|e| GapReport::clone(&e.gap))
                .collect::<Vec<_>>()
        };
        GapQueueState {
            pending: of(GapState::Pending),
            quarantined: of(GapState::Quarantined),
            overflow_count: self.overflow,
            open_outage: self.open_outage.clone(),
        }
    }

    fn flush(&mut self) {
        if self.persist.is_none() {
            return;
        }
        let snap = self.snapshot();
        let ok = self.persist.as_mut().is_some_and(|p| p(&snap));
        if !ok && !self.persist_failed {
            tracing::error!("gap queue is not durable: the write failed (kept in memory)");
        }
        self.persist_failed = !ok;
    }
}

/// Gap reports awaiting acknowledgement. Cheap to clone (shared).
///
/// Durable when a persister is attached ([`GapQueue::with_persister`]) and
/// restorable with [`GapQueue::restore`].
#[derive(Clone, Default)]
pub struct GapQueue(Arc<Mutex<Inner>>);

impl GapQueue {
    pub fn new() -> GapQueue {
        GapQueue::default()
    }

    /// Rebuild a queue from the persisted state (oldest pending first).
    pub fn restore(state: GapQueueState) -> GapQueue {
        let mut inner = Inner {
            overflow: state.overflow_count.max(0),
            open_outage: state.open_outage,
            ..Inner::default()
        };
        for gap in state.quarantined {
            inner.entries.push(Entry {
                gap,
                state: GapState::Quarantined,
            });
        }
        for gap in state.pending {
            inner.entries.push(Entry {
                gap,
                state: GapState::Pending,
            });
        }
        GapQueue(Arc::new(Mutex::new(inner)))
    }

    /// Persist every change from now on, and write the current state once.
    pub fn with_persister(self, p: GapPersister) -> GapQueue {
        {
            let mut g = self.lock();
            g.persist = Some(p);
            g.materialize_overflow();
            g.flush();
        }
        self
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Queue a gap. A gap with the id of a queued one replaces it and is pending
    /// again (an open `central_outage` is resent with its `ended_at`).
    pub fn push(&self, gap: GapReport) -> Result<(), QueueFull> {
        let mut g = self.lock();
        let r = g.push(gap);
        if r.is_ok() {
            g.flush();
        }
        r
    }

    /// Whether the queue can take this gap now. A producer whose own record is
    /// the only copy checks this first, so a refusal never turns into an overflow
    /// count on every retry.
    pub fn has_room_for(&self, gap: &GapReport) -> bool {
        self.lock().has_room_for(gap)
    }

    /// [`GapQueue::push`] for a producer: a gap that does not fit is counted and
    /// reported later as one aggregated `local_record_failed` gap (L6b), so the
    /// loss itself is recorded. Returns whether the gap itself was queued.
    pub fn record(&self, gap: GapReport) -> bool {
        let mut g = self.lock();
        let queued = g.push(gap).is_ok();
        if !queued {
            g.overflow = g.overflow.saturating_add(1);
            tracing::warn!("gap queue full: the gap is counted, not queued");
        }
        g.materialize_overflow();
        g.flush();
        queued
    }

    /// Gaps counted but not yet in the queue as an aggregated gap.
    pub fn overflow_count(&self) -> i64 {
        self.lock().overflow
    }

    /// The last write to the persister failed.
    pub fn persist_failed(&self) -> bool {
        self.lock().persist_failed
    }

    /// The `central_outage` gap opened and not yet closed, if any (persisted,
    /// so found again after a restart).
    pub fn open_outage(&self) -> Option<OpenOutage> {
        self.lock().open_outage.clone()
    }

    /// Remember (or forget) the open outage, durably.
    pub fn set_open_outage(&self, o: Option<OpenOutage>) {
        let mut g = self.lock();
        g.open_outage = o;
        g.flush();
    }

    /// Set `ended_at` on the queued `central_outage` gap `id` and make it
    /// pending again (the only mutation the server allows, L6b). `false` when
    /// the gap is not queued (it was acknowledged and dropped).
    pub fn close_outage(&self, id: &str, ended_at: &str) -> bool {
        let mut g = self.lock();
        let Some(e) = g.entries.iter_mut().find(|e| gap_id(&e.gap) == id) else {
            return false;
        };
        let Ok(mut v) = serde_json::to_value(&e.gap) else {
            return false;
        };
        if v["kind"] != "central_outage" {
            return false;
        }
        v["ended_at"] = Value::String(ended_at.to_string());
        let Ok(gap) = serde_json::from_value::<GapReport>(v) else {
            return false;
        };
        *e = Entry {
            gap,
            state: GapState::Pending,
        };
        g.flush();
        true
    }

    /// Oldest pending gaps, at most one report's worth.
    pub fn pending_batch(&self) -> Vec<GapReport> {
        self.pending_batch_limit(MAX_GAPS_PER_REPORT)
    }

    /// Oldest pending gaps, at most `n` (capped at one report's worth).
    pub fn pending_batch_limit(&self, n: usize) -> Vec<GapReport> {
        self.lock()
            .entries
            .iter()
            .filter(|e| e.state == GapState::Pending)
            .take(n.min(MAX_GAPS_PER_REPORT))
            .map(|e| GapReport::clone(&e.gap))
            .collect()
    }

    pub fn pending_ids(&self) -> Vec<String> {
        self.ids(GapState::Pending)
    }

    pub fn quarantined_ids(&self) -> Vec<String> {
        self.ids(GapState::Quarantined)
    }

    fn ids(&self, s: GapState) -> Vec<String> {
        self.lock()
            .entries
            .iter()
            .filter(|e| e.state == s)
            .map(|e| gap_id(&e.gap).to_string())
            .collect()
    }

    /// Apply a classified answer without checking versions (tests).
    pub fn settle(&self, outcome: &ReportOutcome) {
        self.settle_versioned(outcome, None);
    }

    /// Apply a classified answer for a report that carried the gaps `sent`.
    /// An entry is dropped or quarantined only if it still equals the version
    /// that was sent: a newer version (an outage closed while the report was in
    /// flight) stays pending, because the answer does not cover it.
    pub fn settle_versioned(&self, outcome: &ReportOutcome, sent: Option<&[GapReport]>) {
        let mut g = self.lock();
        let before = g.snapshot();
        let same = |e: &Entry| match sent {
            None => true,
            Some(s) => s.iter().any(|x| gap_id(x) == gap_id(&e.gap) && *x == e.gap),
        };
        let drop_ids = |q: &mut Vec<Entry>, ids: &[String]| {
            q.retain(|e| !(ids.iter().any(|i| i == gap_id(&e.gap)) && same(e)));
        };
        let mut evicted = 0i64;
        match outcome {
            ReportOutcome::Accepted {
                acknowledged,
                duplicate,
            }
            | ReportOutcome::SnapshotIgnored {
                acknowledged,
                duplicate,
            } => {
                drop_ids(&mut g.entries, acknowledged);
                drop_ids(&mut g.entries, duplicate);
            }
            // Stored gaps are durable on the server; refused ones stay pending.
            ReportOutcome::StorageLimit { stored, .. } => drop_ids(&mut g.entries, stored),
            ReportOutcome::Quarantine { gaps, .. } | ReportOutcome::Conflict { gaps } => {
                let q = &mut g.entries;
                for e in q.iter_mut() {
                    if gaps.iter().any(|i| i == gap_id(&e.gap)) && same(e) {
                        e.state = GapState::Quarantined;
                    }
                }
                // Oldest quarantined first, so quarantine stays bounded.
                while q
                    .iter()
                    .filter(|e| e.state == GapState::Quarantined)
                    .count()
                    > MAX_QUARANTINED_GAPS
                {
                    if let Some(i) = q.iter().position(|e| e.state == GapState::Quarantined) {
                        q.remove(i);
                        evicted += 1;
                    }
                }
            }
            ReportOutcome::Ambiguous
            | ReportOutcome::Rejected
            | ReportOutcome::Unreachable
            | ReportOutcome::Unavailable
            | ReportOutcome::Retry => {}
        }
        // An evicted quarantined gap is a lost record: count it so it is reported
        // as a `local_record_failed` gap instead of vanishing.
        if evicted > 0 {
            g.overflow = g.overflow.saturating_add(evicted);
            tracing::warn!(count = evicted, "quarantined gaps evicted (counted)");
        }
        // Room may have opened for an aggregated gap.
        g.materialize_overflow();
        if g.snapshot() != before {
            g.flush();
        }
    }
}

// ------------------------------------------------------------------ outcomes

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReportOutcome {
    /// 200: the listed ids are durable.
    Accepted {
        acknowledged: Vec<String>,
        duplicate: Vec<String>,
    },
    /// 200 with `state_applied = false`: the server kept a newer snapshot (a
    /// lower sequence or a replayed epoch). Gaps are handled as for `Accepted`;
    /// this is not a failure and does not back off, but it is logged so a stuck
    /// sequence can be diagnosed.
    SnapshotIgnored {
        acknowledged: Vec<String>,
        duplicate: Vec<String>,
    },
    /// A 422 that names no gap of a report that carried several (or any, outside
    /// isolation): the snapshot or any gap may be at fault, so nothing is
    /// quarantined; the reporter probes with a snapshot-only report.
    Ambiguous,
    /// 503 `storage_limit`: server storage, not an outage. `refused` stay
    /// pending; `stored` (the rest of a report whose refusal named items) are
    /// durable because the server commits them before answering.
    StorageLimit {
        refused: Vec<String>,
        stored: Vec<String>,
    },
    /// 422. `whole_report` when no usable item named a gap.
    Quarantine {
        gaps: Vec<String>,
        whole_report: bool,
    },
    /// 409: the named gaps conflict with stored ones.
    Conflict { gaps: Vec<String> },
    /// 403 `disabled` or `retired`.
    Rejected,
    /// No answer at all.
    Unreachable,
    /// 5xx that is not `storage_limit`.
    Unavailable,
    /// Any other answer (429, 404, 413, 401, an unreadable 200, ...).
    Retry,
}

impl ReportOutcome {
    /// Whether this answer may count toward a `central_outage` gap. A refusal for
    /// server storage does not: the server is up and answering. (Nothing opens an
    /// outage gap yet; the ingest path of T-11 S4 owns that.)
    pub fn signals_central_outage(&self) -> bool {
        matches!(
            self,
            ReportOutcome::Unreachable | ReportOutcome::Unavailable
        )
    }
}

fn error_code(body: &[u8]) -> Option<sigil_proxy_api::ApiError> {
    sigil_proxy_api::parse_api_error(body).ok()
}

/// Reduce an answer to an outcome. `sent` are the gap ids in the report, in order
/// (the `index` of a 422 item refers to this order). Pure.
pub fn classify(reply: Option<&StatusReply>, sent: &[String]) -> ReportOutcome {
    let Some(r) = reply else {
        return ReportOutcome::Unreachable;
    };
    let in_sent = |id: &str| sent.iter().any(|s| s == id);
    match r.status {
        200 => match sigil_proxy_api::parse_status_response(&r.body) {
            Ok(ok) => {
                let acknowledged = ok
                    .acknowledged_gap_ids
                    .iter()
                    .map(|u| u.as_str().to_string())
                    .filter(|i| in_sent(i))
                    .collect();
                let duplicate = ok
                    .duplicate_gap_ids
                    .iter()
                    .map(|u| u.as_str().to_string())
                    .filter(|i| in_sent(i))
                    .collect();
                if ok.state_applied {
                    ReportOutcome::Accepted {
                        acknowledged,
                        duplicate,
                    }
                } else {
                    ReportOutcome::SnapshotIgnored {
                        acknowledged,
                        duplicate,
                    }
                }
            }
            Err(_) => ReportOutcome::Retry,
        },
        403 => match error_code(&r.body).map(|e| e.error.code) {
            Some(ErrorCode::Disabled | ErrorCode::Retired) => ReportOutcome::Rejected,
            _ => ReportOutcome::Retry,
        },
        409 => {
            let gaps: Vec<String> = error_code(&r.body)
                .and_then(|e| e.error.items)
                .unwrap_or_default()
                .iter()
                .filter_map(|i| i.gap_id.as_ref().map(|g| g.as_str().to_string()))
                .filter(|g| in_sent(g))
                .collect();
            if gaps.is_empty() {
                ReportOutcome::Retry
            } else {
                ReportOutcome::Conflict { gaps }
            }
        }
        422 => {
            let items = error_code(&r.body)
                .and_then(|e| e.error.items)
                .unwrap_or_default();
            let mut gaps: Vec<String> = Vec::new();
            for it in &items {
                if let Some(id) = sent.get(it.index as usize) {
                    if !gaps.contains(id) {
                        gaps.push(id.clone());
                    }
                }
            }
            // Fail closed: items that name nothing in this report quarantine all
            // of it rather than letting the same invalid report be resent.
            if gaps.is_empty() {
                ReportOutcome::Quarantine {
                    gaps: sent.to_vec(),
                    whole_report: true,
                }
            } else {
                ReportOutcome::Quarantine {
                    gaps,
                    whole_report: false,
                }
            }
        }
        503 => {
            let err = error_code(&r.body);
            let storage_limit = err
                .as_ref()
                .is_some_and(|e| e.error.code.as_str() == "storage_limit");
            if !storage_limit {
                return ReportOutcome::Unavailable;
            }
            let items = err.and_then(|e| e.error.items).unwrap_or_default();
            let refused: Vec<String> = items
                .iter()
                .filter_map(|i| i.gap_id.as_ref().map(|g| g.as_str().to_string()))
                .filter(|g| in_sent(g))
                .collect();
            // An item without a gap_id cannot be attributed, so none of the
            // report is assumed stored.
            let unattributed = items.iter().any(|i| i.gap_id.is_none());
            if refused.is_empty() || unattributed {
                // Nothing named: every gap stays pending (resent, idempotent).
                ReportOutcome::StorageLimit {
                    refused: sent.to_vec(),
                    stored: Vec::new(),
                }
            } else {
                let stored = sent
                    .iter()
                    .filter(|s| !refused.contains(s))
                    .cloned()
                    .collect();
                ReportOutcome::StorageLimit { refused, stored }
            }
        }
        s if (500..600).contains(&s) => ReportOutcome::Unavailable,
        _ => ReportOutcome::Retry,
    }
}

// ------------------------------------------------------------------- builder

/// The report could not be built or did not validate. No detail: the cause could
/// echo a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuildError;

/// Called with a new sequence upper bound BEFORE sequences up to it are used;
/// `false` (not durable) stops the report, because a restart could then reuse a
/// sequence the server already holds.
pub type SequencePersister = Box<dyn FnMut(i64) -> bool + Send>;

/// What the `registry` section of a status report says, read from the registry
/// sync (T-13). `None` from a [`RegistryProbe`] means the registry could not be
/// read.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RegistrySnapshot {
    pub pending_entries: u64,
    pub sync_stalled: bool,
    pub quarantined_entries: u64,
    pub poisoned_entries: u64,
    pub discarded_reports: u64,
}

/// Source of the `registry` section; see `RegistryClient::health_probe`.
pub type RegistryProbe = Arc<dyn Fn() -> Option<RegistrySnapshot> + Send + Sync>;

pub struct StatusBuilder {
    proxy_id: String,
    epoch_id: String,
    last_sequence: i64,
    /// Highest bound known to be durable (0 without persistence).
    reserved: i64,
    persister: Option<SequencePersister>,
    central: CentralHealth,
    /// The event spool (T-14b). Without one (unit tests of the builder alone) the
    /// `spool` section is the empty placeholder and `last_assigned_sequence` is 0.
    spool: Option<Spool>,
    /// The registry sync (T-13b). Without one the `registry` section is the
    /// vacuous placeholder without the optional counters.
    registry: Option<RegistryProbe>,
    /// Runtime route health (T-12b2). Without it every configured route of a
    /// valid config is `supported`.
    health: Option<crate::route_health::RouteHealth>,
}

pub(crate) fn rfc3339(t: time::OffsetDateTime) -> String {
    t.replace_nanosecond(0)
        .unwrap_or(t)
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

impl StatusBuilder {
    pub fn new(proxy_id: &str, epoch_id: &str) -> StatusBuilder {
        StatusBuilder {
            proxy_id: proxy_id.to_string(),
            epoch_id: epoch_id.to_string(),
            last_sequence: 0,
            reserved: 0,
            persister: None,
            central: CentralHealth::new(),
            spool: None,
            registry: None,
            health: None,
        }
    }

    /// Report runtime route marks (`unsupported`/`degraded` with a reason).
    pub fn set_route_health(&mut self, health: crate::route_health::RouteHealth) {
        self.health = Some(health);
    }

    /// Report the `registry` section from the registry sync.
    pub fn set_registry(&mut self, probe: RegistryProbe) {
        self.registry = Some(probe);
    }

    /// Report the `spool` section and `last_assigned_sequence` from this spool.
    pub fn set_spool(&mut self, spool: Spool) {
        self.spool = Some(spool);
    }

    /// Read the `central` section from this handle (shared with the ingest client
    /// and the reporter).
    pub fn set_central(&mut self, central: CentralHealth) {
        self.central = central;
    }

    /// Persist the sequence bound in blocks. `floor` is the bound loaded at
    /// start: sequences continue strictly above it even if the clock went back.
    pub fn with_sequence_persistence(
        mut self,
        floor: Option<i64>,
        persister: SequencePersister,
    ) -> StatusBuilder {
        let f = floor.unwrap_or(0).max(0);
        self.last_sequence = f;
        self.reserved = f;
        self.persister = Some(persister);
        self
    }

    /// `status_sequence` is monotonic per epoch, and the epoch survives restarts
    /// (state_dir), while the server applies a snapshot only above its stored
    /// value. So the value is `max(wall clock ms, last + 1)`, and an upper bound
    /// ahead of it is persisted before use (see [`SEQUENCE_RESERVE`]); after a
    /// restart the floor is that bound, so a clock stepped back cannot wedge
    /// snapshots. A persistence failure fails the build (nothing is sent).
    fn next_sequence(&mut self, now: time::OffsetDateTime) -> Result<i64, BuildError> {
        let ms = i64::try_from(now.unix_timestamp_nanos() / 1_000_000).unwrap_or(i64::MAX);
        let seq = ms.max(self.last_sequence.saturating_add(1)).max(1);
        if let Some(p) = self.persister.as_mut() {
            if seq > self.reserved {
                let bound = seq.saturating_add(SEQUENCE_RESERVE);
                if !p(bound) {
                    return Err(BuildError);
                }
                self.reserved = bound;
            }
        }
        self.last_sequence = seq;
        Ok(seq)
    }

    /// The attached registry probe, if any. The async reporter reads it off the
    /// async workers (see [`Reporter::send_once_at`]).
    pub fn registry_probe(&self) -> Option<RegistryProbe> {
        self.registry.clone()
    }

    /// Build and validate one report body. A registry probe is read inline here
    /// (it opens SQLite); the async reporter reads it with `spawn_blocking` and
    /// calls [`StatusBuilder::build_with_registry`] instead.
    pub fn build(
        &mut self,
        view: &ConfigView,
        gaps: &[GapReport],
        now: time::OffsetDateTime,
    ) -> Result<Vec<u8>, BuildError> {
        let reading = self.registry.as_ref().map(|probe| probe());
        self.build_with_registry(view, gaps, now, reading)
    }

    /// [`StatusBuilder::build`] with the registry reading supplied: `None` when no
    /// probe is attached, `Some(None)` when the registry could not be read.
    pub fn build_with_registry(
        &mut self,
        view: &ConfigView,
        gaps: &[GapReport],
        now: time::OffsetDateTime,
        reading: Option<Option<RegistrySnapshot>>,
    ) -> Result<Vec<u8>, BuildError> {
        let mut config = json!({
            "state": view.state,
            "applied_revision": view.applied_revision,
            "observed_desired_revision": view.observed_revision,
            "expires_at": view.expires_at,
        });
        let c = config.as_object_mut().ok_or(BuildError)?;
        if let Some(e) = view.last_update_error {
            c.insert("last_update_error".into(), json!(e));
        }
        if let Some(v) = view.max_offline_retry_age_seconds {
            c.insert("max_offline_retry_age_seconds".into(), json!(v));
        }
        if let Some(v) = view.event_retention_seconds {
            c.insert("event_retention_seconds".into(), json!(v));
        }
        if let Some(h) = &view.config_hash {
            c.insert("config_hash".into(), json!(h));
        }
        let sequence = self.next_sequence(now)?;
        let gaps: Vec<Value> = gaps
            .iter()
            .map(|g| serde_json::to_value(g).map_err(|_| BuildError))
            .collect::<Result<_, _>>()?;
        // REAL sources: `central` (CentralHealth: ingest acks, answers and
        // failures) and `routes` (the upstreams of the applied config).
        //
        // `routes[].state` is derived from the config: `supported` while the
        // config is valid (the route is configured and serving), `disabled`
        // otherwise, unless the relay marked the route at runtime (T-12b2:
        // `unsupported`/`degraded` with a reason, see `route_health`). There is
        // no proactive upstream probe, so `supported` means "configured and not
        // known to be broken", not "verified".
        //
        // REAL (T-14b): `spool` and `last_assigned_sequence` come from the spool
        // snapshot when one is attached (always, in the production lifecycle).
        // PLACEHOLDER: `registry` is vacuous until the registry sync exists
        // (T-13). It says nothing about health. A builder with no spool attached
        // (unit tests only) reports an empty spool and `capacity_bytes = 1`, the
        // least the schema allows.
        let (spool_section, last_assigned) = match self.spool.as_ref().map(Spool::snapshot) {
            Some(s) => (
                json!({
                    "state": s.state,
                    "depth_events": s.unsent_events.saturating_add(s.retained_acked_events),
                    "unsent_events": s.unsent_events,
                    "bytes": s.unsent_bytes.saturating_add(s.retained_acked_bytes),
                    "capacity_bytes": s.capacity_bytes.max(1),
                    "oldest_unsent_age_seconds": s.oldest_unsent_age_seconds,
                    "quarantined_events": s.quarantined_events,
                }),
                s.last_assigned_sequence,
            ),
            None => (
                json!({"state": "ok", "depth_events": 0, "unsent_events": 0, "bytes": 0,
                    "capacity_bytes": 1, "oldest_unsent_age_seconds": null,
                    "quarantined_events": 0}),
                0,
            ),
        };
        // REAL when a registry sync is attached (T-13b): pending entries, a
        // stall flag and the optional quarantined / poisoned / discarded counts.
        // An unreadable registry reports `sync_stalled`. Without a probe (unit
        // tests of the builder alone) it is the old vacuous shape.
        let registry_section = match reading {
            Some(reading) => match reading {
                Some(r) => json!({
                    "pending_entries": r.pending_entries.min(i64::MAX as u64),
                    "sync_stalled": r.sync_stalled,
                    "quarantined_entries": r.quarantined_entries.min(i64::MAX as u64),
                    "poisoned_entries": r.poisoned_entries.min(i64::MAX as u64),
                    "discarded_reports": r.discarded_reports.min(i64::MAX as u64),
                }),
                None => json!({"pending_entries": 0, "sync_stalled": true}),
            },
            None => json!({"pending_entries": 0, "sync_stalled": false}),
        };
        let route_state = if view.state == ConfigState::Valid {
            "supported"
        } else {
            "disabled"
        };
        // A runtime mark (T-12b2) of a route still serving overrides
        // `supported`; a disabled config stays `disabled`.
        let marks = match (&self.health, view.state == ConfigState::Valid) {
            (Some(h), true) => h.current(),
            _ => Default::default(),
        };
        let routes: Vec<Value> = view
            .route_upstreams
            .iter()
            .take(256)
            .map(|u| match marks.get(u) {
                Some(m) => json!({"upstream_id": u, "state": m.state, "reason": m.reason}),
                None => json!({"upstream_id": u, "state": route_state}),
            })
            .collect();
        let body = json!({
            "schema_version": 1,
            "report_id": uuid::Uuid::new_v4().to_string(),
            "proxy_id": self.proxy_id,
            "epoch_id": self.epoch_id,
            "status_sequence": sequence,
            "sent_at": rfc3339(now),
            "config": config,
            "spool": spool_section,
            "registry": registry_section,
            "central": {"last_ingest_ack_at": self.central.last_ingest_ack_at(),
                "consecutive_failures": self.central.consecutive_failures()},
            "routes": routes,
            "counters": {"auth_failures": [], "unmatched_cancels": []},
            "gaps": gaps,
            "last_assigned_sequence": last_assigned,
        });
        let bytes = serde_json::to_vec(&body).map_err(|_| BuildError)?;
        // The shared parser is the contract check; a body it refuses is never sent.
        sigil_proxy_api::parse_status(&bytes).map_err(|_| BuildError)?;
        Ok(bytes)
    }
}

// -------------------------------------------------------------------- pacing

#[derive(Debug, Clone, Copy)]
pub struct ReporterParams {
    /// Interval between reports when all is well (the heartbeat), jittered.
    pub heartbeat: Duration,
    /// First retry delay after a failure; doubles up to `max_backoff`.
    pub retry: Duration,
    pub max_backoff: Duration,
    /// Least spacing between two reports, also for change-triggered ones.
    pub min_spacing: Duration,
}

impl Default for ReporterParams {
    /// Proposed values (unmeasured), like the config poll of section 6.3.
    fn default() -> Self {
        ReporterParams {
            heartbeat: Duration::from_secs(30),
            retry: Duration::from_secs(5),
            max_backoff: Duration::from_secs(300),
            min_spacing: Duration::from_secs(1),
        }
    }
}

/// How gaps are sent. An unattributed 422 must not destroy innocent gaps, so
/// the reporter tells the snapshot apart from the gaps, then the gaps apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Normal,
    /// Snapshot-only reports (no gaps) until one is accepted.
    SnapshotProbe,
    /// One gap per report; a gap is quarantined only if a 422 names it or it
    /// fails alone.
    Isolate,
}

/// Everything the reporter owns across sends.
pub struct Reporter {
    builder: StatusBuilder,
    gaps: GapQueue,
    params: ReporterParams,
    failures: u32,
    mode: Mode,
    central: CentralHealth,
    /// Singles sent in the current `Isolate` run (bounded, see
    /// [`MAX_ISOLATE_SENDS`]).
    isolate_sends: usize,
    /// F1: consecutive `state_applied = false` answers.
    ignored_streak: u32,
    wedged: bool,
    wedge_hook: Option<WedgeHook>,
}

/// Called with `true` when the status sequence looks wedged and `false` when a
/// snapshot is applied again.
pub type WedgeHook = Box<dyn FnMut(bool) + Send>;

/// F1: this many `state_applied = false` answers in a row mean the sequence is
/// stuck below the server's stored one (for example `sequence.json` removed
/// while the clock is behind), not a lost race.
pub const WEDGE_THRESHOLD: u32 = 3;

/// F2: singles sent in one isolation run before returning to batches. The
/// failing gap was among the first `MAX_GAPS_PER_REPORT` pending ones when the
/// 422 came, so a longer run only paces a steady gap producer down.
pub const MAX_ISOLATE_SENDS: usize = MAX_GAPS_PER_REPORT;

impl Reporter {
    pub fn new(proxy_id: &str, epoch_id: &str, gaps: GapQueue, params: ReporterParams) -> Reporter {
        Reporter {
            builder: StatusBuilder::new(proxy_id, epoch_id),
            gaps,
            params,
            failures: 0,
            mode: Mode::Normal,
            central: CentralHealth::new(),
            isolate_sends: 0,
            ignored_streak: 0,
            wedged: false,
            wedge_hook: None,
        }
    }

    /// Share the `central` section source (also fed by the ingest client).
    pub fn with_central(mut self, central: CentralHealth) -> Reporter {
        self.builder.set_central(central.clone());
        self.central = central;
        self
    }

    /// Report the `registry` section from this probe (see
    /// [`StatusBuilder::set_registry`]).
    pub fn with_registry(mut self, probe: RegistryProbe) -> Reporter {
        self.builder.set_registry(probe);
        self
    }

    /// Report the spool (see [`StatusBuilder::set_spool`]).
    pub fn with_spool(mut self, spool: Spool) -> Reporter {
        self.builder.set_spool(spool);
        self
    }

    /// Report the relay's runtime route marks.
    pub fn with_route_health(mut self, health: crate::route_health::RouteHealth) -> Reporter {
        self.builder.set_route_health(health);
        self
    }

    /// F1: tell the owner when the sequence becomes (un)wedged.
    pub fn with_wedge_hook(mut self, hook: WedgeHook) -> Reporter {
        self.wedge_hook = Some(hook);
        self
    }

    /// F1: the status sequence looks wedged (see [`WEDGE_THRESHOLD`]).
    pub fn sequence_wedged(&self) -> bool {
        self.wedged
    }

    /// Persist the status sequence bound (see [`StatusBuilder`]).
    pub fn with_sequence_persistence(
        mut self,
        floor: Option<i64>,
        persister: SequencePersister,
    ) -> Reporter {
        self.builder = self.builder.with_sequence_persistence(floor, persister);
        self
    }

    /// Build, send and settle one report. `None` when nothing was sent (disabled
    /// locally, or the report did not validate).
    pub async fn send_once<T: StatusTransport + ?Sized>(
        &mut self,
        transport: &T,
        view: &ConfigView,
    ) -> Option<ReportOutcome> {
        self.send_once_at(transport, view, time::OffsetDateTime::now_utc())
            .await
    }

    /// [`Reporter::send_once`] with an explicit clock.
    pub async fn send_once_at<T: StatusTransport + ?Sized>(
        &mut self,
        transport: &T,
        view: &ConfigView,
        now: time::OffsetDateTime,
    ) -> Option<ReportOutcome> {
        // A disabled proxy's report is rejected by the server (section 6.2), so
        // `disabled` stays local and nothing is sent; the config fetch learns of
        // a re-enable.
        if view.state == ConfigState::Disabled {
            return None;
        }
        let batch = match self.mode {
            Mode::Normal => self.gaps.pending_batch(),
            Mode::SnapshotProbe => Vec::new(),
            Mode::Isolate => self.gaps.pending_batch_limit(1),
        };
        let sent: Vec<String> = batch.iter().map(|g| gap_id(g).to_string()).collect();
        // The probe opens SQLite: read it off the async workers. A probe that
        // panics or a runtime that is shutting down reads as an unreadable
        // registry (`sync_stalled`), never as a healthy one.
        let reading = match self.builder.registry_probe() {
            Some(probe) => Some(
                tokio::task::spawn_blocking(move || probe())
                    .await
                    .unwrap_or(None),
            ),
            None => None,
        };
        let Ok(body) = self.builder.build_with_registry(view, &batch, now, reading) else {
            tracing::error!("status report did not validate; not sent");
            return None;
        };
        let reply = transport.post_status(body).await;
        let mut outcome = classify(reply.as_ref(), &sent);
        if outcome.signals_central_outage() {
            self.central.record_failure();
        } else if reply.as_ref().is_some_and(|r| r.status != 404) {
            // A 404 (`proxy_unknown`) is an answer, but not a healthy one.
            self.central.record_answer();
        }
        if matches!(
            outcome,
            ReportOutcome::Quarantine {
                whole_report: true,
                ..
            }
        ) && !(self.mode == Mode::Isolate && sent.len() == 1)
        {
            // Not attributable: quarantine nothing. Probe the snapshot alone
            // next; a report with no gaps that still fails is the snapshot's
            // fault and the gaps stay pending.
            outcome = ReportOutcome::Ambiguous;
            if !sent.is_empty() {
                self.mode = Mode::SnapshotProbe;
            }
        }
        self.gaps.settle_versioned(&outcome, Some(&batch));
        let was = self.mode;
        self.mode = match (self.mode, &outcome) {
            (
                Mode::SnapshotProbe,
                ReportOutcome::Accepted { .. } | ReportOutcome::SnapshotIgnored { .. },
            ) => Mode::Isolate,
            // F2: the failing gap is found (quarantined alone, or named): back
            // to batches. Good gaps behind it are not sent one by one.
            (Mode::Isolate, ReportOutcome::Quarantine { .. } | ReportOutcome::Conflict { .. }) => {
                Mode::Normal
            }
            (m, _) => m,
        };
        if self.mode == Mode::Isolate {
            self.isolate_sends = if was == Mode::Isolate {
                self.isolate_sends + 1
            } else {
                1
            };
            // F2: a steady producer must not keep the reporter in singles.
            if self.isolate_sends >= MAX_ISOLATE_SENDS || self.gaps.pending_ids().is_empty() {
                self.mode = Mode::Normal;
            }
        }
        if self.mode != Mode::Isolate {
            self.isolate_sends = 0;
        }
        self.track_wedge(&outcome);
        tracing::info!(outcome = outcome_label(&outcome), "status report");
        Some(outcome)
    }

    /// F1: count consecutive `state_applied = false` answers; warn once at the
    /// threshold and tell the hook. A failure in between is neither an answer
    /// nor a reset. An applied snapshot clears it.
    fn track_wedge(&mut self, outcome: &ReportOutcome) {
        match outcome {
            ReportOutcome::SnapshotIgnored { .. } => {
                self.ignored_streak = self.ignored_streak.saturating_add(1);
                if self.ignored_streak == WEDGE_THRESHOLD && !self.wedged {
                    self.wedged = true;
                    tracing::warn!(
                        consecutive = self.ignored_streak,
                        "status snapshots are being ignored by the server: the status sequence \
                         looks stuck below its stored one (was sequence.json removed while the \
                         clock is behind?)"
                    );
                    if let Some(h) = self.wedge_hook.as_mut() {
                        h(true);
                    }
                }
            }
            ReportOutcome::Accepted { .. } => {
                self.ignored_streak = 0;
                if self.wedged {
                    self.wedged = false;
                    tracing::info!("status snapshots are applied again");
                    if let Some(h) = self.wedge_hook.as_mut() {
                        h(false);
                    }
                }
            }
            _ => {}
        }
    }

    /// Delay before the next report, and whether a config change may bring it
    /// forward (only after a healthy answer: never hot after a rejection, a
    /// storage refusal or a failure).
    fn next_delay(&mut self, outcome: Option<&ReportOutcome>) -> (Duration, bool) {
        let p = self.params;
        let backoff = |f: &mut u32| {
            *f = f.saturating_add(1);
            let shift = (*f - 1).min(16);
            p.retry
                .saturating_mul(1u32 << shift)
                .min(p.max_backoff)
                .max(p.retry)
        };
        let (d, early) = match outcome {
            // Not sent (disabled locally or invalid): wait a heartbeat.
            None => (p.heartbeat, true),
            Some(ReportOutcome::Accepted { .. } | ReportOutcome::SnapshotIgnored { .. }) => {
                self.failures = 0;
                if self.mode == Mode::Normal {
                    (p.heartbeat, true)
                } else {
                    // Still isolating: singles go at the least spacing (F2).
                    (p.min_spacing, false)
                }
            }
            Some(ReportOutcome::StorageLimit { .. }) => {
                self.failures = 0;
                (p.heartbeat, false)
            }
            Some(ReportOutcome::Rejected) => (p.max_backoff, false),
            Some(ReportOutcome::Quarantine { .. }) | Some(ReportOutcome::Conflict { .. }) => {
                // The rest of the gaps go out again soon.
                self.failures = 0;
                (p.retry, false)
            }
            Some(
                ReportOutcome::Ambiguous
                | ReportOutcome::Unreachable
                | ReportOutcome::Unavailable
                | ReportOutcome::Retry,
            ) => (backoff(&mut self.failures), false),
        };
        (crate::config_sync::jitter(d), early)
    }
}

fn outcome_label(o: &ReportOutcome) -> &'static str {
    match o {
        ReportOutcome::Accepted { .. } => "accepted",
        ReportOutcome::SnapshotIgnored { .. } => "accepted_snapshot_ignored",
        ReportOutcome::Ambiguous => "unattributed_422",
        ReportOutcome::StorageLimit { .. } => "storage_limit",
        ReportOutcome::Quarantine {
            whole_report: true, ..
        } => "quarantined_whole_report",
        ReportOutcome::Quarantine { .. } => "quarantined_gaps",
        ReportOutcome::Conflict { .. } => "conflict",
        ReportOutcome::Rejected => "rejected",
        ReportOutcome::Unreachable => "unreachable",
        ReportOutcome::Unavailable => "unavailable",
        ReportOutcome::Retry => "retry",
    }
}

/// Send reports until `shutdown` completes: a heartbeat every `heartbeat` (with
/// jitter), earlier when the config view changes (an apply result, expiry, a
/// disable), never closer than `min_spacing`, and backed off after a failure.
pub async fn run_status_reporter<T: StatusTransport + ?Sized>(
    transport: &T,
    mut reporter: Reporter,
    mut view_rx: watch::Receiver<ConfigView>,
    shutdown: impl Future<Output = ()>,
) {
    tokio::pin!(shutdown);
    let params = reporter.params;
    // The first report waits for the first config attempt (a view change) or one
    // heartbeat, so it does not report a state about to change.
    let mut next = Instant::now() + crate::config_sync::jitter(params.heartbeat);
    let mut last_sent: Option<Instant> = None;
    let mut early_ok = true;
    let mut watching = true;
    loop {
        loop {
            tokio::select! {
                _ = &mut shutdown => return,
                _ = tokio::time::sleep_until(next) => break,
                changed = async {
                    if watching {
                        view_rx.changed().await.is_ok()
                    } else {
                        std::future::pending::<bool>().await
                    }
                } => {
                    if !changed {
                        watching = false;
                    } else if early_ok {
                        let floor = last_sent.map_or_else(Instant::now, |t| t + params.min_spacing);
                        next = next.min(floor.max(Instant::now()));
                    }
                }
            }
        }
        let view = view_rx.borrow_and_update().clone();
        let outcome = tokio::select! {
            _ = &mut shutdown => return,
            o = reporter.send_once(transport, &view) => o,
        };
        let now = Instant::now();
        last_sent = Some(now);
        let (delay, early) = reporter.next_delay(outcome.as_ref());
        early_ok = early;
        next = now + delay.max(params.min_spacing);
    }
}

/// Hand the spool's gaps (`spool_expired`, recorded by the spool itself) to the
/// gap queue once. Returns how many were handed off.
///
/// A gap leaves the spool only after the queue holds it durably: if it does not
/// fit, or the queue could not be persisted, the gap stays in the spool and is
/// offered again on the next call. Offering a gap twice (a crash between the
/// two steps) is harmless:
/// the queue replaces an entry by `gap_id`, and the server answers a repeated
/// `gap_id` with the same body as `duplicate`.
pub async fn hand_off_spool_gaps(spool: &Spool, gaps: &GapQueue) -> usize {
    let Ok(pending) = spool.pending_gaps_async().await else {
        return 0;
    };
    if pending.is_empty() {
        return 0;
    }
    // Only gaps the queue takes are recorded and handed off. A gap that does not
    // fit stays in the spool (durable) and is offered again next time; recording
    // it anyway would only bump the overflow count and lose its range.
    let mut ids: Vec<String> = Vec::new();
    for g in pending {
        // Checked right before each record, so a batch cannot overshoot.
        if gaps.has_room_for(&g) {
            ids.push(gap_id(&g).to_string());
            // `record` flushes the persister, so `persist_failed` below
            // describes this very write, not an earlier one.
            gaps.record(g);
        }
    }
    if ids.is_empty() {
        return 0;
    }
    if gaps.persist_failed() {
        // Not durable yet: keep them in the spool, which is durable.
        return 0;
    }
    match spool.gaps_handed_off_async(&ids).await {
        Ok(()) => ids.len(),
        Err(_) => 0,
    }
}

/// Run [`hand_off_spool_gaps`] every `interval` until `shutdown` completes.
pub async fn run_spool_gap_pump(
    spool: Spool,
    gaps: GapQueue,
    interval: Duration,
    shutdown: impl Future<Output = ()>,
) {
    tokio::pin!(shutdown);
    loop {
        hand_off_spool_gaps(&spool, &gaps).await;
        tokio::select! {
            _ = &mut shutdown => return,
            _ = tokio::time::sleep(interval) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigil_proxy_api::status::LastUpdateError;
    use std::collections::VecDeque;

    fn uid(n: u32) -> String {
        format!("00000000-0000-4000-8000-{n:012x}")
    }

    fn quarantine_gap(n: u32) -> GapReport {
        serde_json::from_value(json!({
            "kind": "event_quarantined", "gap_id": uid(n),
            "detected_at": "2026-10-11T00:00:00Z", "event_ids": [uid(900)],
            "code": "semantic_invalid"}))
        .unwrap()
    }

    fn outage_gap(n: u32, ended: Value) -> GapReport {
        serde_json::from_value(json!({
            "kind": "central_outage", "gap_id": uid(n),
            "detected_at": "2026-10-11T00:00:00Z",
            "started_at": "2026-10-11T00:00:00Z", "ended_at": ended}))
        .unwrap()
    }

    fn view(state: ConfigState) -> ConfigView {
        let valid = state == ConfigState::Valid;
        ConfigView {
            state,
            last_update_error: None,
            applied_revision: valid.then_some(7),
            config_hash: valid.then(|| "a".repeat(64)),
            observed_revision: valid.then_some(7),
            expires_at: valid.then(|| "2026-10-11T00:05:00Z".to_string()),
            max_offline_retry_age_seconds: valid.then_some(2_592_000),
            event_retention_seconds: valid.then_some(7_776_000),
            route_upstreams: if valid {
                vec!["up-r1".into(), "up-r2".into()]
            } else {
                vec![]
            },
        }
    }

    fn reply(status: u16, body: Value) -> Option<StatusReply> {
        Some(StatusReply {
            status,
            body: serde_json::to_vec(&body).unwrap(),
        })
    }

    fn err(code: &str, items: Value) -> Value {
        json!({"error": {"code": code, "message": "fixed", "items": items}})
    }

    fn ids(v: &[u32]) -> Vec<String> {
        v.iter().map(|n| uid(*n)).collect()
    }

    // ---- builder

    #[test]
    fn builds_a_valid_report_from_the_config_view() {
        let mut b = StatusBuilder::new("px-1", &uid(5));
        let now = time::OffsetDateTime::now_utc();
        let mut v = view(ConfigState::Valid);
        v.last_update_error = Some(LastUpdateError::FetchFailed);
        let bytes = b.build(&v, &[quarantine_gap(1)], now).unwrap();
        let st = sigil_proxy_api::parse_status(&bytes).unwrap();
        assert_eq!(st.proxy_id.as_str(), "px-1");
        assert_eq!(st.config.state, ConfigState::Valid);
        assert_eq!(st.config.applied_revision.unwrap().get(), 7);
        assert_eq!(
            st.config.last_update_error,
            Some(LastUpdateError::FetchFailed)
        );
        assert_eq!(st.config.config_hash.unwrap().as_str(), "a".repeat(64));
        assert_eq!(st.gaps.len(), 1);
        // none/expired also validate, with nulls
        for s in [ConfigState::None, ConfigState::Expired] {
            b.build(&view(s), &[], now).unwrap();
        }
    }

    #[test]
    fn sequence_is_strictly_increasing_even_within_one_millisecond() {
        let mut b = StatusBuilder::new("px-1", &uid(5));
        let now = time::OffsetDateTime::now_utc();
        let a =
            sigil_proxy_api::parse_status(&b.build(&view(ConfigState::None), &[], now).unwrap())
                .unwrap();
        let c =
            sigil_proxy_api::parse_status(&b.build(&view(ConfigState::None), &[], now).unwrap())
                .unwrap();
        assert!(c.status_sequence.get() > a.status_sequence.get());
        assert_ne!(a.report_id, c.report_id);
    }

    /// A view the schema forbids (valid without R/E or hash) is never sent.
    #[test]
    fn invalid_view_does_not_build() {
        let mut b = StatusBuilder::new("px-1", &uid(5));
        let mut v = view(ConfigState::Valid);
        v.config_hash = None;
        let now = time::OffsetDateTime::now_utc();
        assert_eq!(b.build(&v, &[], now), Err(BuildError));
        let mut v = view(ConfigState::Valid);
        v.event_retention_seconds = None;
        assert_eq!(b.build(&v, &[], now), Err(BuildError));
        // a malformed proxy id never reaches the wire
        let mut b = StatusBuilder::new("bad id!", &uid(5));
        assert_eq!(b.build(&view(ConfigState::None), &[], now), Err(BuildError));
    }

    // ---- classify

    #[test]
    fn ok_acknowledges_only_sent_ids() {
        let sent = ids(&[1, 2]);
        let o = classify(
            reply(
                200,
                json!({"state_applied": true, "acknowledged_gap_ids": [uid(1), uid(99)],
                    "duplicate_gap_ids": [uid(2)]}),
            )
            .as_ref(),
            &sent,
        );
        assert_eq!(
            o,
            ReportOutcome::Accepted {
                acknowledged: ids(&[1]),
                duplicate: ids(&[2])
            }
        );
        assert_eq!(
            classify(reply(200, json!({"nope": 1})).as_ref(), &sent),
            ReportOutcome::Retry
        );
    }

    #[test]
    fn storage_limit_is_not_an_outage_and_resends_only_refused() {
        let sent = ids(&[1, 2, 3]);
        let o = classify(
            reply(
                503,
                err(
                    "storage_limit",
                    json!([{"index": 1, "gap_id": uid(2), "code": "storage_limit"}]),
                ),
            )
            .as_ref(),
            &sent,
        );
        assert_eq!(
            o,
            ReportOutcome::StorageLimit {
                refused: ids(&[2]),
                stored: ids(&[1, 3])
            }
        );
        assert!(!o.signals_central_outage());
        // no usable items: nothing is assumed stored
        let o = classify(reply(503, err("storage_limit", json!([]))).as_ref(), &sent);
        assert_eq!(
            o,
            ReportOutcome::StorageLimit {
                refused: sent.clone(),
                stored: vec![]
            }
        );
        // any other 503 and a missing answer may be an outage
        for r in [
            reply(503, err("storage_unavailable", json!([]))),
            reply(503, json!("x")),
            reply(500, json!({})),
        ] {
            assert!(classify(r.as_ref(), &sent).signals_central_outage());
        }
        assert!(classify(None, &sent).signals_central_outage());
    }

    #[test]
    fn unprocessable_quarantines_items_or_the_whole_report() {
        let sent = ids(&[1, 2, 3]);
        let o = classify(
            reply(
                422,
                err(
                    "semantic_invalid",
                    json!([{"index": 2, "code": "semantic_invalid"}]),
                ),
            )
            .as_ref(),
            &sent,
        );
        assert_eq!(
            o,
            ReportOutcome::Quarantine {
                gaps: ids(&[3]),
                whole_report: false
            }
        );
        for r in [
            reply(422, err("semantic_invalid", json!([]))),
            reply(
                422,
                json!({"error": {"code": "semantic_invalid", "message": "x"}}),
            ),
            // an index outside the report names nothing
            reply(
                422,
                err(
                    "semantic_invalid",
                    json!([{"index": 9, "code": "semantic_invalid"}]),
                ),
            ),
            reply(422, json!("garbage")),
        ] {
            assert_eq!(
                classify(r.as_ref(), &sent),
                ReportOutcome::Quarantine {
                    gaps: sent.clone(),
                    whole_report: true
                }
            );
        }
    }

    #[test]
    fn conflict_disabled_and_the_rest() {
        let sent = ids(&[1, 2]);
        assert_eq!(
            classify(
                reply(
                    409,
                    err(
                        "conflict",
                        json!([{"index": 0, "gap_id": uid(1), "code": "conflict"}])
                    )
                )
                .as_ref(),
                &sent
            ),
            ReportOutcome::Conflict { gaps: ids(&[1]) }
        );
        for c in ["disabled", "retired"] {
            assert_eq!(
                classify(reply(403, err(c, json!([]))).as_ref(), &sent),
                ReportOutcome::Rejected
            );
        }
        assert_eq!(
            classify(reply(403, err("forbidden", json!([]))).as_ref(), &sent),
            ReportOutcome::Retry
        );
        for s in [401, 404, 413, 429, 302] {
            assert_eq!(
                classify(reply(s, json!({})).as_ref(), &sent),
                ReportOutcome::Retry
            );
        }
    }

    // ---- queue

    #[test]
    fn queue_settles_per_outcome() {
        let q = GapQueue::new();
        for n in 1..=4 {
            q.push(quarantine_gap(n)).unwrap();
        }
        q.settle(&ReportOutcome::StorageLimit {
            refused: ids(&[2]),
            stored: ids(&[1]),
        });
        assert_eq!(q.pending_ids(), ids(&[2, 3, 4]));
        q.settle(&ReportOutcome::Quarantine {
            gaps: ids(&[3]),
            whole_report: false,
        });
        assert_eq!(q.pending_ids(), ids(&[2, 4]));
        assert_eq!(q.quarantined_ids(), ids(&[3]));
        // quarantined gaps are not in the next batch
        assert_eq!(q.pending_batch().len(), 2);
        q.settle(&ReportOutcome::Accepted {
            acknowledged: ids(&[2]),
            duplicate: ids(&[4]),
        });
        assert!(q.pending_ids().is_empty());
        // failures drop nothing
        q.push(quarantine_gap(5)).unwrap();
        for o in [
            ReportOutcome::Unreachable,
            ReportOutcome::Unavailable,
            ReportOutcome::Retry,
            ReportOutcome::Rejected,
        ] {
            q.settle(&o);
        }
        assert_eq!(q.pending_ids(), ids(&[5]));
    }

    #[test]
    fn open_outage_is_replaced_by_its_close_and_resent() {
        let q = GapQueue::new();
        q.push(outage_gap(1, Value::Null)).unwrap();
        q.settle(&ReportOutcome::Accepted {
            acknowledged: ids(&[1]),
            duplicate: vec![],
        });
        q.push(outage_gap(1, json!("2026-10-11T00:10:00Z")))
            .unwrap();
        assert_eq!(q.pending_ids(), ids(&[1]));
        // the same id never queues twice
        q.push(outage_gap(1, json!("2026-10-11T00:10:00Z")))
            .unwrap();
        assert_eq!(q.pending_batch().len(), 1);
    }

    #[test]
    fn full_queue_refuses_instead_of_dropping() {
        let q = GapQueue::new();
        for n in 0..MAX_QUEUED_GAPS as u32 {
            q.push(quarantine_gap(n)).unwrap();
        }
        assert_eq!(q.push(quarantine_gap(99_999)), Err(QueueFull));
        assert_eq!(q.pending_batch().len(), MAX_GAPS_PER_REPORT);
    }

    // ---- reporter loop (paused clock, fake transport)

    struct Fake {
        replies: Mutex<VecDeque<Option<StatusReply>>>,
        sent: Mutex<Vec<(Instant, Vec<u8>)>>,
    }

    impl Fake {
        fn new(replies: Vec<Option<StatusReply>>) -> Arc<Fake> {
            Arc::new(Fake {
                replies: Mutex::new(replies.into()),
                sent: Mutex::default(),
            })
        }
        fn count(&self) -> usize {
            self.sent.lock().unwrap().len()
        }
    }

    impl StatusTransport for Arc<Fake> {
        fn post_status(&self, body: Vec<u8>) -> PostFuture<'_> {
            self.sent.lock().unwrap().push((Instant::now(), body));
            let r = self.replies.lock().unwrap().pop_front().flatten();
            Box::pin(async move { r })
        }
    }

    fn params() -> ReporterParams {
        ReporterParams::default()
    }

    async fn settle_time() {
        // Let spawned work run under the paused clock.
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn heartbeat_repeats_with_jitter_and_stops_on_shutdown() {
        let fake = Fake::new(vec![]);
        let (tx, rx) = watch::channel(view(ConfigState::None));
        let (stop_tx, stop_rx) = watch::channel(false);
        let f2 = fake.clone();
        let task = tokio::spawn(async move {
            let mut stop_rx = stop_rx;
            run_status_reporter(
                &f2,
                Reporter::new("px-1", &uid(5), GapQueue::new(), params()),
                rx,
                async move {
                    let _ = stop_rx.wait_for(|v| *v).await;
                },
            )
            .await;
        });
        settle_time().await;
        assert_eq!(fake.count(), 0, "first report waits for a heartbeat");
        tokio::time::sleep(Duration::from_secs(23)).await;
        assert_eq!(fake.count(), 0, "heartbeat jitter is at least 24 s");
        tokio::time::sleep(Duration::from_secs(14)).await;
        assert!(fake.count() >= 1);
        // unreachable server: backoff from 5 s, never faster than min spacing
        tokio::time::sleep(Duration::from_secs(60)).await;
        let n = fake.count();
        assert!((2..=8).contains(&n), "{n}");
        let times: Vec<Instant> = fake.sent.lock().unwrap().iter().map(|s| s.0).collect();
        assert!(times
            .windows(2)
            .all(|w| w[1] - w[0] >= Duration::from_secs(1)));
        drop(tx);
        let _ = stop_tx.send(true);
        task.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn config_change_is_reported_promptly_after_a_healthy_answer() {
        let ok = reply(
            200,
            json!({"state_applied": true, "acknowledged_gap_ids": [], "duplicate_gap_ids": []}),
        );
        let fake = Fake::new(vec![ok.clone(), ok.clone(), ok]);
        let (tx, rx) = watch::channel(view(ConfigState::None));
        let (stop_tx, stop_rx) = watch::channel(false);
        let f2 = fake.clone();
        let task = tokio::spawn(async move {
            let mut stop_rx = stop_rx;
            run_status_reporter(
                &f2,
                Reporter::new("px-1", &uid(5), GapQueue::new(), params()),
                rx,
                async move {
                    let _ = stop_rx.wait_for(|v| *v).await;
                },
            )
            .await;
        });
        // The first apply result moves the first report forward.
        tx.send(view(ConfigState::Valid)).unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert_eq!(fake.count(), 1);
        let first = sigil_proxy_api::parse_status(&fake.sent.lock().unwrap()[0].1).unwrap();
        assert_eq!(first.config.state, ConfigState::Valid);
        // A later change goes out within about a second, not a heartbeat later.
        let mut v = view(ConfigState::Valid);
        v.last_update_error = Some(LastUpdateError::StaleRevision);
        tx.send(v).unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert_eq!(fake.count(), 2);
        let second = sigil_proxy_api::parse_status(&fake.sent.lock().unwrap()[1].1).unwrap();
        assert_eq!(
            second.config.last_update_error,
            Some(LastUpdateError::StaleRevision)
        );
        assert!(second.status_sequence.get() > first.status_sequence.get());
        let _ = stop_tx.send(true);
        task.await.unwrap();
    }

    /// A rejection backs off to the maximum; a config change does not make it hot.
    #[tokio::test(start_paused = true)]
    async fn rejection_is_not_retried_hot() {
        let rej = reply(403, err("disabled", json!([])));
        let fake = Fake::new(vec![rej.clone(), rej.clone(), rej]);
        let (tx, rx) = watch::channel(view(ConfigState::None));
        let (stop_tx, stop_rx) = watch::channel(false);
        let f2 = fake.clone();
        let task = tokio::spawn(async move {
            let mut stop_rx = stop_rx;
            run_status_reporter(
                &f2,
                Reporter::new("px-1", &uid(5), GapQueue::new(), params()),
                rx,
                async move {
                    let _ = stop_rx.wait_for(|v| *v).await;
                },
            )
            .await;
        });
        tx.send(view(ConfigState::Valid)).unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert_eq!(fake.count(), 1);
        let mut v = view(ConfigState::Valid);
        v.last_update_error = Some(LastUpdateError::FetchFailed);
        tx.send(v).unwrap();
        tokio::time::sleep(Duration::from_secs(200)).await;
        assert_eq!(fake.count(), 1, "no retry within the maximum backoff");
        tokio::time::sleep(Duration::from_secs(200)).await;
        assert_eq!(fake.count(), 2);
        let _ = stop_tx.send(true);
        task.await.unwrap();
    }

    /// Locally disabled: nothing is sent, and the local state is not touched by
    /// the (never-made) report.
    #[tokio::test(start_paused = true)]
    async fn locally_disabled_sends_nothing() {
        let fake = Fake::new(vec![]);
        let mut r = Reporter::new("px-1", &uid(5), GapQueue::new(), params());
        assert!(r
            .send_once(&fake, &view(ConfigState::Disabled))
            .await
            .is_none());
        assert_eq!(fake.count(), 0);
        assert!(r.send_once(&fake, &view(ConfigState::None)).await.is_some());
        assert_eq!(fake.count(), 1);
    }

    /// End to end through the reporter: storage_limit keeps only refused gaps and
    /// the next report carries only them.
    #[tokio::test(start_paused = true)]
    async fn storage_limit_then_resend_only_refused() {
        let q = GapQueue::new();
        for n in 1..=3 {
            q.push(quarantine_gap(n)).unwrap();
        }
        let fake = Fake::new(vec![
            reply(
                503,
                err(
                    "storage_limit",
                    json!([{"index": 2, "gap_id": uid(3), "code": "storage_limit"}]),
                ),
            ),
            reply(
                200,
                json!({"state_applied": true, "acknowledged_gap_ids": [uid(3)], "duplicate_gap_ids": []}),
            ),
        ]);
        let mut r = Reporter::new("px-1", &uid(5), q.clone(), params());
        let v = view(ConfigState::None);
        let o = r.send_once(&fake, &v).await.unwrap();
        assert!(matches!(o, ReportOutcome::StorageLimit { .. }));
        assert_eq!(q.pending_ids(), ids(&[3]));
        let o = r.send_once(&fake, &v).await.unwrap();
        assert!(matches!(o, ReportOutcome::Accepted { .. }));
        assert!(q.pending_ids().is_empty());
        let sent = fake.sent.lock().unwrap();
        let first = sigil_proxy_api::parse_status(&sent[0].1).unwrap();
        let second = sigil_proxy_api::parse_status(&sent[1].1).unwrap();
        assert_eq!(first.gaps.len(), 3);
        assert_eq!(second.gaps.len(), 1);
        // no central_outage gap was opened by the refusal
        assert!(second
            .gaps
            .iter()
            .all(|g| !matches!(g, GapReport::CentralOutage(_))));
    }

    #[test]
    fn debug_of_a_reply_hides_the_body() {
        let r = StatusReply {
            status: 200,
            body: b"SECRET-BODY".to_vec(),
        };
        assert!(!format!("{r:?}").contains("SECRET"));
    }

    // ---- review fixes: sequence persistence (M1), isolation (M2), bounds (L1), L3

    type ScriptFn = Box<dyn FnMut(&Value) -> Option<StatusReply> + Send>;

    /// Closure-driven transport that records every body.
    struct Script {
        f: Mutex<ScriptFn>,
        bodies: Mutex<Vec<Value>>,
    }

    impl Script {
        fn new(f: impl FnMut(&Value) -> Option<StatusReply> + Send + 'static) -> Script {
            Script {
                f: Mutex::new(Box::new(f)),
                bodies: Mutex::default(),
            }
        }
        fn sent_gap_ids(&self, n: usize) -> Vec<String> {
            gap_ids_of(&self.bodies.lock().unwrap()[n])
        }
    }

    impl StatusTransport for Script {
        fn post_status(&self, body: Vec<u8>) -> PostFuture<'_> {
            let v: Value = serde_json::from_slice(&body).unwrap();
            self.bodies.lock().unwrap().push(v.clone());
            let r = (self.f.lock().unwrap())(&v);
            Box::pin(async move { r })
        }
    }

    fn gap_ids_of(v: &Value) -> Vec<String> {
        v["gaps"]
            .as_array()
            .unwrap()
            .iter()
            .map(|g| g["gap_id"].as_str().unwrap().to_string())
            .collect()
    }

    fn ok200() -> Option<StatusReply> {
        reply(
            200,
            json!({"state_applied": true, "acknowledged_gap_ids": [], "duplicate_gap_ids": []}),
        )
    }

    fn ack200(ids: &[String]) -> Option<StatusReply> {
        reply(
            200,
            json!({"state_applied": true, "acknowledged_gap_ids": ids, "duplicate_gap_ids": []}),
        )
    }

    fn unattributed_422() -> Option<StatusReply> {
        reply(
            422,
            json!({"error": {"code": "semantic_invalid", "message": "fixed"}}),
        )
    }

    /// Server model: a snapshot applies only above the stored sequence of the
    /// epoch (sigil-server status.rs).
    fn enforcing() -> Script {
        let stored = Mutex::new(0i64);
        Script::new(move |v| {
            let seq = v["status_sequence"].as_i64().unwrap();
            let mut st = stored.lock().unwrap();
            let applied = seq > *st;
            if applied {
                *st = seq;
            }
            reply(
                200,
                json!({"state_applied": applied, "acknowledged_gap_ids": [],
                    "duplicate_gap_ids": []}),
            )
        })
    }

    /// M1/L5: after a restart the clock is a day behind. With the persisted
    /// bound every snapshot is still applied; without it they are silently
    /// dropped (state_applied=false), which is now its own outcome.
    #[tokio::test]
    async fn restart_with_clock_stepped_back_keeps_sequences_increasing() {
        let server = enforcing();
        let bound = Arc::new(Mutex::new(0i64));
        let calls = Arc::new(Mutex::new(0u32));
        let persister = |bound: &Arc<Mutex<i64>>, calls: &Arc<Mutex<u32>>| {
            let (b, c) = (bound.clone(), calls.clone());
            Box::new(move |n: i64| {
                *b.lock().unwrap() = n;
                *c.lock().unwrap() += 1;
                true
            }) as SequencePersister
        };
        let t0 = time::OffsetDateTime::now_utc();
        let v = view(ConfigState::None);
        let mut a = Reporter::new("px-1", &uid(5), GapQueue::new(), params())
            .with_sequence_persistence(None, persister(&bound, &calls));
        for k in 0..3 {
            let at = t0 + time::Duration::seconds(k * 30);
            let o = a.send_once_at(&server, &v, at).await.unwrap();
            assert!(matches!(o, ReportOutcome::Accepted { .. }), "{o:?}");
        }
        assert_eq!(
            *calls.lock().unwrap(),
            1,
            "one block, not one write per report"
        );
        let persisted = *bound.lock().unwrap();
        assert!(persisted > t0.unix_timestamp() * 1000);

        // Restart: same epoch, clock a day behind.
        let back = t0 - time::Duration::days(1);
        let mut b = Reporter::new("px-1", &uid(5), GapQueue::new(), params())
            .with_sequence_persistence(Some(persisted), persister(&bound, &calls));
        for k in 0..3 {
            let at = back + time::Duration::seconds(k * 30);
            let o = b.send_once_at(&server, &v, at).await.unwrap();
            assert!(
                matches!(o, ReportOutcome::Accepted { .. }),
                "applied: {o:?}"
            );
        }
        // Control: no persisted floor, same stepped-back clock.
        let mut c = Reporter::new("px-1", &uid(5), GapQueue::new(), params());
        let o = c.send_once_at(&server, &v, back).await.unwrap();
        assert!(matches!(o, ReportOutcome::SnapshotIgnored { .. }), "{o:?}");
        let seqs: Vec<i64> = server
            .bodies
            .lock()
            .unwrap()
            .iter()
            .take(6)
            .map(|b| b["status_sequence"].as_i64().unwrap())
            .collect();
        assert!(seqs.windows(2).all(|w| w[1] > w[0]), "{seqs:?}");
    }

    /// A bound that cannot be made durable stops the report: nothing is sent.
    #[tokio::test]
    async fn unpersistable_sequence_bound_sends_nothing() {
        let fake = Fake::new(vec![]);
        let mut r = Reporter::new("px-1", &uid(5), GapQueue::new(), params())
            .with_sequence_persistence(None, Box::new(|_| false));
        assert!(r.send_once(&fake, &view(ConfigState::None)).await.is_none());
        assert_eq!(fake.count(), 0);
    }

    /// state_applied=false is its own outcome and label, and is not a failure.
    #[tokio::test(start_paused = true)]
    async fn snapshot_ignored_is_not_a_failure() {
        let ig = reply(
            200,
            json!({"state_applied": false, "acknowledged_gap_ids": [uid(1)],
                "duplicate_gap_ids": []}),
        );
        let o = classify(ig.as_ref(), &ids(&[1]));
        assert_eq!(
            o,
            ReportOutcome::SnapshotIgnored {
                acknowledged: ids(&[1]),
                duplicate: vec![]
            }
        );
        assert_eq!(outcome_label(&o), "accepted_snapshot_ignored");
        assert!(!o.signals_central_outage());
        let q = GapQueue::new();
        q.push(quarantine_gap(1)).unwrap();
        q.settle(&o);
        assert!(q.pending_ids().is_empty(), "gaps are still acknowledged");
        let mut r = Reporter::new("px-1", &uid(5), GapQueue::new(), params());
        let (d, early) = r.next_delay(Some(&o));
        assert!(
            d <= Duration::from_secs(40) && early,
            "heartbeat pace, no backoff"
        );
        assert_eq!(r.failures, 0);
    }

    /// M2: an unattributed 422 keeps every gap; a snapshot-only probe tells the
    /// cases apart; the guilty gap is found by sending gaps one per report.
    #[tokio::test]
    async fn unattributed_422_isolates_the_failing_gap() {
        let q = GapQueue::new();
        for n in 1..=3 {
            q.push(quarantine_gap(n)).unwrap();
        }
        let bad = uid(2);
        let server = Script::new(move |v| {
            let g = gap_ids_of(v);
            if g.contains(&bad) {
                unattributed_422()
            } else {
                ack200(&g)
            }
        });
        let mut r = Reporter::new("px-1", &uid(5), q.clone(), params());
        let v = view(ConfigState::None);
        // 1: all three together fail without naming anyone
        let o = r.send_once(&server, &v).await.unwrap();
        assert_eq!(o, ReportOutcome::Ambiguous);
        assert_eq!(q.pending_ids(), ids(&[1, 2, 3]));
        assert!(q.quarantined_ids().is_empty());
        // 2: snapshot only, accepted
        r.send_once(&server, &v).await.unwrap();
        assert!(server.sent_gap_ids(1).is_empty());
        // 3-5: one gap per report
        r.send_once(&server, &v).await.unwrap();
        assert_eq!(server.sent_gap_ids(2), ids(&[1]));
        assert_eq!(q.pending_ids(), ids(&[2, 3]));
        r.send_once(&server, &v).await.unwrap();
        assert_eq!(server.sent_gap_ids(3), ids(&[2]));
        assert_eq!(
            q.quarantined_ids(),
            ids(&[2]),
            "only the one that failed alone"
        );
        r.send_once(&server, &v).await.unwrap();
        assert_eq!(server.sent_gap_ids(4), ids(&[3]));
        assert!(q.pending_ids().is_empty());
        // back to normal batches
        q.push(quarantine_gap(4)).unwrap();
        q.push(quarantine_gap(5)).unwrap();
        r.send_once(&server, &v).await.unwrap();
        assert_eq!(server.sent_gap_ids(5), ids(&[4, 5]));
    }

    /// M2: when the snapshot is the problem, no gap is ever quarantined.
    #[tokio::test]
    async fn broken_snapshot_quarantines_nothing() {
        let q = GapQueue::new();
        for n in 1..=3 {
            q.push(quarantine_gap(n)).unwrap();
        }
        let server = Script::new(|_| unattributed_422());
        let mut r = Reporter::new("px-1", &uid(5), q.clone(), params());
        let v = view(ConfigState::None);
        for _ in 0..4 {
            let o = r.send_once(&server, &v).await.unwrap();
            assert_eq!(o, ReportOutcome::Ambiguous);
            r.next_delay(Some(&o));
        }
        assert_eq!(q.pending_ids(), ids(&[1, 2, 3]));
        assert!(q.quarantined_ids().is_empty());
        assert!(server.sent_gap_ids(1).is_empty(), "probe is snapshot-only");
        assert!(server.sent_gap_ids(3).is_empty());
        // and the pace backs off (not hot)
        assert!(r.failures >= 4);
    }

    /// A single pending gap is not blamed on a bare 422 either.
    #[tokio::test]
    async fn single_gap_bare_422_is_not_quarantined_immediately() {
        let q = GapQueue::new();
        q.push(quarantine_gap(1)).unwrap();
        let server = Script::new(|v| {
            if gap_ids_of(v).is_empty() {
                ok200()
            } else {
                unattributed_422()
            }
        });
        let mut r = Reporter::new("px-1", &uid(5), q.clone(), params());
        let v = view(ConfigState::None);
        r.send_once(&server, &v).await.unwrap();
        assert!(q.quarantined_ids().is_empty());
        r.send_once(&server, &v).await.unwrap(); // probe ok
        r.send_once(&server, &v).await.unwrap(); // alone, 422
        assert_eq!(q.quarantined_ids(), ids(&[1]));
    }

    /// L1: quarantine has its own bound and evicts the oldest quarantined gap;
    /// it never takes room from pending gaps.
    #[test]
    fn quarantine_is_bounded_separately() {
        let q = GapQueue::new();
        let total = MAX_QUARANTINED_GAPS as u32 + 40;
        for n in 0..total {
            q.push(quarantine_gap(n)).unwrap();
        }
        let all: Vec<String> = (0..total).map(uid).collect();
        q.settle(&ReportOutcome::Quarantine {
            gaps: all.clone(),
            whole_report: false,
        });
        let kept = q.quarantined_ids();
        assert_eq!(kept.len(), MAX_QUARANTINED_GAPS);
        assert_eq!(kept.first(), all.get(40), "oldest evicted first");
        // quarantined entries do not count against the pending bound
        // L3: the 40 evicted records became one local_record_failed gap
        let agg: Vec<Value> = q
            .pending_batch()
            .iter()
            .map(|g| serde_json::to_value(g).unwrap())
            .filter(|g| g["kind"] == "local_record_failed")
            .collect();
        assert_eq!(agg.len(), 1);
        assert_eq!(agg[0]["count"], 40);
        for n in 0..MAX_QUEUED_GAPS as u32 - 1 {
            q.push(quarantine_gap(10_000 + n)).unwrap();
        }
        assert_eq!(q.push(quarantine_gap(99_999)), Err(QueueFull));
        assert_eq!(q.quarantined_ids().len(), MAX_QUARANTINED_GAPS);
    }

    /// L3: an item without a gap_id makes the whole report pending.
    #[test]
    fn storage_limit_item_without_gap_id_keeps_everything_pending() {
        let sent = ids(&[1, 2, 3]);
        let o = classify(
            reply(
                503,
                err(
                    "storage_limit",
                    json!([{"index": 0, "gap_id": uid(1), "code": "storage_limit"},
                        {"index": 1, "code": "storage_limit"}]),
                ),
            )
            .as_ref(),
            &sent,
        );
        assert_eq!(
            o,
            ReportOutcome::StorageLimit {
                refused: sent.clone(),
                stored: vec![]
            }
        );
        let q = GapQueue::new();
        for n in 1..=3 {
            q.push(quarantine_gap(n)).unwrap();
        }
        q.settle(&o);
        assert_eq!(q.pending_ids(), sent);
    }

    // ---- #275: durable queue, aggregation, F1, F2, central and routes

    type Snaps = Arc<Mutex<Vec<GapQueueState>>>;

    fn recording_queue() -> (GapQueue, Snaps) {
        let snaps: Snaps = Arc::default();
        let s2 = snaps.clone();
        let q = GapQueue::new().with_persister(Box::new(move |st| {
            s2.lock().unwrap().push(st.clone());
            true
        }));
        (q, snaps)
    }

    /// L6b: every change is persisted and a restored queue is the same queue.
    #[test]
    fn queue_is_persisted_after_each_change_and_restores() {
        let (q, snaps) = recording_queue();
        assert_eq!(snaps.lock().unwrap().len(), 1, "initial state written");
        for n in 1..=3 {
            q.push(quarantine_gap(n)).unwrap();
        }
        q.settle(&ReportOutcome::Conflict { gaps: ids(&[2]) });
        q.settle(&ReportOutcome::Accepted {
            acknowledged: ids(&[1]),
            duplicate: vec![],
        });
        let last = snaps.lock().unwrap().last().cloned().unwrap();
        assert_eq!(last.pending.len(), 1);
        assert_eq!(last.quarantined.len(), 1);
        let n = snaps.lock().unwrap().len();
        // an outcome that changes nothing writes nothing
        q.settle(&ReportOutcome::Retry);
        assert_eq!(snaps.lock().unwrap().len(), n);
        let r = GapQueue::restore(last);
        assert_eq!(r.pending_ids(), ids(&[3]));
        assert_eq!(r.quarantined_ids(), ids(&[2]));
    }

    #[test]
    fn a_failing_persister_keeps_gaps_in_memory() {
        let q = GapQueue::new().with_persister(Box::new(|_| false));
        assert!(q.persist_failed());
        q.push(quarantine_gap(1)).unwrap();
        assert_eq!(q.pending_ids(), ids(&[1]));
        assert!(q.persist_failed());
    }

    /// A gap that does not fit is counted and later reported as one aggregated
    /// `local_record_failed` gap; the loss itself is recorded and persisted.
    #[test]
    fn queue_full_becomes_an_aggregated_gap() {
        let (q, snaps) = recording_queue();
        for n in 0..MAX_QUEUED_GAPS as u32 {
            assert!(q.record(quarantine_gap(n)));
        }
        for n in 0..3u32 {
            assert!(!q.record(quarantine_gap(50_000 + n)), "not queued");
        }
        assert_eq!(q.pending_ids().len(), MAX_QUEUED_GAPS);
        assert_eq!(q.overflow_count(), 3);
        assert_eq!(snaps.lock().unwrap().last().unwrap().overflow_count, 3);
        // room opens when the server acknowledges one: the tally becomes a gap
        q.settle(&ReportOutcome::Accepted {
            acknowledged: ids(&[0]),
            duplicate: vec![],
        });
        assert_eq!(q.overflow_count(), 0);
        let pending = q.pending_batch_limit(usize::MAX);
        assert_eq!(pending.len(), MAX_GAPS_PER_REPORT);
        let all = snaps.lock().unwrap().last().unwrap().pending.clone();
        let agg: Vec<Value> = all
            .iter()
            .map(|g| serde_json::to_value(g).unwrap())
            .filter(|g| g["kind"] == "local_record_failed")
            .collect();
        assert_eq!(agg.len(), 1);
        assert_eq!(agg[0]["count"], 3);
        assert_eq!(agg[0]["invocation_ids"], json!([]));
        assert_eq!(
            all.len(),
            MAX_QUEUED_GAPS,
            "the aggregate took the freed slot"
        );
        // the tally survives a restart while it is still waiting for room
        let (q2, snaps2) = recording_queue();
        for n in 0..MAX_QUEUED_GAPS as u32 {
            q2.push(quarantine_gap(n)).unwrap();
        }
        q2.record(quarantine_gap(60_000));
        let st = snaps2.lock().unwrap().last().cloned().unwrap();
        assert_eq!(GapQueue::restore(st).overflow_count(), 1);
    }

    #[test]
    fn open_outage_is_found_in_a_restored_queue() {
        let q = GapQueue::new();
        q.push(outage_gap(7, Value::Null)).unwrap();
        q.push(quarantine_gap(8)).unwrap();
        assert!(q.close_outage(&uid(7), "2026-10-11T00:30:00Z"));
        assert!(
            !q.close_outage(&uid(8), "2026-10-11T00:30:00Z"),
            "not an outage"
        );
        assert!(!q.close_outage(&uid(99), "2026-10-11T00:30:00Z"));
    }

    /// F1: after WEDGE_THRESHOLD ignored snapshots in a row, warn once and tell
    /// the hook; an applied snapshot clears it.
    #[tokio::test]
    async fn repeated_ignored_snapshots_flag_a_wedged_sequence_once() {
        let calls: Arc<Mutex<Vec<bool>>> = Arc::default();
        let c2 = calls.clone();
        let applied = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let a2 = applied.clone();
        let server = Script::new(move |_| {
            reply(
                200,
                json!({"state_applied": a2.load(std::sync::atomic::Ordering::SeqCst),
                    "acknowledged_gap_ids": [], "duplicate_gap_ids": []}),
            )
        });
        let mut r = Reporter::new("px-1", &uid(5), GapQueue::new(), params())
            .with_wedge_hook(Box::new(move |w| c2.lock().unwrap().push(w)));
        let v = view(ConfigState::None);
        for i in 1..=2 {
            r.send_once(&server, &v).await.unwrap();
            assert!(!r.sequence_wedged(), "{i} in a row is not yet a wedge");
        }
        r.send_once(&server, &v).await.unwrap();
        assert!(r.sequence_wedged());
        for _ in 0..3 {
            r.send_once(&server, &v).await.unwrap();
        }
        assert_eq!(*calls.lock().unwrap(), vec![true], "reported once");
        applied.store(true, std::sync::atomic::Ordering::SeqCst);
        r.send_once(&server, &v).await.unwrap();
        assert!(!r.sequence_wedged());
        assert_eq!(*calls.lock().unwrap(), vec![true, false]);
    }

    /// F1: a transport failure between ignored answers does not reset the streak.
    #[tokio::test]
    async fn a_failure_between_ignored_snapshots_does_not_reset_the_streak() {
        let mut n = 0;
        let server = Script::new(move |_| {
            n += 1;
            if n == 2 {
                None
            } else {
                reply(
                    200,
                    json!({"state_applied": false, "acknowledged_gap_ids": [],
                        "duplicate_gap_ids": []}),
                )
            }
        });
        let mut r = Reporter::new("px-1", &uid(5), GapQueue::new(), params());
        let v = view(ConfigState::None);
        for _ in 0..4 {
            r.send_once(&server, &v).await.unwrap();
        }
        assert!(r.sequence_wedged());
    }

    /// F2: once the failing gap is isolated, the good gaps behind it go out in
    /// one batch, not one by one; singles are paced at the least spacing.
    #[tokio::test]
    async fn after_the_failing_gap_is_found_batches_resume() {
        let q = GapQueue::new();
        for n in 1..=10 {
            q.push(quarantine_gap(n)).unwrap();
        }
        let bad = uid(2);
        let server = Script::new(move |v| {
            let g = gap_ids_of(v);
            if g.contains(&bad) {
                unattributed_422()
            } else {
                ack200(&g)
            }
        });
        let mut r = Reporter::new("px-1", &uid(5), q.clone(), params());
        let v = view(ConfigState::None);
        let mut delays = Vec::new();
        for _ in 0..4 {
            let o = r.send_once(&server, &v).await.unwrap();
            delays.push(r.next_delay(Some(&o)).0);
        }
        // batch (ambiguous), probe, single 1, single 2 (quarantined)
        assert_eq!(q.quarantined_ids(), ids(&[2]));
        // singles are not paced at the 5 s retry delay
        assert!(delays[2] < Duration::from_secs(2), "{delays:?}");
        r.send_once(&server, &v).await.unwrap();
        assert_eq!(
            server.sent_gap_ids(4),
            ids(&[3, 4, 5, 6, 7, 8, 9, 10]),
            "back to one batch"
        );
        assert!(q.pending_ids().is_empty());
    }

    /// F2: a steady producer cannot keep the reporter in singles for good.
    #[tokio::test]
    async fn isolation_returns_to_batches_after_a_bounded_run() {
        let q = GapQueue::new();
        let total = 3 * MAX_ISOLATE_SENDS as u32;
        for n in 1..=total {
            q.push(quarantine_gap(n)).unwrap();
        }
        let mut first = true;
        let server = Script::new(move |v| {
            let g = gap_ids_of(v);
            if first && g.len() > 1 {
                first = false;
                unattributed_422()
            } else {
                ack200(&g)
            }
        });
        let mut r = Reporter::new("px-1", &uid(5), q.clone(), params());
        let v = view(ConfigState::None);
        // batch fails, probe, then singles, then a batch again
        for _ in 0..3 + MAX_ISOLATE_SENDS {
            r.send_once(&server, &v).await.unwrap();
        }
        let sizes: Vec<usize> = (0..3 + MAX_ISOLATE_SENDS)
            .map(|i| server.sent_gap_ids(i).len())
            .collect();
        let singles = sizes[2..].iter().take_while(|n| **n == 1).count();
        assert!(
            (MAX_ISOLATE_SENDS / 2..=MAX_ISOLATE_SENDS).contains(&singles),
            "{singles} singles"
        );
        assert!(sizes[2 + singles] > 1, "batches resume: {sizes:?}");
    }

    /// `central` and `routes` come from real sources; spool and registry stay
    /// placeholders.
    #[test]
    fn central_and_routes_are_real_and_spool_registry_are_placeholders() {
        let central = CentralHealth::new();
        let mut b = StatusBuilder::new("px-1", &uid(5));
        b.set_central(central.clone());
        let now = time::OffsetDateTime::now_utc();
        let st = |bytes: Vec<u8>| sigil_proxy_api::parse_status(&bytes).unwrap();
        let s = st(b.build(&view(ConfigState::Valid), &[], now).unwrap());
        let routes: Vec<(String, String)> = s
            .routes
            .iter()
            .map(|r| {
                (
                    r.upstream_id.as_str().to_string(),
                    serde_json::to_value(r.state)
                        .unwrap()
                        .as_str()
                        .unwrap()
                        .to_string(),
                )
            })
            .collect();
        assert_eq!(
            routes,
            vec![
                ("up-r1".to_string(), "supported".to_string()),
                ("up-r2".to_string(), "supported".to_string())
            ]
        );
        assert!(s.central.last_ingest_ack_at.is_none());
        assert_eq!(s.central.consecutive_failures.get(), 0);
        central.record_failure();
        central.record_failure();
        let s = st(b.build(&view(ConfigState::Valid), &[], now).unwrap());
        assert_eq!(s.central.consecutive_failures.get(), 2);
        central.record_ingest_ack(now);
        let s = st(b.build(&view(ConfigState::Valid), &[], now).unwrap());
        assert_eq!(s.central.consecutive_failures.get(), 0);
        assert!(s.central.last_ingest_ack_at.is_some());
        // an expired config does not claim its routes are supported
        let mut expired = view(ConfigState::Expired);
        expired.route_upstreams = vec!["up-r1".into()];
        let s = st(b.build(&expired, &[], now).unwrap());
        assert_eq!(
            serde_json::to_value(s.routes[0].state).unwrap(),
            json!("disabled")
        );
        // placeholders: vacuous values (T-13/T-14)
        assert_eq!(s.spool.depth_events.get(), 0);
        assert_eq!(s.spool.capacity_bytes.get(), 1);
        assert!(!s.registry.sync_stalled);
    }

    /// The reporter feeds the central failure count: no answer or 5xx counts, an
    /// answer (even a refusal) resets it.
    #[tokio::test]
    async fn reporter_feeds_central_health() {
        let central = CentralHealth::new();
        let mut n = 0;
        let server = Script::new(move |_| {
            n += 1;
            match n {
                1 | 2 => None,
                3 => reply(
                    503,
                    json!({"error": {"code": "storage_limit", "message": "x"}}),
                ),
                _ => ok200(),
            }
        });
        let mut r =
            Reporter::new("px-1", &uid(5), GapQueue::new(), params()).with_central(central.clone());
        let v = view(ConfigState::None);
        r.send_once(&server, &v).await.unwrap();
        r.send_once(&server, &v).await.unwrap();
        assert_eq!(central.consecutive_failures(), 2);
        r.send_once(&server, &v).await.unwrap();
        assert_eq!(
            central.consecutive_failures(),
            0,
            "storage_limit is an answer"
        );
    }

    // ---- review fixes (M1, M2, L2)

    fn open_outage_value() -> OpenOutage {
        OpenOutage {
            gap_id: uid(7),
            started_at: "2026-10-11T00:00:00Z".into(),
            detected_at: "2026-10-11T00:00:05Z".into(),
        }
    }

    /// M2: the open outage is part of the persisted state.
    #[test]
    fn open_outage_is_persisted_and_restored() {
        let (q, snaps) = recording_queue();
        q.set_open_outage(Some(open_outage_value()));
        let st = snaps.lock().unwrap().last().cloned().unwrap();
        assert_eq!(st.open_outage, Some(open_outage_value()));
        assert_eq!(
            GapQueue::restore(st).open_outage(),
            Some(open_outage_value())
        );
        q.set_open_outage(None);
        assert!(snaps.lock().unwrap().last().unwrap().open_outage.is_none());
    }

    /// M1: an answer that acknowledges the version that was sent does not drop a
    /// newer version of the same gap (an outage closed while the report was in
    /// flight).
    #[tokio::test]
    async fn newer_gap_version_stays_pending_when_the_sent_one_is_acked() {
        let q = GapQueue::new();
        q.push(outage_gap(1, Value::Null)).unwrap();
        let q2 = q.clone();
        let server = Script::new(move |v| {
            // the close lands while the report is in flight
            assert!(q2.close_outage(&uid(1), "2026-10-11T00:30:00Z"));
            ack200(&gap_ids_of(v))
        });
        let mut r = Reporter::new("px-1", &uid(5), q.clone(), params());
        r.send_once(&server, &view(ConfigState::None))
            .await
            .unwrap();
        assert_eq!(
            q.pending_ids(),
            ids(&[1]),
            "the closed version is not covered"
        );
        let now = serde_json::to_value(&q.pending_batch()[0]).unwrap();
        assert_ne!(now["ended_at"], Value::Null);
        // the next report sends it, and that ack drops it
        let server = Script::new(|v| ack200(&gap_ids_of(v)));
        r.send_once(&server, &view(ConfigState::None))
            .await
            .unwrap();
        assert!(q.pending_ids().is_empty());
    }

    /// L2: a 404 answer is not a healthy one for `central`.
    #[tokio::test]
    async fn not_found_does_not_reset_central_failures() {
        let central = CentralHealth::new();
        central.record_failure();
        let server = Script::new(|_| {
            reply(
                404,
                json!({"error": {"code": "proxy_unknown", "message": "x"}}),
            )
        });
        let mut r =
            Reporter::new("px-1", &uid(5), GapQueue::new(), params()).with_central(central.clone());
        r.send_once(&server, &view(ConfigState::None))
            .await
            .unwrap();
        assert_eq!(central.consecutive_failures(), 1);
    }

    // ----------------------------------------------------- spool (T-14b)

    fn test_spool(dir: &std::path::Path) -> Spool {
        let mut c = crate::spool::SpoolConfig::new(
            dir,
            "px-1",
            &uid(5000),
            true,
            &crate::limits::Limits::default(),
        );
        c.maintenance_interval = Duration::from_secs(3600);
        Spool::open(c).unwrap()
    }

    fn built(b: &mut StatusBuilder) -> Value {
        let bytes = b
            .build(
                &view(ConfigState::Valid),
                &[],
                time::OffsetDateTime::now_utc(),
            )
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    /// The report carries the spool's real numbers and its tail sequence, not
    /// the placeholders (F13/AC-06, AC-12).
    #[tokio::test]
    async fn report_carries_real_spool_numbers_and_the_tail_sequence() {
        let d = tempfile::tempdir().unwrap();
        let spool = test_spool(d.path());
        let mut b = StatusBuilder::new("px-1", &uid(5000));
        b.set_spool(spool.clone());
        let v = built(&mut b);
        assert_eq!(v["last_assigned_sequence"], 0);
        assert_eq!(v["spool"]["state"], "ok");
        assert_eq!(v["spool"]["unsent_events"], 0);
        assert_eq!(
            v["spool"]["capacity_bytes"],
            crate::limits::Limits::default().spool_max_bytes
        );
        assert!(v["spool"]["oldest_unsent_age_seconds"].is_null());

        spool.inject_test_event("up-1").await.unwrap();
        spool.inject_test_event("up-1").await.unwrap();
        let v = built(&mut b);
        assert_eq!(v["last_assigned_sequence"], 2);
        assert_eq!(v["spool"]["unsent_events"], 2);
        assert_eq!(v["spool"]["depth_events"], 2);
        assert!(v["spool"]["bytes"].as_u64().unwrap() > 0);
        assert!(v["spool"]["oldest_unsent_age_seconds"].is_u64());
        assert_eq!(v["spool"]["quarantined_events"], 0);

        // Full: admission is closed and the state says so.
        let one = spool.snapshot().unsent_bytes / 2;
        spool.set_capacity_for_test(one * 2 + 5, 5);
        let v = built(&mut b);
        assert_eq!(v["spool"]["state"], "full");
        assert_eq!(v["spool"]["capacity_bytes"], one * 2 + 5);

        // Acknowledged events leave `unsent` but the sequence never goes back.
        let mut src = spool.clone();
        let ids: Vec<String> = crate::ingest_client::EventSource::next_events(
            &mut src,
            10,
            &std::collections::HashSet::new(),
        )
        .iter()
        .map(|e| e.event_id.as_str().to_string())
        .collect();
        crate::ingest_client::EventSource::acknowledged(&mut src, &ids);
        let v = built(&mut b);
        assert_eq!(v["spool"]["unsent_events"], 0);
        assert_eq!(v["last_assigned_sequence"], 2);
    }

    /// A builder without a spool still validates (unit-test path only).
    #[test]
    fn builder_without_a_spool_reports_the_empty_placeholder() {
        let mut b = StatusBuilder::new("px-1", &uid(5000));
        let v = built(&mut b);
        assert_eq!(v["last_assigned_sequence"], 0);
        assert_eq!(v["spool"]["capacity_bytes"], 1);
    }

    fn expired_spool_gap(spool: &Spool) -> GapReport {
        // R expiry is the producer in production; here the spool records an
        // equivalent gap directly.
        let g: GapReport = serde_json::from_value(json!({
            "kind": "spool_expired", "gap_id": uid(77),
            "detected_at": "2026-10-11T00:00:00Z", "epoch_id": uid(5000),
            "from_sequence": 1, "to_sequence": 3, "count": 3}))
        .unwrap();
        spool.record_gap(g.clone()).unwrap();
        g
    }

    /// A spool gap moves to the gap queue and leaves the spool only afterwards;
    /// offering it again is idempotent (one pending entry, same body).
    #[tokio::test]
    async fn spool_gaps_are_handed_to_the_queue_then_removed_from_the_spool() {
        let d = tempfile::tempdir().unwrap();
        let spool = test_spool(d.path());
        let g = expired_spool_gap(&spool);
        let queue = GapQueue::new();
        assert_eq!(hand_off_spool_gaps(&spool, &queue).await, 1);
        assert_eq!(queue.pending_ids(), vec![uid(77)]);
        assert!(spool.pending_gaps().unwrap().is_empty());
        assert_eq!(spool.snapshot().pending_gaps, 0);
        assert_eq!(hand_off_spool_gaps(&spool, &queue).await, 0);

        // A crash between the two steps: the gap is in both places. The next
        // hand-off replaces by id: still exactly one entry, same body, so the
        // server answers `duplicate` (it dedupes by gap_id).
        spool.record_gap(g.clone()).unwrap();
        assert_eq!(hand_off_spool_gaps(&spool, &queue).await, 1);
        assert_eq!(queue.pending_ids(), vec![uid(77)]);
        assert_eq!(queue.pending_batch(), vec![g]);
    }

    /// A gap whose queue write failed stays in the spool (durable) and is
    /// offered again.
    #[tokio::test]
    async fn spool_gap_stays_in_the_spool_while_the_queue_is_not_durable() {
        let d = tempfile::tempdir().unwrap();
        let spool = test_spool(d.path());
        expired_spool_gap(&spool);
        let ok = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let ok2 = ok.clone();
        let queue = GapQueue::new().with_persister(Box::new(move |_| {
            ok2.load(std::sync::atomic::Ordering::SeqCst)
        }));
        assert_eq!(hand_off_spool_gaps(&spool, &queue).await, 0);
        assert_eq!(spool.pending_gaps().unwrap().len(), 1, "kept");
        ok.store(true, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(hand_off_spool_gaps(&spool, &queue).await, 1);
        assert!(spool.pending_gaps().unwrap().is_empty());
    }

    /// A full gap queue: spool gaps that do not fit stay in the spool, and the
    /// overflow count does not grow on retries; they move once there is room.
    #[tokio::test]
    async fn spool_gaps_stay_in_the_spool_while_the_queue_is_full() {
        let d = tempfile::tempdir().unwrap();
        let spool = test_spool(d.path());
        expired_spool_gap(&spool);
        let queue = GapQueue::new();
        for n in 0..MAX_QUEUED_GAPS as u32 {
            queue.push(quarantine_gap(10_000 + n)).unwrap();
        }
        for _ in 0..3 {
            assert_eq!(hand_off_spool_gaps(&spool, &queue).await, 0);
        }
        assert_eq!(spool.pending_gaps().unwrap().len(), 1, "range not lost");
        assert_eq!(queue.overflow_count(), 0, "retries do not count overflow");
        assert!(!queue.pending_ids().contains(&uid(77)));
        // Room appears (an acknowledged gap leaves the queue).
        queue.settle(&ReportOutcome::Accepted {
            acknowledged: vec![uid(10_000)],
            duplicate: vec![],
        });
        assert_eq!(hand_off_spool_gaps(&spool, &queue).await, 1);
        assert!(queue.pending_ids().contains(&uid(77)));
        assert!(spool.pending_gaps().unwrap().is_empty());
    }

    /// A `persist_failed` left over from an earlier write neither blocks nor
    /// wrongly allows a hand-off: only the write made for this gap counts.
    #[tokio::test]
    async fn stale_persist_failure_does_not_decide_the_hand_off() {
        let d = tempfile::tempdir().unwrap();
        let spool = test_spool(d.path());
        let ok = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let ok2 = ok.clone();
        let queue = GapQueue::new().with_persister(Box::new(move |_| {
            ok2.load(std::sync::atomic::Ordering::SeqCst)
        }));
        // The initial flush failed: the flag is stale-true.
        assert!(queue.persist_failed());
        ok.store(true, std::sync::atomic::Ordering::SeqCst);
        expired_spool_gap(&spool);
        assert_eq!(hand_off_spool_gaps(&spool, &queue).await, 1);
        assert!(!queue.persist_failed());
        // And the other direction: a failing write keeps the gap in the spool.
        ok.store(false, std::sync::atomic::Ordering::SeqCst);
        spool
            .record_gap(
                serde_json::from_value(json!({
                    "kind": "spool_expired", "gap_id": uid(78),
                    "detected_at": "2026-10-11T00:00:00Z", "epoch_id": uid(5000),
                    "from_sequence": 4, "to_sequence": 5, "count": 2}))
                .unwrap(),
            )
            .unwrap();
        assert_eq!(hand_off_spool_gaps(&spool, &queue).await, 0);
        assert_eq!(spool.pending_gaps().unwrap().len(), 1);
    }
}
