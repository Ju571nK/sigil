//! T-11 S4 slice B1 — the proxy event ledger (storage layer only).
//!
//! Spec: ledger-and-query.md L1 (retention, tombstones), L4 (server-derived
//! gaps), L5 SV-1 (invocation owner); contracts README N2/M1/M2a. PX-010/011,
//! AC-05/06. There is no HTTP route and no metadata upload here (slice B2).
//!
//! Storage: one SQLite file next to the proxy state file, owner-only (0600).
//!
//! * **Durability.** `journal_mode=WAL` with `synchronous=FULL` (and `fullfsync`
//!   where the OS has it). In WAL mode `NORMAL` does not sync the log at commit,
//!   so a power loss could drop an acknowledged batch; the handler ACKs only
//!   after [`Ledger::insert_batch`] returns, so commits must be durable.
//!   `secure_delete=ON` zeroes freed content in the database file; because the
//!   WAL can still hold older page copies, every sweep ends with
//!   `wal_checkpoint(TRUNCATE)`. The file itself does not shrink (freed pages
//!   are reused).
//! * **Concurrency.** The connection sits behind a `Mutex`. `rusqlite::Connection`
//!   is `Send` but not `Sync`; the mutex makes [`Ledger`] `Send + Sync` and also
//!   serialises batches in-process (SQLite allows one writer anyway). Calls block
//!   on disk I/O: the HTTP handler must use `spawn_blocking`. Each batch is one
//!   `BEGIN IMMEDIATE` transaction; a read-only S5 connection can be added later
//!   without changing this (WAL readers do not block the writer).
//! * **All or nothing.** Any conflict, cap hit or storage error rolls the whole
//!   batch back; `accepted`/`duplicate` are returned only after `COMMIT`.
//! * **Errors echo nothing.** [`LedgerError`] carries only indexes, event ids the
//!   caller already validated, and fixed codes. SQLite error text is never kept.
//!
//! Dedup equality is the proxy-api canonical form (`canonical_event_bytes`).
//! Equal bytes <=> equal SHA-256, so the stored digest decides duplicate versus
//! conflict even after the body has been removed by retention.

use super::projection::{
    project_with, ActorInfo, EventAggregate, EventIdentity, Flag, GapPage, InvocationDetail,
    InvocationFilter, InvocationPage, Lifecycle, Projection, ProjectionInput, ProxyScope,
    TailGapChange, TimeBasis, ToolInfo, MAX_DETAIL_EVENTS, MAX_GAP_PAGE, MAX_LIST_LIMIT,
    MAX_PROJECTION_EVENTS,
};
use crate::config::ProxyConfig;
use anyhow::{bail, Context, Result};
use parking_lot::{Mutex, MutexGuard};
use rusqlite::types::Value as SqlValue;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};
use sigil_proxy_api::{
    canonical_event_bytes, parse_event, ErrorCode, EventPayload, ProxyEvent, Uuid,
};
use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::Duration;

/// Format version stored in `PRAGMA user_version`.
pub const SCHEMA_VERSION: i64 = 2;
/// Read connections of the S5 read API (WAL readers do not block each other or
/// the writer). Initial test value (D-04).
pub const READ_POOL_SIZE: usize = 4;
/// Wall-clock limit of one read query; beyond it the query is interrupted and
/// the call returns [`LedgerError::QueryTimeout`]. Initial test value (D-04).
pub const READ_QUERY_TIMEOUT_MS: u64 = 5_000;
/// Open server-derived gaps per proxy. A batch that would exceed it is refused
/// (`storage_limit`) rather than dropping a stored gap. Closed gaps do not
/// count: they are only retained until E.
pub const MAX_GAPS_PER_PROXY: i64 = 10_000;

/// Storage caps. Defaults are conservative, **unmeasured** test values (D-04).
///
/// * `rows_*` count event rows; `bytes_*` count **canonical event bytes only**
///   (no index, tombstone or page overhead).
/// * Tombstones have their own bound, derived as `TOMBSTONE_FACTOR` x the rows
///   cap (tombstones can outlive event bodies when T > E, but must not eat the
///   event rows budget).
/// * `file_bytes` is a hard backstop on the live database size
///   (`(page_count - freelist_count) * page_size`), derived as
///   `FILE_FACTOR` x `bytes_total` to cover indexes and tombstones.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LedgerCaps {
    pub rows_per_proxy: u64,
    pub bytes_per_proxy: u64,
    pub rows_total: u64,
    pub bytes_total: u64,
    pub tombstones_per_proxy: u64,
    pub tombstones_total: u64,
    pub file_bytes: u64,
}

pub const TOMBSTONE_FACTOR: u64 = 4;
pub const FILE_FACTOR: u64 = 3;

impl LedgerCaps {
    pub fn new(
        rows_per_proxy: u64,
        bytes_per_proxy: u64,
        rows_total: u64,
        bytes_total: u64,
    ) -> Self {
        Self {
            rows_per_proxy,
            bytes_per_proxy,
            rows_total,
            bytes_total,
            tombstones_per_proxy: rows_per_proxy.saturating_mul(TOMBSTONE_FACTOR),
            tombstones_total: rows_total.saturating_mul(TOMBSTONE_FACTOR),
            file_bytes: bytes_total.saturating_mul(FILE_FACTOR),
        }
    }
}

impl Default for LedgerCaps {
    fn default() -> Self {
        Self::new(
            ProxyConfig::DEFAULT_LEDGER_ROWS_PER_PROXY,
            ProxyConfig::DEFAULT_LEDGER_BYTES_PER_PROXY,
            ProxyConfig::DEFAULT_LEDGER_ROWS_TOTAL,
            ProxyConfig::DEFAULT_LEDGER_BYTES_TOTAL,
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LedgerOptions {
    /// T: seconds a tombstone is kept after acceptance.
    pub tombstone_retention_secs: i64,
    pub caps: LedgerCaps,
}

impl LedgerOptions {
    pub fn from_config(pc: &ProxyConfig) -> Self {
        Self {
            tombstone_retention_secs: i64::from(pc.dedup_tombstone_retention()),
            caps: LedgerCaps::new(
                pc.ledger_max_rows_per_proxy(),
                pc.ledger_max_bytes_per_proxy(),
                pc.ledger_max_rows_total(),
                pc.ledger_max_bytes_total(),
            ),
        }
    }
}

impl Default for LedgerOptions {
    fn default() -> Self {
        Self {
            tombstone_retention_secs: i64::from(ProxyConfig::DEFAULT_TOMBSTONE_RETENTION_SECONDS),
            caps: LedgerCaps::default(),
        }
    }
}

/// Startup invariant (L1): `T >= R + M` for every stored proxy config.
///
/// `proxy_retry_ages` yields `(proxy_id, R seconds)`. The error text names the
/// proxy id (operator-controlled) and numbers only.
///
/// Relation to `stale_retention` (mod.rs): that check is `E >= R + M` and stays
/// a warning, because a stale E only shortens how long event *bodies* live; the
/// dedup window that protects against double-ingest is `max(E, T)`. A broken T
/// silently re-accepts retransmitted events as new, so it is a boot error.
///
/// A retransmission later than T after acceptance is outside this invariant
/// (T >= R + M means a legitimate producer never retransmits that late). If one
/// arrives anyway it is treated as new: it may also look like a new epoch
/// (spurious `producer_epoch_change`) once its epoch row was swept. That is
/// accepted behaviour, not a defect.
pub fn check_tombstone_invariant<'a>(
    tombstone_secs: i64,
    margin_secs: u32,
    proxy_retry_ages: impl IntoIterator<Item = (&'a str, i64)>,
) -> Result<()> {
    for (id, r) in proxy_retry_ages {
        if tombstone_secs < r.saturating_add(i64::from(margin_secs)) {
            bail!(
                "proxy.dedup_tombstone_retention_seconds ({tombstone_secs}) is below \
                 max_offline_retry_age_seconds ({r}) of proxy {id} plus \
                 proxy.ack_loss_margin_seconds ({margin_secs}); a retransmitted event could be \
                 accepted twice (ledger L1 requires T >= R + M). Raise the tombstone retention \
                 or lower the margin or the proxy's retry age"
            );
        }
    }
    Ok(())
}

/// The config-PUT form of the L1 rules: `E >= R + M` and `T >= R + M`. A PUT
/// that breaks either is refused (422) so it cannot make the next boot fail.
pub fn config_retention_ok(
    event_retention: i64,
    max_offline_retry_age: i64,
    margin_secs: u32,
    tombstone_retention: i64,
) -> bool {
    let need = max_offline_retry_age.saturating_add(i64::from(margin_secs));
    event_retention >= need && tombstone_retention >= need
}

/// Result of a committed batch, in batch order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IngestOutcome {
    pub accepted: Vec<Uuid>,
    pub duplicate: Vec<Uuid>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConflictKind {
    /// Same `(proxy_id, event_id)`, different canonical event.
    Conflict,
    /// Same `(proxy_id, epoch_id, sequence)`, different `event_id`.
    SequenceConflict,
    /// SV-1: `invocation_id` already bound to another proxy.
    InvocationOwnerConflict,
}

impl ConflictKind {
    pub fn error_code(self) -> ErrorCode {
        match self {
            ConflictKind::Conflict => ErrorCode::Conflict,
            ConflictKind::SequenceConflict => ErrorCode::SequenceConflict,
            ConflictKind::InvocationOwnerConflict => ErrorCode::InvocationOwnerConflict,
        }
    }
}

/// One 409 item: index in the submitted batch, the (validated) event id, code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConflictItem {
    pub index: usize,
    pub event_id: Uuid,
    pub kind: ConflictKind,
}

#[derive(Debug, PartialEq, Eq)]
pub enum LedgerError {
    /// 409: nothing was stored. Lists every conflicting item.
    Conflicts(Vec<ConflictItem>),
    /// 503 `storage_limit`: a cap would be exceeded. Nothing was stored.
    StorageLimit,
    /// 503 `storage_unavailable`: the store failed. Nothing was stored.
    StorageUnavailable,
    /// Caller bug: an event's `proxy_id` differs from the authenticated one.
    /// The handler checks this before calling; nothing was stored.
    ProxyMismatch,
    /// A read query exceeded [`READ_QUERY_TIMEOUT_MS`] and was interrupted.
    /// The query layer maps it to 503 `storage_unavailable`.
    QueryTimeout,
}

impl LedgerError {
    /// The envelope-level code for non-item errors.
    pub fn error_code(&self) -> Option<ErrorCode> {
        match self {
            LedgerError::StorageLimit => Some(ErrorCode::StorageLimit),
            LedgerError::StorageUnavailable | LedgerError::QueryTimeout => {
                Some(ErrorCode::StorageUnavailable)
            }
            _ => None,
        }
    }
}

impl std::fmt::Display for LedgerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            LedgerError::Conflicts(_) => "ledger conflict",
            LedgerError::StorageLimit => "ledger storage limit reached",
            LedgerError::StorageUnavailable => "ledger storage unavailable",
            LedgerError::ProxyMismatch => "event proxy_id does not match the caller",
            LedgerError::QueryTimeout => "ledger read query timed out",
        })
    }
}

impl std::error::Error for LedgerError {}

impl From<rusqlite::Error> for LedgerError {
    fn from(e: rusqlite::Error) -> Self {
        if matches!(&e, rusqlite::Error::SqliteFailure(f, _)
            if f.code == rusqlite::ErrorCode::OperationInterrupted)
        {
            return LedgerError::QueryTimeout;
        }
        // Log the SQLite result code only, never the message.
        let code = match &e {
            rusqlite::Error::SqliteFailure(f, _) => format!("{:?}", f.code),
            _ => "other".to_string(),
        };
        tracing::error!(sqlite_code = %code, "proxy ledger storage failure");
        LedgerError::StorageUnavailable
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GapKind {
    ProducerEpochChange,
    SequenceGap,
}

impl GapKind {
    fn as_str(self) -> &'static str {
        match self {
            GapKind::ProducerEpochChange => "producer_epoch_change",
            GapKind::SequenceGap => "sequence_gap",
        }
    }
}

/// A server-derived audit gap (L4). Only `sequence_gap` can close; a closed gap
/// stays listed until its retention expires.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GapRecord {
    pub gap_id: String,
    pub kind: GapKind,
    pub detected_at: i64,
    pub epoch_id: String,
    pub previous_epoch_id: Option<String>,
    pub from_sequence: Option<i64>,
    pub to_sequence: Option<i64>,
    pub open: bool,
    pub closed_at: Option<i64>,
    /// `sequence_gap` derived from a status report's `last_assigned_sequence`
    /// (`highest accepted + 1 ..= last_assigned`): events may still be in flight.
    pub tail: bool,
}

/// What S5 needs from a stored event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredEvent {
    pub created_seq: i64,
    pub received_at: i64,
    pub epoch_id: String,
    pub sequence: i64,
    pub canonical: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Usage {
    pub event_rows: i64,
    pub event_bytes: i64,
    pub tombstone_rows: i64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SweepStats {
    pub events: usize,
    pub tombstones: usize,
    pub gaps: usize,
    pub epochs: usize,
    pub invocations: usize,
    /// Projection rows removed (one per expired invocation).
    pub projections: usize,
}

pub struct Ledger {
    /// The single writer (ingest, sweep, tail gaps).
    conn: Mutex<Connection>,
    /// Separate read-only WAL connection for the S5 read API, so reads never
    /// wait on the writer mutex (WAL readers do not block the writer either).
    read: ReadPool,
    opts: LedgerOptions,
}

/// A few read-only connections; a query takes the first free one (or waits on
/// one in round-robin order). Each query runs under a wall-clock limit.
struct ReadPool {
    conns: Vec<Mutex<Connection>>,
    next: AtomicUsize,
    timeout_ms: AtomicU64,
}

impl ReadPool {
    fn acquire(&self) -> ReadGuard<'_> {
        let conn = self
            .conns
            .iter()
            .find_map(|m| m.try_lock())
            .unwrap_or_else(|| {
                let i = self.next.fetch_add(1, Ordering::Relaxed) % self.conns.len();
                self.conns[i].lock()
            });
        // A timer thread interrupts the connection if the guard outlives the
        // limit. Dropping the guard stops and joins it before the connection is
        // released, so a late interrupt can never hit the next query.
        let handle = conn.get_interrupt_handle();
        let limit = Duration::from_millis(self.timeout_ms.load(Ordering::Relaxed));
        let (done, rx) = mpsc::channel::<()>();
        let timer = match std::thread::Builder::new()
            .name("ledger-read-timer".into())
            .spawn(move || {
                if let Err(mpsc::RecvTimeoutError::Timeout) = rx.recv_timeout(limit) {
                    handle.interrupt();
                }
            }) {
            Ok(t) => Some(t),
            Err(_) => {
                // Fail soft but loudly: this one query runs without a time limit.
                tracing::error!("proxy ledger: read timer thread could not start; query unlimited");
                None
            }
        };
        ReadGuard {
            conn,
            done: Some(done),
            timer,
        }
    }
}

struct ReadGuard<'a> {
    conn: MutexGuard<'a, Connection>,
    done: Option<mpsc::Sender<()>>,
    timer: Option<std::thread::JoinHandle<()>>,
}

impl std::ops::Deref for ReadGuard<'_> {
    type Target = Connection;
    fn deref(&self) -> &Connection {
        &self.conn
    }
}

impl std::ops::DerefMut for ReadGuard<'_> {
    fn deref_mut(&mut self) -> &mut Connection {
        &mut self.conn
    }
}

impl Drop for ReadGuard<'_> {
    fn drop(&mut self) {
        drop(self.done.take());
        if let Some(t) = self.timer.take() {
            let _ = t.join();
        }
    }
}

const SCHEMA: &str = "
CREATE TABLE events (
    created_seq   INTEGER PRIMARY KEY AUTOINCREMENT,
    proxy_id      TEXT NOT NULL,
    event_id      TEXT NOT NULL,
    epoch_id      TEXT NOT NULL,
    sequence      INTEGER NOT NULL,
    invocation_id TEXT NOT NULL,
    event_type    TEXT NOT NULL,
    occurred_at   TEXT NOT NULL,
    received_at   INTEGER NOT NULL,
    canonical     BLOB NOT NULL,
    sha256        BLOB NOT NULL,
    size          INTEGER NOT NULL,
    UNIQUE (proxy_id, event_id),
    UNIQUE (proxy_id, epoch_id, sequence)
);
CREATE INDEX events_received ON events (proxy_id, received_at);
CREATE INDEX events_invocation ON events (invocation_id);
CREATE INDEX events_inv_type ON events (proxy_id, invocation_id, event_type, created_seq);
CREATE TABLE tombstones (
    proxy_id    TEXT NOT NULL,
    event_id    TEXT NOT NULL,
    epoch_id    TEXT NOT NULL,
    sequence    INTEGER NOT NULL,
    sha256      BLOB NOT NULL,
    received_at INTEGER NOT NULL,
    PRIMARY KEY (proxy_id, event_id),
    UNIQUE (proxy_id, epoch_id, sequence)
) WITHOUT ROWID;
CREATE INDEX tombstones_received ON tombstones (received_at);
CREATE TABLE epochs (
    ord              INTEGER PRIMARY KEY AUTOINCREMENT,
    proxy_id         TEXT NOT NULL,
    epoch_id         TEXT NOT NULL,
    highest_sequence INTEGER NOT NULL,
    last_received_at INTEGER NOT NULL,
    UNIQUE (proxy_id, epoch_id)
);
CREATE TABLE gaps (
    rowid_seq         INTEGER PRIMARY KEY AUTOINCREMENT,
    gap_id            TEXT NOT NULL UNIQUE,
    proxy_id          TEXT NOT NULL,
    kind              TEXT NOT NULL,
    detected_at       INTEGER NOT NULL,
    epoch_id          TEXT NOT NULL,
    previous_epoch_id TEXT,
    from_sequence     INTEGER,
    to_sequence       INTEGER,
    open              INTEGER NOT NULL,
    closed_at         INTEGER,
    present           INTEGER NOT NULL DEFAULT 0,
    tail              INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX gaps_open ON gaps (proxy_id, epoch_id, open, from_sequence);
CREATE TABLE invocations (
    invocation_id    TEXT PRIMARY KEY,
    proxy_id         TEXT NOT NULL,
    last_received_at INTEGER NOT NULL
) WITHOUT ROWID;
CREATE TABLE usage (
    proxy_id       TEXT PRIMARY KEY,
    event_rows     INTEGER NOT NULL,
    event_bytes    INTEGER NOT NULL,
    tombstone_rows INTEGER NOT NULL
) WITHOUT ROWID;
";

/// The v2 projection table (L2) with its filter columns and the `created_seq`
/// keyset index. Shared by a fresh create and the v1 -> v2 migration so the two
/// cannot drift. `epoch_superseded` is deliberately not stored (see
/// `projection.rs`).
const PROJECTIONS_DDL: &str = "
CREATE TABLE projections (
    proxy_id                TEXT NOT NULL,
    invocation_id           TEXT NOT NULL,
    created_seq             INTEGER NOT NULL,
    lifecycle               TEXT NOT NULL,
    outcome                 TEXT,
    delivery_state          TEXT,
    reason                  TEXT,
    reported_outcome        TEXT,
    reported_delivery_state TEXT,
    reported_reason         TEXT,
    duration_ms             INTEGER,
    response_bytes          INTEGER,
    method                  TEXT,
    protocol_version        TEXT,
    upstream_id             TEXT,
    route_revision          INTEGER,
    actor_id                TEXT,
    actor_kind              TEXT,
    authentication_method   TEXT,
    evidence_source         TEXT,
    credential_owner_id     TEXT,
    tool_status             TEXT,
    tool_ref                TEXT,
    tool_reason             TEXT,
    cancel_observed         INTEGER NOT NULL,
    started_at              TEXT,
    started_at_s            INTEGER,
    completed_at            TEXT,
    completed_at_s          INTEGER,
    first_received_at       INTEGER NOT NULL,
    last_received_at        INTEGER NOT NULL,
    start_epoch_id          TEXT,
    flags                   TEXT NOT NULL,
    event_count             INTEGER NOT NULL,
    PRIMARY KEY (proxy_id, invocation_id)
) WITHOUT ROWID;
CREATE UNIQUE INDEX projections_created ON projections (created_seq);
CREATE INDEX projections_proxy_created ON projections (proxy_id, created_seq);
CREATE INDEX projections_proxy_received ON projections (proxy_id, first_received_at);
CREATE INDEX projections_proxy_lifecycle ON projections (proxy_id, lifecycle, created_seq);
CREATE INDEX projections_proxy_upstream ON projections (proxy_id, upstream_id, created_seq);
CREATE INDEX projections_last_received ON projections (proxy_id, last_received_at);
CREATE INDEX projections_tool_ref ON projections (tool_ref) WHERE tool_ref IS NOT NULL;
";

/// Indexes for the gap page (`ORDER BY rowid_seq DESC`) and the open counts.
const GAPS_INDEXES_DDL: &str = "
CREATE INDEX gaps_proxy_rowid ON gaps (proxy_id, rowid_seq);
CREATE INDEX gaps_proxy_open_kind ON gaps (proxy_id, open, kind);
";

/// v2 index bounding the per-type projection loads (also in `SCHEMA`).
const EVENTS_INV_TYPE_DDL: &str =
    "CREATE INDEX events_inv_type ON events (proxy_id, invocation_id, event_type, created_seq);";

/// What v2 adds to a v1 `gaps` table (fresh files get it from `SCHEMA`).
const GAPS_TAIL_DDL: &str = "ALTER TABLE gaps ADD COLUMN tail INTEGER NOT NULL DEFAULT 0;";

impl Ledger {
    /// Open (creating if needed) the ledger. Refuses a symlink (checked, and
    /// SQLite is opened with `NOFOLLOW`), a non-regular file, a file owned by
    /// another user, a group/world accessible file, a newer or foreign schema,
    /// or a filesystem that cannot do WAL.
    pub fn open(path: &Path, opts: LedgerOptions) -> Result<Self> {
        let mut conn = open_hardened(path)?;
        init_schema(&mut conn)?;
        let conns = (0..READ_POOL_SIZE)
            .map(|_| open_read_only(path).map(Mutex::new))
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            conn: Mutex::new(conn),
            read: ReadPool {
                conns,
                next: AtomicUsize::new(0),
                timeout_ms: AtomicU64::new(READ_QUERY_TIMEOUT_MS),
            },
            opts,
        })
    }

    /// Test hook: change the per-query read time limit.
    #[cfg(any(test, feature = "test-support"))]
    pub fn set_read_timeout_for_test(&self, ms: u64) {
        self.read.timeout_ms.store(ms, Ordering::Relaxed);
    }

    /// Test hook: run one raw read-only SQL statement (single integer result)
    /// through the pooled, time-limited read path.
    #[cfg(any(test, feature = "test-support"))]
    pub fn read_scalar_for_test(&self, sql: &str) -> Result<i64, LedgerError> {
        let conn = self.read.acquire();
        Ok(conn.query_row(sql, [], |r| r.get(0))?)
    }

    /// Test hook: the read connection's open path (checks included), nothing else.
    #[cfg(any(test, feature = "test-support"))]
    pub fn open_read_only_probe(path: &Path) -> Result<()> {
        open_read_only(path).map(|_| ())
    }

    /// Test hook: run `f` while the writer mutex is held, to prove the read
    /// API does not take it.
    #[cfg(any(test, feature = "test-support"))]
    pub fn with_writer_locked<R>(&self, f: impl FnOnce() -> R) -> R {
        let _g = self.conn.lock();
        f()
    }

    pub fn options(&self) -> &LedgerOptions {
        &self.opts
    }

    /// Insert a validated batch atomically. `received_at` is the server clock
    /// (unix seconds); retention uses it and never `occurred_at` (L1).
    pub fn insert_batch(
        &self,
        proxy_id: &str,
        events: &[ProxyEvent],
        received_at: i64,
    ) -> Result<IngestOutcome, LedgerError> {
        self.insert_inner(proxy_id, events, received_at, false)
    }

    /// Conflict check only: runs the same detection as [`Self::insert_batch`]
    /// and stores nothing (the transaction is always rolled back). The ingest
    /// handler uses it to answer 409 before 424 when a batch also waits on
    /// metadata refs. `Ok` means "no conflict now", not "accepted".
    pub fn check_batch(
        &self,
        proxy_id: &str,
        events: &[ProxyEvent],
        received_at: i64,
    ) -> Result<(), LedgerError> {
        self.insert_inner(proxy_id, events, received_at, true)
            .map(|_| ())
    }

    /// Per event: is it already stored byte-equal (live row or tombstone)?
    /// Read only; the ingest handler skips registry validation for these.
    pub fn existing_equal(
        &self,
        proxy_id: &str,
        events: &[ProxyEvent],
    ) -> Result<Vec<bool>, LedgerError> {
        let conn = self.conn.lock();
        let mut out = Vec::with_capacity(events.len());
        for ev in events {
            let digest = Prepared::new(ev).digest;
            let hit: bool = conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM events WHERE proxy_id = ?1 AND event_id = ?2 AND sha256 = ?3)
                     OR EXISTS(SELECT 1 FROM tombstones WHERE proxy_id = ?1 AND event_id = ?2 AND sha256 = ?3)",
                params![proxy_id, ev.event_id.as_str(), digest],
                |r| r.get(0),
            )?;
            out.push(hit);
        }
        Ok(out)
    }

    fn insert_inner(
        &self,
        proxy_id: &str,
        events: &[ProxyEvent],
        received_at: i64,
        dry_run: bool,
    ) -> Result<IngestOutcome, LedgerError> {
        if events.iter().any(|e| e.proxy_id.as_str() != proxy_id) {
            return Err(LedgerError::ProxyMismatch);
        }
        let prepared: Vec<Prepared> = events.iter().map(Prepared::new).collect();
        let mut conn = self.conn.lock();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

        let mut out = IngestOutcome::default();
        let mut conflicts = Vec::new();
        let mut fresh: Vec<(usize, &Prepared)> = Vec::new();
        // Per touched invocation: (created_seq, is_cancel) of the fresh events.
        let mut touched: BTreeMap<&str, Vec<(i64, bool)>> = BTreeMap::new();
        for (index, (ev, p)) in events.iter().zip(&prepared).enumerate() {
            let existing_digest: Option<Vec<u8>> = tx
                .query_row(
                    "SELECT sha256 FROM events WHERE proxy_id = ?1 AND event_id = ?2",
                    params![proxy_id, ev.event_id.as_str()],
                    |r| r.get(0),
                )
                .optional()?;
            let existing_digest = match existing_digest {
                Some(d) => Some(d),
                None => tx
                    .query_row(
                        "SELECT sha256 FROM tombstones WHERE proxy_id = ?1 AND event_id = ?2",
                        params![proxy_id, ev.event_id.as_str()],
                        |r| r.get(0),
                    )
                    .optional()?,
            };
            if let Some(d) = existing_digest {
                if d == p.digest {
                    out.duplicate.push(ev.event_id.clone());
                } else {
                    conflicts.push(conflict(index, ev, ConflictKind::Conflict));
                }
                continue;
            }
            let seq_taken: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM tombstones WHERE proxy_id = ?1 AND epoch_id = ?2 AND sequence = ?3)
                     OR EXISTS(SELECT 1 FROM events WHERE proxy_id = ?1 AND epoch_id = ?2 AND sequence = ?3)",
                params![proxy_id, ev.epoch_id.as_str(), p.sequence],
                |r| r.get(0),
            )?;
            if seq_taken {
                // Only the later colliding event is reported (the stored one
                // is already accepted and not part of this batch's items).
                conflicts.push(conflict(index, ev, ConflictKind::SequenceConflict));
                continue;
            }
            let owner: Option<String> = tx
                .query_row(
                    "SELECT proxy_id FROM invocations WHERE invocation_id = ?1",
                    params![p.invocation_id],
                    |r| r.get(0),
                )
                .optional()?;
            if owner.as_deref().is_some_and(|o| o != proxy_id) {
                conflicts.push(conflict(index, ev, ConflictKind::InvocationOwnerConflict));
                continue;
            }
            tx.execute(
                "INSERT INTO events (proxy_id, event_id, epoch_id, sequence, invocation_id,
                     event_type, occurred_at, received_at, canonical, sha256, size)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    proxy_id,
                    ev.event_id.as_str(),
                    ev.epoch_id.as_str(),
                    p.sequence,
                    p.invocation_id,
                    p.event_type,
                    ev.occurred_at.as_str(),
                    received_at,
                    p.canonical,
                    p.digest,
                    p.canonical.len() as i64,
                ],
            )?;
            let created_seq = tx.last_insert_rowid();
            touched
                .entry(p.invocation_id.as_str())
                .or_default()
                .push((created_seq, p.event_type == "invocation.cancel_requested"));
            tx.execute(
                "INSERT INTO tombstones (proxy_id, event_id, epoch_id, sequence, sha256, received_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    proxy_id,
                    ev.event_id.as_str(),
                    ev.epoch_id.as_str(),
                    p.sequence,
                    p.digest,
                    received_at
                ],
            )?;
            tx.execute(
                "INSERT INTO invocations (invocation_id, proxy_id, last_received_at)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT (invocation_id) DO UPDATE SET last_received_at = excluded.last_received_at",
                params![p.invocation_id, proxy_id, received_at],
            )?;
            out.accepted.push(ev.event_id.clone());
            fresh.push((index, p));
        }
        if !conflicts.is_empty() {
            // Dropping `tx` rolls back every insert of this batch.
            return Err(LedgerError::Conflicts(conflicts));
        }
        if dry_run || fresh.is_empty() {
            // `dry_run`: dropping `tx` rolls the inserts back.
            return Ok(out);
        }

        // Gap derivation runs over the batch sorted by (epoch order of first
        // appearance, sequence), so the result does not depend on the order
        // inside the batch.
        let mut epoch_order: HashMap<&str, usize> = HashMap::new();
        for (index, _) in &fresh {
            let next = epoch_order.len();
            epoch_order
                .entry(events[*index].epoch_id.as_str())
                .or_insert(next);
        }
        let mut seqs: Vec<(usize, &str, i64)> = fresh
            .iter()
            .map(|(i, p)| {
                let e = events[*i].epoch_id.as_str();
                (epoch_order[e], e, p.sequence)
            })
            .collect();
        seqs.sort_unstable();
        let mut gaps_added = false;
        for (_, epoch, seq) in seqs {
            gaps_added |= derive_gaps(
                &tx,
                proxy_id,
                epoch,
                seq,
                received_at,
                self.opts.tombstone_retention_secs,
            )?;
        }

        // Recompute the projection of every touched invocation from its full
        // event set, in this transaction (pure function: arrival order and
        // resends cannot change the result).
        // The aggregates are merged with the stored row, so the cost of a batch
        // does not depend on how many events the invocation already has.
        for (inv, new) in &touched {
            let prev: Option<(i64, i64, i64, i64, i64)> = tx
                .query_row(
                    "SELECT created_seq, first_received_at, last_received_at, event_count,
                            cancel_observed FROM projections
                     WHERE proxy_id = ?1 AND invocation_id = ?2",
                    params![proxy_id, inv],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
                )
                .optional()?;
            let new_min = new.iter().map(|n| n.0).min().unwrap_or(i64::MAX);
            let agg = EventAggregate {
                created_seq: prev.map_or(new_min, |p| p.0.min(new_min)),
                first_received_at: prev.map_or(received_at, |p| p.1.min(received_at)),
                last_received_at: prev.map_or(received_at, |p| p.2.max(received_at)),
                event_count: prev.map_or(0, |p| p.3) + new.len() as i64,
                cancel_observed: prev.is_some_and(|p| p.4 != 0) || new.iter().any(|n| n.1),
            };
            recompute_projection(&tx, proxy_id, inv, &agg)?;
        }

        let rows = fresh.len() as i64;
        let bytes: i64 = fresh.iter().map(|(_, p)| p.canonical.len() as i64).sum();
        tx.execute(
            "INSERT INTO usage (proxy_id, event_rows, event_bytes, tombstone_rows)
             VALUES (?1, ?2, ?3, ?2)
             ON CONFLICT (proxy_id) DO UPDATE SET
                 event_rows = event_rows + excluded.event_rows,
                 event_bytes = event_bytes + excluded.event_bytes,
                 tombstone_rows = tombstone_rows + excluded.tombstone_rows",
            params![proxy_id, rows, bytes],
        )?;
        if self.over_caps(&tx, proxy_id)? {
            return Err(LedgerError::StorageLimit);
        }
        if gaps_added {
            let n: i64 = tx.query_row(
                "SELECT COUNT(*) FROM gaps WHERE proxy_id = ?1 AND open = 1 AND kind = 'sequence_gap'",
                params![proxy_id],
                |r| r.get(0),
            )?;
            if n > MAX_GAPS_PER_PROXY {
                return Err(LedgerError::StorageLimit);
            }
        }
        tx.commit()?;
        Ok(out)
    }

    fn over_caps(
        &self,
        tx: &rusqlite::Transaction<'_>,
        proxy_id: &str,
    ) -> Result<bool, LedgerError> {
        let c = &self.opts.caps;
        let (pr, pb, pt): (i64, i64, i64) = tx.query_row(
            "SELECT event_rows, event_bytes, tombstone_rows FROM usage WHERE proxy_id = ?1",
            params![proxy_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        let (tr, tb, tt): (i64, i64, i64) = tx.query_row(
            "SELECT COALESCE(SUM(event_rows),0), COALESCE(SUM(event_bytes),0),
                    COALESCE(SUM(tombstone_rows),0) FROM usage",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        let pages: i64 = tx.pragma_query_value(None, "page_count", |r| r.get(0))?;
        let free: i64 = tx.pragma_query_value(None, "freelist_count", |r| r.get(0))?;
        let page_size: i64 = tx.pragma_query_value(None, "page_size", |r| r.get(0))?;
        let live_bytes = (pages - free).saturating_mul(page_size);
        let over = |v: i64, cap: u64| u64::try_from(v).is_ok_and(|v| v > cap);
        Ok(over(pr, c.rows_per_proxy)
            || over(pt, c.tombstones_per_proxy)
            || over(pb, c.bytes_per_proxy)
            || over(tr, c.rows_total)
            || over(tt, c.tombstones_total)
            || over(tb, c.bytes_total)
            || over(live_bytes, c.file_bytes))
    }

    /// Retention sweep by server `received_at` only (L1). An invocation (its
    /// event rows and its projection together) goes `event_retention(proxy_id)`
    /// seconds after its *last* received event, tombstones after T, gap records after
    /// E, invocation owner bindings after `max(E, T)`, and non-latest epoch
    /// rows after T. A row is kept while `now - received_at <= retention`.
    /// Callable at any time; one transaction.
    pub fn sweep(
        &self,
        now: i64,
        event_retention: &dyn Fn(&str) -> i64,
    ) -> Result<SweepStats, LedgerError> {
        let t = self.opts.tombstone_retention_secs;
        let mut conn = self.conn.lock();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let proxies: Vec<String> = {
            let mut st = tx.prepare(
                "SELECT proxy_id FROM events UNION SELECT proxy_id FROM gaps
                 UNION SELECT proxy_id FROM invocations UNION SELECT proxy_id FROM projections",
            )?;
            let rows = st.query_map([], |r| r.get(0))?;
            rows.collect::<std::result::Result<_, _>>()?
        };
        let mut s = SweepStats::default();
        for p in &proxies {
            let e = event_retention(p);
            // An invocation expires as one unit at `last_received_at + E`:
            // its events and its projection go together (L1).
            let cutoff = now.saturating_sub(e);
            s.events += tx.execute(
                "DELETE FROM events WHERE proxy_id = ?1 AND invocation_id IN
                     (SELECT invocation_id FROM projections
                      WHERE proxy_id = ?1 AND last_received_at < ?2)",
                params![p, cutoff],
            )?;
            s.projections += tx.execute(
                "DELETE FROM projections WHERE proxy_id = ?1 AND last_received_at < ?2",
                params![p, cutoff],
            )?;
            s.gaps += tx.execute(
                "DELETE FROM gaps WHERE proxy_id = ?1 AND detected_at < ?2",
                params![p, now.saturating_sub(e)],
            )?;
            s.invocations += tx.execute(
                "DELETE FROM invocations WHERE proxy_id = ?1 AND last_received_at < ?2",
                params![p, now.saturating_sub(e.max(t))],
            )?;
        }
        s.tombstones += tx.execute(
            "DELETE FROM tombstones WHERE received_at < ?1",
            params![now.saturating_sub(t)],
        )?;
        s.epochs += tx.execute(
            "DELETE FROM epochs WHERE last_received_at < ?1
               AND ord NOT IN (SELECT MAX(ord) FROM epochs GROUP BY proxy_id)",
            params![now.saturating_sub(t)],
        )?;
        tx.execute_batch(
            "DELETE FROM usage;
             INSERT INTO usage (proxy_id, event_rows, event_bytes, tombstone_rows)
                 SELECT proxy_id, COUNT(*), COALESCE(SUM(size),0), 0 FROM events GROUP BY proxy_id;
             INSERT INTO usage (proxy_id, event_rows, event_bytes, tombstone_rows)
                 SELECT proxy_id, 0, 0, COUNT(*) FROM tombstones GROUP BY proxy_id
                 ON CONFLICT (proxy_id) DO UPDATE SET tombstone_rows = excluded.tombstone_rows;",
        )?;
        tx.commit()?;
        // secure_delete zeroes freed pages in the database, but the WAL can
        // still hold older copies until it is checkpointed and truncated.
        if let Err(e) = conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(())) {
            tracing::warn!(error = %LedgerError::from(e), "proxy ledger WAL checkpoint after sweep failed");
        }
        Ok(s)
    }

    /// Server-derived gaps of a proxy in detection order.
    pub fn gaps(&self, proxy_id: &str) -> Result<Vec<GapRecord>, LedgerError> {
        let conn = self.conn.lock();
        let mut st = conn.prepare(
            "SELECT gap_id, kind, detected_at, epoch_id, previous_epoch_id, from_sequence,
                    to_sequence, open, closed_at, tail FROM gaps WHERE proxy_id = ?1 ORDER BY rowid_seq",
        )?;
        let rows = st.query_map(params![proxy_id], gap_from_row)?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// The stored event row (absent after retention removed the body).
    pub fn stored_event(
        &self,
        proxy_id: &str,
        event_id: &str,
    ) -> Result<Option<StoredEvent>, LedgerError> {
        let conn = self.conn.lock();
        Ok(conn
            .query_row(
                "SELECT created_seq, received_at, epoch_id, sequence, canonical FROM events
                 WHERE proxy_id = ?1 AND event_id = ?2",
                params![proxy_id, event_id],
                |r| {
                    Ok(StoredEvent {
                        created_seq: r.get(0)?,
                        received_at: r.get(1)?,
                        epoch_id: r.get(2)?,
                        sequence: r.get(3)?,
                        canonical: r.get(4)?,
                    })
                },
            )
            .optional()?)
    }

    // -- S5 read API (read-only connection; never takes the writer mutex) -----

    /// Invocation list, newest first by `created_seq` (L3). `after_key` is the
    /// `next_key` of the previous page (rows strictly older than it). `limit`
    /// is clamped to `1..=500`. When `filter.proxy_id` is set every row belongs
    /// to that proxy; with none set the query spans all proxies, so the caller
    /// (the HTTP layer) must apply its own proxy scope.
    pub fn list_invocations(
        &self,
        filter: &InvocationFilter,
        after_key: Option<i64>,
        limit: usize,
    ) -> Result<InvocationPage, LedgerError> {
        let limit = limit.clamp(1, MAX_LIST_LIMIT);
        let mut sql = format!("SELECT {PROJ_SELECT} FROM projections p WHERE 1 = 1");
        let mut args: Vec<SqlValue> = Vec::new();
        let mut text = |col: &str, v: &Option<String>, sql: &mut String| {
            if let Some(v) = v {
                sql.push_str(&format!(" AND {col} = ?"));
                args.push(SqlValue::Text(v.clone()));
            }
        };
        text("p.proxy_id", &filter.proxy_id, &mut sql);
        text("p.upstream_id", &filter.upstream_id, &mut sql);
        text("p.actor_id", &filter.actor_id, &mut sql);
        text("p.method", &filter.method, &mut sql);
        text("p.outcome", &filter.outcome, &mut sql);
        text("p.tool_ref", &filter.tool_ref, &mut sql);
        if let ProxyScope::Only(allowed) = &filter.scope {
            if allowed.is_empty() {
                sql.push_str(" AND 0");
            } else {
                sql.push_str(" AND p.proxy_id IN (");
                sql.push_str(&vec!["?"; allowed.len()].join(","));
                sql.push(')');
                args.extend(allowed.iter().map(|a| SqlValue::Text(a.clone())));
            }
        }
        if let Some(l) = filter.lifecycle {
            sql.push_str(" AND p.lifecycle = ?");
            args.push(SqlValue::Text(l.as_str().to_string()));
        }
        let time_col = match filter.time_basis {
            TimeBasis::Received => "p.first_received_at",
            TimeBasis::Occurred => "COALESCE(p.started_at_s, p.completed_at_s)",
        };
        if let Some(from) = filter.from {
            sql.push_str(&format!(" AND {time_col} >= ?"));
            args.push(SqlValue::Integer(from));
        }
        if let Some(to) = filter.to {
            sql.push_str(&format!(" AND {time_col} < ?"));
            args.push(SqlValue::Integer(to));
        }
        if let Some(k) = after_key {
            sql.push_str(" AND p.created_seq < ?");
            args.push(SqlValue::Integer(k));
        }
        sql.push_str(" ORDER BY p.created_seq DESC LIMIT ?");
        args.push(SqlValue::Integer(limit as i64 + 1));

        let conn = self.read.acquire();
        let mut st = conn.prepare(&sql)?;
        let rows = st.query_map(rusqlite::params_from_iter(args.iter()), projection_from_row)?;
        let mut items: Vec<Projection> = rows.collect::<std::result::Result<_, _>>()?;
        let next_key = if items.len() > limit {
            items.truncate(limit);
            items.last().map(|p| p.created_seq)
        } else {
            None
        };
        Ok(InvocationPage { items, next_key })
    }

    /// One invocation of `proxy_id` with up to 32 envelope-identifier events.
    /// `None` when unknown for that proxy (an invocation of another proxy is
    /// indistinguishable from an unknown one).
    pub fn get_invocation(
        &self,
        proxy_id: &str,
        invocation_id: &str,
    ) -> Result<Option<InvocationDetail>, LedgerError> {
        let mut conn = self.read.acquire();
        // One snapshot for the projection and its events.
        let tx = conn.transaction()?;
        let invocation = tx
            .query_row(
                &format!(
                    "SELECT {PROJ_SELECT} FROM projections p
                     WHERE p.proxy_id = ?1 AND p.invocation_id = ?2"
                ),
                params![proxy_id, invocation_id],
                projection_from_row,
            )
            .optional()?;
        let Some(invocation) = invocation else {
            return Ok(None);
        };
        let events = {
            let mut st = tx.prepare(
                "SELECT created_seq, event_type, event_id, epoch_id, sequence, occurred_at,
                        received_at FROM events
                 WHERE proxy_id = ?1 AND invocation_id = ?2 ORDER BY created_seq LIMIT ?3",
            )?;
            let rows = st.query_map(
                params![proxy_id, invocation_id, MAX_DETAIL_EVENTS as i64],
                |r| {
                    Ok(EventIdentity {
                        created_seq: r.get(0)?,
                        event_type: r.get(1)?,
                        event_id: r.get(2)?,
                        epoch_id: r.get(3)?,
                        sequence: r.get(4)?,
                        occurred_at: r.get(5)?,
                        received_at: r.get(6)?,
                    })
                },
            )?;
            rows.collect::<std::result::Result<Vec<_>, _>>()?
        };
        let events_total = invocation.event_count;
        Ok(Some(InvocationDetail {
            events_truncated: events_total > MAX_DETAIL_EVENTS as i64,
            events,
            events_total,
            invocation,
        }))
    }

    /// Server-derived gaps of `proxy_id`, newest first, at most 50, plus the
    /// total (L3 `audit_gaps` / `audit_gaps_total`).
    pub fn gaps_page(&self, proxy_id: &str, limit: usize) -> Result<GapPage, LedgerError> {
        let limit = limit.min(MAX_GAP_PAGE);
        let mut conn = self.read.acquire();
        let tx = conn.transaction()?;
        let total: i64 = tx.query_row(
            "SELECT COUNT(*) FROM gaps WHERE proxy_id = ?1",
            params![proxy_id],
            |r| r.get(0),
        )?;
        let items = {
            let mut st = tx.prepare(
                "SELECT gap_id, kind, detected_at, epoch_id, previous_epoch_id, from_sequence,
                        to_sequence, open, closed_at, tail FROM gaps
                 WHERE proxy_id = ?1 ORDER BY rowid_seq DESC LIMIT ?2",
            )?;
            let rows = st.query_map(params![proxy_id, limit as i64], gap_from_row)?;
            rows.collect::<std::result::Result<Vec<_>, _>>()?
        };
        Ok(GapPage { items, total })
    }

    /// Open server-derived gaps of `proxy_id` by kind (`sequence_gap`,
    /// `producer_epoch_change`); kinds with none are absent.
    pub fn open_gap_counts(&self, proxy_id: &str) -> Result<BTreeMap<String, i64>, LedgerError> {
        let conn = self.read.acquire();
        let mut st = conn.prepare(
            "SELECT kind, COUNT(*) FROM gaps WHERE proxy_id = ?1 AND open = 1 GROUP BY kind",
        )?;
        let rows = st.query_map(params![proxy_id], |r| Ok((r.get(0)?, r.get(1)?)))?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// F13/AC-06 tail gap. The status slice calls this with the report's
    /// `last_assigned_sequence` for the report's (current) epoch.
    ///
    /// When it is above the highest stored sequence of the epoch (0 when none),
    /// an open `tail=true` sequence_gap `(highest+1 ..= last_assigned)` is
    /// created, or extended when one is already open. Arriving events shrink and
    /// finally close it (see `derive_gaps`); the record is kept. Returns
    /// `Unchanged` when nothing is missing or the open tail already covers it.
    ///
    /// Returns `Unchanged` when `epoch_id` is known but is not the proxy's latest
    /// known epoch (a stale or reordered report must not open a gap in a closed
    /// epoch). An epoch with no row yet is accepted: it is the new epoch whose
    /// first events have not arrived.
    ///
    /// A proxy keeps at most one open tail gap for epochs that have no
    /// `epochs` row (never announced by an event, or pruned by retention); a
    /// report for another such epoch closes the previous one, record kept.
    ///
    /// Caller contract: `Err(StorageLimit)` means the open-gap cap is reached
    /// and the tail gap was not recorded. The status handler should still apply
    /// the rest of the report (state snapshot, gap upserts) and not fail the
    /// whole report with it; the next report retries.
    pub fn note_last_assigned(
        &self,
        proxy_id: &str,
        epoch_id: &str,
        last_assigned_sequence: i64,
        now: i64,
    ) -> Result<TailGapChange, LedgerError> {
        let mut conn = self.conn.lock();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let highest: i64 = tx
            .query_row(
                "SELECT highest_sequence FROM epochs WHERE proxy_id = ?1 AND epoch_id = ?2",
                params![proxy_id, epoch_id],
                |r| r.get(0),
            )
            .optional()?
            .unwrap_or(0);
        let latest: Option<String> = tx
            .query_row(
                "SELECT epoch_id FROM epochs WHERE proxy_id = ?1 ORDER BY ord DESC LIMIT 1",
                params![proxy_id],
                |r| r.get(0),
            )
            .optional()?;
        let known: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM epochs WHERE proxy_id = ?1 AND epoch_id = ?2)",
            params![proxy_id, epoch_id],
            |r| r.get(0),
        )?;
        if known && latest.as_deref() != Some(epoch_id) {
            return Ok(TailGapChange::Unchanged);
        }
        if last_assigned_sequence <= highest {
            return Ok(TailGapChange::Unchanged);
        }
        let open_tail: Option<(String, i64)> = tx
            .query_row(
                "SELECT gap_id, to_sequence FROM gaps
                 WHERE proxy_id = ?1 AND epoch_id = ?2 AND open = 1 AND tail = 1",
                params![proxy_id, epoch_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let change = match open_tail {
            Some((_, to)) if last_assigned_sequence <= to => return Ok(TailGapChange::Unchanged),
            Some((gap_id, _)) => {
                tx.execute(
                    "UPDATE gaps SET to_sequence = ?2 WHERE gap_id = ?1",
                    params![gap_id, last_assigned_sequence],
                )?;
                TailGapChange::Extended
            }
            None => {
                if !known {
                    // At most one open tail gap per proxy for epochs with no
                    // `epochs` row: such a tail can only close by an arrival
                    // in that epoch, which a bogus or retention-pruned epoch
                    // never gets. A new unknown epoch supersedes the previous
                    // one (closed, record kept); an epoch that has since been
                    // announced no longer matches and stays a normal tail.
                    tx.execute(
                        "UPDATE gaps SET open = 0, closed_at = ?3
                         WHERE proxy_id = ?1 AND open = 1 AND tail = 1 AND epoch_id <> ?2
                           AND NOT EXISTS (SELECT 1 FROM epochs e
                                           WHERE e.proxy_id = gaps.proxy_id
                                             AND e.epoch_id = gaps.epoch_id)",
                        params![proxy_id, epoch_id, now],
                    )?;
                }
                let open: i64 = tx.query_row(
                    "SELECT COUNT(*) FROM gaps WHERE proxy_id = ?1 AND open = 1
                       AND kind = 'sequence_gap'",
                    params![proxy_id],
                    |r| r.get(0),
                )?;
                if open >= MAX_GAPS_PER_PROXY {
                    return Err(LedgerError::StorageLimit);
                }
                insert_gap(
                    &tx,
                    proxy_id,
                    GapKind::SequenceGap,
                    now,
                    epoch_id,
                    None,
                    Some((highest + 1, last_assigned_sequence)),
                    true,
                )?;
                TailGapChange::Created
            }
        };
        tx.commit()?;
        Ok(change)
    }

    /// Usage counters of one proxy (zeros when none).
    pub fn usage(&self, proxy_id: &str) -> Result<Usage, LedgerError> {
        let conn = self.conn.lock();
        Ok(conn
            .query_row(
                "SELECT event_rows, event_bytes, tombstone_rows FROM usage WHERE proxy_id = ?1",
                params![proxy_id],
                |r| {
                    Ok(Usage {
                        event_rows: r.get(0)?,
                        event_bytes: r.get(1)?,
                        tombstone_rows: r.get(2)?,
                    })
                },
            )
            .optional()?
            .unwrap_or_default())
    }
}

fn gap_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<GapRecord> {
    let kind: String = r.get(1)?;
    let kind = match kind.as_str() {
        "sequence_gap" => GapKind::SequenceGap,
        "producer_epoch_change" => GapKind::ProducerEpochChange,
        _ => {
            return Err(rusqlite::Error::FromSqlConversionFailure(
                1,
                rusqlite::types::Type::Text,
                "unknown gap kind".into(),
            ))
        }
    };
    Ok(GapRecord {
        gap_id: r.get(0)?,
        kind,
        detected_at: r.get(2)?,
        epoch_id: r.get(3)?,
        previous_epoch_id: r.get(4)?,
        from_sequence: r.get(5)?,
        to_sequence: r.get(6)?,
        open: r.get::<_, i64>(7)? != 0,
        closed_at: r.get(8)?,
        tail: r.get::<_, i64>(9)? != 0,
    })
}

struct Prepared {
    canonical: Vec<u8>,
    digest: Vec<u8>,
    sequence: i64,
    invocation_id: String,
    event_type: &'static str,
}

impl Prepared {
    fn new(ev: &ProxyEvent) -> Self {
        let canonical = canonical_event_bytes(ev);
        let digest = Sha256::digest(&canonical).to_vec();
        Prepared {
            canonical,
            digest,
            sequence: ev.sequence.get(),
            invocation_id: ev.payload.invocation_id().as_str().to_string(),
            event_type: match &ev.payload {
                EventPayload::Started(_) => "invocation.started",
                EventPayload::Completed(_) => "invocation.completed",
                EventPayload::CancelRequested(_) => "invocation.cancel_requested",
            },
        }
    }
}

fn conflict(index: usize, ev: &ProxyEvent, kind: ConflictKind) -> ConflictItem {
    ConflictItem {
        index,
        event_id: ev.event_id.clone(),
        kind,
    }
}

/// Apply one newly accepted `(epoch, sequence)` to the gap model. Returns true
/// when a gap row was inserted.
fn derive_gaps(
    tx: &rusqlite::Transaction<'_>,
    proxy_id: &str,
    epoch: &str,
    seq: i64,
    now: i64,
    tombstone_secs: i64,
) -> Result<bool, LedgerError> {
    let mut added = false;
    let highest: Option<i64> = tx
        .query_row(
            "SELECT highest_sequence FROM epochs WHERE proxy_id = ?1 AND epoch_id = ?2",
            params![proxy_id, epoch],
            |r| r.get(0),
        )
        .optional()?;
    let highest = match highest {
        Some(h) => h,
        None => {
            let previous: Option<String> = tx
                .query_row(
                    "SELECT epoch_id FROM epochs WHERE proxy_id = ?1 ORDER BY ord DESC LIMIT 1",
                    params![proxy_id],
                    |r| r.get(0),
                )
                .optional()?;
            tx.execute(
                "INSERT INTO epochs (proxy_id, epoch_id, highest_sequence, last_received_at)
                 VALUES (?1, ?2, 0, ?3)",
                params![proxy_id, epoch, now],
            )?;
            if let Some(prev) = previous {
                insert_gap(
                    tx,
                    proxy_id,
                    GapKind::ProducerEpochChange,
                    now,
                    epoch,
                    Some(&prev),
                    None,
                    false,
                )?;
                added = true;
            }
            0
        }
    };
    if seq > highest {
        // An open tail gap (`highest+1 ..= last_assigned`, from a status
        // report) is the only open gap above `highest`. An arrival inside it
        // splits off the missing prefix as an ordinary gap and shrinks the tail;
        // the arrival of its last sequence closes it (record kept); an arrival
        // beyond it turns it into an ordinary missing range.
        let tail: Option<(String, i64, i64, i64)> = tx
            .query_row(
                "SELECT gap_id, from_sequence, to_sequence, detected_at FROM gaps
                 WHERE proxy_id = ?1 AND epoch_id = ?2 AND open = 1 AND tail = 1",
                params![proxy_id, epoch],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?;
        match tail {
            Some((gap_id, from, to, detected_at)) if seq <= to => {
                if seq > from {
                    // The split-off prefix was missing since the tail was
                    // detected, so it inherits that time.
                    insert_gap(
                        tx,
                        proxy_id,
                        GapKind::SequenceGap,
                        detected_at,
                        epoch,
                        None,
                        Some((from, seq - 1)),
                        false,
                    )?;
                    added = true;
                }
                if seq == to {
                    // The closed record names the sequence that actually
                    // arrived, so it never claims a missing range.
                    tx.execute(
                        "UPDATE gaps SET open = 0, closed_at = ?2, from_sequence = ?3,
                             to_sequence = ?3 WHERE gap_id = ?1",
                        params![gap_id, now, seq],
                    )?;
                } else {
                    tx.execute(
                        "UPDATE gaps SET from_sequence = ?2 WHERE gap_id = ?1",
                        params![gap_id, seq + 1],
                    )?;
                }
            }
            Some((gap_id, _, _, _)) => {
                tx.execute(
                    "UPDATE gaps SET tail = 0, to_sequence = ?2 WHERE gap_id = ?1",
                    params![gap_id, seq - 1],
                )?;
            }
            None if seq > highest + 1 => {
                insert_gap(
                    tx,
                    proxy_id,
                    GapKind::SequenceGap,
                    now,
                    epoch,
                    None,
                    Some((highest + 1, seq - 1)),
                    false,
                )?;
                added = true;
            }
            None => {}
        }
        tx.execute(
            "UPDATE epochs SET highest_sequence = ?3, last_received_at = ?4
             WHERE proxy_id = ?1 AND epoch_id = ?2",
            params![proxy_id, epoch, seq, now],
        )?;
    } else {
        tx.execute(
            "UPDATE epochs SET last_received_at = ?3 WHERE proxy_id = ?1 AND epoch_id = ?2",
            params![proxy_id, epoch, now],
        )?;
        // Each open gap has a `present` counter: an accepted sequence inside
        // its range adds one, and the gap closes when present == range length.
        // O(log n) per arrival, no range scan. A sequence is accepted once per
        // (epoch, sequence) while its tombstone lives, so counts cannot double.
        // Gaps older than T stop counting: a replay of an already-filled
        // sequence (tombstone expired) must not close a gap wrongly, so such a
        // gap can only stay open (safe direction).
        // Gaps within an epoch are disjoint (a gap always starts above the
        // highest accepted sequence), so at most one open gap contains `seq`:
        // the one with the greatest start <= seq. Index range lookup, O(log n).
        let cand: Option<(String, i64, i64, i64, i64)> = tx
            .query_row(
                "SELECT gap_id, from_sequence, to_sequence, present, detected_at FROM gaps
                 WHERE proxy_id = ?1 AND epoch_id = ?2 AND open = 1 AND from_sequence <= ?3
                 ORDER BY from_sequence DESC LIMIT 1",
                params![proxy_id, epoch, seq],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .optional()?;
        if let Some((gap_id, from, to, present, detected_at)) = cand {
            if to >= seq && detected_at >= now.saturating_sub(tombstone_secs) {
                let present = present + 1;
                if present > to - from {
                    tx.execute(
                        "UPDATE gaps SET present = ?2, open = 0, closed_at = ?3 WHERE gap_id = ?1",
                        params![gap_id, present, now],
                    )?;
                } else {
                    tx.execute(
                        "UPDATE gaps SET present = ?2 WHERE gap_id = ?1",
                        params![gap_id, present],
                    )?;
                }
            }
        }
    }
    Ok(added)
}

#[allow(clippy::too_many_arguments)]
fn insert_gap(
    tx: &rusqlite::Transaction<'_>,
    proxy_id: &str,
    kind: GapKind,
    now: i64,
    epoch: &str,
    previous_epoch: Option<&str>,
    range: Option<(i64, i64)>,
    tail: bool,
) -> Result<(), LedgerError> {
    tx.execute(
        "INSERT INTO gaps (gap_id, proxy_id, kind, detected_at, epoch_id, previous_epoch_id,
             from_sequence, to_sequence, open, tail)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1, ?9)",
        params![
            uuid::Uuid::new_v4().to_string(),
            proxy_id,
            kind.as_str(),
            now,
            epoch,
            previous_epoch,
            range.map(|r| r.0),
            range.map(|r| r.1),
            i64::from(tail),
        ],
    )?;
    Ok(())
}

/// Create the file owner-only when missing; refuse unsafe existing files.
/// Open a SQLite file with the ledger's hardening: refuses a symlink (checked,
/// and SQLite is opened with `NOFOLLOW`), a non-regular file, a file owned by
/// another user, a group/world accessible file, or a filesystem that cannot do
/// WAL; sets `synchronous=FULL`, `secure_delete`. Schema setup is the caller's.
/// Shared with the metadata store (`metadata.rs`).
pub(super) fn open_hardened(path: &Path) -> Result<Connection> {
    let conn = open_checked(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        true,
    )?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "FULL")?;
    conn.pragma_update(None, "fullfsync", true)?;
    conn.pragma_update(None, "secure_delete", true)?;
    let jm: String = conn.pragma_query_value(None, "journal_mode", |r| r.get(0))?;
    let sync: i64 = conn.pragma_query_value(None, "synchronous", |r| r.get(0))?;
    if !jm.eq_ignore_ascii_case("wal") || sync != 2 {
        bail!("ledger database could not be set to WAL with synchronous=FULL");
    }
    Ok(conn)
}

/// The path safety checks shared by the writer and the read-only connection
/// (symlink, regular file, owner, mode), then open with `flags`.
fn open_checked(path: &Path, flags: OpenFlags, create: bool) -> Result<Connection> {
    prepare_file(path, create)?;
    // SQLite's NOFOLLOW rejects a symlink in ANY path component (for example
    // /var -> /private/var), so resolve the directory first; the final
    // component was already checked by prepare_file and NOFOLLOW covers it.
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
        .canonicalize()
        .context("resolve ledger directory")?;
    let real = dir.join(path.file_name().context("ledger path has no file name")?);
    let conn = Connection::open_with_flags(&real, flags).context("open ledger database")?;
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    Ok(conn)
}

/// Read-only WAL connection for the S5 read API. The writer is opened first, so
/// the file exists and is already WAL. `query_only` is belt and braces.
fn open_read_only(path: &Path) -> Result<Connection> {
    let conn = open_checked(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        false,
    )?;
    conn.pragma_update(None, "query_only", true)?;
    Ok(conn)
}

fn prepare_file(path: &Path, create: bool) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && !create => {
            Err(e).context("ledger database does not exist")
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            options
                .open(path)
                .context("create ledger database")?
                .sync_all()?;
            #[cfg(unix)]
            std::fs::File::open(
                path.parent()
                    .filter(|p| !p.as_os_str().is_empty())
                    .unwrap_or(Path::new(".")),
            )?
            .sync_all()?;
            Ok(())
        }
        Err(e) => Err(e).context("stat ledger database"),
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                bail!("ledger database must not be a symlink");
            }
            if !meta.is_file() {
                bail!("ledger database is not a regular file");
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if meta.permissions().mode() & 0o077 != 0 {
                    bail!("ledger database must be owner-only (it holds event data)");
                }
                use std::os::unix::fs::MetadataExt;
                // SAFETY: geteuid has no preconditions and cannot fail.
                if meta.uid() != unsafe { libc::geteuid() } {
                    bail!("ledger database must be owned by the server user");
                }
            }
            Ok(())
        }
    }
}

fn init_schema(conn: &mut Connection) -> Result<()> {
    let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    let tables: i64 = conn.query_row("SELECT COUNT(*) FROM sqlite_master", [], |r| r.get(0))?;
    match (version, tables) {
        (0, 0) => {
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute_batch(SCHEMA)
                .and_then(|()| tx.execute_batch(PROJECTIONS_DDL))
                .and_then(|()| tx.execute_batch(GAPS_INDEXES_DDL))
                .context("create ledger schema")?;
            tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
            tx.commit().context("create ledger schema")?;
            Ok(())
        }
        (SCHEMA_VERSION, _) => Ok(()),
        (1, _) => migrate_v1_to_v2(conn),
        _ => bail!("ledger database has an unknown format version"),
    }
}

/// v1 -> v2 in ONE transaction: add `gaps.tail`, create the projection table,
/// rebuild a projection for every invocation that still has events, bump the
/// version. Any failure (for example an undecodable stored event) drops the
/// transaction, so the file stays exactly at v1 and the server refuses to start
/// rather than serving a partial projection.
fn migrate_v1_to_v2(conn: &mut Connection) -> Result<()> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let version: i64 = tx.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if version == SCHEMA_VERSION {
        return Ok(()); // another process migrated first
    }
    if version != 1 {
        bail!("ledger database has an unknown format version");
    }
    tx.execute_batch(GAPS_TAIL_DDL)
        .and_then(|()| tx.execute_batch(EVENTS_INV_TYPE_DDL))
        .and_then(|()| tx.execute_batch(GAPS_INDEXES_DDL))
        .and_then(|()| tx.execute_batch(PROJECTIONS_DDL))
        .context("migrate ledger schema to v2")?;
    let keys: Vec<(String, String)> = {
        let mut st = tx.prepare("SELECT DISTINCT proxy_id, invocation_id FROM events")?;
        let rows = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
        rows.collect::<std::result::Result<_, _>>()?
    };
    for (proxy_id, invocation_id) in &keys {
        let agg: EventAggregate = tx.query_row(
            "SELECT MIN(created_seq), MIN(received_at), MAX(received_at), COUNT(*),
                    EXISTS(SELECT 1 FROM events c WHERE c.proxy_id = ?1 AND c.invocation_id = ?2
                           AND c.event_type = 'invocation.cancel_requested')
             FROM events WHERE proxy_id = ?1 AND invocation_id = ?2",
            params![proxy_id, invocation_id],
            |r| {
                Ok(EventAggregate {
                    created_seq: r.get(0)?,
                    first_received_at: r.get(1)?,
                    last_received_at: r.get(2)?,
                    event_count: r.get(3)?,
                    cancel_observed: r.get::<_, i64>(4)? != 0,
                })
            },
        )?;
        recompute_projection(&tx, proxy_id, invocation_id, &agg)
            .map_err(|e| anyhow::anyhow!("rebuild projection during v2 migration: {e}"))?;
    }
    tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    tx.commit().context("commit ledger v2 migration")?;
    tracing::info!(
        invocations = keys.len(),
        "proxy ledger migrated to schema v2"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Stored projection
// ---------------------------------------------------------------------------

/// Recompute and store the projection of one invocation. Inputs are the first
/// `MAX_PROJECTION_EVENTS` *started* and the first `MAX_PROJECTION_EVENTS`
/// *completed* events by `created_seq` (bounded by the `events_inv_type`
/// index); `cancel_requested` events are not loaded or counted and can never
/// crowd out a completion. `agg` carries the whole-invocation aggregates.
/// More events of a type than the cap adds the `event_limit` flag; beyond the
/// cap the result depends on arrival order.
fn recompute_projection(
    tx: &rusqlite::Transaction<'_>,
    proxy_id: &str,
    invocation_id: &str,
    agg: &EventAggregate,
) -> Result<(), LedgerError> {
    let mut inputs = Vec::new();
    let mut truncated = false;
    for event_type in ["invocation.started", "invocation.completed"] {
        let mut st = tx.prepare_cached(
            "SELECT created_seq, received_at, canonical FROM events
             WHERE proxy_id = ?1 AND invocation_id = ?2 AND event_type = ?3
             ORDER BY created_seq LIMIT ?4",
        )?;
        let rows = st.query_map(
            params![
                proxy_id,
                invocation_id,
                event_type,
                MAX_PROJECTION_EVENTS as i64 + 1
            ],
            |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                ))
            },
        )?;
        let mut n = 0;
        for row in rows {
            let (created_seq, received_at, canonical) = row?;
            n += 1;
            if n > MAX_PROJECTION_EVENTS {
                truncated = true;
                break;
            }
            let event = parse_event(&canonical).map_err(|_| {
                // Identifies the row only; never any value from it.
                tracing::error!(created_seq, "proxy ledger: stored event does not decode");
                LedgerError::StorageUnavailable
            })?;
            inputs.push(ProjectionInput {
                event,
                created_seq,
                received_at,
            });
        }
    }
    match project_with(proxy_id, invocation_id, &inputs, truncated, Some(agg)) {
        Some(p) => store_projection(tx, &p),
        None => {
            tx.execute(
                "DELETE FROM projections WHERE proxy_id = ?1 AND invocation_id = ?2",
                params![proxy_id, invocation_id],
            )?;
            Ok(())
        }
    }
}

fn store_projection(tx: &rusqlite::Transaction<'_>, p: &Projection) -> Result<(), LedgerError> {
    let (tool_status, tool_ref, tool_reason) = match &p.tool {
        None => (None, None, None),
        Some(ToolInfo::Identified { metadata_ref }) => {
            (Some("identified"), Some(metadata_ref.as_str()), None)
        }
        Some(ToolInfo::MetadataUnavailable { reason }) => {
            (Some("metadata_unavailable"), None, Some(reason.as_str()))
        }
        Some(ToolInfo::Unavailable { reason }) => {
            (Some("unavailable"), None, Some(reason.as_str()))
        }
    };
    let a = p.actor.as_ref();
    let flags = p
        .flags
        .iter()
        .map(|f| f.as_str())
        .collect::<Vec<_>>()
        .join(",");
    tx.execute(
        "INSERT OR REPLACE INTO projections (
            proxy_id, invocation_id, created_seq, lifecycle, outcome, delivery_state, reason,
            reported_outcome, reported_delivery_state, reported_reason, duration_ms,
            response_bytes, method, protocol_version, upstream_id, route_revision, actor_id,
            actor_kind, authentication_method, evidence_source, credential_owner_id,
            tool_status, tool_ref, tool_reason, cancel_observed, started_at, started_at_s,
            completed_at, completed_at_s, first_received_at, last_received_at, start_epoch_id,
            flags, event_count)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,
                 ?22,?23,?24,?25,?26,?27,?28,?29,?30,?31,?32,?33,?34)",
        params![
            p.proxy_id,
            p.invocation_id,
            p.created_seq,
            p.lifecycle.as_str(),
            p.outcome,
            p.delivery_state,
            p.reason,
            p.reported_outcome,
            p.reported_delivery_state,
            p.reported_reason,
            p.duration_ms,
            p.response_bytes,
            p.method,
            p.protocol_version,
            p.upstream_id,
            p.route_revision,
            a.map(|a| a.actor_id.as_str()),
            a.map(|a| a.actor_kind.as_str()),
            a.map(|a| a.authentication_method.as_str()),
            a.map(|a| a.evidence_source.as_str()),
            a.and_then(|a| a.credential_owner_id.as_deref()),
            tool_status,
            tool_ref,
            tool_reason,
            i64::from(p.cancel_observed),
            p.started_at,
            p.started_at_s,
            p.completed_at,
            p.completed_at_s,
            p.first_received_at,
            p.last_received_at,
            p.start_epoch_id,
            flags,
            p.event_count,
        ],
    )?;
    Ok(())
}

/// Column list of [`projection_from_row`]; the last column is the derived
/// `epoch_superseded` (the start's epoch is not the proxy's latest announced
/// epoch; a swept epoch row is always a non-latest one).
const PROJ_SELECT: &str = "p.proxy_id, p.invocation_id, p.created_seq, p.lifecycle, p.outcome,
    p.delivery_state, p.reason, p.reported_outcome, p.reported_delivery_state, p.reported_reason,
    p.duration_ms, p.response_bytes, p.method, p.protocol_version, p.upstream_id,
    p.route_revision, p.actor_id, p.actor_kind, p.authentication_method, p.evidence_source,
    p.credential_owner_id, p.tool_status, p.tool_ref, p.tool_reason, p.cancel_observed,
    p.started_at, p.started_at_s, p.completed_at, p.completed_at_s, p.first_received_at,
    p.last_received_at, p.start_epoch_id, p.flags, p.event_count,
    (p.lifecycle = 'started' AND p.start_epoch_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM epochs e WHERE e.proxy_id = p.proxy_id AND e.epoch_id = p.start_epoch_id
          AND e.ord = (SELECT MAX(m.ord) FROM epochs m WHERE m.proxy_id = p.proxy_id)))";

fn projection_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Projection> {
    let lifecycle: String = r.get(3)?;
    let actor_id: Option<String> = r.get(16)?;
    let tool_status: Option<String> = r.get(21)?;
    let tool_ref: Option<String> = r.get(22)?;
    let tool_reason: Option<String> = r.get(23)?;
    let flags: String = r.get(32)?;
    let bad = |what: &'static str| {
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Text,
            what.to_string().into(),
        )
    };
    let tool = match tool_status.as_deref() {
        None => None,
        Some("identified") => Some(ToolInfo::Identified {
            metadata_ref: tool_ref.ok_or_else(|| bad("tool_ref"))?,
        }),
        Some("metadata_unavailable") => Some(ToolInfo::MetadataUnavailable {
            reason: tool_reason.ok_or_else(|| bad("tool_reason"))?,
        }),
        Some("unavailable") => Some(ToolInfo::Unavailable {
            reason: tool_reason.ok_or_else(|| bad("tool_reason"))?,
        }),
        Some(_) => return Err(bad("tool_status")),
    };
    let actor = match actor_id {
        None => None,
        Some(actor_id) => Some(ActorInfo {
            actor_id,
            actor_kind: r.get(17)?,
            authentication_method: r.get(18)?,
            evidence_source: r.get(19)?,
            credential_owner_id: r.get(20)?,
        }),
    };
    Ok(Projection {
        proxy_id: r.get(0)?,
        invocation_id: r.get(1)?,
        created_seq: r.get(2)?,
        lifecycle: Lifecycle::parse(&lifecycle).ok_or_else(|| bad("lifecycle"))?,
        outcome: r.get(4)?,
        delivery_state: r.get(5)?,
        reason: r.get(6)?,
        reported_outcome: r.get(7)?,
        reported_delivery_state: r.get(8)?,
        reported_reason: r.get(9)?,
        duration_ms: r.get(10)?,
        response_bytes: r.get(11)?,
        method: r.get(12)?,
        protocol_version: r.get(13)?,
        upstream_id: r.get(14)?,
        route_revision: r.get(15)?,
        actor,
        tool,
        cancel_observed: r.get::<_, i64>(24)? != 0,
        decision: None,
        started_at: r.get(25)?,
        started_at_s: r.get(26)?,
        completed_at: r.get(27)?,
        completed_at_s: r.get(28)?,
        first_received_at: r.get(29)?,
        last_received_at: r.get(30)?,
        start_epoch_id: r.get(31)?,
        epoch_superseded: r.get::<_, i64>(34)? != 0,
        flags: flags.split(',').filter_map(Flag::parse).collect(),
        event_count: r.get(33)?,
    })
}
