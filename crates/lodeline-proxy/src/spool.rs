//! Durable event spool (T-14a, PX-011, PX-013).
//!
//! A local SQLite database (WAL, `synchronous=FULL`) owned by one dedicated
//! writer thread, so no tokio worker ever waits on an fsync inside a lock. The
//! relay (T-13) appends validated [`ProxyEvent`] envelopes; the ingest client
//! (T-11 S4) drains them through the [`EventSource`] implementation.
//!
//! Guarantees:
//!
//! * [`Spool::append`] returns only after the row is committed and fsynced; the
//!   event sequence is assigned inside that same transaction from a counter in
//!   the database (monotonic per epoch, never reused, survives restart and the
//!   purge of acknowledged rows). Nothing is acknowledged before it is durable.
//! * Events are delivered oldest sequence first. `acknowledged` marks rows
//!   (kept for [`SpoolConfig::ack_retention`], then purged). `quarantined` moves
//!   rows unchanged to the `quarantine` table; nothing is ever dropped silently.
//!   The one exception to "unchanged" is the registry-conflict rewrite of an unsent
//!   start's `tool` (README M2b): its ORIGINAL bytes are kept in `quarantine` when
//!   the event is quarantined, and under [`ORIGINAL_CODE`] when the acknowledged
//!   rewritten row is purged.
//! * A quarantine row of any code is deleted once its `quarantined_at` is older
//!   than Q (`ledger-and-query.md` L1: Q = E, the server-issued
//!   `event_retention_seconds`, see [`Spool::set_quarantine_retention`]). The
//!   server keeps the matching gap for E after its `detected_at`, which is no
//!   later than `quarantined_at` (stamped just before for `event_quarantined`,
//!   at conflict time for `registry_conflict`), so local evidence lives at least
//!   as long as the server must keep the gap. Known limits: proxy clock skew,
//!   and a gap delivered more than E after the quarantine (an outage of at
//!   least E; R + E for `spool_expired`). Until E is known nothing is deleted.
//! * Admission stops at `capacity - gap_reserve` of unsent event bytes
//!   ([`AppendError::Full`]); the reserve is only for gap records.
//! * Unsent events older than [`SpoolConfig::max_offline_retry_age`] (R) are
//!   moved unchanged to quarantine and a `spool_expired` gap is recorded for each
//!   contiguous sequence run (O-1 option A). The gap is handed to the status
//!   layer with [`Spool::pending_gaps`] and removed only after
//!   [`Spool::gaps_handed_off`], so a crash in between repeats the gap instead
//!   of losing it.
//! * R and Q are measured so that a wall-clock step cannot age rows (#302
//!   decision 4). Each unsent event and each quarantine row has a stamp from the
//!   [`crate::boot_clock`] in a side table. A row stamped in the current boot ages
//!   on the boot clock. A row stamped in another boot, or with no stamp (no boot
//!   clock, or a row an older binary wrote), ages on the wall clock from
//!   `created_at` or `quarantined_at`. Stamps are in side tables so that an older
//!   binary still opens the database; triggers remove them with their rows, also
//!   under that binary. `ack_retention` and every timestamp on the wire stay on
//!   the wall clock.
//! * A corrupt, foreign or unreadable database refuses to open
//!   ([`SpoolError`]); it is never recreated or truncated.
//!
//! The database stores only the serialized, already validated event envelope.
//! Errors and logs carry SQLite result-code names, never event content.
//!
//! The sequence counter is the *event* sequence of the epoch. It is independent
//! of the *status* sequence bound in `state_dir` (`sequence.json`).

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use lodeline_proxy_api::status::{QuarantineCode, SpoolExpiredGap};
use lodeline_proxy_api::{GapReport, PositiveI64, ProxyEvent, Timestamp, Uuid};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use tokio::sync::oneshot;

use crate::boot_clock::{system_boot_clock, BootClock, BootInstant};
use crate::ingest_client::{EventSource, SourceFuture};
use crate::limits::Limits;

/// File name of the database inside the state directory.
pub const SPOOL_FILE: &str = "spool.db";
const SCHEMA_VERSION: i64 = 1;
/// Quarantine reason of events that outlived R.
pub const EXPIRED_CODE: &str = "spool_expired";
/// Quarantine code of the UNCHANGED pre-rewrite bytes of an event whose `tool` was
/// rewritten after a registry conflict (README M2b), kept when the acknowledged
/// rewritten event is purged. Such a row is evidence, not a lost event: it is not
/// counted in `quarantined_events` (its bytes are in `quarantined_bytes`).
pub const ORIGINAL_CODE: &str = "registry_conflict_original";
/// Rows moved or purged per maintenance transaction, so one pass cannot stall
/// the writer (appends wait behind it) for long.
#[cfg(not(test))]
const MAINTENANCE_BATCH: i64 = 500;
#[cfg(test)]
const MAINTENANCE_BATCH: i64 = 20;

/// Unix-seconds clock. Injectable so retention is testable.
pub type Clock = Arc<dyn Fn() -> i64 + Send + Sync>;

fn system_clock() -> Clock {
    Arc::new(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    })
}

#[derive(Clone)]
pub struct SpoolConfig {
    /// State directory (already created and locked by `StateDir`).
    pub dir: PathBuf,
    pub proxy_id: String,
    pub epoch_id: String,
    /// True only while creating the database is safe: this start created the
    /// epoch (`StateDir::is_new_epoch`), or the epoch's spool was never marked
    /// ready (`StateDir::spool_ready`, a first start that failed before the
    /// schema committed). A missing or schema-less database is created only then;
    /// otherwise open returns [`SpoolError::Missing`] (recreating would restart
    /// the sequence in an epoch the server already knows).
    pub new_epoch: bool,
    pub event_max_bytes: u64,
    /// `spool_max_bytes`.
    pub capacity_bytes: u64,
    /// `spool_gap_reserve_bytes`: kept free of events for gap records.
    pub gap_reserve_bytes: u64,
    /// R: age after which an unsent event expires into quarantine.
    pub max_offline_retry_age: Duration,
    /// How long acknowledged rows stay (default 24 h).
    pub ack_retention: Duration,
    /// How often the writer thread expires and purges by itself.
    pub maintenance_interval: Duration,
    pub clock: Clock,
    pub boot_clock: BootClock,
}

impl SpoolConfig {
    /// Defaults: R = 30 days, acknowledged retention 24 h, maintenance every 60 s.
    pub fn new(
        dir: &Path,
        proxy_id: &str,
        epoch_id: &str,
        new_epoch: bool,
        limits: &Limits,
    ) -> SpoolConfig {
        SpoolConfig {
            dir: dir.to_path_buf(),
            proxy_id: proxy_id.to_string(),
            epoch_id: epoch_id.to_string(),
            new_epoch,
            event_max_bytes: limits.event_max_bytes,
            capacity_bytes: limits.spool_max_bytes,
            gap_reserve_bytes: limits.spool_gap_reserve_bytes,
            max_offline_retry_age: Duration::from_secs(30 * 86_400),
            ack_retention: Duration::from_secs(86_400),
            maintenance_interval: Duration::from_secs(60),
            clock: system_clock(),
            boot_clock: system_boot_clock(),
        }
    }
}

// ------------------------------------------------------------------- errors

#[derive(Debug, thiserror::Error)]
pub enum SpoolError {
    #[error("spool database is corrupt or not a database; refusing to start")]
    Corrupt,
    #[error("spool database belongs to another proxy or epoch; refusing to start")]
    Foreign,
    #[error("spool database has an unsupported schema version")]
    UnsupportedSchema,
    #[error("spool database path is not a regular file")]
    BadPath,
    /// The epoch is not new but the database file is missing or empty. Never
    /// recreated here; the operator or lifecycle decides (quarantine, new epoch).
    #[error("spool database is missing in an existing epoch; refusing to recreate it")]
    Missing,
    /// A gap record would exceed `spool_gap_reserve_bytes`.
    #[error("gap records would exceed the gap reserve")]
    GapReserveExceeded,
    #[error("spool storage error ({0})")]
    Storage(String),
    #[error("spool writer is not running")]
    Unavailable,
}

/// Why an append was refused. Nothing was stored in any of these cases.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AppendError {
    /// Unsent bytes reached `capacity - gap_reserve`. The relay blocks new calls.
    #[error("spool is full")]
    Full,
    #[error("event exceeds event_max_bytes")]
    TooLarge,
    #[error("event_id already in the spool")]
    Duplicate,
    /// `proxy_id` or `epoch_id` differs from the spool's.
    #[error("event belongs to another proxy or epoch")]
    WrongIdentity,
    /// The filesystem is out of space (SQLITE_FULL). Spool state: degraded.
    #[error("spool disk is full")]
    DiskFull,
    /// Any other storage failure. Spool state: degraded.
    #[error("spool storage failure")]
    Storage,
    #[error("spool writer is not running")]
    Unavailable,
}

fn code_name(e: &rusqlite::Error) -> String {
    match e {
        rusqlite::Error::SqliteFailure(f, _) => format!("{:?}", f.code),
        _ => "other".to_string(),
    }
}

fn classify_open(e: &rusqlite::Error) -> SpoolError {
    if let rusqlite::Error::SqliteFailure(f, _) = e {
        if matches!(
            f.code,
            rusqlite::ErrorCode::DatabaseCorrupt | rusqlite::ErrorCode::NotADatabase
        ) {
            return SpoolError::Corrupt;
        }
    }
    SpoolError::Storage(code_name(e))
}

fn is_disk_full(e: &rusqlite::Error) -> bool {
    matches!(e, rusqlite::Error::SqliteFailure(f, _) if f.code == rusqlite::ErrorCode::DiskFull)
}

// --------------------------------------------------------------- public data

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Appended {
    /// The sequence assigned to the event (the input's own sequence is ignored).
    pub sequence: i64,
}

pub use lodeline_proxy_api::status::SpoolState;

/// What T-14b puts into the status report (`spool.*`, `last_assigned_sequence`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpoolSnapshot {
    pub state: SpoolState,
    pub unsent_events: u64,
    /// Serialized bytes of the unsent events.
    pub unsent_bytes: u64,
    /// Serialized bytes of gap records not yet handed off.
    pub gap_bytes: u64,
    /// Serialized bytes of acknowledged rows still retained (purged first when full).
    pub retained_acked_bytes: u64,
    /// Serialized bytes in quarantine (not bounded yet).
    pub quarantined_bytes: u64,
    pub capacity_bytes: u64,
    pub gap_reserve_bytes: u64,
    /// Seconds since the oldest unsent event was appended; `None` when empty.
    pub oldest_unsent_age_seconds: Option<u64>,
    /// Highest sequence ever assigned in this epoch (0 if none).
    pub last_assigned_sequence: i64,
    pub quarantined_events: u64,
    /// Acknowledged rows still kept for the retention window.
    pub retained_acked_events: u64,
    pub pending_gaps: u64,
    /// A gap record did not fit the reserve (sticky, see `Shared::gap_exhausted`).
    /// The state is `Degraded` while it is set.
    pub gap_reserve_exhausted: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExpireReport {
    pub expired_events: u64,
    pub gaps_recorded: u64,
    pub purged_acked: u64,
    /// Quarantine rows deleted because they outlived Q (all codes).
    pub purged_quarantined: u64,
}

// ------------------------------------------------------------------ internals

#[derive(Default)]
struct Counters {
    unsent_events: u64,
    unsent_bytes: u64,
    gap_bytes: u64,
    oldest_created: Option<i64>,
    last_seq: i64,
    quarantined: u64,
    quarantined_bytes: u64,
    acked: u64,
    acked_bytes: u64,
    pending_gaps: u64,
}

struct Shared {
    counters: Mutex<Counters>,
    degraded: AtomicBool,
    /// Set when the writer thread has exited (also by a panic).
    dead: AtomicBool,
    capacity: AtomicU64,
    reserve: AtomicU64,
    /// R in seconds; the applied server config can change it at runtime.
    retry_age_secs: AtomicU64,
    /// Q in seconds; 0 until the applied server config provides E (no purge).
    quarantine_retention_secs: AtomicU64,
    /// Sticky: a gap record did not fit `spool_gap_reserve_bytes`. Set when that
    /// happens and cleared only once gaps were handed off (room came back) or a
    /// later gap fit, so the reported state does not flap with every append.
    gap_exhausted: AtomicBool,
    #[cfg(any(test, feature = "test-util"))]
    inject_failure: AtomicBool,
    #[cfg(any(test, feature = "test-util"))]
    delivery_paused: AtomicBool,
    /// Seconds added to the clock (test knob, see [`Spool::advance_clock_for_test`]).
    #[cfg(any(test, feature = "test-util"))]
    clock_skew: std::sync::atomic::AtomicI64,
}

enum Reply<T> {
    Sync(mpsc::Sender<T>),
    Async(oneshot::Sender<T>),
}

impl<T> Reply<T> {
    fn send(self, v: T) {
        match self {
            Reply::Sync(s) => {
                let _ = s.send(v);
            }
            Reply::Async(s) => {
                let _ = s.send(v);
            }
        }
    }
}

enum Cmd {
    Append(Box<ProxyEvent>, Reply<Result<Appended, AppendError>>),
    Next(usize, HashSet<String>, Reply<Vec<ProxyEvent>>),
    Ack(Vec<String>, Reply<Result<u64, SpoolError>>),
    Quarantine(Vec<String>, String, Reply<Result<u64, SpoolError>>),
    Expire(Reply<Result<ExpireReport, SpoolError>>),
    RecordGap(Box<GapReport>, Reply<Result<(), SpoolError>>),
    PendingGaps(Reply<Result<Vec<GapReport>, SpoolError>>),
    HandedOff(Vec<String>, Reply<Result<(), SpoolError>>),
    RegistryConflict(String, Reply<Result<Vec<String>, SpoolError>>),
    Shutdown,
}

struct Inner {
    tx: mpsc::Sender<Cmd>,
    shared: Arc<Shared>,
    clock: Clock,
    proxy_id: String,
    epoch_id: String,
    join: Mutex<Option<JoinHandle<()>>>,
}

impl Drop for Inner {
    fn drop(&mut self) {
        let _ = self.tx.send(Cmd::Shutdown);
        if let Some(j) = self.join.lock().ok().and_then(|mut g| g.take()) {
            let _ = j.join();
        }
    }
}

/// Handle to the spool. Cheap to clone; the writer thread stops (and the database
/// closes) when the last clone is dropped.
#[derive(Clone)]
pub struct Spool {
    inner: Arc<Inner>,
}

impl Spool {
    /// Open (or create) the spool and start the writer thread.
    ///
    /// Refuses to start on a corrupt, non-database, foreign (other proxy or
    /// epoch) or newer-schema file. It never recreates or truncates an existing
    /// file.
    pub fn open(cfg: SpoolConfig) -> Result<Spool, SpoolError> {
        let shared = Arc::new(Shared {
            counters: Mutex::new(Counters::default()),
            degraded: AtomicBool::new(false),
            dead: AtomicBool::new(false),
            capacity: AtomicU64::new(cfg.capacity_bytes),
            reserve: AtomicU64::new(cfg.gap_reserve_bytes),
            retry_age_secs: AtomicU64::new(cfg.max_offline_retry_age.as_secs()),
            quarantine_retention_secs: AtomicU64::new(0),
            gap_exhausted: AtomicBool::new(false),
            #[cfg(any(test, feature = "test-util"))]
            inject_failure: AtomicBool::new(false),
            #[cfg(any(test, feature = "test-util"))]
            delivery_paused: AtomicBool::new(false),
            #[cfg(any(test, feature = "test-util"))]
            clock_skew: std::sync::atomic::AtomicI64::new(0),
        });
        #[cfg(any(test, feature = "test-util"))]
        let cfg = {
            let (base, sh) = (cfg.clock.clone(), shared.clone());
            let (boot_base, boot_sh) = (cfg.boot_clock.clone(), shared.clone());
            SpoolConfig {
                clock: Arc::new(move || base() + sh.clock_skew.load(Ordering::SeqCst)),
                boot_clock: Arc::new(move || {
                    boot_base().map(|b| BootInstant {
                        secs: b.secs + boot_sh.clock_skew.load(Ordering::SeqCst),
                        ..b
                    })
                }),
                ..cfg
            }
        };
        let (proxy_id, epoch_id) = (cfg.proxy_id.clone(), cfg.epoch_id.clone());
        let (tx, rx) = mpsc::channel::<Cmd>();
        let (init_tx, init_rx) = mpsc::sync_channel::<Result<(), SpoolError>>(1);
        let clock = cfg.clock.clone();
        let sh = shared.clone();
        let join = std::thread::Builder::new()
            .name("lodeline-proxy-spool".into())
            .spawn(move || {
                // Marks the writer dead on any exit, including a panic.
                struct DeadOnExit(Arc<Shared>);
                impl Drop for DeadOnExit {
                    fn drop(&mut self) {
                        self.0.dead.store(true, Ordering::SeqCst);
                    }
                }
                let _guard = DeadOnExit(sh.clone());
                match Writer::open(cfg, sh) {
                    Ok(mut w) => {
                        let _ = init_tx.send(Ok(()));
                        w.run(rx);
                    }
                    Err(e) => {
                        let _ = init_tx.send(Err(e));
                    }
                }
            })
            .map_err(|_| SpoolError::Unavailable)?;
        match init_rx.recv() {
            Ok(Ok(())) => Ok(Spool {
                inner: Arc::new(Inner {
                    tx,
                    shared,
                    clock,
                    proxy_id,
                    epoch_id,
                    join: Mutex::new(Some(join)),
                }),
            }),
            Ok(Err(e)) => {
                let _ = join.join();
                Err(e)
            }
            Err(_) => {
                let _ = join.join();
                Err(SpoolError::Unavailable)
            }
        }
    }

    fn call<T>(&self, make: impl FnOnce(Reply<T>) -> Cmd) -> Option<T> {
        let (s, r) = mpsc::channel();
        let got = match self.inner.tx.send(make(Reply::Sync(s))) {
            Ok(()) => r.recv().ok(),
            Err(_) => None,
        };
        if got.is_none() {
            // The writer is unreachable: never look healthy.
            self.inner.shared.dead.store(true, Ordering::SeqCst);
        }
        got
    }

    async fn call_async<T>(&self, make: impl FnOnce(Reply<T>) -> Cmd) -> Option<T> {
        let (s, r) = oneshot::channel();
        if self.inner.tx.send(make(Reply::Async(s))).is_err() {
            self.inner.shared.dead.store(true, Ordering::SeqCst);
            return None;
        }
        match r.await {
            Ok(v) => Some(v),
            Err(_) => {
                self.inner.shared.dead.store(true, Ordering::SeqCst);
                None
            }
        }
    }

    /// Stop the writer thread and wait for it without blocking a tokio worker
    /// (the join runs on the blocking pool). Afterwards the database is closed;
    /// other clones see `Unavailable`. Dropping the last clone does the same
    /// synchronously, so call this where that drop would land on a worker.
    pub async fn close(&self) {
        let _ = self.inner.tx.send(Cmd::Shutdown);
        let join = self.inner.join.lock().ok().and_then(|mut g| g.take());
        if let Some(j) = join {
            let _ = tokio::task::spawn_blocking(move || {
                let _ = j.join();
            })
            .await;
        }
    }

    pub fn proxy_id(&self) -> &str {
        &self.inner.proxy_id
    }

    pub fn epoch_id(&self) -> &str {
        &self.inner.epoch_id
    }

    /// Change R (the server-issued `max_offline_retry_age_seconds`). Applies from
    /// the next maintenance pass.
    pub fn set_max_offline_retry_age(&self, age: Duration) {
        self.inner
            .shared
            .retry_age_secs
            .store(age.as_secs(), Ordering::SeqCst);
    }

    /// Set Q, the purge horizon of quarantined rows (the server-issued
    /// `event_retention_seconds`). Applies from the next maintenance pass.
    pub fn set_quarantine_retention(&self, age: Duration) {
        self.inner
            .shared
            .quarantine_retention_secs
            .store(age.as_secs(), Ordering::SeqCst);
    }

    /// Append an event durably. Blocks until commit and fsync (call from a
    /// blocking context, or use [`Spool::append_async`]). The event's `sequence`
    /// is ignored and replaced; its `proxy_id` and `epoch_id` must match.
    pub fn append(&self, event: ProxyEvent) -> Result<Appended, AppendError> {
        self.call(|r| Cmd::Append(Box::new(event), r))
            .unwrap_or(Err(AppendError::Unavailable))
    }

    /// Like [`Spool::append`], without blocking the async worker. This is the
    /// admission call of the relay (see [`Admission`]).
    pub async fn append_async(&self, event: ProxyEvent) -> Result<Appended, AppendError> {
        self.call_async(|r| Cmd::Append(Box::new(event), r))
            .await
            .unwrap_or(Err(AppendError::Unavailable))
    }

    /// Cheap, non-blocking view of the counters (no database access).
    pub fn snapshot(&self) -> SpoolSnapshot {
        let sh = &self.inner.shared;
        let c = sh.counters.lock().unwrap_or_else(|p| p.into_inner());
        let cap = sh.capacity.load(Ordering::Relaxed);
        let reserve = sh.reserve.load(Ordering::Relaxed);
        let now = (self.inner.clock)();
        let state = if sh.degraded.load(Ordering::Relaxed)
            || sh.dead.load(Ordering::SeqCst)
            || sh.gap_exhausted.load(Ordering::SeqCst)
        {
            SpoolState::Degraded
        } else if c.unsent_bytes >= cap.saturating_sub(reserve) {
            SpoolState::Full
        } else {
            SpoolState::Ok
        };
        SpoolSnapshot {
            state,
            unsent_events: c.unsent_events,
            unsent_bytes: c.unsent_bytes,
            gap_bytes: c.gap_bytes,
            retained_acked_bytes: c.acked_bytes,
            quarantined_bytes: c.quarantined_bytes,
            capacity_bytes: cap,
            gap_reserve_bytes: reserve,
            oldest_unsent_age_seconds: c.oldest_created.map(|t| (now - t).max(0) as u64),
            last_assigned_sequence: c.last_seq,
            quarantined_events: c.quarantined,
            retained_acked_events: c.acked,
            pending_gaps: c.pending_gaps,
            gap_reserve_exhausted: sh.gap_exhausted.load(Ordering::SeqCst),
        }
    }

    /// Expire old unsent events and purge old acknowledged rows now. The writer
    /// also does this every `maintenance_interval`.
    pub fn expire_now(&self) -> Result<ExpireReport, SpoolError> {
        self.call(Cmd::Expire)
            .unwrap_or(Err(SpoolError::Unavailable))
    }

    /// Record a gap (any kind) durably so it survives a crash until the status
    /// layer has taken it over.
    pub fn record_gap(&self, gap: GapReport) -> Result<(), SpoolError> {
        self.call(|r| Cmd::RecordGap(Box::new(gap), r))
            .unwrap_or(Err(SpoolError::Unavailable))
    }

    /// Gaps recorded by the spool and not yet handed off, oldest first.
    pub fn pending_gaps(&self) -> Result<Vec<GapReport>, SpoolError> {
        self.call(Cmd::PendingGaps)
            .unwrap_or(Err(SpoolError::Unavailable))
    }

    /// [`Spool::pending_gaps`] without blocking the async worker.
    pub async fn pending_gaps_async(&self) -> Result<Vec<GapReport>, SpoolError> {
        self.call_async(Cmd::PendingGaps)
            .await
            .unwrap_or(Err(SpoolError::Unavailable))
    }

    /// [`Spool::gaps_handed_off`] without blocking the async worker.
    pub async fn gaps_handed_off_async(&self, gap_ids: &[String]) -> Result<(), SpoolError> {
        let ids = gap_ids.to_vec();
        self.call_async(|r| Cmd::HandedOff(ids, r))
            .await
            .unwrap_or(Err(SpoolError::Unavailable))
    }

    /// The status layer persisted these gaps (by `gap_id`); remove them here.
    pub fn gaps_handed_off(&self, gap_ids: &[String]) -> Result<(), SpoolError> {
        self.call(|r| Cmd::HandedOff(gap_ids.to_vec(), r))
            .unwrap_or(Err(SpoolError::Unavailable))
    }

    /// The registry-conflict spool seam (README M2b, `registry_client::ConflictHandler`).
    ///
    /// For the quarantined entry `metadata_ref`: every `invocation.started` in the
    /// spool whose `tool` is `identified` with that ref DEPENDS on it. Those never
    /// centrally accepted (still unsent) get ONLY their `tool` field rewritten to
    /// `{"status":"metadata_unavailable","reason":"registry_conflict"}`; the original
    /// bytes are kept unchanged in the `rewrite_originals` table (never sent, never
    /// deleted here). Dependents already acknowledged are left alone. Returns the
    /// `event_id`s of ALL dependents, rewritten or not, oldest first. Idempotent: a
    /// second call finds nothing left to rewrite and returns the acknowledged ones.
    ///
    /// Blocks until committed and fsynced: call it from a blocking context.
    pub fn registry_conflict(&self, metadata_ref: &str) -> Result<Vec<String>, SpoolError> {
        self.call(|r| Cmd::RegistryConflict(metadata_ref.to_string(), r))
            .unwrap_or(Err(SpoolError::Unavailable))
    }

    /// Test knob: make every append fail as a storage error (ENOSPC-like).
    #[cfg(any(test, feature = "test-util"))]
    pub fn inject_storage_failure(&self, on: bool) {
        self.inner.shared.inject_failure.store(on, Ordering::SeqCst);
    }

    /// Test knob: change the capacity and gap reserve.
    #[cfg(any(test, feature = "test-util"))]
    pub fn set_capacity_for_test(&self, capacity: u64, reserve: u64) {
        self.inner.shared.capacity.store(capacity, Ordering::SeqCst);
        self.inner.shared.reserve.store(reserve, Ordering::SeqCst);
    }
}

#[cfg(any(test, feature = "test-util"))]
impl Spool {
    /// Test knob: move the spool's wall and boot clocks forward (retention and
    /// expiry follow them).
    pub fn advance_clock_for_test(&self, secs: i64) {
        self.inner
            .shared
            .clock_skew
            .fetch_add(secs, Ordering::SeqCst);
    }

    /// Stop the writer and wait for it (tests read the database file after).
    pub fn close_blocking_for_test(&self) {
        let _ = self.inner.tx.send(Cmd::Shutdown);
        if let Some(j) = self.inner.join.lock().ok().and_then(|mut g| g.take()) {
            let _ = j.join();
        }
    }

    /// Test knob: stop handing events to the ingest client (appends still work),
    /// so a test can observe the status report of a spool that is filling up.
    pub fn set_delivery_paused_for_test(&self, on: bool) {
        self.inner
            .shared
            .delivery_paused
            .store(on, Ordering::SeqCst);
    }

    /// TEST-ONLY event injector (feature `test-util`, or this crate's own tests;
    /// never compiled into a release build). Appends one valid
    /// `invocation.started` of this spool's proxy and epoch, with fresh ids.
    /// Production events come from the relay (T-13) through [`Admission`].
    pub async fn inject_test_event(&self, upstream_id: &str) -> Result<Appended, AppendError> {
        self.append_async(test_event(self, upstream_id)).await
    }

    /// [`Spool::inject_test_event`] from a blocking context.
    pub fn inject_test_event_blocking(&self, upstream_id: &str) -> Result<Appended, AppendError> {
        self.append(test_event(self, upstream_id))
    }
}

#[cfg(any(test, feature = "test-util"))]
fn test_event(spool: &Spool, upstream_id: &str) -> ProxyEvent {
    let now = crate::status_report::rfc3339(time::OffsetDateTime::now_utc());
    serde_json::from_value(serde_json::json!({
        "schema_version": 1,
        "event_id": uuid::Uuid::new_v4().hyphenated().to_string(),
        "proxy_id": spool.proxy_id(),
        "epoch_id": spool.epoch_id(),
        "sequence": 1,
        "occurred_at": now,
        "event_type": "invocation.started",
        "payload": {
            "invocation_id": uuid::Uuid::new_v4().hyphenated().to_string(),
            "upstream_id": upstream_id,
            "route_revision": 1,
            "protocol_version": "unknown",
            "method": "ping",
            "actor": {"actor_id": "actor-1", "actor_kind": "non_human",
                "authentication_method": "bearer",
                "evidence_source": "proxy_credential_mapping"}
        }
    }))
    .expect("test event is valid")
}

/// Why the spool refused an event. Nothing was stored in any case, and nothing is
/// dropped silently: the caller decides what the client sees (AC-12).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    /// Unsent bytes reached `capacity - gap_reserve`. The relay must refuse the
    /// call (fail closed); admission opens again as the ingest client drains.
    #[error("spool is full")]
    Full,
    /// The spool cannot record right now (disk full, storage failure, writer
    /// gone). Same handling as `Full` for the call, different operator signal.
    #[error("spool cannot record events")]
    Unavailable,
    /// The event itself is not admissible (too large, duplicate id, other proxy
    /// or epoch). A producer bug, not a capacity condition.
    #[error("event not admissible: {0}")]
    Invalid(AppendError),
}

/// The relay's way into the spool (T-13d calls [`Admission::append`]).
///
/// The returned future completes after the event is committed and fsynced, so
/// the caller may forward the call only after `Ok`. It never blocks a tokio
/// worker.
#[derive(Clone)]
pub struct Admission {
    spool: Spool,
}

impl Admission {
    pub fn new(spool: Spool) -> Admission {
        Admission { spool }
    }

    /// Append the event or refuse it with a typed [`Refusal`].
    pub async fn append(&self, event: ProxyEvent) -> Result<Appended, Refusal> {
        self.spool.append_async(event).await.map_err(|e| match e {
            AppendError::Full => Refusal::Full,
            AppendError::DiskFull | AppendError::Storage | AppendError::Unavailable => {
                Refusal::Unavailable
            }
            e @ (AppendError::TooLarge | AppendError::Duplicate | AppendError::WrongIdentity) => {
                Refusal::Invalid(e)
            }
        })
    }

    /// Cheap view for the status report and for early refusal.
    pub fn snapshot(&self) -> SpoolSnapshot {
        self.spool.snapshot()
    }
}

impl std::fmt::Debug for Spool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Spool").finish_non_exhaustive()
    }
}

impl EventSource for Spool {
    fn next_events(&mut self, max: usize, skip: &HashSet<String>) -> Vec<ProxyEvent> {
        self.call(|r| Cmd::Next(max, skip.clone(), r))
            .unwrap_or_default()
    }
    fn acknowledged(&mut self, event_ids: &[String]) {
        if let Some(Err(_)) = self.call(|r| Cmd::Ack(event_ids.to_vec(), r)) {
            // Stays unsent and is resent; the server deduplicates.
            self.inner.shared.degraded.store(true, Ordering::Relaxed);
        }
    }
    fn quarantined(&mut self, event_ids: &[String], code: QuarantineCode) {
        let c = quarantine_code_name(code);
        if let Some(Err(_)) = self.call(|r| Cmd::Quarantine(event_ids.to_vec(), c, r)) {
            self.inner.shared.degraded.store(true, Ordering::Relaxed);
        }
    }

    // The ingest loop runs on the tokio workers: the writer thread is reached
    // through a oneshot reply, so no worker waits on an fsync (M2).
    fn next_events_async<'a>(
        &'a mut self,
        max: usize,
        skip: &'a HashSet<String>,
    ) -> SourceFuture<'a, Vec<ProxyEvent>> {
        Box::pin(async move {
            self.call_async(|r| Cmd::Next(max, skip.clone(), r))
                .await
                .unwrap_or_default()
        })
    }
    fn acknowledged_async<'a>(&'a mut self, event_ids: &'a [String]) -> SourceFuture<'a, ()> {
        Box::pin(async move {
            if let Some(Err(_)) = self.call_async(|r| Cmd::Ack(event_ids.to_vec(), r)).await {
                // Stays unsent and is resent; the server deduplicates.
                self.inner.shared.degraded.store(true, Ordering::Relaxed);
            }
        })
    }
    fn quarantined_async<'a>(
        &'a mut self,
        event_ids: &'a [String],
        code: QuarantineCode,
    ) -> SourceFuture<'a, ()> {
        Box::pin(async move {
            let c = quarantine_code_name(code);
            if let Some(Err(_)) = self
                .call_async(|r| Cmd::Quarantine(event_ids.to_vec(), c, r))
                .await
            {
                self.inner.shared.degraded.store(true, Ordering::Relaxed);
            }
        })
    }
}

fn quarantine_code_name(code: QuarantineCode) -> String {
    serde_json::to_value(code)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| "conflict".to_string())
}

// --------------------------------------------------------------- writer thread

struct Writer {
    conn: Connection,
    cfg: SpoolConfig,
    shared: Arc<Shared>,
}

const ADDITIVE_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS rewrite_originals (
  event_id TEXT PRIMARY KEY,
  sequence INTEGER NOT NULL,
  metadata_ref TEXT NOT NULL,
  bytes BLOB NOT NULL,
  rewritten_at INTEGER NOT NULL
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_quarantine_at ON quarantine(quarantined_at);
CREATE INDEX IF NOT EXISTS idx_unsent_created ON events(created_at) WHERE state = 0;
CREATE TABLE IF NOT EXISTS event_boot_stamps (
  sequence INTEGER PRIMARY KEY,
  boot_id TEXT NOT NULL,
  boot_secs INTEGER NOT NULL
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_event_boot_stamps ON event_boot_stamps(boot_id, boot_secs);
CREATE TABLE IF NOT EXISTS quarantine_boot_stamps (
  sequence INTEGER PRIMARY KEY,
  boot_id TEXT NOT NULL,
  boot_secs INTEGER NOT NULL
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_quarantine_boot_stamps ON quarantine_boot_stamps(boot_id, boot_secs);
CREATE TRIGGER IF NOT EXISTS event_boot_stamps_on_delete AFTER DELETE ON events BEGIN
  DELETE FROM event_boot_stamps WHERE sequence = OLD.sequence;
END;
CREATE TRIGGER IF NOT EXISTS event_boot_stamps_on_ack AFTER UPDATE OF state ON events
WHEN NEW.state <> 0 BEGIN
  DELETE FROM event_boot_stamps WHERE sequence = NEW.sequence;
END;
CREATE TRIGGER IF NOT EXISTS quarantine_boot_stamps_on_delete AFTER DELETE ON quarantine BEGIN
  DELETE FROM quarantine_boot_stamps WHERE sequence = OLD.sequence;
END;
";

/// Unsent events past R on the boot clock, oldest first. `CROSS JOIN` keeps the
/// stamp index as the outer loop.
const DUE_BY_BOOT: &str = "SELECT s.sequence, e.event_id FROM event_boot_stamps s \
     CROSS JOIN events e ON e.sequence = s.sequence \
     WHERE s.boot_id = ?1 AND s.boot_secs <= ?2 AND e.state = 0 \
     ORDER BY s.boot_secs LIMIT ?3";

/// Unsent events past R on the wall clock, without a stamp of the current boot.
const DUE_BY_WALL: &str = "SELECT e.sequence, e.event_id FROM events e \
     WHERE e.state = 0 AND e.created_at <= ?1 AND NOT EXISTS \
     (SELECT 1 FROM event_boot_stamps s WHERE s.sequence = e.sequence AND s.boot_id = ?2) \
     ORDER BY e.created_at LIMIT ?3";

/// The Q purge, one batch of the oldest rows past Q on the boot clock.
const PURGE_QUARANTINE_BY_BOOT: &str = "DELETE FROM quarantine WHERE sequence IN \
     (SELECT sequence FROM quarantine_boot_stamps WHERE boot_id = ?1 AND boot_secs < ?2 \
     ORDER BY boot_secs LIMIT ?3) RETURNING size, code = ?4";

/// The Q purge, one batch of the oldest rows past Q on the wall clock, without a
/// stamp of the current boot. Ordered by `quarantined_at` so it walks
/// `idx_quarantine_at` instead of scanning the table inside the write transaction.
const PURGE_QUARANTINE_BY_WALL: &str = "DELETE FROM quarantine WHERE sequence IN \
     (SELECT q.sequence FROM quarantine q WHERE q.quarantined_at < ?1 AND NOT EXISTS \
     (SELECT 1 FROM quarantine_boot_stamps s WHERE s.sequence = q.sequence AND s.boot_id = ?2) \
     ORDER BY q.quarantined_at LIMIT ?3) RETURNING size, code = ?4";

const SCHEMA: &str = "
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID;
CREATE TABLE seq (id INTEGER PRIMARY KEY CHECK (id = 1), last INTEGER NOT NULL);
CREATE TABLE events (
  sequence INTEGER PRIMARY KEY,
  event_id TEXT NOT NULL UNIQUE,
  bytes BLOB NOT NULL,
  size INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  state INTEGER NOT NULL,
  acked_at INTEGER
);
CREATE INDEX idx_unsent ON events(sequence) WHERE state = 0;
CREATE TABLE quarantine (
  sequence INTEGER PRIMARY KEY,
  event_id TEXT NOT NULL UNIQUE,
  bytes BLOB NOT NULL,
  size INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  quarantined_at INTEGER NOT NULL,
  code TEXT NOT NULL
);
CREATE TABLE gaps (
  rowid_ INTEGER PRIMARY KEY AUTOINCREMENT,
  gap_id TEXT NOT NULL UNIQUE,
  body TEXT NOT NULL,
  size INTEGER NOT NULL
);
";

impl Writer {
    fn open(cfg: SpoolConfig, shared: Arc<Shared>) -> Result<Writer, SpoolError> {
        // NOFOLLOW below refuses a symlink in any component, so resolve the
        // directory first; only the spool file itself must not be a link.
        let dir = cfg
            .dir
            .canonicalize()
            .map_err(|_| SpoolError::Storage("stat".into()))?;
        let path = dir.join(SPOOL_FILE);
        match std::fs::symlink_metadata(&path) {
            Ok(md) if !md.is_file() => return Err(SpoolError::BadPath),
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if !cfg.new_epoch {
                    return Err(SpoolError::Missing);
                }
                create_private(&path)?
            }
            Err(_) => return Err(SpoolError::Storage("stat".into())),
        }
        // NOFOLLOW closes the window between the check above and the open.
        let conn = Connection::open_with_flags(
            &path,
            OpenFlags::default() | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|e| classify_open(&e))?;
        // Read-only probe first: an empty file in an existing epoch must stay
        // untouched (the pragmas below would write a header into it).
        let tables: i64 = conn
            .query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get(0))
            .map_err(|e| classify_open(&e))?;
        if tables == 0 && !cfg.new_epoch {
            return Err(SpoolError::Missing);
        }
        let mode: String = conn
            .query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))
            .map_err(|e| classify_open(&e))?;
        if !mode.eq_ignore_ascii_case("wal") {
            return Err(SpoolError::Storage("wal_unavailable".into()));
        }
        conn.execute_batch("PRAGMA synchronous=FULL;")
            .map_err(|e| classify_open(&e))?;
        let level: i64 = conn
            .query_row("PRAGMA synchronous", [], |r| r.get(0))
            .map_err(|e| classify_open(&e))?;
        if level != 2 {
            return Err(SpoolError::Storage("synchronous".into()));
        }
        let quick: String = conn
            .query_row("PRAGMA quick_check", [], |r| r.get(0))
            .map_err(|e| classify_open(&e))?;
        if quick != "ok" {
            return Err(SpoolError::Corrupt);
        }
        let mut w = Writer { conn, cfg, shared };
        if tables == 0 {
            w.init_schema().map_err(|e| classify_open(&e))?;
        } else {
            w.verify_schema()?;
        }
        // Additive tables: the unchanged bytes of events whose `tool` was
        // rewritten after a registry conflict (T-13c), the boot stamps, and the
        // indexes maintenance uses. Created in place for databases written before
        // they existed (same schema version).
        w.conn
            .execute_batch(ADDITIVE_SCHEMA)
            .map_err(|e| classify_open(&e))?;
        w.load_counters().map_err(|e| classify_open(&e))?;
        Ok(w)
    }

    fn init_schema(&mut self) -> rusqlite::Result<()> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch(SCHEMA)?;
        tx.execute(
            "INSERT INTO meta(key, value) VALUES ('schema_version', ?1), ('proxy_id', ?2), ('epoch_id', ?3)",
            params![SCHEMA_VERSION.to_string(), self.cfg.proxy_id, self.cfg.epoch_id],
        )?;
        tx.execute("INSERT INTO seq(id, last) VALUES (1, 0)", [])?;
        tx.commit()
    }

    fn verify_schema(&self) -> Result<(), SpoolError> {
        let get = |k: &str| -> Result<Option<String>, SpoolError> {
            self.conn
                .query_row("SELECT value FROM meta WHERE key = ?1", [k], |r| r.get(0))
                .optional()
                .map_err(|_| SpoolError::Corrupt)
        };
        let version = get("schema_version")?.ok_or(SpoolError::Corrupt)?;
        if version.parse::<i64>().ok() != Some(SCHEMA_VERSION) {
            return Err(SpoolError::UnsupportedSchema);
        }
        if get("proxy_id")?.as_deref() != Some(self.cfg.proxy_id.as_str())
            || get("epoch_id")?.as_deref() != Some(self.cfg.epoch_id.as_str())
        {
            return Err(SpoolError::Foreign);
        }
        for t in ["seq", "events", "quarantine", "gaps"] {
            self.conn
                .query_row(&format!("SELECT count(*) FROM {t}"), [], |r| {
                    r.get::<_, i64>(0)
                })
                .map_err(|_| SpoolError::Corrupt)?;
        }
        Ok(())
    }

    fn load_counters(&self) -> rusqlite::Result<()> {
        let c = &self.conn;
        let (n, b): (i64, i64) = c.query_row(
            "SELECT count(*), coalesce(sum(size), 0) FROM events WHERE state = 0",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let (acked, acked_bytes): (i64, i64) = c.query_row(
            "SELECT count(*), coalesce(sum(size), 0) FROM events WHERE state = 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let (quarantined, quarantined_bytes): (i64, i64) = c.query_row(
            "SELECT coalesce(sum(code <> 'registry_conflict_original'), 0), \
             coalesce(sum(size), 0) FROM quarantine",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let (gn, gb): (i64, i64) = c.query_row(
            "SELECT count(*), coalesce(sum(size), 0) FROM gaps",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let last: i64 = c.query_row("SELECT last FROM seq WHERE id = 1", [], |r| r.get(0))?;
        let oldest = self.oldest_unsent()?;
        let mut k = self
            .shared
            .counters
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        *k = Counters {
            unsent_events: n as u64,
            unsent_bytes: b as u64,
            gap_bytes: gb as u64,
            oldest_created: oldest,
            last_seq: last,
            quarantined: quarantined as u64,
            quarantined_bytes: quarantined_bytes as u64,
            acked: acked as u64,
            acked_bytes: acked_bytes as u64,
            pending_gaps: gn as u64,
        };
        Ok(())
    }

    fn oldest_unsent(&self) -> rusqlite::Result<Option<i64>> {
        self.conn
            .query_row(
                "SELECT created_at FROM events WHERE state = 0 ORDER BY sequence LIMIT 1",
                [],
                |r| r.get(0),
            )
            .optional()
    }

    fn set_degraded(&self, on: bool) {
        self.shared.degraded.store(on, Ordering::Relaxed);
    }

    fn run(&mut self, rx: mpsc::Receiver<Cmd>) {
        // Maintenance is driven by a deadline, not by idleness: a steady stream of
        // commands (the ingest loop polls about once a second) must not starve it.
        // It also runs once at start.
        let mut next_maintenance = std::time::Instant::now();
        loop {
            let now = std::time::Instant::now();
            if now >= next_maintenance {
                next_maintenance = now + self.cfg.maintenance_interval;
                match self.expire_batch() {
                    // More expired or purgeable rows remain: come back at once,
                    // after any commands already queued.
                    Ok((_, true)) => next_maintenance = now,
                    Ok(_) => {}
                    // Sticky signal set where it happened; not a storage fault.
                    Err(SpoolError::GapReserveExceeded) => {}
                    Err(_) => self.set_degraded(true),
                }
            }
            let wait = next_maintenance.saturating_duration_since(std::time::Instant::now());
            let cmd = match rx.recv_timeout(wait) {
                Ok(c) => c,
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => return,
            };
            match cmd {
                Cmd::Append(ev, r) => r.send(self.append(*ev)),
                Cmd::Next(max, skip, r) => {
                    #[cfg(any(test, feature = "test-util"))]
                    if self.shared.delivery_paused.load(Ordering::SeqCst) {
                        r.send(Vec::new());
                        continue;
                    }
                    r.send(self.next(max, &skip))
                }
                Cmd::Ack(ids, r) => r.send(self.ack(&ids).inspect_err(|_| self.set_degraded(true))),
                Cmd::Quarantine(ids, code, r) => r.send(
                    self.quarantine(&ids, &code)
                        .inspect_err(|_| self.set_degraded(true)),
                ),
                Cmd::Expire(r) => r.send(self.expire()),
                Cmd::RecordGap(g, r) => r.send(self.record_gap(&g)),
                Cmd::PendingGaps(r) => r.send(self.pending_gaps()),
                Cmd::HandedOff(ids, r) => r.send(self.handed_off(&ids)),
                Cmd::RegistryConflict(r_, r) => r.send(self.registry_conflict(&r_)),
                Cmd::Shutdown => return,
            }
        }
    }

    fn counters(&self) -> std::sync::MutexGuard<'_, Counters> {
        self.shared
            .counters
            .lock()
            .unwrap_or_else(|p| p.into_inner())
    }

    fn append(&mut self, mut event: ProxyEvent) -> Result<Appended, AppendError> {
        if event.proxy_id.as_str() != self.cfg.proxy_id
            || event.epoch_id.as_str() != self.cfg.epoch_id
        {
            return Err(AppendError::WrongIdentity);
        }
        #[cfg(any(test, feature = "test-util"))]
        if self.shared.inject_failure.load(Ordering::SeqCst) {
            self.set_degraded(true);
            return Err(AppendError::DiskFull);
        }
        let cap = self.shared.capacity.load(Ordering::Relaxed);
        let reserve = self.shared.reserve.load(Ordering::Relaxed);
        let limit = cap.saturating_sub(reserve);
        let now = (self.cfg.clock)();
        let boot = (self.cfg.boot_clock)();
        let mut res = self.append_tx(&mut event, now, boot.as_ref(), limit);
        if matches!(res, Err(AppendTx::PurgeAcked)) {
            // Over capacity only because acknowledged rows are still retained:
            // the server holds them, so drop them before refusing the call.
            res = match self.purge_all_acked() {
                Ok(()) => self.append_tx(&mut event, now, boot.as_ref(), limit),
                Err(_) => Err(AppendTx::Refused(AppendError::Storage)),
            };
        }
        let res = res.map_err(|e| match e {
            AppendTx::Refused(e) => e,
            AppendTx::PurgeAcked => AppendError::Full,
        });
        match res {
            Ok((seq, size)) => {
                let mut k = self.counters();
                k.unsent_events += 1;
                k.unsent_bytes += size;
                k.last_seq = seq;
                k.oldest_created.get_or_insert(now);
                drop(k);
                self.set_degraded(false);
                Ok(Appended { sequence: seq })
            }
            Err(e) => {
                if matches!(e, AppendError::DiskFull | AppendError::Storage) {
                    self.set_degraded(true);
                }
                Err(e)
            }
        }
    }

    /// One append transaction. Counters change only after commit, by the caller.
    fn append_tx(
        &mut self,
        event: &mut ProxyEvent,
        now: i64,
        boot: Option<&BootInstant>,
        limit: u64,
    ) -> Result<(i64, u64), AppendTx> {
        let (unsent_bytes, acked_bytes) = {
            let k = self.counters();
            (k.unsent_bytes, k.acked_bytes)
        };
        let st = |e: rusqlite::Error| AppendTx::Refused(append_storage(&e));
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(st)?;
        let dup: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM events WHERE event_id = ?1) \
                 OR EXISTS(SELECT 1 FROM quarantine WHERE event_id = ?1)",
                [event.event_id.as_str()],
                |r| r.get(0),
            )
            .map_err(st)?;
        if dup {
            return Err(AppendTx::Refused(AppendError::Duplicate));
        }
        let last: i64 = tx
            .query_row("SELECT last FROM seq WHERE id = 1", [], |r| r.get(0))
            .map_err(st)?;
        let seq = last
            .checked_add(1)
            .ok_or(AppendTx::Refused(AppendError::Storage))?;
        event.sequence =
            PositiveI64::new(seq).map_err(|_| AppendTx::Refused(AppendError::Storage))?;
        let bytes =
            serde_json::to_vec(&*event).map_err(|_| AppendTx::Refused(AppendError::Storage))?;
        let size = bytes.len() as u64;
        if size > self.cfg.event_max_bytes {
            return Err(AppendTx::Refused(AppendError::TooLarge));
        }
        if unsent_bytes.saturating_add(size) > limit {
            return Err(AppendTx::Refused(AppendError::Full));
        }
        if unsent_bytes
            .saturating_add(acked_bytes)
            .saturating_add(size)
            > limit
        {
            return Err(AppendTx::PurgeAcked);
        }
        tx.execute(
            "INSERT INTO events(sequence, event_id, bytes, size, created_at, state) \
             VALUES (?1, ?2, ?3, ?4, ?5, 0)",
            params![seq, event.event_id.as_str(), bytes, size as i64, now],
        )
        .map_err(st)?;
        stamp_row(&tx, STAMP_EVENT, seq, boot).map_err(st)?;
        tx.execute("UPDATE seq SET last = ?1 WHERE id = 1", [seq])
            .map_err(st)?;
        tx.commit().map_err(st)?;
        Ok((seq, size))
    }

    /// Delete every acknowledged row (the server holds them).
    fn purge_all_acked(&mut self) -> Result<(), SpoolError> {
        let st = |e: rusqlite::Error| SpoolError::Storage(code_name(&e));
        let now = (self.cfg.clock)();
        let boot = (self.cfg.boot_clock)();
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(st)?;
        let ids: Vec<String> = {
            let mut q = tx
                .prepare("SELECT event_id FROM events WHERE state = 1")
                .map_err(st)?;
            let mapped = q.query_map([], |r| r.get(0)).map_err(st)?;
            mapped.collect::<Result<_, _>>().map_err(st)?
        };
        let mut archived = 0u64;
        for id in &ids {
            archived += archive_original(&tx, id, now, boot.as_ref()).map_err(st)?;
        }
        tx.execute("DELETE FROM events WHERE state = 1", [])
            .map_err(st)?;
        tx.commit().map_err(st)?;
        let mut k = self.counters();
        k.acked = 0;
        k.acked_bytes = 0;
        k.quarantined_bytes += archived;
        Ok(())
    }

    fn next(&mut self, max: usize, skip: &HashSet<String>) -> Vec<ProxyEvent> {
        let mut out = Vec::new();
        if max == 0 {
            return out;
        }
        let mut stmt = match self
            .conn
            .prepare_cached("SELECT event_id, bytes FROM events WHERE state = 0 ORDER BY sequence")
        {
            Ok(s) => s,
            Err(_) => {
                self.set_degraded(true);
                return out;
            }
        };
        let rows = stmt.query_map([], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
        });
        let Ok(rows) = rows else {
            self.set_degraded(true);
            return out;
        };
        for row in rows {
            let Ok((id, bytes)) = row else {
                self.set_degraded(true);
                break;
            };
            if skip.contains(&id) {
                continue;
            }
            match lodeline_proxy_api::parse::parse_event(&bytes) {
                Ok(ev) => out.push(ev),
                // A stored row that no longer parses is never sent and never
                // deleted; the spool reports degraded.
                Err(_) => self.shared.degraded.store(true, Ordering::Relaxed),
            }
            if out.len() >= max {
                break;
            }
        }
        out
    }

    fn ack(&mut self, ids: &[String]) -> Result<u64, SpoolError> {
        let now = (self.cfg.clock)();
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| SpoolError::Storage(code_name(&e)))?;
        let (mut n, mut bytes) = (0u64, 0u64);
        {
            let mut st = tx
                .prepare(
                    "UPDATE events SET state = 1, acked_at = ?2 \
                     WHERE event_id = ?1 AND state = 0 RETURNING size",
                )
                .map_err(|e| SpoolError::Storage(code_name(&e)))?;
            for id in ids {
                let size: Option<i64> = st
                    .query_row(params![id, now], |r| r.get(0))
                    .optional()
                    .map_err(|e| SpoolError::Storage(code_name(&e)))?;
                if let Some(s) = size {
                    n += 1;
                    bytes += s as u64;
                }
            }
        }
        tx.commit()
            .map_err(|e| SpoolError::Storage(code_name(&e)))?;
        let oldest = self.oldest_unsent().ok().flatten();
        let mut k = self.counters();
        k.unsent_events = k.unsent_events.saturating_sub(n);
        k.unsent_bytes = k.unsent_bytes.saturating_sub(bytes);
        k.acked += n;
        k.acked_bytes += bytes;
        k.oldest_created = oldest;
        Ok(n)
    }

    /// Move unsent rows to `quarantine` unchanged, inside the caller's decision.
    fn quarantine(&mut self, ids: &[String], code: &str) -> Result<u64, SpoolError> {
        let now = (self.cfg.clock)();
        let boot = (self.cfg.boot_clock)();
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| SpoolError::Storage(code_name(&e)))?;
        let mut moved = Vec::new();
        for id in ids {
            if let Some(sizes) = move_to_quarantine(&tx, id, code, now, boot.as_ref())? {
                moved.push(sizes);
            }
        }
        tx.commit()
            .map_err(|e| SpoolError::Storage(code_name(&e)))?;
        let oldest = self.oldest_unsent().ok().flatten();
        let n = moved.len() as u64;
        let unsent_bytes: u64 = moved.iter().map(|(u, _)| u).sum();
        let quarantined_bytes: u64 = moved.iter().map(|(_, q)| q).sum();
        let mut k = self.counters();
        k.unsent_events = k.unsent_events.saturating_sub(n);
        k.unsent_bytes = k.unsent_bytes.saturating_sub(unsent_bytes);
        k.quarantined += n;
        k.quarantined_bytes += quarantined_bytes;
        k.oldest_created = oldest;
        Ok(n)
    }

    /// See [`Spool::registry_conflict`].
    fn registry_conflict(&mut self, metadata_ref: &str) -> Result<Vec<String>, SpoolError> {
        use lodeline_proxy_api::event::{
            EventPayload, MetadataUnavailableReason, Tool, ToolMetadataUnavailable,
        };
        let st = |e: rusqlite::Error| SpoolError::Storage(code_name(&e));
        let now = (self.cfg.clock)();
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(st)?;
        // Candidate rows: the ref is a token, so a bytewise search finds every
        // event that mentions it; the parse below decides which really depend.
        let rows: Vec<(i64, String, Vec<u8>, i64, i64)> = {
            let mut q = tx
                .prepare(
                    "SELECT sequence, event_id, bytes, size, state FROM events \
                     WHERE state IN (0, 1) AND instr(bytes, ?1) > 0 ORDER BY sequence",
                )
                .map_err(st)?;
            let mapped = q
                .query_map([metadata_ref.as_bytes()], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
                })
                .map_err(st)?;
            mapped.collect::<Result<_, _>>().map_err(st)?
        };
        // Events rewritten by an earlier call (or before a crash) still depend on
        // the entry: the central gap must name them too.
        let mut dependents: Vec<(i64, String)> = {
            let mut q = tx
                .prepare("SELECT sequence, event_id FROM rewrite_originals WHERE metadata_ref = ?1")
                .map_err(st)?;
            let mapped = q
                .query_map([metadata_ref], |r| Ok((r.get(0)?, r.get(1)?)))
                .map_err(st)?;
            mapped.collect::<Result<_, _>>().map_err(st)?
        };
        let (mut removed, mut added) = (0u64, 0u64);
        for (sequence, event_id, bytes, size, state) in rows {
            let Ok(mut ev) = lodeline_proxy_api::parse::parse_event(&bytes) else {
                continue;
            };
            let depends = matches!(
                &ev.payload,
                EventPayload::Started(s)
                    if matches!(&s.tool, Some(Tool::Identified(t)) if t.metadata_ref.as_str() == metadata_ref)
            );
            if !depends {
                continue;
            }
            dependents.push((sequence, event_id.clone()));
            if state != 0 {
                continue; // centrally accepted already: never rewritten
            }
            if let EventPayload::Started(s) = &mut ev.payload {
                s.tool = Some(Tool::MetadataUnavailable(ToolMetadataUnavailable {
                    reason: MetadataUnavailableReason::RegistryConflict,
                }));
            }
            let new_bytes = serde_json::to_vec(&ev).map_err(|_| SpoolError::Corrupt)?;
            tx.execute(
                "INSERT OR IGNORE INTO rewrite_originals(event_id, sequence, metadata_ref, bytes, rewritten_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![event_id, sequence, metadata_ref, bytes, now],
            )
            .map_err(st)?;
            tx.execute(
                "UPDATE events SET bytes = ?2, size = ?3 WHERE sequence = ?1 AND state = 0",
                params![sequence, new_bytes, new_bytes.len() as i64],
            )
            .map_err(st)?;
            removed += size as u64;
            added += new_bytes.len() as u64;
        }
        tx.commit().map_err(st)?;
        let mut k = self.counters();
        k.unsent_bytes = k.unsent_bytes.saturating_sub(removed).saturating_add(added);
        dependents.sort();
        dependents.dedup();
        Ok(dependents.into_iter().map(|(_, id)| id).collect())
    }

    /// Expire and purge until nothing is left to do (batched; see
    /// [`MAINTENANCE_BATCH`]).
    fn expire(&mut self) -> Result<ExpireReport, SpoolError> {
        let mut total = ExpireReport::default();
        loop {
            let (r, more) = self.expire_batch()?;
            total.expired_events += r.expired_events;
            total.gaps_recorded += r.gaps_recorded;
            total.purged_acked += r.purged_acked;
            total.purged_quarantined += r.purged_quarantined;
            if !more {
                return Ok(total);
            }
        }
    }

    /// One bounded maintenance transaction. The flag says more work remains.
    fn expire_batch(&mut self) -> Result<(ExpireReport, bool), SpoolError> {
        let st = |e: rusqlite::Error| SpoolError::Storage(code_name(&e));
        let now = (self.cfg.clock)();
        let boot = (self.cfg.boot_clock)();
        let boot_id = boot.as_ref().map(|b| &*b.boot_id);
        let retry_age = self.shared.retry_age_secs.load(Ordering::SeqCst);
        let retry_age = i64::try_from(retry_age).unwrap_or(i64::MAX);
        let cutoff = now.saturating_sub(retry_age);
        let ack_cutoff = now - self.cfg.ack_retention.as_secs() as i64;
        let reserve = self.shared.reserve.load(Ordering::Relaxed);
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(st)?;
        let mut expired: Vec<(i64, String)> = Vec::new();
        if let Some(b) = &boot {
            let mut q = tx.prepare(DUE_BY_BOOT).map_err(st)?;
            let boot_cutoff = b.secs.saturating_sub(retry_age);
            let rows = q
                .query_map(params![b.boot_id, boot_cutoff, MAINTENANCE_BATCH], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })
                .map_err(st)?;
            expired = rows.collect::<Result<_, _>>().map_err(st)?;
        }
        {
            let mut q = tx.prepare(DUE_BY_WALL).map_err(st)?;
            let left = MAINTENANCE_BATCH - expired.len() as i64;
            let rows = q
                .query_map(params![cutoff, boot_id, left], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })
                .map_err(st)?;
            for row in rows {
                expired.push(row.map_err(st)?);
            }
        }
        expired.sort();
        let mut report = ExpireReport::default();
        let (mut bytes, mut expired_q_bytes) = (0u64, 0u64);
        // Contiguous sequence runs: (from, to, count).
        let mut runs: Vec<(i64, i64, i64)> = Vec::new();
        for (seq, id) in &expired {
            if let Some((unsent, quarantined)) =
                move_to_quarantine(&tx, id, EXPIRED_CODE, now, boot.as_ref())?
            {
                bytes += unsent;
                expired_q_bytes += quarantined;
                report.expired_events += 1;
                match runs.last_mut() {
                    Some((_, to, n)) if *to + 1 == *seq => {
                        *to = *seq;
                        *n += 1;
                    }
                    _ => runs.push((*seq, *seq, 1)),
                }
            }
        }
        let mut gap_bytes = 0u64;
        // A gap that does not fit the reserve aborts the pass: the events stay
        // unsent rather than expiring without a record.
        let mut room = reserve.saturating_sub(shared_gap_bytes(&self.shared));
        for (from, to, count) in &runs {
            let gap = spool_expired_gap(&self.cfg.epoch_id, now, *from, *to, *count)
                .ok_or_else(|| SpoolError::Storage("gap".into()))?;
            let added = insert_gap(&tx, &gap, room).inspect_err(|e| {
                if matches!(e, SpoolError::GapReserveExceeded) {
                    self.shared.gap_exhausted.store(true, Ordering::SeqCst);
                }
            })?;
            room = room.saturating_sub(added);
            gap_bytes += added;
            report.gaps_recorded += 1;
        }
        let mut purged_bytes = 0u64;
        let mut archived = 0u64;
        {
            let due: Vec<(i64, String)> = {
                let mut q = tx
                    .prepare(
                        "SELECT sequence, event_id FROM events \
                         WHERE state = 1 AND acked_at <= ?1 ORDER BY sequence LIMIT ?2",
                    )
                    .map_err(st)?;
                let mapped = q
                    .query_map(params![ack_cutoff, MAINTENANCE_BATCH], |r| {
                        Ok((r.get(0)?, r.get(1)?))
                    })
                    .map_err(st)?;
                mapped.collect::<Result<_, _>>().map_err(st)?
            };
            for (seq, id) in due {
                // The pre-rewrite bytes outlive the purged acknowledged row.
                archived += archive_original(&tx, &id, now, boot.as_ref()).map_err(st)?;
                let sz: i64 = tx
                    .query_row(
                        "DELETE FROM events WHERE sequence = ?1 RETURNING size",
                        [seq],
                        |r| r.get(0),
                    )
                    .map_err(st)?;
                purged_bytes += sz as u64;
                report.purged_acked += 1;
            }
        }
        let q_secs = self.shared.quarantine_retention_secs.load(Ordering::SeqCst);
        let (mut purged_q_bytes, mut purged_originals) = (0u64, 0u64);
        if q_secs > 0 {
            let q_age = i64::try_from(q_secs).unwrap_or(i64::MAX);
            let q_cutoff = now.saturating_sub(q_age);
            let mut purged = Vec::new();
            if let Some(b) = &boot {
                let mut q = tx.prepare(PURGE_QUARANTINE_BY_BOOT).map_err(st)?;
                let boot_cutoff = b.secs.saturating_sub(q_age);
                let rows = q
                    .query_map(
                        params![b.boot_id, boot_cutoff, MAINTENANCE_BATCH, ORIGINAL_CODE],
                        |r| Ok((r.get::<_, i64>(0)?, r.get::<_, bool>(1)?)),
                    )
                    .map_err(st)?;
                purged = rows.collect::<Result<_, _>>().map_err(st)?;
            }
            {
                let mut q = tx.prepare(PURGE_QUARANTINE_BY_WALL).map_err(st)?;
                let left = MAINTENANCE_BATCH - purged.len() as i64;
                let rows = q
                    .query_map(params![q_cutoff, boot_id, left, ORIGINAL_CODE], |r| {
                        Ok((r.get::<_, i64>(0)?, r.get::<_, bool>(1)?))
                    })
                    .map_err(st)?;
                for row in rows {
                    purged.push(row.map_err(st)?);
                }
            }
            for (size, original) in purged {
                purged_q_bytes += size as u64;
                purged_originals += u64::from(original);
                report.purged_quarantined += 1;
            }
        }
        tx.commit().map_err(st)?;
        if report.purged_quarantined > 0 {
            tracing::info!(
                count = report.purged_quarantined,
                "quarantined rows purged after retention"
            );
        }
        if report.gaps_recorded > 0 && gap_bytes > 0 {
            self.shared.gap_exhausted.store(false, Ordering::SeqCst);
        }
        let more = report.expired_events >= MAINTENANCE_BATCH as u64
            || report.purged_acked >= MAINTENANCE_BATCH as u64
            || report.purged_quarantined >= MAINTENANCE_BATCH as u64;
        let oldest = self.oldest_unsent().ok().flatten();
        let mut k = self.counters();
        k.unsent_events = k.unsent_events.saturating_sub(report.expired_events);
        k.unsent_bytes = k.unsent_bytes.saturating_sub(bytes);
        k.quarantined = (k.quarantined + report.expired_events)
            .saturating_sub(report.purged_quarantined - purged_originals);
        k.quarantined_bytes =
            (k.quarantined_bytes + expired_q_bytes + archived).saturating_sub(purged_q_bytes);
        k.acked = k.acked.saturating_sub(report.purged_acked);
        k.acked_bytes = k.acked_bytes.saturating_sub(purged_bytes);
        k.gap_bytes += gap_bytes;
        k.pending_gaps += report.gaps_recorded;
        k.oldest_created = oldest;
        Ok((report, more))
    }

    fn record_gap(&mut self, gap: &GapReport) -> Result<(), SpoolError> {
        let st = |e: rusqlite::Error| SpoolError::Storage(code_name(&e));
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(st)?;
        let reserve = self.shared.reserve.load(Ordering::Relaxed);
        let room = reserve.saturating_sub(shared_gap_bytes(&self.shared));
        let size = match insert_gap(&tx, gap, room) {
            Ok(n) => n,
            Err(e) => {
                if matches!(e, SpoolError::GapReserveExceeded) {
                    self.shared.gap_exhausted.store(true, Ordering::SeqCst);
                }
                return Err(e);
            }
        };
        tx.commit().map_err(st)?;
        let mut k = self.counters();
        k.gap_bytes += size;
        if size > 0 {
            k.pending_gaps += 1;
            self.shared.gap_exhausted.store(false, Ordering::SeqCst);
        }
        Ok(())
    }

    fn pending_gaps(&mut self) -> Result<Vec<GapReport>, SpoolError> {
        let st = |e: rusqlite::Error| SpoolError::Storage(code_name(&e));
        let mut q = self
            .conn
            .prepare("SELECT body FROM gaps ORDER BY rowid_")
            .map_err(st)?;
        let rows = q.query_map([], |r| r.get::<_, String>(0)).map_err(st)?;
        let mut out = Vec::new();
        for body in rows {
            let body = body.map_err(st)?;
            out.push(serde_json::from_str(&body).map_err(|_| SpoolError::Corrupt)?);
        }
        Ok(out)
    }

    fn handed_off(&mut self, ids: &[String]) -> Result<(), SpoolError> {
        let st = |e: rusqlite::Error| SpoolError::Storage(code_name(&e));
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(st)?;
        let (mut n, mut bytes) = (0u64, 0u64);
        {
            let mut d = tx
                .prepare("DELETE FROM gaps WHERE gap_id = ?1 RETURNING size")
                .map_err(st)?;
            for id in ids {
                if let Some(s) = d
                    .query_row([id], |r| r.get::<_, i64>(0))
                    .optional()
                    .map_err(st)?
                {
                    n += 1;
                    bytes += s as u64;
                }
            }
        }
        tx.commit().map_err(st)?;
        let mut k = self.counters();
        k.pending_gaps = k.pending_gaps.saturating_sub(n);
        k.gap_bytes = k.gap_bytes.saturating_sub(bytes);
        if n > 0 {
            // Room came back; the next maintenance pass or gap sets it again if
            // that was not enough.
            self.shared.gap_exhausted.store(false, Ordering::SeqCst);
        }
        Ok(())
    }
}

fn shared_gap_bytes(sh: &Shared) -> u64 {
    sh.counters
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .gap_bytes
}

enum AppendTx {
    Refused(AppendError),
    /// Fits only after the retained acknowledged rows are purged.
    PurgeAcked,
}

fn append_storage(e: &rusqlite::Error) -> AppendError {
    if is_disk_full(e) {
        AppendError::DiskFull
    } else {
        AppendError::Storage
    }
}

const STAMP_EVENT: &str =
    "INSERT INTO event_boot_stamps(sequence, boot_id, boot_secs) VALUES (?1, ?2, ?3)";
const STAMP_QUARANTINE: &str =
    "INSERT INTO quarantine_boot_stamps(sequence, boot_id, boot_secs) VALUES (?1, ?2, ?3)";

/// Stamp a row written in the caller's transaction. Without a boot clock the row
/// stays unstamped and ages on the wall clock.
fn stamp_row(
    tx: &rusqlite::Transaction<'_>,
    insert: &str,
    sequence: i64,
    boot: Option<&BootInstant>,
) -> rusqlite::Result<()> {
    if let Some(b) = boot {
        tx.execute(insert, params![sequence, b.boot_id, b.secs])?;
    }
    Ok(())
}

/// Copy one unsent row to `quarantine` and delete it. Returns
/// `(unsent_size, quarantined_size)`, which differ for a rewritten event, or
/// `None` when the id is not an unsent row.
fn move_to_quarantine(
    tx: &rusqlite::Transaction<'_>,
    id: &str,
    code: &str,
    now: i64,
    boot: Option<&BootInstant>,
) -> Result<Option<(u64, u64)>, SpoolError> {
    let st = |e: rusqlite::Error| SpoolError::Storage(code_name(&e));
    let row: Option<(i64, i64)> = tx
        .query_row(
            "SELECT sequence, size FROM events WHERE event_id = ?1 AND state = 0",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(st)?;
    let Some((sequence, size)) = row else {
        return Ok(None);
    };
    // An event whose `tool` was rewritten goes to quarantine with its ORIGINAL
    // bytes (README M2b / N11): the rewritten form is derived and is not evidence.
    let moved = tx
        .execute(
            "INSERT INTO quarantine(sequence, event_id, bytes, size, created_at, quarantined_at, code) \
             SELECT e.sequence, e.event_id, o.bytes, length(o.bytes), e.created_at, ?2, ?3 \
             FROM events e JOIN rewrite_originals o ON o.event_id = e.event_id \
             WHERE e.event_id = ?1 AND e.state = 0",
            params![id, now, code],
        )
        .map_err(st)?;
    if moved == 0 {
        tx.execute(
            "INSERT INTO quarantine(sequence, event_id, bytes, size, created_at, quarantined_at, code) \
             SELECT sequence, event_id, bytes, size, created_at, ?2, ?3 FROM events \
             WHERE event_id = ?1 AND state = 0",
            params![id, now, code],
        )
        .map_err(st)?;
    }
    let quarantined: i64 = tx
        .query_row(
            "SELECT size FROM quarantine WHERE event_id = ?1",
            [id],
            |r| r.get(0),
        )
        .map_err(st)?;
    tx.execute("DELETE FROM events WHERE event_id = ?1 AND state = 0", [id])
        .map_err(st)?;
    tx.execute("DELETE FROM rewrite_originals WHERE event_id = ?1", [id])
        .map_err(st)?;
    stamp_row(tx, STAMP_QUARANTINE, sequence, boot).map_err(st)?;
    Ok(Some((size as u64, quarantined as u64)))
}

/// Before an acknowledged row is purged: move the pre-rewrite bytes of its event
/// (if it was rewritten) into `quarantine` under [`ORIGINAL_CODE`] and drop the
/// originals row, in the caller's transaction. Returns the bytes archived.
fn archive_original(
    tx: &rusqlite::Transaction<'_>,
    id: &str,
    now: i64,
    boot: Option<&BootInstant>,
) -> rusqlite::Result<u64> {
    let row: Option<(i64, i64)> = tx
        .query_row(
            "SELECT sequence, length(bytes) FROM rewrite_originals WHERE event_id = ?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let Some((sequence, size)) = row else {
        return Ok(0);
    };
    tx.execute(
        "INSERT INTO quarantine(sequence, event_id, bytes, size, created_at, quarantined_at, code) \
         SELECT o.sequence, o.event_id, o.bytes, length(o.bytes), e.created_at, ?2, ?3 \
         FROM rewrite_originals o JOIN events e ON e.event_id = o.event_id \
         WHERE o.event_id = ?1",
        params![id, now, ORIGINAL_CODE],
    )?;
    tx.execute("DELETE FROM rewrite_originals WHERE event_id = ?1", [id])?;
    stamp_row(tx, STAMP_QUARANTINE, sequence, boot)?;
    Ok(size as u64)
}

/// Insert a gap record if it fits the `room` left in the gap reserve; otherwise
/// `GapReserveExceeded`. Returns the bytes stored (0 when the `gap_id` was
/// already there).
fn insert_gap(
    tx: &rusqlite::Transaction<'_>,
    gap: &GapReport,
    room: u64,
) -> Result<u64, SpoolError> {
    let body = serde_json::to_string(gap).map_err(|_| SpoolError::Corrupt)?;
    let gap_id = serde_json::from_str::<serde_json::Value>(&body)
        .ok()
        .and_then(|v| v.get("gap_id").and_then(|g| g.as_str().map(str::to_string)))
        .ok_or(SpoolError::Corrupt)?;
    let size = body.len() as u64;
    // N3: a gap_id that is already stored is a no-op, even when the reserve is
    // full (re-recording after a restart must not fail).
    let exists: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM gaps WHERE gap_id = ?1)",
            [&gap_id],
            |r| r.get(0),
        )
        .map_err(|e| SpoolError::Storage(code_name(&e)))?;
    if exists {
        return Ok(0);
    }
    if size > room {
        return Err(SpoolError::GapReserveExceeded);
    }
    let n = tx
        .execute(
            "INSERT OR IGNORE INTO gaps(gap_id, body, size) VALUES (?1, ?2, ?3)",
            params![gap_id, body, size as i64],
        )
        .map_err(|e| SpoolError::Storage(code_name(&e)))?;
    Ok(if n > 0 { size } else { 0 })
}

fn spool_expired_gap(epoch: &str, now: i64, from: i64, to: i64, count: i64) -> Option<GapReport> {
    let at = time::OffsetDateTime::from_unix_timestamp(now).ok()?;
    Some(GapReport::SpoolExpired(SpoolExpiredGap {
        gap_id: Uuid::new(uuid::Uuid::new_v4().hyphenated().to_string()).ok()?,
        detected_at: Timestamp::new(crate::status_report::rfc3339(at)).ok()?,
        epoch_id: Uuid::new(epoch.to_string()).ok()?,
        from_sequence: PositiveI64::new(from).ok()?,
        to_sequence: PositiveI64::new(to).ok()?,
        count: PositiveI64::new(count).ok()?,
    }))
}

/// Create the empty database file owner-only (0600) before SQLite opens it.
fn create_private(path: &Path) -> Result<(), SpoolError> {
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    match o.open(path) {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(_) => Err(SpoolError::Storage("create".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::atomic::AtomicI64;

    pub(crate) fn uid(n: u32) -> String {
        format!("00000000-0000-4000-8000-{n:012x}")
    }
    const EPOCH: u32 = 5000;

    #[cfg(unix)]
    #[test]
    fn a_symlinked_spool_file_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().canonicalize().unwrap();
        let open = |p: &Path| {
            Connection::open_with_flags(p, OpenFlags::default() | OpenFlags::SQLITE_OPEN_NOFOLLOW)
        };
        assert!(open(&dir.join("plain.db")).is_ok(), "a resolved dir opens");
        std::os::unix::fs::symlink(dir.join("plain.db"), dir.join(SPOOL_FILE)).unwrap();
        assert!(
            open(&dir.join(SPOOL_FILE)).is_err(),
            "SQLite followed the symlink"
        );
    }

    fn event(n: u32) -> ProxyEvent {
        serde_json::from_value(json!({
            "schema_version": 1, "event_id": uid(n), "proxy_id": "px-1",
            "epoch_id": uid(EPOCH), "sequence": 1,
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

    fn cfg(dir: &Path, now: Arc<AtomicI64>) -> SpoolConfig {
        let mut c = SpoolConfig::new(dir, "px-1", &uid(EPOCH), true, &Limits::default());
        c.maintenance_interval = Duration::from_secs(3600);
        c.clock = Arc::new(move || now.load(Ordering::SeqCst));
        c.boot_clock = Arc::new(|| None);
        c
    }

    fn open(dir: &Path) -> (Spool, Arc<AtomicI64>) {
        let now = Arc::new(AtomicI64::new(1_800_000_000));
        (Spool::open(cfg(dir, now.clone())).unwrap(), now)
    }

    fn event_size() -> u64 {
        serde_json::to_vec(&event(1)).unwrap().len() as u64
    }

    fn ids(v: &[ProxyEvent]) -> Vec<String> {
        v.iter().map(|e| e.event_id.as_str().to_string()).collect()
    }

    #[test]
    fn delivers_in_sequence_order_and_assigns_sequence() {
        let d = tempfile::tempdir().unwrap();
        let (mut s, _) = open(d.path());
        for n in 1..=5 {
            assert_eq!(s.append(event(n)).unwrap().sequence, n as i64);
        }
        let got = s.next_events(3, &HashSet::new());
        assert_eq!(ids(&got), vec![uid(1), uid(2), uid(3)]);
        assert_eq!(got[0].sequence.get(), 1);
        let skip: HashSet<String> = [uid(1)].into_iter().collect();
        assert_eq!(ids(&s.next_events(2, &skip)), vec![uid(2), uid(3)]);
        let snap = s.snapshot();
        assert_eq!((snap.unsent_events, snap.last_assigned_sequence), (5, 5));
        assert_eq!(snap.state, SpoolState::Ok);
    }

    #[test]
    fn rejects_foreign_identity_duplicate_and_oversize() {
        let d = tempfile::tempdir().unwrap();
        let now = Arc::new(AtomicI64::new(1_800_000_000));
        let mut c = cfg(d.path(), now);
        c.event_max_bytes = event_size() + 2;
        let s = Spool::open(c).unwrap();
        s.append(event(1)).unwrap();
        assert_eq!(s.append(event(1)), Err(AppendError::Duplicate));
        let mut other = event(2);
        other.epoch_id = Uuid::new(uid(9)).unwrap();
        assert_eq!(s.append(other), Err(AppendError::WrongIdentity));
        let mut big = serde_json::to_value(event(3)).unwrap();
        big["payload"]["actor"]["actor_id"] = json!("a".repeat(100));
        let big: ProxyEvent = serde_json::from_value(big).unwrap();
        assert_eq!(s.append(big), Err(AppendError::TooLarge));
        // A refusal consumes no sequence.
        assert_eq!(s.append(event(4)).unwrap().sequence, 2);
    }

    #[test]
    fn ack_marks_rows_and_purges_after_retention() {
        let d = tempfile::tempdir().unwrap();
        let (mut s, now) = open(d.path());
        for n in 1..=3 {
            s.append(event(n)).unwrap();
        }
        s.acknowledged(&[uid(1), uid(2), uid(99)]);
        assert_eq!(ids(&s.next_events(10, &HashSet::new())), vec![uid(3)]);
        let snap = s.snapshot();
        assert_eq!((snap.unsent_events, snap.retained_acked_events), (1, 2));
        now.fetch_add(86_400 + 1, Ordering::SeqCst);
        let r = s.expire_now().unwrap();
        assert_eq!(r.purged_acked, 2);
        assert_eq!(s.snapshot().retained_acked_events, 0);
        // Sequence never reused after the purge.
        assert_eq!(s.append(event(4)).unwrap().sequence, 4);
    }

    /// #339: what a stopped ingest client leaves unsent still expires at R.
    #[tokio::test]
    async fn events_left_by_a_stopped_ingest_client_expire_at_r() {
        use crate::ingest_client::{IngestClient, IngestParams, IngestTransport};
        use crate::status_report::{CentralHealth, GapQueue, PostFuture, StatusReply};

        struct RefusesAll;
        impl IngestTransport for RefusesAll {
            fn post_events(&self, _: Vec<u8>) -> PostFuture<'_> {
                let items = json!([{"index": 0, "code": "semantic_invalid"}]);
                let body = json!({"error": {
                    "code": "semantic_invalid", "message": "fixed", "items": items,
                }});
                Box::pin(async move {
                    Some(StatusReply {
                        status: 422,
                        body: serde_json::to_vec(&body).unwrap(),
                    })
                })
            }
        }
        let d = tempfile::tempdir().unwrap();
        let (mut s, now) = open(d.path());
        for n in 1..=12 {
            s.append(event(n)).unwrap();
        }
        let mut c = IngestClient::new(
            GapQueue::new(),
            CentralHealth::new(),
            IngestParams::default(),
        );
        for _ in 0..12 {
            c.send_once(&RefusesAll, &mut s, tokio::time::Instant::now())
                .await;
        }
        assert_eq!(s.snapshot().unsent_events, 4);
        now.fetch_add(
            SpoolConfig::new(d.path(), "px-1", &uid(EPOCH), true, &Limits::default())
                .max_offline_retry_age
                .as_secs() as i64
                + 1,
            Ordering::SeqCst,
        );
        assert_eq!(s.expire_now().unwrap().expired_events, 4);
        assert_eq!(s.snapshot().unsent_events, 0);
    }

    #[test]
    fn quarantine_moves_rows_unchanged() {
        let d = tempfile::tempdir().unwrap();
        let (mut s, _) = open(d.path());
        for n in 1..=3 {
            s.append(event(n)).unwrap();
        }
        let before = ids(&s.next_events(10, &HashSet::new()));
        s.quarantined(&[uid(2)], QuarantineCode::SemanticInvalid);
        let after = ids(&s.next_events(10, &HashSet::new()));
        assert_eq!(before.len(), 3);
        assert_eq!(after, vec![uid(1), uid(3)]);
        assert_eq!(s.snapshot().quarantined_events, 1);
        drop(s);
        let conn = Connection::open(d.path().join(SPOOL_FILE)).unwrap();
        let (code, bytes): (String, Vec<u8>) = conn
            .query_row(
                "SELECT code, bytes FROM quarantine WHERE event_id = ?1",
                [uid(2)],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(code, "semantic_invalid");
        let ev = lodeline_proxy_api::parse::parse_event(&bytes).unwrap();
        assert_eq!(ev.sequence.get(), 2);
        // A quarantined id cannot be appended again.
    }

    #[test]
    fn capacity_blocks_and_keeps_gap_reserve() {
        let d = tempfile::tempdir().unwrap();
        let (s, _) = open(d.path());
        let sz = event_size();
        // Room for exactly 2 events plus a 1 KiB reserve.
        s.set_capacity_for_test(2 * sz + 1024, 1024);
        s.append(event(1)).unwrap();
        s.append(event(2)).unwrap();
        assert_eq!(s.snapshot().state, SpoolState::Full);
        assert_eq!(s.append(event(3)), Err(AppendError::Full));
        // The reserve still takes a gap record.
        let gap = spool_expired_gap(&uid(EPOCH), 1_800_000_000, 1, 1, 1).unwrap();
        s.record_gap(gap).unwrap();
        assert_eq!(s.snapshot().pending_gaps, 1);
        assert_eq!(s.append(event(3)), Err(AppendError::Full));
        // Draining frees room again.
        let mut s2 = s.clone();
        s2.acknowledged(&[uid(1)]);
        assert_eq!(s.snapshot().state, SpoolState::Ok);
        assert!(s.append(event(3)).is_ok());
    }

    #[test]
    fn storage_failure_degrades_then_recovers() {
        let d = tempfile::tempdir().unwrap();
        let (s, _) = open(d.path());
        s.inject_storage_failure(true);
        assert_eq!(s.append(event(1)), Err(AppendError::DiskFull));
        assert_eq!(s.snapshot().state, SpoolState::Degraded);
        assert_eq!(s.snapshot().unsent_events, 0);
        s.inject_storage_failure(false);
        assert_eq!(s.append(event(1)).unwrap().sequence, 1);
        assert_eq!(s.snapshot().state, SpoolState::Ok);
    }

    #[test]
    fn expiry_quarantines_and_records_gap_per_run() {
        let d = tempfile::tempdir().unwrap();
        let (mut s, now) = open(d.path());
        for n in 1..=4 {
            s.append(event(n)).unwrap();
        }
        // seq 2 was acked: the expired events are runs {1} and {3,4}.
        s.acknowledged(&[uid(2)]);
        now.fetch_add(30 * 86_400 + 1, Ordering::SeqCst);
        s.append(event(5)).unwrap(); // fresh, survives
        let r = s.expire_now().unwrap();
        assert_eq!((r.expired_events, r.gaps_recorded), (3, 2));
        assert_eq!(ids(&s.next_events(10, &HashSet::new())), vec![uid(5)]);
        let snap = s.snapshot();
        assert_eq!((snap.quarantined_events, snap.pending_gaps), (3, 2));
        let gaps = s.pending_gaps().unwrap();
        let mut ranges: Vec<(i64, i64, i64)> = gaps
            .iter()
            .map(|g| match g {
                GapReport::SpoolExpired(x) => {
                    (x.from_sequence.get(), x.to_sequence.get(), x.count.get())
                }
                _ => panic!("kind"),
            })
            .collect();
        ranges.sort();
        assert_eq!(ranges, vec![(1, 1, 1), (3, 4, 2)]);
        // Handoff removes them; a second expiry pass makes none.
        let gids: Vec<String> = gaps
            .iter()
            .map(|g| match g {
                GapReport::SpoolExpired(x) => x.gap_id.as_str().to_string(),
                _ => unreachable!(),
            })
            .collect();
        s.gaps_handed_off(&gids).unwrap();
        assert_eq!(s.snapshot().pending_gaps, 0);
        assert_eq!(s.snapshot().gap_bytes, 0);
        assert_eq!(s.expire_now().unwrap(), ExpireReport::default());
    }

    #[test]
    fn restart_recovers_unsent_gaps_and_sequence() {
        let d = tempfile::tempdir().unwrap();
        {
            let (mut s, now) = open(d.path());
            for n in 1..=3 {
                s.append(event(n)).unwrap();
            }
            s.acknowledged(&[uid(1)]);
            now.fetch_add(30 * 86_400 + 1, Ordering::SeqCst);
            s.expire_now().unwrap();
            s.append(event(4)).unwrap();
        }
        let (mut s, _) = open(d.path());
        let snap = s.snapshot();
        assert_eq!(snap.last_assigned_sequence, 4);
        assert_eq!(snap.unsent_events, 1);
        assert_eq!(snap.pending_gaps, 1);
        assert_eq!(snap.quarantined_events, 2);
        assert_eq!(ids(&s.next_events(10, &HashSet::new())), vec![uid(4)]);
        assert_eq!(s.append(event(5)).unwrap().sequence, 5);
    }

    #[test]
    fn refuses_corrupt_foreign_and_non_regular() {
        let d = tempfile::tempdir().unwrap();
        let now = Arc::new(AtomicI64::new(1_800_000_000));
        drop(Spool::open(cfg(d.path(), now.clone())).unwrap());
        // Foreign epoch.
        let mut c = cfg(d.path(), now.clone());
        c.epoch_id = uid(1);
        assert!(matches!(Spool::open(c), Err(SpoolError::Foreign)));
        let mut c = cfg(d.path(), now.clone());
        c.proxy_id = "px-2".into();
        assert!(matches!(Spool::open(c), Err(SpoolError::Foreign)));
        // Garbage file is left untouched.
        let p = d.path().join(SPOOL_FILE);
        let junk = vec![0x41u8; 4096];
        for ext in ["-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{ext}", p.display()));
        }
        std::fs::write(&p, &junk).unwrap();
        assert!(matches!(
            Spool::open(cfg(d.path(), now.clone())),
            Err(SpoolError::Corrupt)
        ));
        assert_eq!(std::fs::read(&p).unwrap(), junk);
        // A directory in the way.
        let d2 = tempfile::tempdir().unwrap();
        std::fs::create_dir(d2.path().join(SPOOL_FILE)).unwrap();
        assert!(matches!(
            Spool::open(cfg(d2.path(), now)),
            Err(SpoolError::BadPath)
        ));
    }

    #[test]
    fn database_is_owner_only_and_wal() {
        let d = tempfile::tempdir().unwrap();
        let (s, _) = open(d.path());
        s.append(event(1)).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let m = std::fs::metadata(d.path().join(SPOOL_FILE)).unwrap();
            assert_eq!(m.permissions().mode() & 0o077, 0);
        }
        assert!(d.path().join(format!("{SPOOL_FILE}-wal")).exists());
    }

    #[test]
    fn maintenance_runs_under_continuous_traffic() {
        let d = tempfile::tempdir().unwrap();
        let now = Arc::new(AtomicI64::new(1_800_000_000));
        let mut c = cfg(d.path(), now.clone());
        c.maintenance_interval = Duration::from_millis(30);
        let mut s = Spool::open(c).unwrap();
        s.append(event(1)).unwrap();
        s.append(event(2)).unwrap();
        s.acknowledged(&[uid(2)]);
        now.fetch_add(31 * 86_400, Ordering::SeqCst);
        // Never idle: a command arrives far more often than the interval.
        let start = std::time::Instant::now();
        loop {
            let _ = s.next_events(1, &HashSet::new());
            let snap = s.snapshot();
            if snap.quarantined_events == 1 && snap.retained_acked_events == 0 {
                break;
            }
            assert!(
                start.elapsed() < Duration::from_secs(5),
                "maintenance starved"
            );
            std::thread::sleep(Duration::from_millis(2));
        }
        assert_eq!(s.snapshot().pending_gaps, 1);
    }

    #[test]
    fn missing_or_empty_db_in_existing_epoch_is_not_recreated() {
        let d = tempfile::tempdir().unwrap();
        let now = Arc::new(AtomicI64::new(1_800_000_000));
        let mut existing = cfg(d.path(), now.clone());
        existing.new_epoch = false;
        let p = d.path().join(SPOOL_FILE);
        assert!(matches!(
            Spool::open(existing.clone()),
            Err(SpoolError::Missing)
        ));
        assert!(!p.exists(), "no file may be created");
        // Zero-byte file: left exactly as it is.
        std::fs::write(&p, b"").unwrap();
        assert!(matches!(
            Spool::open(existing.clone()),
            Err(SpoolError::Missing)
        ));
        assert_eq!(std::fs::metadata(&p).unwrap().len(), 0);
        // A new epoch creates (and initialises the empty file) ...
        let s = Spool::open(cfg(d.path(), now)).unwrap();
        s.append(event(1)).unwrap();
        drop(s);
        // ... and the same database then opens as an existing epoch.
        let s = Spool::open(existing).unwrap();
        assert_eq!(s.snapshot().last_assigned_sequence, 1);
    }

    #[test]
    fn full_purges_acked_rows_before_refusing() {
        let d = tempfile::tempdir().unwrap();
        let (mut s, _) = open(d.path());
        let sz = event_size();
        s.set_capacity_for_test(2 * sz + 1024, 1024);
        s.append(event(1)).unwrap();
        s.append(event(2)).unwrap();
        s.acknowledged(&[uid(1), uid(2)]);
        let snap = s.snapshot();
        assert_eq!(snap.retained_acked_bytes, 2 * sz);
        assert_eq!(snap.unsent_bytes, 0);
        // Retained acked rows count toward capacity but are purged on demand.
        assert_eq!(s.append(event(3)).unwrap().sequence, 3);
        assert_eq!(s.snapshot().retained_acked_bytes, 0);
        s.append(event(4)).unwrap();
        // Truly full of unsent events: still refused.
        assert_eq!(s.append(event(5)), Err(AppendError::Full));
    }

    #[test]
    fn gap_records_are_bounded_by_the_reserve() {
        let d = tempfile::tempdir().unwrap();
        let (mut s, now) = open(d.path());
        let gap = spool_expired_gap(&uid(EPOCH), 1_800_000_000, 1, 1, 1).unwrap();
        let gap_len = serde_json::to_string(&gap).unwrap().len() as u64;
        s.set_capacity_for_test(1 << 30, gap_len - 1);
        assert!(matches!(
            s.record_gap(gap.clone()),
            Err(SpoolError::GapReserveExceeded)
        ));
        assert_eq!(s.snapshot().pending_gaps, 0);
        // Expiry that cannot record its gap aborts: events stay unsent.
        s.append(event(1)).unwrap();
        now.fetch_add(31 * 86_400, Ordering::SeqCst);
        assert!(matches!(
            s.expire_now(),
            Err(SpoolError::GapReserveExceeded)
        ));
        let snap = s.snapshot();
        assert_eq!((snap.unsent_events, snap.quarantined_events), (1, 0));
        assert_eq!(ids(&s.next_events(5, &HashSet::new())), vec![uid(1)]);
        s.set_capacity_for_test(1 << 30, gap_len * 4);
        assert_eq!(s.expire_now().unwrap().expired_events, 1);
        let snap = s.snapshot();
        assert_eq!(snap.quarantined_events, 1);
        assert!(snap.quarantined_bytes > 0);
    }

    #[test]
    fn expiry_is_batched() {
        let d = tempfile::tempdir().unwrap();
        let (s, now) = open(d.path());
        let total = MAINTENANCE_BATCH as u32 * 2 + 10;
        for n in 1..=total {
            s.append(event(n)).unwrap();
        }
        now.fetch_add(31 * 86_400, Ordering::SeqCst);
        let r = s.expire_now().unwrap();
        assert_eq!(r.expired_events, total as u64);
        // One gap per batch transaction, ranges stay exact.
        assert_eq!(r.gaps_recorded, 3);
        let n: i64 = s
            .pending_gaps()
            .unwrap()
            .iter()
            .map(|g| match g {
                GapReport::SpoolExpired(x) => x.count.get(),
                _ => 0,
            })
            .sum();
        assert_eq!(n, total as i64);
    }

    #[test]
    fn dead_writer_is_reported_degraded() {
        let d = tempfile::tempdir().unwrap();
        let (mut s, _) = open(d.path());
        s.append(event(1)).unwrap();
        assert_eq!(s.snapshot().state, SpoolState::Ok);
        s.inner.tx.send(Cmd::Shutdown).unwrap();
        let j = s.inner.join.lock().unwrap().take().unwrap();
        j.join().unwrap();
        assert!(s.next_events(5, &HashSet::new()).is_empty());
        assert_eq!(s.snapshot().state, SpoolState::Degraded);
        assert_eq!(s.append(event(2)), Err(AppendError::Unavailable));
    }

    #[test]
    fn open_pins_wal_and_synchronous_full() {
        let d = tempfile::tempdir().unwrap();
        let now = Arc::new(AtomicI64::new(1_800_000_000));
        let sh = Arc::new(Shared {
            counters: Mutex::new(Counters::default()),
            degraded: AtomicBool::new(false),
            dead: AtomicBool::new(false),
            capacity: AtomicU64::new(1 << 30),
            reserve: AtomicU64::new(1 << 20),
            retry_age_secs: AtomicU64::new(3600),
            quarantine_retention_secs: AtomicU64::new(0),
            gap_exhausted: AtomicBool::new(false),
            inject_failure: AtomicBool::new(false),
            delivery_paused: AtomicBool::new(false),
            clock_skew: std::sync::atomic::AtomicI64::new(0),
        });
        let w = Writer::open(cfg(d.path(), now), sh).unwrap();
        let sync: i64 = w
            .conn
            .query_row("PRAGMA synchronous", [], |r| r.get(0))
            .unwrap();
        let mode: String = w
            .conn
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .unwrap();
        assert_eq!(sync, 2, "synchronous must be FULL");
        assert_eq!(mode.to_ascii_lowercase(), "wal");
    }

    #[tokio::test]
    async fn append_async_acks_after_commit() {
        let d = tempfile::tempdir().unwrap();
        let (s, _) = open(d.path());
        assert_eq!(s.append_async(event(1)).await.unwrap().sequence, 1);
        assert_eq!(s.snapshot().unsent_events, 1);
    }

    fn outage_gap(n: u32) -> GapReport {
        serde_json::from_value(json!({
            "kind": "central_outage", "gap_id": uid(n),
            "detected_at": "2026-10-14T00:00:00Z",
            "started_at": "2026-10-14T00:00:00Z", "ended_at": null}))
        .unwrap()
    }

    fn gap_size(n: u32) -> u64 {
        serde_json::to_string(&outage_gap(n)).unwrap().len() as u64
    }

    /// N3: recording a gap_id that is already stored is a no-op even when the
    /// reserve is full; a new id is refused and the refusal is sticky.
    #[test]
    fn re_recording_an_existing_gap_is_a_noop_when_the_reserve_is_full() {
        let d = tempfile::tempdir().unwrap();
        let (s, _) = open(d.path());
        s.set_capacity_for_test(1 << 20, gap_size(1));
        s.record_gap(outage_gap(1)).unwrap();
        assert_eq!(s.snapshot().pending_gaps, 1);
        // Same id again: Ok, nothing added.
        s.record_gap(outage_gap(1)).unwrap();
        let snap = s.snapshot();
        assert_eq!((snap.pending_gaps, snap.gap_bytes), (1, gap_size(1)));
        assert!(!snap.gap_reserve_exhausted);
        assert_eq!(snap.state, SpoolState::Ok);
        // A different id does not fit.
        assert!(matches!(
            s.record_gap(outage_gap(2)),
            Err(SpoolError::GapReserveExceeded)
        ));
        assert!(s.snapshot().gap_reserve_exhausted);
        assert_eq!(s.pending_gaps().unwrap().len(), 1);
    }

    /// The exhausted signal is sticky: appends do not clear it (no flapping);
    /// handing a gap off does.
    #[test]
    fn gap_reserve_exhausted_is_sticky_until_a_gap_is_handed_off() {
        let d = tempfile::tempdir().unwrap();
        let (s, _) = open(d.path());
        s.set_capacity_for_test(1 << 20, gap_size(1));
        s.record_gap(outage_gap(1)).unwrap();
        assert!(s.record_gap(outage_gap(2)).is_err());
        for n in 1..=3 {
            s.append(event(n)).unwrap();
            let snap = s.snapshot();
            assert!(snap.gap_reserve_exhausted, "append {n} must not clear it");
            assert_eq!(snap.state, SpoolState::Degraded, "append {n}");
        }
        s.gaps_handed_off(&[uid(1)]).unwrap();
        let snap = s.snapshot();
        assert!(!snap.gap_reserve_exhausted);
        assert_eq!(snap.state, SpoolState::Ok);
    }

    /// An expiry whose gap does not fit leaves the events unsent (never expired
    /// without a record) and raises the sticky signal, not a storage fault.
    #[test]
    fn expiry_with_a_full_gap_reserve_keeps_events_and_flags_exhaustion() {
        let d = tempfile::tempdir().unwrap();
        let (s, now) = open(d.path());
        s.append(event(1)).unwrap();
        s.set_capacity_for_test(1 << 20, 1);
        now.fetch_add(31 * 86_400, Ordering::SeqCst);
        assert!(matches!(
            s.expire_now(),
            Err(SpoolError::GapReserveExceeded)
        ));
        let snap = s.snapshot();
        assert_eq!(snap.unsent_events, 1);
        assert_eq!(snap.quarantined_events, 0);
        assert!(snap.gap_reserve_exhausted);
        assert_eq!(snap.state, SpoolState::Degraded);
    }

    /// R follows the applied config.
    #[test]
    fn retry_age_can_be_changed_at_runtime() {
        let d = tempfile::tempdir().unwrap();
        let (s, now) = open(d.path());
        s.append(event(1)).unwrap();
        now.fetch_add(2 * 3600, Ordering::SeqCst);
        assert_eq!(s.expire_now().unwrap().expired_events, 0);
        s.set_max_offline_retry_age(Duration::from_secs(3600));
        assert_eq!(s.expire_now().unwrap().expired_events, 1);
        assert_eq!(s.pending_gaps().unwrap().len(), 1);
    }

    fn quarantine_rows(dir: &Path) -> i64 {
        Connection::open(dir.join(SPOOL_FILE))
            .unwrap()
            .query_row("SELECT count(*) FROM quarantine", [], |r| r.get(0))
            .unwrap()
    }

    /// Q purge: a quarantined row is deleted only once it is older than Q.
    #[test]
    fn quarantined_rows_are_purged_once_older_than_q() {
        let d = tempfile::tempdir().unwrap();
        let (mut s, _) = open(d.path());
        s.set_quarantine_retention(Duration::from_secs(3600));
        s.append(event(1)).unwrap();
        s.append(event(2)).unwrap();
        s.quarantined(&[uid(1)], QuarantineCode::SemanticInvalid);
        s.advance_clock_for_test(3600);
        assert_eq!(s.expire_now().unwrap().purged_quarantined, 0);
        assert_eq!(s.snapshot().quarantined_events, 1);
        assert_eq!(quarantine_rows(d.path()), 1);
        s.advance_clock_for_test(1);
        assert_eq!(s.expire_now().unwrap().purged_quarantined, 1);
        let snap = s.snapshot();
        assert_eq!((snap.quarantined_events, snap.quarantined_bytes), (0, 0));
        assert_eq!(snap.unsent_events, 1);
        assert_eq!(quarantine_rows(d.path()), 0);
    }

    /// Every code is purged, including registry-conflict originals, and the
    /// counters match what a restart would load from the database.
    #[test]
    fn q_purge_covers_originals_and_keeps_counters_exact() {
        let d = tempfile::tempdir().unwrap();
        let (mut s, _) = open(d.path());
        s.append(call_event(1, 1)).unwrap();
        s.registry_conflict(&mref(1)).unwrap();
        s.acknowledged(&[uid(1)]);
        s.advance_clock_for_test(86_400 + 1);
        s.expire_now().unwrap();
        s.append(event(2)).unwrap();
        s.append(event(3)).unwrap();
        s.quarantined(&[uid(2)], QuarantineCode::SemanticInvalid);
        assert_eq!(s.snapshot().quarantined_events, 1);
        s.advance_clock_for_test(1001);
        s.quarantined(&[uid(3)], QuarantineCode::SemanticInvalid);
        let (_, _, newest_size) = quarantined_row(d.path(), &uid(3));
        s.set_quarantine_retention(Duration::from_secs(1000));
        assert_eq!(s.expire_now().unwrap().purged_quarantined, 2);
        let snap = s.snapshot();
        assert_eq!(snap.quarantined_events, 1);
        assert_eq!(snap.quarantined_bytes, newest_size as u64);
        assert_eq!(quarantined_row(d.path(), &uid(3)).0, "semantic_invalid");
        s.close_blocking_for_test();
        let now = Arc::new(AtomicI64::new(1_800_000_000));
        let mut c = cfg(d.path(), now);
        c.new_epoch = false;
        let reloaded = Spool::open(c).unwrap().snapshot();
        assert_eq!(
            (reloaded.quarantined_events, reloaded.quarantined_bytes),
            (snap.quarantined_events, snap.quarantined_bytes)
        );
    }

    fn query_plan(c: &Connection, sql: &str, args: impl rusqlite::Params) -> String {
        let mut q = c.prepare(&format!("EXPLAIN QUERY PLAN {sql}")).unwrap();
        let plan: Vec<String> = q
            .query_map(args, |r| r.get(3))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        plan.join("\n")
    }

    /// Expiry and the Q purge run inside the append-blocking write transaction, so
    /// each query walks an index range, never scans or sorts a table.
    #[test]
    fn maintenance_queries_walk_indexes() {
        let d = tempfile::tempdir().unwrap();
        let (s, _) = open(d.path());
        s.close_blocking_for_test();
        let c = Connection::open(d.path().join(SPOOL_FILE)).unwrap();
        let cases: [(&str, String, &str); 4] = [
            (
                "DUE_BY_BOOT",
                query_plan(&c, DUE_BY_BOOT, params!["b", 0, MAINTENANCE_BATCH]),
                "idx_event_boot_stamps (boot_id=? AND boot_secs<?)",
            ),
            (
                "DUE_BY_WALL",
                query_plan(&c, DUE_BY_WALL, params![0, "b", MAINTENANCE_BATCH]),
                "idx_unsent_created (created_at<?)",
            ),
            (
                "PURGE_QUARANTINE_BY_BOOT",
                query_plan(
                    &c,
                    PURGE_QUARANTINE_BY_BOOT,
                    params!["b", 0, MAINTENANCE_BATCH, ORIGINAL_CODE],
                ),
                "idx_quarantine_boot_stamps (boot_id=? AND boot_secs<?)",
            ),
            (
                "PURGE_QUARANTINE_BY_WALL",
                query_plan(
                    &c,
                    PURGE_QUARANTINE_BY_WALL,
                    params![0, "b", MAINTENANCE_BATCH, ORIGINAL_CODE],
                ),
                "idx_quarantine_at (quarantined_at<?)",
            ),
        ];
        for (name, plan, index) in cases {
            assert!(plan.contains(index), "{name}: {plan}");
            assert!(!plan.contains("SCAN"), "{name}: {plan}");
            assert!(!plan.contains("TEMP B-TREE"), "{name}: {plan}");
        }
    }

    /// A spool written before the index existed gets it on reopen.
    #[test]
    fn reopen_adds_the_quarantined_at_index() {
        let d = tempfile::tempdir().unwrap();
        let (s, _) = open(d.path());
        s.close_blocking_for_test();
        let has_index = || -> i64 {
            Connection::open(d.path().join(SPOOL_FILE))
                .unwrap()
                .query_row(
                    "SELECT count(*) FROM sqlite_master WHERE type = 'index' AND name = 'idx_quarantine_at'",
                    [],
                    |r| r.get(0),
                )
                .unwrap()
        };
        assert_eq!(has_index(), 1);
        Connection::open(d.path().join(SPOOL_FILE))
            .unwrap()
            .execute_batch("DROP INDEX idx_quarantine_at")
            .unwrap();
        assert_eq!(has_index(), 0);
        let mut c = cfg(d.path(), Arc::new(AtomicI64::new(1_800_000_000)));
        c.new_epoch = false;
        Spool::open(c).unwrap().close_blocking_for_test();
        assert_eq!(has_index(), 1);
    }

    /// Before the applied config provides E, nothing is purged however old.
    #[test]
    fn nothing_is_purged_while_e_is_unknown() {
        let d = tempfile::tempdir().unwrap();
        let (mut s, _) = open(d.path());
        s.append(event(1)).unwrap();
        s.quarantined(&[uid(1)], QuarantineCode::SemanticInvalid);
        s.advance_clock_for_test(1000 * 86_400);
        assert_eq!(s.expire_now().unwrap().purged_quarantined, 0);
        assert_eq!(s.snapshot().quarantined_events, 1);
        assert_eq!(quarantine_rows(d.path()), 1);
    }

    #[test]
    fn q_purge_is_batched() {
        let d = tempfile::tempdir().unwrap();
        let (s, _) = open(d.path());
        let total = MAINTENANCE_BATCH as u32 * 2 + 10;
        for n in 1..=total {
            s.append(event(n)).unwrap();
        }
        s.set_max_offline_retry_age(Duration::from_secs(10));
        s.advance_clock_for_test(11);
        assert_eq!(s.expire_now().unwrap().expired_events, total as u64);
        s.set_quarantine_retention(Duration::from_secs(3600));
        s.advance_clock_for_test(3601);
        // More rows than one maintenance transaction purges.
        assert_eq!(s.expire_now().unwrap().purged_quarantined, total as u64);
        let snap = s.snapshot();
        assert_eq!((snap.quarantined_events, snap.quarantined_bytes), (0, 0));
        assert_eq!(quarantine_rows(d.path()), 0);
    }

    /// Admission: full is a typed refusal and nothing is stored; space returns as
    /// events are acknowledged.
    #[tokio::test]
    async fn admission_refuses_when_full_and_reopens_after_ack() {
        let d = tempfile::tempdir().unwrap();
        let (mut s, _) = open(d.path());
        let size = event_size();
        s.set_capacity_for_test(size * 2 + 10, 10);
        let adm = Admission::new(s.clone());
        assert_eq!(adm.append(event(1)).await.unwrap().sequence, 1);
        assert_eq!(adm.append(event(2)).await.unwrap().sequence, 2);
        assert_eq!(adm.append(event(3)).await, Err(Refusal::Full));
        let snap = adm.snapshot();
        assert_eq!(snap.state, SpoolState::Full);
        assert_eq!(snap.unsent_events, 2);
        assert_eq!(
            snap.last_assigned_sequence, 2,
            "a refused event takes no sequence"
        );
        // Duplicate and foreign-identity events are Invalid, not capacity.
        assert!(matches!(
            adm.append(event(1)).await,
            Err(Refusal::Invalid(AppendError::Duplicate))
        ));
        s.acknowledged_async(&[uid(1)]).await;
        assert!(adm.append(event(3)).await.is_ok());
    }

    #[tokio::test]
    async fn admission_maps_storage_failure_to_unavailable() {
        let d = tempfile::tempdir().unwrap();
        let (s, _) = open(d.path());
        s.inject_storage_failure(true);
        let adm = Admission::new(s.clone());
        assert_eq!(adm.append(event(1)).await, Err(Refusal::Unavailable));
        assert_eq!(s.snapshot().state, SpoolState::Degraded);
    }

    /// The async EventSource path behaves like the sync one.
    #[tokio::test(flavor = "current_thread")]
    async fn async_event_source_roundtrip() {
        let d = tempfile::tempdir().unwrap();
        let (mut s, _) = open(d.path());
        for n in 1..=3 {
            s.append_async(event(n)).await.unwrap();
        }
        let got = s.next_events_async(10, &HashSet::new()).await;
        assert_eq!(ids(&got), vec![uid(1), uid(2), uid(3)]);
        let skip: HashSet<String> = [uid(1)].into_iter().collect();
        assert_eq!(s.next_events_async(10, &skip).await.len(), 2);
        s.acknowledged_async(&[uid(1)]).await;
        s.quarantined_async(&[uid(2)], QuarantineCode::Conflict)
            .await;
        let snap = s.snapshot();
        assert_eq!((snap.unsent_events, snap.quarantined_events), (1, 1));
        assert_eq!(s.pending_gaps_async().await.unwrap().len(), 0);
    }

    #[test]
    fn injector_events_are_valid_and_sequenced() {
        let d = tempfile::tempdir().unwrap();
        let (s, _) = open(d.path());
        assert_eq!(s.inject_test_event_blocking("up-1").unwrap().sequence, 1);
        assert_eq!(s.inject_test_event_blocking("up-1").unwrap().sequence, 2);
        s.set_delivery_paused_for_test(true);
        let mut s2 = s.clone();
        assert!(s2.next_events(10, &HashSet::new()).is_empty());
        s.set_delivery_paused_for_test(false);
        assert_eq!(s2.next_events(10, &HashSet::new()).len(), 2);
    }

    #[tokio::test]
    async fn close_stops_the_writer_and_releases_the_database() {
        let d = tempfile::tempdir().unwrap();
        let (s, _) = open(d.path());
        s.append_async(event(1)).await.unwrap();
        s.close().await;
        assert_eq!(
            s.append_async(event(2)).await,
            Err(AppendError::Unavailable)
        );
        // The file can be opened again by a new spool at once.
        let (s2, _) = {
            let now = Arc::new(AtomicI64::new(1_800_000_000));
            let mut c = cfg(d.path(), now.clone());
            c.new_epoch = false;
            (Spool::open(c).unwrap(), now)
        };
        assert_eq!(s2.snapshot().unsent_events, 1);
    }

    fn mref(n: u32) -> String {
        format!("00000000-0000-8000-8000-{n:012}")
    }

    /// A `tools/call` start whose tool is identified by `mref(m)`.
    fn call_event(n: u32, m: u32) -> ProxyEvent {
        let mut v = serde_json::to_value(event(n)).unwrap();
        v["payload"]["method"] = json!("tools/call");
        v["payload"]["tool"] = json!({"status": "identified", "metadata_ref": mref(m)});
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn registry_conflict_rewrites_only_the_tool_of_unsent_dependents() {
        let d = tempfile::tempdir().unwrap();
        let (mut s, _) = open(d.path());
        s.append(call_event(1, 1)).unwrap(); // dependent, will be acked
        s.append(call_event(2, 1)).unwrap(); // dependent, unsent
        s.append(call_event(3, 2)).unwrap(); // other ref
        s.append(event(4)).unwrap(); // no tool
        s.acknowledged(&[uid(1)]);
        let before = s.snapshot();
        let dep = s.registry_conflict(&mref(1)).unwrap();
        assert_eq!(dep, vec![uid(1), uid(2)]);
        let got = s.next_events(10, &HashSet::new());
        assert_eq!(ids(&got), vec![uid(2), uid(3), uid(4)]);
        // Only the tool of event 2 changed.
        let mut want = serde_json::to_value(call_event(2, 1)).unwrap();
        want["payload"]["tool"] =
            json!({"status": "metadata_unavailable", "reason": "registry_conflict"});
        want["sequence"] = json!(2);
        assert_eq!(serde_json::to_value(&got[0]).unwrap(), want);
        // The others are untouched.
        let mut other = serde_json::to_value(call_event(3, 2)).unwrap();
        other["sequence"] = json!(3);
        assert_eq!(serde_json::to_value(&got[1]).unwrap(), other);
        // The counters follow the new size.
        let after = s.snapshot();
        assert_eq!(after.unsent_events, before.unsent_events);
        assert_ne!(after.unsent_bytes, before.unsent_bytes);
        // Idempotent: nothing left to rewrite, the same dependents are named.
        assert_eq!(s.registry_conflict(&mref(1)).unwrap(), dep);
        // An unrelated ref names nothing.
        assert!(s.registry_conflict(&mref(9)).unwrap().is_empty());
    }

    #[test]
    fn registry_conflict_keeps_the_original_bytes() {
        let d = tempfile::tempdir().unwrap();
        let (s, _) = open(d.path());
        s.append(call_event(1, 1)).unwrap();
        let original = serde_json::to_vec(&{
            let mut e = call_event(1, 1);
            e.sequence = PositiveI64::new(1).unwrap();
            e
        })
        .unwrap();
        s.registry_conflict(&mref(1)).unwrap();
        s.close_blocking_for_test();
        let c = Connection::open(d.path().join(SPOOL_FILE)).unwrap();
        let kept: Vec<u8> = c
            .query_row(
                "SELECT bytes FROM rewrite_originals WHERE event_id = ?1",
                [uid(1)],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(kept, original);
    }

    /// A rewritten event is quarantined with its original bytes, so the
    /// quarantined byte counter must follow the stored row, not the unsent one.
    #[test]
    fn quarantining_a_rewritten_event_counts_the_stored_bytes() {
        let d = tempfile::tempdir().unwrap();
        let (mut s, _) = open(d.path());
        s.append(call_event(1, 1)).unwrap();
        s.registry_conflict(&mref(1)).unwrap();
        s.quarantined(&[uid(1)], QuarantineCode::SemanticInvalid);
        let snap = s.snapshot();
        assert_eq!(snap.unsent_bytes, 0);
        s.close_blocking_for_test();
        let on_disk: i64 = Connection::open(d.path().join(SPOOL_FILE))
            .unwrap()
            .query_row("SELECT sum(size) FROM quarantine", [], |r| r.get(0))
            .unwrap();
        assert_eq!(snap.quarantined_bytes, on_disk as u64);
        let mut c = cfg(d.path(), Arc::new(AtomicI64::new(1_800_000_000)));
        c.new_epoch = false;
        let reloaded = Spool::open(c).unwrap().snapshot();
        assert_eq!(reloaded.quarantined_bytes, snap.quarantined_bytes);
        assert_eq!(reloaded.unsent_bytes, 0);
    }

    /// Expiry of a rewritten event counts its stored (original) bytes too.
    #[test]
    fn expiring_a_rewritten_event_counts_the_stored_bytes() {
        let d = tempfile::tempdir().unwrap();
        let (s, _) = open(d.path());
        s.append(call_event(1, 1)).unwrap();
        s.registry_conflict(&mref(1)).unwrap();
        s.set_max_offline_retry_age(Duration::from_secs(10));
        s.advance_clock_for_test(11);
        assert_eq!(s.expire_now().unwrap().expired_events, 1);
        let snap = s.snapshot();
        assert_eq!(snap.unsent_bytes, 0);
        s.close_blocking_for_test();
        let on_disk: i64 = Connection::open(d.path().join(SPOOL_FILE))
            .unwrap()
            .query_row("SELECT sum(size) FROM quarantine", [], |r| r.get(0))
            .unwrap();
        assert_eq!(snap.quarantined_bytes, on_disk as u64);
    }

    #[test]
    fn a_rewritten_event_can_still_be_quarantined_later() {
        let d = tempfile::tempdir().unwrap();
        let (mut s, _) = open(d.path());
        s.append(call_event(1, 1)).unwrap();
        s.registry_conflict(&mref(1)).unwrap();
        s.quarantined(&[uid(1)], QuarantineCode::SemanticInvalid);
        assert_eq!(s.snapshot().quarantined_events, 1);
        assert!(s.next_events(10, &HashSet::new()).is_empty());
    }

    fn originals(dir: &Path) -> i64 {
        Connection::open(dir.join(SPOOL_FILE))
            .unwrap()
            .query_row("SELECT count(*) FROM rewrite_originals", [], |r| r.get(0))
            .unwrap()
    }

    /// `(code, bytes, size)` of the quarantine row of `event_id`.
    fn quarantined_row(dir: &Path, event_id: &str) -> (String, Vec<u8>, i64) {
        Connection::open(dir.join(SPOOL_FILE))
            .unwrap()
            .query_row(
                "SELECT code, bytes, size FROM quarantine WHERE event_id = ?1",
                [event_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap()
    }

    /// The bytes the spool stored for `call_event(n, m)` before any rewrite.
    fn original_bytes(n: u32, m: u32, sequence: i64) -> Vec<u8> {
        let mut e = call_event(n, m);
        e.sequence = PositiveI64::new(sequence).unwrap();
        serde_json::to_vec(&e).unwrap()
    }

    #[test]
    fn a_quarantined_rewritten_event_keeps_its_original_bytes() {
        let d = tempfile::tempdir().unwrap();
        let (mut s, _) = open(d.path());
        s.append(call_event(1, 1)).unwrap();
        s.registry_conflict(&mref(1)).unwrap();
        let rewritten_size = s.snapshot().unsent_bytes;
        s.quarantined(&[uid(1)], QuarantineCode::SemanticInvalid);
        let (_, bytes, size) = quarantined_row(d.path(), &uid(1));
        let want = original_bytes(1, 1, 1);
        assert_eq!(bytes, want);
        assert_eq!(size, want.len() as i64);
        // The unsent counters dropped the REWRITTEN size they had held.
        let snap = s.snapshot();
        assert_eq!((snap.unsent_events, snap.unsent_bytes), (0, 0));
        assert!(rewritten_size > 0);
        assert_eq!(snap.quarantined_events, 1);
        assert_eq!(originals(d.path()), 0);
    }

    #[test]
    fn an_acknowledged_rewritten_event_leaves_its_original_in_quarantine_when_purged() {
        let d = tempfile::tempdir().unwrap();
        let (mut s, now) = open(d.path());
        s.append(call_event(1, 1)).unwrap();
        s.append(call_event(2, 2)).unwrap();
        s.append(event(3)).unwrap();
        s.registry_conflict(&mref(1)).unwrap();
        s.registry_conflict(&mref(2)).unwrap();
        s.acknowledged(&[uid(1), uid(2), uid(3)]);
        // Kept as a rewrite original while the acknowledged row is retained.
        assert_eq!(originals(d.path()), 2);
        now.fetch_add(86_400 + 1, Ordering::SeqCst);
        s.expire_now().unwrap();
        assert_eq!(originals(d.path()), 0);
        for (n, m) in [(1, 1), (2, 2)] {
            let (code, bytes, size) = quarantined_row(d.path(), &uid(n));
            assert_eq!(code, ORIGINAL_CODE);
            let want = original_bytes(n, m, n as i64);
            assert_eq!(bytes, want);
            assert_eq!(size, want.len() as i64);
        }
        let snap = s.snapshot();
        // Evidence, not lost events: not counted as quarantined events, but the
        // bytes are accounted for.
        assert_eq!(snap.quarantined_events, 0);
        assert!(snap.quarantined_bytes > 0);
        assert_eq!(snap.retained_acked_events, 0);
        // The evidence id cannot be appended again.
        assert_eq!(s.append(call_event(1, 1)), Err(AppendError::Duplicate));
    }

    #[test]
    fn purging_all_acknowledged_rows_also_archives_the_originals() {
        let d = tempfile::tempdir().unwrap();
        let now = Arc::new(AtomicI64::new(1_800_000_000));
        let mut c = cfg(d.path(), now);
        // Room for one event only: the second append purges the acknowledged row.
        c.capacity_bytes = event_size() * 2 + 400;
        c.gap_reserve_bytes = 100;
        let s = Spool::open(c).unwrap();
        s.append(call_event(1, 1)).unwrap();
        s.registry_conflict(&mref(1)).unwrap();
        let mut src = s.clone();
        src.acknowledged(&[uid(1)]);
        for n in 2..6 {
            let _ = s.append(call_event(n, 99));
        }
        let (code, bytes, _) = quarantined_row(d.path(), &uid(1));
        assert_eq!(code, ORIGINAL_CODE);
        assert_eq!(bytes, original_bytes(1, 1, 1));
    }

    #[test]
    fn an_expired_rewritten_unsent_event_quarantines_its_original_bytes() {
        let d = tempfile::tempdir().unwrap();
        let (s, now) = open(d.path());
        s.append(call_event(1, 1)).unwrap();
        s.registry_conflict(&mref(1)).unwrap();
        s.set_max_offline_retry_age(Duration::from_secs(10));
        now.fetch_add(11, Ordering::SeqCst);
        let r = s.expire_now().unwrap();
        assert_eq!(r.expired_events, 1);
        let (code, bytes, size) = quarantined_row(d.path(), &uid(1));
        assert_eq!(code, EXPIRED_CODE);
        let want = original_bytes(1, 1, 1);
        assert_eq!(bytes, want);
        assert_eq!(size, want.len() as i64);
        assert_eq!(originals(d.path()), 0);
    }

    #[test]
    fn counters_after_a_restart_do_not_count_originals_as_quarantined_events() {
        let d = tempfile::tempdir().unwrap();
        {
            let (mut s, now) = open(d.path());
            s.append(call_event(1, 1)).unwrap();
            s.registry_conflict(&mref(1)).unwrap();
            s.acknowledged(&[uid(1)]);
            now.fetch_add(86_400 + 1, Ordering::SeqCst);
            s.expire_now().unwrap();
            s.close_blocking_for_test();
        }
        let now = Arc::new(AtomicI64::new(1_800_000_000));
        let mut c = cfg(d.path(), now);
        c.new_epoch = false;
        let s = Spool::open(c).unwrap();
        let snap = s.snapshot();
        assert_eq!(snap.quarantined_events, 0);
        assert!(snap.quarantined_bytes > 0);
    }

    #[test]
    fn databases_without_the_originals_table_are_upgraded_in_place() {
        let d = tempfile::tempdir().unwrap();
        {
            let (s, _) = open(d.path());
            s.append(call_event(1, 1)).unwrap();
            s.close_blocking_for_test();
            let c = Connection::open(d.path().join(SPOOL_FILE)).unwrap();
            c.execute_batch("DROP TABLE rewrite_originals").unwrap();
        }
        let now = Arc::new(AtomicI64::new(1_800_000_000));
        let mut c = cfg(d.path(), now);
        c.new_epoch = false;
        let s = Spool::open(c).unwrap();
        assert_eq!(s.registry_conflict(&mref(1)).unwrap(), vec![uid(1)]);
    }

    const R: i64 = 3600;
    const Q: i64 = 7200;

    /// Injected wall and boot clocks. `boot_id` `None` means no boot clock.
    struct Clocks {
        wall: Arc<AtomicI64>,
        boot: Arc<AtomicI64>,
        boot_id: Arc<Mutex<Option<Arc<str>>>>,
    }

    impl Clocks {
        fn new() -> Clocks {
            Clocks {
                wall: Arc::new(AtomicI64::new(1_800_000_000)),
                boot: Arc::new(AtomicI64::new(1000)),
                boot_id: Arc::new(Mutex::new(Some("boot-a".into()))),
            }
        }

        /// Call while no spool is open, as a real reboot would be.
        fn set_boot(&self, id: Option<&str>, secs: i64) {
            *self.boot_id.lock().unwrap() = id.map(Arc::from);
            self.boot.store(secs, Ordering::SeqCst);
        }

        fn step_wall(&self, secs: i64) {
            self.wall.fetch_add(secs, Ordering::SeqCst);
        }

        fn run_boot(&self, secs: i64) {
            self.boot.fetch_add(secs, Ordering::SeqCst);
        }

        fn open(&self, dir: &Path) -> Spool {
            let mut c = cfg(dir, self.wall.clone());
            c.max_offline_retry_age = Duration::from_secs(R as u64);
            let (boot, id) = (self.boot.clone(), self.boot_id.clone());
            c.boot_clock = Arc::new(move || {
                Some(BootInstant {
                    boot_id: id.lock().unwrap().clone()?,
                    secs: boot.load(Ordering::SeqCst),
                })
            });
            let s = Spool::open(c).unwrap();
            s.set_quarantine_retention(Duration::from_secs(Q as u64));
            // Commands queue behind the writer's start pass, so this waits it out.
            s.expire_now().unwrap();
            s
        }

        fn restart(&self, s: Spool, dir: &Path) -> Spool {
            s.close_blocking_for_test();
            self.open(dir)
        }
    }

    fn expired(s: &Spool) -> u64 {
        s.expire_now().unwrap().expired_events
    }

    fn purged(s: &Spool) -> u64 {
        s.expire_now().unwrap().purged_quarantined
    }

    /// One quarantined row, as of the clocks at the call.
    fn quarantined_one(s: &mut Spool, n: u32) {
        s.append(event(n)).unwrap();
        s.quarantined(&[uid(n)], QuarantineCode::SemanticInvalid);
    }

    #[test]
    fn a_forward_wall_step_does_not_expire_events_within_a_boot() {
        let d = tempfile::tempdir().unwrap();
        let clk = Clocks::new();
        let s = clk.open(d.path());
        s.append(event(1)).unwrap();
        clk.step_wall(100 * R);
        assert_eq!(expired(&s), 0);
        assert_eq!(s.snapshot().unsent_events, 1);
        clk.run_boot(R - 1);
        assert_eq!(expired(&s), 0);
        clk.run_boot(1);
        assert_eq!(expired(&s), 1);
    }

    #[test]
    fn a_backward_wall_step_does_not_delay_expiry_past_the_boot_age() {
        let d = tempfile::tempdir().unwrap();
        let clk = Clocks::new();
        let s = clk.open(d.path());
        s.append(event(1)).unwrap();
        clk.step_wall(-100 * R);
        clk.run_boot(R - 1);
        assert_eq!(expired(&s), 0);
        clk.run_boot(1);
        assert_eq!(expired(&s), 1);
    }

    #[test]
    fn an_event_of_another_boot_ages_on_the_wall_clock() {
        let d = tempfile::tempdir().unwrap();
        let clk = Clocks::new();
        let s = clk.open(d.path());
        s.append(event(1)).unwrap();
        s.close_blocking_for_test();
        clk.set_boot(Some("boot-b"), 100 * R);
        let s = clk.open(d.path());
        clk.step_wall(R - 1);
        assert_eq!(expired(&s), 0);
        clk.step_wall(1);
        assert_eq!(expired(&s), 1);
    }

    #[test]
    fn an_event_without_a_stamp_ages_on_the_wall_clock() {
        let d = tempfile::tempdir().unwrap();
        let clk = Clocks::new();
        clk.set_boot(None, 0);
        let s = clk.open(d.path());
        s.append(event(1)).unwrap();
        s.close_blocking_for_test();
        clk.set_boot(Some("boot-a"), 1000);
        let s = clk.open(d.path());
        clk.run_boot(100 * R);
        assert_eq!(expired(&s), 0);
        clk.step_wall(R);
        assert_eq!(expired(&s), 1);
    }

    #[test]
    fn a_row_written_without_a_reading_while_open_ages_on_the_wall_clock() {
        let d = tempfile::tempdir().unwrap();
        let clk = Clocks::new();
        let mut s = clk.open(d.path());
        *clk.boot_id.lock().unwrap() = None;
        s.append(event(1)).unwrap();
        quarantined_one(&mut s, 2);
        *clk.boot_id.lock().unwrap() = Some("boot-a".into());
        clk.step_wall(Q + 1);
        let r = s.expire_now().unwrap();
        assert_eq!((r.expired_events, r.purged_quarantined), (1, 1));
    }

    #[test]
    fn an_event_keeps_its_boot_age_across_a_restart_in_the_same_boot() {
        let d = tempfile::tempdir().unwrap();
        let clk = Clocks::new();
        let s = clk.open(d.path());
        s.append(event(1)).unwrap();
        clk.run_boot(R - 1);
        clk.step_wall(100 * R);
        let s = clk.restart(s, d.path());
        assert_eq!(expired(&s), 0);
        clk.run_boot(1);
        assert_eq!(expired(&s), 1);
    }

    #[test]
    fn a_forward_wall_step_does_not_purge_quarantine_within_a_boot() {
        let d = tempfile::tempdir().unwrap();
        let clk = Clocks::new();
        let mut s = clk.open(d.path());
        quarantined_one(&mut s, 1);
        clk.step_wall(100 * Q);
        assert_eq!(purged(&s), 0);
        clk.run_boot(Q);
        assert_eq!(purged(&s), 0);
        clk.run_boot(1);
        assert_eq!(purged(&s), 1);
        assert_eq!(s.snapshot().quarantined_events, 0);
    }

    #[test]
    fn a_backward_wall_step_does_not_delay_the_q_purge_past_the_boot_age() {
        let d = tempfile::tempdir().unwrap();
        let clk = Clocks::new();
        let mut s = clk.open(d.path());
        quarantined_one(&mut s, 1);
        clk.step_wall(-100 * Q);
        clk.run_boot(Q + 1);
        assert_eq!(purged(&s), 1);
    }

    #[test]
    fn a_quarantine_row_of_another_boot_ages_on_the_wall_clock() {
        let d = tempfile::tempdir().unwrap();
        let clk = Clocks::new();
        let mut s = clk.open(d.path());
        quarantined_one(&mut s, 1);
        s.close_blocking_for_test();
        clk.set_boot(Some("boot-b"), 100 * Q);
        let s = clk.open(d.path());
        clk.step_wall(Q);
        assert_eq!(purged(&s), 0);
        clk.step_wall(1);
        assert_eq!(purged(&s), 1);
    }

    #[test]
    fn a_quarantine_row_without_a_stamp_ages_on_the_wall_clock() {
        let d = tempfile::tempdir().unwrap();
        let clk = Clocks::new();
        clk.set_boot(None, 0);
        let mut s = clk.open(d.path());
        quarantined_one(&mut s, 1);
        s.close_blocking_for_test();
        clk.set_boot(Some("boot-a"), 1000);
        let s = clk.open(d.path());
        clk.run_boot(100 * Q);
        assert_eq!(purged(&s), 0);
        clk.step_wall(Q + 1);
        assert_eq!(purged(&s), 1);
    }

    #[test]
    fn a_quarantine_row_keeps_its_boot_age_across_a_restart_in_the_same_boot() {
        let d = tempfile::tempdir().unwrap();
        let clk = Clocks::new();
        let mut s = clk.open(d.path());
        quarantined_one(&mut s, 1);
        clk.run_boot(Q);
        clk.step_wall(100 * Q);
        let s = clk.restart(s, d.path());
        assert_eq!(purged(&s), 0);
        clk.run_boot(1);
        assert_eq!(purged(&s), 1);
    }

    /// An event moved to quarantine ages from the move, on the boot clock, even if
    /// it came from another boot.
    #[test]
    fn expiry_stamps_the_quarantine_row_it_creates() {
        let d = tempfile::tempdir().unwrap();
        let clk = Clocks::new();
        let s = clk.open(d.path());
        s.append(event(1)).unwrap();
        s.close_blocking_for_test();
        clk.set_boot(Some("boot-b"), 1000);
        let s = clk.open(d.path());
        clk.step_wall(R);
        assert_eq!(expired(&s), 1);
        clk.step_wall(100 * Q);
        assert_eq!(purged(&s), 0);
        clk.run_boot(Q + 1);
        assert_eq!(purged(&s), 1);
    }

    /// The archived original of a purged acknowledged event is a quarantine row
    /// like any other.
    #[test]
    fn an_archived_original_ages_on_the_boot_clock() {
        let d = tempfile::tempdir().unwrap();
        let clk = Clocks::new();
        let s = clk.open(d.path());
        let mut src = s.clone();
        s.append(call_event(1, 1)).unwrap();
        s.registry_conflict(&mref(1)).unwrap();
        src.acknowledged(&[uid(1)]);
        clk.step_wall(86_400 + 1);
        assert_eq!(s.expire_now().unwrap().purged_acked, 1);
        assert_eq!(quarantine_rows(d.path()), 1);
        clk.step_wall(100 * Q);
        assert_eq!(purged(&s), 0);
        clk.run_boot(Q + 1);
        assert_eq!(purged(&s), 1);
    }

    fn expired_ranges(s: &Spool) -> Vec<(i64, i64)> {
        let mut ranges: Vec<(i64, i64)> = s
            .pending_gaps()
            .unwrap()
            .iter()
            .map(|g| match g {
                GapReport::SpoolExpired(x) => (x.from_sequence.get(), x.to_sequence.get()),
                _ => panic!("kind"),
            })
            .collect();
        ranges.sort();
        ranges
    }

    /// `appended` events in boot-a, then `appended_b` in boot-b, all past R, with
    /// the spool open in boot-b.
    fn due_on_both_clocks(d: &Path, clk: &Clocks, appended: u32, appended_b: u32) -> Spool {
        let s = clk.open(d);
        for n in 1..=appended {
            s.append(event(n)).unwrap();
        }
        s.close_blocking_for_test();
        clk.set_boot(Some("boot-b"), 1000);
        let s = clk.open(d);
        for n in 1..=appended_b {
            s.append(event(appended + n)).unwrap();
        }
        clk.step_wall(R);
        clk.run_boot(R);
        s
    }

    #[test]
    fn boot_and_wall_rows_due_together_form_one_sequence_run() {
        let d = tempfile::tempdir().unwrap();
        let clk = Clocks::new();
        let s = due_on_both_clocks(d.path(), &clk, 2, 2);
        assert_eq!(expired(&s), 4);
        assert_eq!(expired_ranges(&s), vec![(1, 4)]);
    }

    /// Boot rows and wall rows share one batch: a pass that fills it with boot rows
    /// leaves the wall rows for the next pass.
    #[test]
    fn boot_and_wall_rows_share_one_maintenance_batch() {
        let d = tempfile::tempdir().unwrap();
        let clk = Clocks::new();
        let batch = MAINTENANCE_BATCH as u32;
        let s = due_on_both_clocks(d.path(), &clk, 5, batch);
        assert_eq!(expired(&s), batch as u64 + 5);
        assert_eq!(expired_ranges(&s), vec![(1, 5), (6, MAINTENANCE_BATCH + 5)]);
    }

    /// The wall walk skips stamped rows without counting them against the batch.
    #[test]
    fn stamped_rows_ahead_of_wall_rows_do_not_shrink_the_batch() {
        let d = tempfile::tempdir().unwrap();
        let clk = Clocks::new();
        let batch = MAINTENANCE_BATCH as u32;
        let s = clk.open(d.path());
        for n in 1..=batch + 5 {
            s.append(event(n)).unwrap();
        }
        s.close_blocking_for_test();
        clk.set_boot(Some("boot-b"), 1000);
        let s = clk.open(d.path());
        clk.step_wall(-10 * R);
        for n in batch + 6..=batch + 10 {
            s.append(event(n)).unwrap();
        }
        clk.step_wall(11 * R + 1);
        assert_eq!(expired(&s), batch as u64 + 5);
        let last = MAINTENANCE_BATCH + 5;
        assert_eq!(
            expired_ranges(&s),
            vec![(1, MAINTENANCE_BATCH), (MAINTENANCE_BATCH + 1, last)]
        );
        assert_eq!(s.snapshot().unsent_events, 5);
    }

    /// A stamped row can sit among older rows of another boot after a backward step.
    /// Its stamp still decides.
    #[test]
    fn a_current_stamp_wins_over_wall_age() {
        let d = tempfile::tempdir().unwrap();
        let clk = Clocks::new();
        let mut s = clk.open(d.path());
        quarantined_one(&mut s, 1);
        s.append(event(2)).unwrap();
        s.close_blocking_for_test();
        clk.set_boot(Some("boot-b"), 1000);
        let mut s = clk.open(d.path());
        clk.step_wall(-100 * Q);
        s.append(event(3)).unwrap();
        quarantined_one(&mut s, 4);
        clk.step_wall(100 * Q);
        let r = s.expire_now().unwrap();
        assert_eq!((r.expired_events, r.purged_quarantined), (0, 0));
    }

    fn stamps(dir: &Path) -> (i64, i64) {
        let c = Connection::open(dir.join(SPOOL_FILE)).unwrap();
        let n = |t: &str| {
            c.query_row(&format!("SELECT count(*) FROM {t}"), [], |r| r.get(0))
                .unwrap()
        };
        (n("event_boot_stamps"), n("quarantine_boot_stamps"))
    }

    /// Ack, quarantine, expiry and the Q purge each leave exactly one stamp per
    /// unsent event and per quarantine row.
    #[test]
    fn stamps_follow_their_rows_on_every_path() {
        let d = tempfile::tempdir().unwrap();
        let clk = Clocks::new();
        let mut s = clk.open(d.path());
        for n in 1..=4 {
            s.append(event(n)).unwrap();
        }
        assert_eq!(stamps(d.path()), (4, 0));
        s.acknowledged(&[uid(1)]);
        assert_eq!(stamps(d.path()), (3, 0));
        s.quarantined(&[uid(2)], QuarantineCode::SemanticInvalid);
        assert_eq!(stamps(d.path()), (2, 1));
        clk.run_boot(R);
        assert_eq!(expired(&s), 2);
        assert_eq!(stamps(d.path()), (0, 3));
        clk.run_boot(Q + 1);
        assert_eq!(purged(&s), 3);
        assert_eq!(stamps(d.path()), (0, 0));
    }

    /// An older binary knows nothing of the stamps. The triggers live in the
    /// database, so its plain SQL leaves no orphan either.
    #[test]
    fn stamps_leave_with_rows_that_an_older_binary_changes() {
        let d = tempfile::tempdir().unwrap();
        let clk = Clocks::new();
        let mut s = clk.open(d.path());
        s.append(event(1)).unwrap();
        s.append(event(2)).unwrap();
        quarantined_one(&mut s, 3);
        s.close_blocking_for_test();
        assert_eq!(stamps(d.path()), (2, 1));
        let c = Connection::open(d.path().join(SPOOL_FILE)).unwrap();
        c.execute_batch(
            "UPDATE events SET state = 1, acked_at = 0 WHERE sequence = 1;
             DELETE FROM events WHERE sequence = 2;
             DELETE FROM quarantine;",
        )
        .unwrap();
        assert_eq!(stamps(d.path()), (0, 0));
    }

    /// The schema change is additive: the version stays, and a database from
    /// before the stamps upgrades in place with its rows aging on the wall clock.
    #[test]
    fn databases_without_boot_stamps_are_upgraded_in_place() {
        let d = tempfile::tempdir().unwrap();
        let clk = Clocks::new();
        let mut s = clk.open(d.path());
        s.append(event(1)).unwrap();
        quarantined_one(&mut s, 2);
        s.close_blocking_for_test();
        let c = Connection::open(d.path().join(SPOOL_FILE)).unwrap();
        let version: String = c
            .query_row(
                "SELECT value FROM meta WHERE key = 'schema_version'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(version, "1");
        c.execute_batch(
            "DROP TRIGGER event_boot_stamps_on_delete;
             DROP TRIGGER event_boot_stamps_on_ack;
             DROP TRIGGER quarantine_boot_stamps_on_delete;
             DROP TABLE event_boot_stamps;
             DROP TABLE quarantine_boot_stamps;
             DROP INDEX idx_unsent_created;",
        )
        .unwrap();
        let s = clk.open(d.path());
        assert_eq!(stamps(d.path()), (0, 0));
        clk.step_wall(Q + 1);
        let r = s.expire_now().unwrap();
        assert_eq!((r.expired_events, r.purged_quarantined), (1, 1));
    }
}
