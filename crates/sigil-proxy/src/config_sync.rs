//! Remote config fetch and apply (T-12c1, control-plane.md §5.2, §6.2-§6.4).
//!
//! * [`ConfigSync`] is the pure state machine: it takes fetch results and the
//!   monotonic clock, parses with `sigil_proxy_api::parse_config`, builds a
//!   [`RouteTable`] and swaps it into the [`TableHandle`]. It reads no network.
//! * [`MtlsFetcher`] (unix) does the `GET /v1/proxy-config` over mTLS.
//! * [`run_sync`] polls, with jitter, and enforces the TTL deadline.
//!
//! Rules, all fail closed:
//! * The deadline is `receipt + ttl_seconds` on the monotonic clock. `expires_at`
//!   is display only and never read. The deadline also lives in the
//!   [`TableHandle`], so expiry holds even if the polling task dies. (A
//!   monotonic `Instant` does not count system suspend on Linux/macOS, so a VM or
//!   host suspend stretches the TTL; known limit.)
//! * A failed fetch, parse, build or ordering check keeps the last good table
//!   until its deadline, never extends it, and then the table is removed (the
//!   listener answers 401).
//! * A revision below the highest one ever applied (the high-water mark, kept
//!   after expiry) is never applied.
//! * The config itself is never persisted: a restarted proxy needs a fresh fetch
//!   (§6.3 "Restart", decided 2026-10-10). Only the `{revision, config_hash}`
//!   high-water mark is persisted (through [`Persister`], written after the new
//!   table is built and before it is installed), so a restart cannot accept a
//!   rolled-back revision.
//! * The remote config is never merged with the local bootstrap. The local
//!   credentials and limits are constraints: an unknown `credential_ref` or an
//!   origin outside its binding fails the whole apply, and remote limits can only
//!   lower the local ones.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use sigil_proxy_api::status::{ConfigState, LastUpdateError};
use sigil_proxy_api::{ConfigRoute, ProxyConfig};
use tokio::time::Instant;

use crate::bootstrap::Credential;
use crate::limits::{Limits, RemoteLimits};
use crate::route::{PrincipalSpec, RouteSpec, RouteTable, TableHandle, VerifierSpec};

/// Largest config body accepted from the server. The PUT cap is 1 MiB; a fetched
/// document carries a few extra stamps, so 4 MiB is generous and still bounded.
pub const MAX_CONFIG_BYTES: usize = 4 * 1024 * 1024;

/// Result of one fetch attempt, already reduced to what the state machine needs.
/// No variant carries a body other than the config document itself.
#[derive(Clone, PartialEq, Eq)]
pub enum FetchResult {
    /// `200` with the raw body (not yet validated).
    Config(Vec<u8>),
    /// `403` with the fixed `disabled` (or `retired`) code (§6.2 M-10).
    Disabled,
    /// `503`: the server's boot gate. A retryable miss, not an apply failure.
    Unavailable,
    /// Transport error, timeout, oversized body or any other status.
    Failed,
}

/// The body holds verifiers, so `Debug` prints only its length.
impl std::fmt::Debug for FetchResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FetchResult::Config(b) => write!(f, "Config({} bytes)", b.len()),
            FetchResult::Disabled => f.write_str("Disabled"),
            FetchResult::Unavailable => f.write_str("Unavailable"),
            FetchResult::Failed => f.write_str("Failed"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncOutcome {
    /// A new revision was built and installed.
    Applied { revision: i64 },
    /// Same revision and hash: the deadline was extended.
    Refreshed,
    /// The proxy was told it is disabled; the table was removed.
    Disabled,
    /// Nothing changed (or the old config stays) for this reason.
    Kept(LastUpdateError),
}

/// What the lifecycle publishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncStatus {
    pub config_state: ConfigState,
    pub last_update_error: Option<LastUpdateError>,
}

/// The config facts a status report needs (control-plane.md section 6.2 "Status
/// report"). Identifiers, counts and the hash only: no route, principal, verifier
/// or credential content. Published through a watch channel so the status
/// reporter sees every change without sharing the state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigView {
    pub state: ConfigState,
    pub last_update_error: Option<LastUpdateError>,
    /// Highest revision applied (survives expiry, disable and restart).
    pub applied_revision: Option<i64>,
    pub config_hash: Option<String>,
    /// Latest revision the server offered, applied or not.
    pub observed_revision: Option<i64>,
    /// Display values of the last applied document; `None` before the first
    /// apply of this process.
    pub expires_at: Option<String>,
    pub max_offline_retry_age_seconds: Option<i64>,
    pub event_retention_seconds: Option<i64>,
    /// `upstream_id`s of the last applied document, in config order (the status
    /// report's `routes`; empty before the first apply of this process).
    pub route_upstreams: Vec<String>,
}

/// Why a parsed config could not become a table. Fixed categories only.
struct BuildError;

/// Unix seconds of a validated RFC 3339 timestamp.
fn unix_of(ts: &sigil_proxy_api::Timestamp) -> Option<i64> {
    time::OffsetDateTime::parse(ts.as_str(), &time::format_description::well_known::Rfc3339)
        .ok()
        .map(|t| t.unix_timestamp())
}

fn remote_limits(r: &ConfigRoute) -> RemoteLimits {
    let pos = |v: Option<i64>| v.and_then(|n| u64::try_from(n).ok()).filter(|n| *n > 0);
    match &r.limits {
        None => RemoteLimits::default(),
        Some(l) => RemoteLimits {
            max_request_bytes: pos(l.max_request_bytes),
            max_response_bytes: pos(l.max_response_bytes),
            request_timeout_seconds: pos(l.request_timeout_seconds),
        },
    }
}

/// Map the config DTO to the route builder's input. The config-wide
/// `allowed_origins` applies to every route; principals are attached to the routes
/// they name. `allow_private_destination` is always false: the DTO has no such
/// field yet (contract OPEN), so a private destination is refused (fail closed).
fn route_specs(cfg: &ProxyConfig) -> Result<Vec<RouteSpec>, BuildError> {
    let mut out = Vec::with_capacity(cfg.routes.len());
    for r in &cfg.routes {
        let mut principals = Vec::new();
        for p in cfg
            .principals
            .iter()
            .filter(|p| p.routes.iter().any(|id| id == &r.route_id))
        {
            let mut verifiers = Vec::new();
            for v in &p.verifiers {
                let not_after = match &v.not_after {
                    None => None,
                    Some(ts) => Some(unix_of(ts).ok_or(BuildError)?),
                };
                verifiers.push(VerifierSpec {
                    verifier: v.verifier.clone(),
                    not_after,
                });
            }
            principals.push(PrincipalSpec {
                principal_id: p.principal_id.clone(),
                verifiers,
                actor_kind: p.actor_kind,
                credential_owner_id: p.credential_owner_id.clone(),
            });
        }
        out.push(RouteSpec {
            route_id: r.route_id.clone(),
            upstream_url: r.upstream_url.clone(),
            credential_ref: r.credential_ref.as_str().to_string(),
            principals,
            allowed_origins: cfg.allowed_origins.clone(),
            allow_private_destination: false,
            limits: remote_limits(r),
            scope: Some(crate::route::RouteScope {
                upstream_id: r.upstream_id.as_str().to_string(),
                credential_scope_id: r.credential_scope_id.as_str().to_string(),
            }),
        });
    }
    Ok(out)
}

fn meta_of(cfg: &ProxyConfig) -> (String, i64, i64) {
    (
        cfg.expires_at.as_str().to_string(),
        cfg.max_offline_retry_age_seconds,
        cfg.event_retention_seconds,
    )
}

fn upstreams_of(cfg: &ProxyConfig) -> Vec<String> {
    cfg.routes
        .iter()
        .map(|r| r.upstream_id.as_str().to_string())
        .collect()
}

struct Applied {
    revision: i64,
    hash: String,
}

/// Called with `(revision, config_hash)` after a new config has been built and
/// before it is installed. `false` (persist failed) aborts the apply: without a
/// durable high-water mark a restart could accept a rollback, so fail closed.
pub type Persister = Box<dyn FnMut(i64, &str) -> bool + Send>;

/// The apply state machine. Its only I/O is the optional [`Persister`].
pub struct ConfigSync {
    persister: Option<Persister>,
    proxy_id: String,
    credentials: BTreeMap<String, Credential>,
    limits: Limits,
    table: TableHandle,
    /// Highest revision applied by this process; survives expiry and disable.
    high_water: Option<Applied>,
    /// Monotonic deadline of the installed table. `None` means no table.
    deadline: Option<Instant>,
    /// `ttl_seconds` of the last accepted config, used to pace polling.
    last_ttl: Option<i64>,
    state: ConfigState,
    last_error: Option<LastUpdateError>,
    observed_revision: Option<i64>,
    /// `(expires_at, R, E)` of the last applied document, display only.
    applied_meta: Option<(String, i64, i64)>,
    /// `upstream_id`s of the last applied document (status report `routes`).
    applied_upstreams: Vec<String>,
    view_tx: Option<tokio::sync::watch::Sender<ConfigView>>,
}

impl ConfigSync {
    /// `initial` is the lifecycle's startup state (`none`, `expired` or
    /// `disabled`); a `valid` initial state is never accepted.
    pub fn new(
        proxy_id: &str,
        credentials: BTreeMap<String, Credential>,
        limits: Limits,
        table: TableHandle,
        initial: ConfigState,
    ) -> ConfigSync {
        ConfigSync {
            persister: None,
            proxy_id: proxy_id.to_string(),
            credentials,
            limits,
            table,
            high_water: None,
            deadline: None,
            last_ttl: None,
            state: if initial == ConfigState::Valid {
                ConfigState::Expired
            } else {
                initial
            },
            last_error: None,
            observed_revision: None,
            applied_meta: None,
            applied_upstreams: Vec::new(),
            view_tx: None,
        }
    }

    /// Current facts for a status report.
    pub fn view(&self) -> ConfigView {
        let meta = self.applied_meta.as_ref();
        ConfigView {
            state: self.state,
            last_update_error: self.last_error,
            applied_revision: self.high_water.as_ref().map(|a| a.revision),
            config_hash: self.high_water.as_ref().map(|a| a.hash.clone()),
            observed_revision: self.observed_revision,
            expires_at: meta.map(|m| m.0.clone()),
            max_offline_retry_age_seconds: meta.map(|m| m.1),
            event_retention_seconds: meta.map(|m| m.2),
            route_upstreams: self.applied_upstreams.clone(),
        }
    }

    /// Publish every change of [`ConfigSync::view`] on the returned receiver. The
    /// receiver starts with the current view.
    pub fn with_view_channel(mut self) -> (ConfigSync, tokio::sync::watch::Receiver<ConfigView>) {
        let (tx, rx) = tokio::sync::watch::channel(self.view());
        self.view_tx = Some(tx);
        (self, rx)
    }

    fn notify_view(&self) {
        if let Some(tx) = &self.view_tx {
            let v = self.view();
            tx.send_if_modified(|cur| {
                if *cur == v {
                    false
                } else {
                    *cur = v;
                    true
                }
            });
        }
    }

    /// Persist the high-water mark on every new apply.
    pub fn with_persister(mut self, p: Persister) -> ConfigSync {
        self.persister = Some(p);
        self
    }

    /// Seed the high-water mark loaded from `state_dir` at start. Nothing is
    /// installed: the table still needs a fresh fetch (§6.3 "Restart").
    pub fn with_high_water(mut self, revision: i64, hash: String) -> ConfigSync {
        self.high_water = Some(Applied { revision, hash });
        self
    }

    pub fn status(&self) -> SyncStatus {
        SyncStatus {
            config_state: self.state,
            last_update_error: self.last_error,
        }
    }

    pub fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    pub fn last_ttl_seconds(&self) -> Option<i64> {
        self.last_ttl
    }

    pub fn applied_revision(&self) -> Option<i64> {
        self.high_water.as_ref().map(|a| a.revision)
    }

    /// Remove the table once its deadline has passed. Idempotent. (The handle also
    /// enforces the deadline by itself on every `current()`; this is the state
    /// machine catching up and clearing the slot.)
    pub fn expire(&mut self, now: Instant) {
        self.expire_inner(now);
        self.notify_view();
    }

    fn expire_inner(&mut self, now: Instant) {
        if self.deadline.is_some_and(|d| now >= d) {
            self.table.set(None);
            self.deadline = None;
            self.state = ConfigState::Expired;
        }
    }

    fn keep(&mut self, e: LastUpdateError) -> SyncOutcome {
        self.last_error = Some(e);
        SyncOutcome::Kept(e)
    }

    /// Feed one fetch result received at `now` (monotonic, the receipt time).
    pub fn on_fetch(&mut self, now: Instant, result: FetchResult) -> SyncOutcome {
        let outcome = self.on_fetch_inner(now, result);
        self.notify_view();
        outcome
    }

    fn on_fetch_inner(&mut self, now: Instant, result: FetchResult) -> SyncOutcome {
        self.expire_inner(now);
        match result {
            FetchResult::Failed | FetchResult::Unavailable => {
                self.keep(LastUpdateError::FetchFailed)
            }
            FetchResult::Disabled => {
                // Stop new calls at once (§6.2 M-10). The high-water mark stays.
                self.table.set(None);
                self.deadline = None;
                self.state = ConfigState::Disabled;
                self.last_error = None;
                SyncOutcome::Disabled
            }
            FetchResult::Config(body) => self.on_config(now, &body),
        }
    }

    fn on_config(&mut self, now: Instant, body: &[u8]) -> SyncOutcome {
        let cfg = match sigil_proxy_api::parse_config(body) {
            Ok(c) => c,
            Err(_) => return self.keep(LastUpdateError::ValidationFailed),
        };
        if cfg.proxy_id.as_str() != self.proxy_id {
            return self.keep(LastUpdateError::ValidationFailed);
        }
        self.observed_revision = Some(cfg.revision.get());
        let revision = cfg.revision.get();
        let hash = cfg.config_hash().as_str().to_string();
        let ttl = cfg.ttl_seconds;
        // `parse_config` validated 60..=900; re-check so a changed parser can
        // never produce a negative or huge duration here.
        let Ok(ttl_secs) = u64::try_from(ttl) else {
            return self.keep(LastUpdateError::ValidationFailed);
        };

        let mut refresh = false;
        if let Some(hw) = &self.high_water {
            if revision < hw.revision {
                // Server counter restored lower: keep, do not extend (§6.2).
                return self.keep(LastUpdateError::StaleRevision);
            }
            if revision == hw.revision {
                if hash != hw.hash {
                    return self.keep(LastUpdateError::ConfigHashMismatch);
                }
                refresh = true;
            }
        }

        // A refresh of an installed table only extends the deadline. If the table
        // is gone (expired or disabled), the same revision is installed again.
        if refresh && self.deadline.is_some() {
            let d = now + Duration::from_secs(ttl_secs);
            self.deadline = Some(d);
            self.table.extend_deadline(d);
            self.last_ttl = Some(ttl);
            self.applied_meta = Some(meta_of(&cfg));
            self.applied_upstreams = upstreams_of(&cfg);
            self.state = ConfigState::Valid;
            self.last_error = None;
            return SyncOutcome::Refreshed;
        }

        // Admission state of the installed table carries over (M4).
        let prev = self.table.last();
        let table = match route_specs(&cfg).and_then(|s| {
            RouteTable::build_carrying(&s, &self.credentials, &self.limits, prev.as_deref())
                .map(|t| t.with_revision(cfg.revision))
                .map_err(|_| BuildError)
        }) {
            Ok(t) => t,
            Err(_) => return self.keep(LastUpdateError::ApplyFailed),
        };
        if !refresh {
            if let Some(p) = self.persister.as_mut() {
                if !p(revision, &hash) {
                    return self.keep(LastUpdateError::ApplyFailed);
                }
            }
        }
        let deadline = now + Duration::from_secs(ttl_secs);
        self.table.set_with_deadline(table, deadline);
        self.high_water = Some(Applied { revision, hash });
        self.deadline = Some(deadline);
        self.last_ttl = Some(ttl);
        self.applied_meta = Some(meta_of(&cfg));
        self.applied_upstreams = upstreams_of(&cfg);
        self.state = ConfigState::Valid;
        self.last_error = None;
        if refresh {
            SyncOutcome::Refreshed
        } else {
            SyncOutcome::Applied { revision }
        }
    }
}

// ------------------------------------------------------------------ polling

pub type FetchFuture<'a> = Pin<Box<dyn Future<Output = FetchResult> + Send + 'a>>;

pub trait Fetcher: Send + Sync {
    fn fetch(&self) -> FetchFuture<'_>;
}

#[derive(Debug, Clone, Copy)]
pub struct SyncParams {
    /// Poll interval after a success, capped at a third of the TTL.
    pub poll: Duration,
    /// Retry interval after a failed fetch.
    pub retry: Duration,
}

impl Default for SyncParams {
    /// Proposed values of §6.3 (unmeasured): poll 30 s with jitter.
    fn default() -> Self {
        SyncParams {
            poll: Duration::from_secs(30),
            retry: Duration::from_secs(5),
        }
    }
}

/// `d` scaled by a random factor in `[0.8, 1.2]`. Without OS randomness there is
/// no jitter (the interval is still bounded).
pub(crate) fn jitter(d: Duration) -> Duration {
    let mut b = [0u8; 2];
    if getrandom::getrandom(&mut b).is_err() {
        return d;
    }
    let f = u16::from_le_bytes(b) as u64; // 0..=65535
    let permille = 800 + f * 400 / 65535;
    d * permille as u32 / 1000
}

fn next_poll_delay(sync: &ConfigSync, ok: bool, p: &SyncParams) -> Duration {
    if !ok {
        return jitter(p.retry);
    }
    let cap = sync
        .last_ttl_seconds()
        .and_then(|t| u64::try_from(t).ok())
        .map_or(p.poll, |t| Duration::from_secs(t / 3));
    jitter(p.poll.min(cap))
}

/// Poll until `shutdown` completes. `on_status` is called after every change of
/// the published status (including expiry that happens between polls).
///
/// The TTL deadline is enforced by its own timer, also while a fetch is in
/// flight, so a slow server cannot keep an expired table alive.
pub async fn run_sync<F, S>(
    mut sync: ConfigSync,
    fetcher: &F,
    params: SyncParams,
    mut on_status: S,
    shutdown: impl Future<Output = ()>,
) where
    F: Fetcher + ?Sized,
    S: FnMut(SyncStatus),
{
    tokio::pin!(shutdown);
    let mut last = sync.status();
    let mut next_poll = Instant::now();
    loop {
        // Wait for the next poll, expiring the table on time.
        loop {
            let wake = sync.deadline().map_or(next_poll, |d| d.min(next_poll));
            tokio::select! {
                _ = &mut shutdown => return,
                _ = tokio::time::sleep_until(wake) => {}
            }
            sync.expire(Instant::now());
            publish(&sync, &mut last, &mut on_status);
            if Instant::now() >= next_poll {
                break;
            }
        }

        // Fetch, still watching the deadline.
        let result = {
            let fetch = fetcher.fetch();
            tokio::pin!(fetch);
            loop {
                let dl = sync.deadline();
                tokio::select! {
                    _ = &mut shutdown => return,
                    r = &mut fetch => break r,
                    _ = async {
                        match dl {
                            Some(d) => tokio::time::sleep_until(d).await,
                            None => std::future::pending::<()>().await,
                        }
                    } => {
                        sync.expire(Instant::now());
                        publish(&sync, &mut last, &mut on_status);
                    }
                }
            }
        };
        let now = Instant::now();
        let outcome = sync.on_fetch(now, result);
        tracing::info!(outcome = outcome_label(outcome), "config fetch");
        publish(&sync, &mut last, &mut on_status);
        let ok = matches!(
            outcome,
            SyncOutcome::Applied { .. } | SyncOutcome::Refreshed | SyncOutcome::Disabled
        );
        next_poll = now + next_poll_delay(&sync, ok, &params);
    }
}

fn outcome_label(o: SyncOutcome) -> &'static str {
    match o {
        SyncOutcome::Applied { .. } => "applied",
        SyncOutcome::Refreshed => "refreshed",
        SyncOutcome::Disabled => "disabled",
        SyncOutcome::Kept(LastUpdateError::StaleRevision) => "kept_stale_revision",
        SyncOutcome::Kept(LastUpdateError::ValidationFailed) => "kept_validation_failed",
        SyncOutcome::Kept(LastUpdateError::FetchFailed) => "kept_fetch_failed",
        SyncOutcome::Kept(LastUpdateError::ApplyFailed) => "kept_apply_failed",
        SyncOutcome::Kept(LastUpdateError::ConfigHashMismatch) => "kept_config_hash_mismatch",
    }
}

fn publish(sync: &ConfigSync, last: &mut SyncStatus, on_status: &mut impl FnMut(SyncStatus)) {
    let now = sync.status();
    if now != *last {
        *last = now;
        on_status(now);
    }
}

// ------------------------------------------------------------- mTLS fetcher

#[cfg(unix)]
pub use mtls::MtlsFetcher;

#[cfg(unix)]
mod mtls {
    use super::*;
    use crate::bootstrap::{split_host_port, Bootstrap};
    use bytes::Bytes;
    use http_body_util::{BodyExt, Full, Limited};
    use hyper_util::rt::TokioIo;
    use std::path::PathBuf;

    /// Per-attempt bound: connect, handshake, request and body together.
    const FETCH_TIMEOUT: Duration = Duration::from_secs(10);

    pub struct MtlsFetcher {
        host: String,
        port: u16,
        authority: String,
        path: String,
        status_path: String,
        events_path: String,
        ca_file: PathBuf,
        cert_file: PathBuf,
        key_file: PathBuf,
        timeout: Duration,
    }

    impl MtlsFetcher {
        /// `None` when `control_plane_url` cannot be split (the bootstrap already
        /// validated it, so this does not happen for a loaded bootstrap).
        pub fn from_bootstrap(b: &Bootstrap) -> Option<MtlsFetcher> {
            let rest = b.control_plane_url.strip_prefix("https://")?;
            let (authority, prefix) = match rest.find('/') {
                Some(i) => (&rest[..i], rest[i..].trim_end_matches('/')),
                None => (rest, ""),
            };
            let (host, port) = split_host_port(authority).ok()?;
            let host = host
                .strip_prefix('[')
                .and_then(|h| h.strip_suffix(']'))
                .unwrap_or(&host)
                .to_string();
            Some(MtlsFetcher {
                authority: authority.to_ascii_lowercase(),
                host,
                port: port.unwrap_or(443),
                path: format!("{prefix}/v1/proxy-config"),
                status_path: format!("{prefix}/v1/proxy-status"),
                events_path: format!("{prefix}/v1/proxy-events"),
                ca_file: b.ca_file.clone(),
                cert_file: b.client_cert_file.clone(),
                key_file: b.client_key_file.clone(),
                timeout: FETCH_TIMEOUT,
            })
        }

        /// Test hook: a different per-attempt bound.
        pub fn with_timeout(mut self, t: Duration) -> Self {
            self.timeout = t;
            self
        }

        /// One request over a fresh mTLS connection (`Connection: close`). Shared
        /// by the config fetch and the status report, so there is a single client
        /// and a single set of key/CA checks. The body is `None` when it exceeds
        /// `max_body` or cannot be read.
        pub(crate) async fn exchange(
            &self,
            method: http::Method,
            path: &str,
            payload: Option<Vec<u8>>,
            max_body: usize,
        ) -> Option<(http::StatusCode, Option<Bytes>)> {
            let connector =
                crate::tls::control_plane_connector(&self.ca_file, &self.cert_file, &self.key_file)
                    .ok()?;
            let name = crate::tls::server_name(&self.host)?;
            let tcp = tokio::net::TcpStream::connect((self.host.as_str(), self.port))
                .await
                .ok()?;
            let _ = tcp.set_nodelay(true);
            let tls = connector.connect(name, tcp).await.ok()?;
            let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
                .await
                .ok()?;
            tokio::spawn(async move {
                let _ = conn.await;
            });
            let mut req = http::Request::builder()
                .method(method)
                .uri(path)
                .header(http::header::HOST, self.authority.as_str())
                .header(http::header::ACCEPT, "application/json")
                .header(http::header::CONNECTION, "close");
            if payload.is_some() {
                req = req.header(http::header::CONTENT_TYPE, "application/json");
            }
            let req = req
                .body(Full::new(Bytes::from(payload.unwrap_or_default())))
                .ok()?;
            let resp = sender.send_request(req).await.ok()?;
            let (parts, body) = resp.into_parts();
            let bytes = Limited::new(body, max_body)
                .collect()
                .await
                .ok()
                .map(|c| c.to_bytes());
            Some((parts.status, bytes))
        }

        async fn get(&self) -> Option<FetchResult> {
            let (status, bytes) = self
                .exchange(http::Method::GET, &self.path, None, MAX_CONFIG_BYTES)
                .await?;
            if status == http::StatusCode::SERVICE_UNAVAILABLE {
                return Some(FetchResult::Unavailable);
            }
            let bytes = bytes?;
            Some(match status {
                s if s == http::StatusCode::OK => FetchResult::Config(bytes.to_vec()),
                s if s == http::StatusCode::FORBIDDEN => {
                    match sigil_proxy_api::parse_api_error(&bytes) {
                        Ok(e)
                            if matches!(
                                e.error.code,
                                sigil_proxy_api::ErrorCode::Disabled
                                    | sigil_proxy_api::ErrorCode::Retired
                            ) =>
                        {
                            FetchResult::Disabled
                        }
                        _ => FetchResult::Failed,
                    }
                }
                _ => FetchResult::Failed,
            })
        }
    }

    impl crate::status_report::StatusTransport for MtlsFetcher {
        fn post_status(&self, body: Vec<u8>) -> crate::status_report::PostFuture<'_> {
            Box::pin(async move {
                let work = self.exchange(
                    http::Method::POST,
                    &self.status_path,
                    Some(body),
                    crate::status_report::MAX_STATUS_RESPONSE_BYTES,
                );
                match tokio::time::timeout(self.timeout, work).await {
                    Ok(Some((status, body))) => Some(crate::status_report::StatusReply {
                        status: status.as_u16(),
                        body: body.map(|b| b.to_vec()).unwrap_or_default(),
                    }),
                    // Transport error, timeout, bad TLS material: no answer.
                    _ => None,
                }
            })
        }
    }

    impl crate::ingest_client::IngestTransport for MtlsFetcher {
        fn post_events(&self, body: Vec<u8>) -> crate::status_report::PostFuture<'_> {
            Box::pin(async move {
                // Same client, caps and per-attempt bound as the status report.
                let work = self.exchange(
                    http::Method::POST,
                    &self.events_path,
                    Some(body),
                    crate::ingest_client::MAX_INGEST_RESPONSE_BYTES,
                );
                match tokio::time::timeout(self.timeout, work).await {
                    Ok(Some((status, body))) => Some(crate::status_report::StatusReply {
                        status: status.as_u16(),
                        body: body.map(|b| b.to_vec()).unwrap_or_default(),
                    }),
                    _ => None,
                }
            })
        }
    }

    impl Fetcher for MtlsFetcher {
        fn fetch(&self) -> FetchFuture<'_> {
            Box::pin(async move {
                match tokio::time::timeout(self.timeout, self.get()).await {
                    Ok(Some(r)) => r,
                    // Transport error, timeout, bad TLS material: all fetch_failed.
                    // The cause is not logged (it can carry paths or peer data).
                    _ => FetchResult::Failed,
                }
            })
        }
    }
}

/// Windows: the control-plane client is unix-only until the Windows proxy
/// service is verified; every fetch fails, so the proxy never forwards.
#[cfg(not(unix))]
pub struct MtlsFetcher;

#[cfg(not(unix))]
impl MtlsFetcher {
    pub fn from_bootstrap(_: &crate::bootstrap::Bootstrap) -> Option<MtlsFetcher> {
        Some(MtlsFetcher)
    }
}

#[cfg(not(unix))]
impl crate::status_report::StatusTransport for MtlsFetcher {
    fn post_status(&self, _: Vec<u8>) -> crate::status_report::PostFuture<'_> {
        Box::pin(async { None })
    }
}

#[cfg(not(unix))]
impl crate::ingest_client::IngestTransport for MtlsFetcher {
    fn post_events(&self, _: Vec<u8>) -> crate::status_report::PostFuture<'_> {
        Box::pin(async { None })
    }
}

#[cfg(not(unix))]
impl Fetcher for MtlsFetcher {
    fn fetch(&self) -> FetchFuture<'_> {
        Box::pin(async { FetchResult::Failed })
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    use std::os::unix::fs::PermissionsExt;

    const ORIGIN: &str = "https://api.example.com";

    struct Fx {
        _dir: tempfile::TempDir,
        creds: BTreeMap<String, Credential>,
    }

    fn fx() -> Fx {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("secret");
        std::fs::write(&p, "UPSTREAM-SECRET-VALUE\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        let creds = BTreeMap::from([(
            "gh".to_string(),
            Credential {
                secret_file: p,
                upstream_origins: vec![ORIGIN.to_string()],
            },
        )]);
        Fx { _dir: dir, creds }
    }

    fn sync(f: &Fx, table: &TableHandle) -> ConfigSync {
        ConfigSync::new(
            "px-1",
            f.creds.clone(),
            Limits::default(),
            table.clone(),
            ConfigState::None,
        )
    }

    fn v(tok: &str) -> String {
        sigil_proxy_api::verifier_for(tok)
    }

    fn cfg(revision: i64, ttl: i64, cred: &str, verifiers: Value) -> Value {
        json!({
            "schema_version": 1, "proxy_id": "px-1", "revision": revision,
            "issued_at": "2026-10-11T00:00:00Z", "expires_at": "2026-10-11T00:05:00Z",
            "ttl_seconds": ttl, "mode": "observe",
            "max_offline_retry_age_seconds": 2592000, "event_retention_seconds": 7776000,
            "allowed_origins": ["https://app.example.com"],
            "routes": [{"route_id": "r1", "upstream_id": "up-r1",
                "upstream_url": "https://api.example.com/mcp",
                "upstream_protocol": "2025-11-25", "credential_ref": cred,
                "credential_scope_id": "cs-0123456789abcdef0123456789abcdef"}],
            "principals": [{"principal_id": "claude", "verifiers": verifiers, "routes": ["r1"]}],
        })
    }

    fn std_cfg(revision: i64) -> Value {
        cfg(
            revision,
            300,
            "gh",
            json!([{"key_id": "k1", "verifier": v("tok-1")}]),
        )
    }

    fn body(v: &Value) -> FetchResult {
        FetchResult::Config(serde_json::to_vec(v).unwrap())
    }

    fn authenticates(t: &TableHandle, tok: &str) -> bool {
        t.current()
            .and_then(|t| t.route("r1").map(|r| r.authenticate(tok).is_some()))
            .unwrap_or(false)
    }

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    #[test]
    fn applies_a_valid_config() {
        let f = fx();
        let table = TableHandle::new();
        let mut s = sync(&f, &table);
        assert_eq!(s.status().config_state, ConfigState::None);
        let t0 = Instant::now();
        assert_eq!(
            s.on_fetch(t0, body(&std_cfg(5))),
            SyncOutcome::Applied { revision: 5 }
        );
        assert_eq!(s.status().config_state, ConfigState::Valid);
        assert_eq!(s.status().last_update_error, None);
        assert!(authenticates(&table, "tok-1"));
        // deadline = receipt + ttl on the monotonic clock
        assert_eq!(s.deadline(), Some(t0 + secs(300)));
        // the allowed_origins of the document reach the route
        assert!(table
            .current()
            .unwrap()
            .route("r1")
            .unwrap()
            .origin_allowed("https://app.example.com"));
    }

    /// A failed fetch/parse/build keeps the last good table until its deadline and
    /// never extends it; after the deadline the table is gone (fail closed).
    #[test]
    fn last_good_until_expiry_then_fail_closed() {
        let f = fx();
        let table = TableHandle::new();
        let mut s = sync(&f, &table);
        let t0 = Instant::now();
        s.on_fetch(t0, body(&std_cfg(1)));
        let deadline = s.deadline().unwrap();

        let bad_cred = cfg(
            2,
            300,
            "missing",
            json!([{"key_id":"k1","verifier": v("tok-2")}]),
        );
        let mut wrong_proxy = std_cfg(2);
        wrong_proxy["proxy_id"] = json!("other");
        let failures = [
            (FetchResult::Failed, LastUpdateError::FetchFailed),
            (FetchResult::Unavailable, LastUpdateError::FetchFailed),
            (
                FetchResult::Config(b"not json".to_vec()),
                LastUpdateError::ValidationFailed,
            ),
            (body(&wrong_proxy), LastUpdateError::ValidationFailed),
            (body(&bad_cred), LastUpdateError::ApplyFailed),
        ];
        for (i, (r, want)) in failures.into_iter().enumerate() {
            let at = t0 + secs(10 + i as u64);
            assert_eq!(s.on_fetch(at, r), SyncOutcome::Kept(want));
            assert_eq!(s.status().last_update_error, Some(want));
            // old config stays, deadline untouched, still valid
            assert!(authenticates(&table, "tok-1"), "{want:?}");
            assert!(!authenticates(&table, "tok-2"), "{want:?}");
            assert_eq!(s.deadline(), Some(deadline));
            assert_eq!(s.status().config_state, ConfigState::Valid);
        }
        // a failed apply did not advance the high-water mark
        assert_eq!(s.applied_revision(), Some(1));
        // just before the deadline: still served; at it: gone
        s.expire(deadline - Duration::from_millis(1));
        assert!(authenticates(&table, "tok-1"));
        s.expire(deadline);
        assert!(table.current().is_none());
        assert_eq!(s.status().config_state, ConfigState::Expired);
        // a later failure keeps it closed
        s.on_fetch(deadline + secs(1), FetchResult::Failed);
        assert!(table.current().is_none());
    }

    #[test]
    fn revision_ordering() {
        let f = fx();
        let table = TableHandle::new();
        let mut s = sync(&f, &table);
        let t0 = Instant::now();
        s.on_fetch(t0, body(&std_cfg(5)));
        let d0 = s.deadline().unwrap();

        // lower revision: never applied, never extends, stale_revision
        let r = s.on_fetch(t0 + secs(100), body(&std_cfg(4)));
        assert_eq!(r, SyncOutcome::Kept(LastUpdateError::StaleRevision));
        assert_eq!(s.deadline(), Some(d0));
        assert_eq!(s.applied_revision(), Some(5));

        // same revision, same hash: refresh, extends the deadline from receipt
        let r = s.on_fetch(t0 + secs(100), body(&std_cfg(5)));
        assert_eq!(r, SyncOutcome::Refreshed);
        assert_eq!(s.deadline(), Some(t0 + secs(400)));
        assert_eq!(s.status().last_update_error, None);

        // same revision, different hash: fault, no extension, old config kept
        let mut other = std_cfg(5);
        other["allowed_origins"] = json!(["https://evil.example.com"]);
        let d1 = s.deadline();
        let r = s.on_fetch(t0 + secs(200), body(&other));
        assert_eq!(r, SyncOutcome::Kept(LastUpdateError::ConfigHashMismatch));
        assert_eq!(s.deadline(), d1);
        assert!(!table
            .current()
            .unwrap()
            .route("r1")
            .unwrap()
            .origin_allowed("https://evil.example.com"));

        // higher revision: applied (new verifier replaces the old one)
        let next = cfg(
            6,
            300,
            "gh",
            json!([{"key_id":"k2","verifier": v("tok-2")}]),
        );
        assert_eq!(
            s.on_fetch(t0 + secs(210), body(&next)),
            SyncOutcome::Applied { revision: 6 }
        );
        assert!(authenticates(&table, "tok-2"));
        assert!(!authenticates(&table, "tok-1"));
    }

    /// The high-water mark survives expiry: an older revision is refused even
    /// with no table, and the same revision is installed again.
    #[test]
    fn high_water_survives_expiry() {
        let f = fx();
        let table = TableHandle::new();
        let mut s = sync(&f, &table);
        let t0 = Instant::now();
        s.on_fetch(t0, body(&std_cfg(5)));
        let past = t0 + secs(301);
        s.expire(past);
        assert!(table.current().is_none());

        assert_eq!(
            s.on_fetch(past, body(&std_cfg(4))),
            SyncOutcome::Kept(LastUpdateError::StaleRevision)
        );
        assert!(table.current().is_none());
        assert_eq!(s.status().config_state, ConfigState::Expired);

        // same revision + hash after expiry: the table is installed again
        let r = s.on_fetch(past + secs(1), body(&std_cfg(5)));
        assert_eq!(r, SyncOutcome::Refreshed);
        assert!(authenticates(&table, "tok-1"));
        assert_eq!(s.deadline(), Some(past + secs(301)));
        assert_eq!(s.status().config_state, ConfigState::Valid);
    }

    #[test]
    fn disabled_stops_new_calls_at_once_and_recovers() {
        let f = fx();
        let table = TableHandle::new();
        let mut s = sync(&f, &table);
        let t0 = Instant::now();
        s.on_fetch(t0, body(&std_cfg(5)));
        assert_eq!(
            s.on_fetch(t0 + secs(5), FetchResult::Disabled),
            SyncOutcome::Disabled
        );
        assert!(table.current().is_none());
        assert_eq!(s.status().config_state, ConfigState::Disabled);
        assert_eq!(s.deadline(), None);
        // re-enabled: the same revision comes back and is installed
        s.on_fetch(t0 + secs(30), body(&std_cfg(5)));
        assert!(authenticates(&table, "tok-1"));
        assert_eq!(s.status().config_state, ConfigState::Valid);
        // an older one is still refused after disable
        s.on_fetch(t0 + secs(40), FetchResult::Disabled);
        assert_eq!(
            s.on_fetch(t0 + secs(50), body(&std_cfg(3))),
            SyncOutcome::Kept(LastUpdateError::StaleRevision)
        );
        assert!(table.current().is_none());
    }

    /// A valid-looking initial state is never trusted (restart needs a fetch).
    #[test]
    fn initial_valid_is_expired() {
        let f = fx();
        let s = ConfigSync::new(
            "px-1",
            f.creds.clone(),
            Limits::default(),
            TableHandle::new(),
            ConfigState::Valid,
        );
        assert_eq!(s.status().config_state, ConfigState::Expired);
    }

    /// #260: `not_after` per verifier from the document, two-verifier overlap.
    #[test]
    fn verifier_not_after_from_config() {
        let f = fx();
        let table = TableHandle::new();
        let mut s = sync(&f, &table);
        let verifiers = json!([
            {"key_id": "old", "verifier": v("old-tok"), "not_after": "2001-01-01T00:00:00Z"},
            {"key_id": "new", "verifier": v("new-tok"), "not_after": "2999-01-01T00:00:00Z"},
        ]);
        s.on_fetch(Instant::now(), body(&cfg(1, 300, "gh", verifiers)));
        assert!(
            !authenticates(&table, "old-tok"),
            "expired verifier accepted"
        );
        assert!(authenticates(&table, "new-tok"));
        // a verifier with a future deadline works until then (overlap)
        let overlap = json!([
            {"key_id": "old", "verifier": v("old-tok"), "not_after": "2999-01-01T00:00:00Z"},
            {"key_id": "new", "verifier": v("new-tok")},
        ]);
        s.on_fetch(Instant::now(), body(&cfg(2, 300, "gh", overlap)));
        assert!(authenticates(&table, "old-tok"));
        assert!(authenticates(&table, "new-tok"));
    }

    /// #260: remote limits only lower the local values, per route.
    #[test]
    fn remote_limits_min_with_local() {
        let f = fx();
        let table = TableHandle::new();
        let local = Limits {
            max_request_body_bytes: 1000,
            call_timeout_secs: 60,
            ..Limits::default()
        };
        let mut s = ConfigSync::new(
            "px-1",
            f.creds.clone(),
            local.clone(),
            table.clone(),
            ConfigState::None,
        );
        let mut c = std_cfg(1);
        c["routes"][0]["limits"] = json!({
            "max_request_bytes": 10,          // lower: wins
            "request_timeout_seconds": 600,   // higher: ignored
        });
        s.on_fetch(Instant::now(), body(&c));
        let t = table.current().unwrap();
        let l = t.route("r1").unwrap().limits();
        assert_eq!(l.max_request_body_bytes, 10);
        assert_eq!(l.call_timeout_secs, 60);
        assert_eq!(l.max_json_response_bytes, local.max_json_response_bytes);
    }

    struct Scripted(std::sync::Mutex<std::collections::VecDeque<FetchResult>>);

    impl Fetcher for Scripted {
        fn fetch(&self) -> FetchFuture<'_> {
            Box::pin(async move {
                self.0
                    .lock()
                    .unwrap()
                    .pop_front()
                    .unwrap_or(FetchResult::Failed)
            })
        }
    }

    /// The polling loop: applies, then a failing server cannot keep the table past
    /// its TTL, and the published status follows. Uses the paused tokio clock.
    #[tokio::test(start_paused = true)]
    async fn poll_loop_enforces_the_ttl() {
        let f = fx();
        let table = TableHandle::new();
        let s = sync(&f, &table);
        let first = body(&cfg(
            1,
            60,
            "gh",
            json!([{"key_id":"k1","verifier": v("tok-1")}]),
        ));
        let fetcher = Scripted(std::sync::Mutex::new([first].into()));
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen2 = seen.clone();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let table2 = table.clone();
        let probe = async move {
            // 10 s in: applied and valid
            tokio::time::sleep(secs(10)).await;
            let up = authenticates(&table2, "tok-1");
            // 59 s in: the server has been failing since the first poll, but
            // the deadline (60 s from receipt) has not been reached
            tokio::time::sleep(secs(49)).await;
            let still = authenticates(&table2, "tok-1");
            // 65 s in: gone
            tokio::time::sleep(secs(6)).await;
            let gone = table2.current().is_none();
            let _ = tx.send(());
            (up, still, gone)
        };
        let run = run_sync(
            s,
            &fetcher,
            SyncParams {
                poll: secs(20),
                retry: secs(5),
            },
            move |st| seen2.lock().unwrap().push(st),
            async {
                let _ = rx.await;
            },
        );
        let (_, (up, still, gone)) = tokio::join!(run, probe);
        assert!(up, "applied after the first poll");
        assert!(still, "kept until the deadline despite failed fetches");
        assert!(gone, "removed after the deadline");
        let seen = seen.lock().unwrap();
        assert_eq!(seen.first().unwrap().config_state, ConfigState::Valid);
        assert_eq!(seen.last().unwrap().config_state, ConfigState::Expired);
        assert_eq!(
            seen.last().unwrap().last_update_error,
            Some(LastUpdateError::FetchFailed)
        );
    }

    /// First call answers, every later call never completes.
    struct ThenHang(std::sync::Mutex<Option<FetchResult>>);

    impl Fetcher for ThenHang {
        fn fetch(&self) -> FetchFuture<'_> {
            let first = self.0.lock().unwrap().take();
            Box::pin(async move {
                match first {
                    Some(r) => r,
                    None => std::future::pending().await,
                }
            })
        }
    }

    /// The in-flight arm: while a fetch hangs, the deadline timer still clears the
    /// slot and publishes `expired`. `last()` ignores the handle's own deadline
    /// check, so this proves the loop (not just `current()`) removed the table.
    #[tokio::test(start_paused = true)]
    async fn deadline_is_enforced_while_a_fetch_hangs() {
        let f = fx();
        let table = TableHandle::new();
        let s = sync(&f, &table);
        let first = body(&cfg(
            1,
            60,
            "gh",
            json!([{"key_id":"k1","verifier": v("tok-1")}]),
        ));
        let fetcher = ThenHang(std::sync::Mutex::new(Some(first)));
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen2 = seen.clone();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let t2 = table.clone();
        let probe = async move {
            tokio::time::sleep(secs(40)).await; // second fetch (t=20) is hanging
            let held = t2.last().is_some();
            tokio::time::sleep(secs(25)).await; // t=65, past the 60 s deadline
            let cleared = t2.last().is_none();
            let _ = tx.send(());
            (held, cleared)
        };
        let run = run_sync(
            s,
            &fetcher,
            SyncParams {
                poll: secs(20),
                retry: secs(5),
            },
            move |st| seen2.lock().unwrap().push(st),
            async {
                let _ = rx.await;
            },
        );
        let (_, (held, cleared)) = tokio::join!(run, probe);
        assert!(held, "table must survive until the deadline");
        assert!(cleared, "hung fetch kept the table past its deadline");
        assert_eq!(
            seen.lock().unwrap().last().unwrap().config_state,
            ConfigState::Expired
        );
    }

    /// M3: the high-water mark survives a restart (new process, new state), a
    /// lower revision is refused, and the same revision is installed again.
    #[test]
    fn restart_refuses_a_rolled_back_revision() {
        let f = fx();
        let dir = tempfile::tempdir().unwrap();
        let sd_path = dir.path().join("st");
        let id = sigil_proxy_api::Id::new("px-1").unwrap();
        let hash;
        {
            let sd = crate::state_dir::StateDir::open(&sd_path, &id).unwrap();
            let sd = std::sync::Arc::new(std::sync::Mutex::new(sd));
            let sd2 = sd.clone();
            let table = TableHandle::new();
            let mut s = sync(&f, &table).with_persister(Box::new(move |r, h| {
                sd2.lock().unwrap().write_applied(r, h).is_ok()
            }));
            s.on_fetch(Instant::now(), body(&std_cfg(5)));
            // a refresh does not write
            s.on_fetch(Instant::now(), body(&std_cfg(5)));
            hash = sd
                .lock()
                .unwrap()
                .read_applied()
                .unwrap()
                .unwrap()
                .config_hash;
            assert_eq!(
                sd.lock().unwrap().read_applied().unwrap().unwrap().revision,
                5
            );
        }
        // "restart": a new state handle and a new sync seeded from the file
        let sd = crate::state_dir::StateDir::open(&sd_path, &id).unwrap();
        let mark = sd.read_applied().unwrap().unwrap();
        let table = TableHandle::new();
        let mut s = ConfigSync::new(
            "px-1",
            f.creds.clone(),
            Limits::default(),
            table.clone(),
            ConfigState::Expired,
        )
        .with_high_water(mark.revision, mark.config_hash);
        // nothing is served before a fresh fetch
        assert!(table.current().is_none());
        let t0 = Instant::now();
        assert_eq!(
            s.on_fetch(t0, body(&std_cfg(4))),
            SyncOutcome::Kept(LastUpdateError::StaleRevision)
        );
        assert!(table.current().is_none());
        // same revision and hash: installed again from the fresh fetch
        assert_eq!(s.on_fetch(t0, body(&std_cfg(5))), SyncOutcome::Refreshed);
        assert!(authenticates(&table, "tok-1"));
        // the persisted hash is the config hash
        let parsed =
            sigil_proxy_api::parse_config(&serde_json::to_vec(&std_cfg(5)).unwrap()).unwrap();
        assert_eq!(parsed.config_hash().as_str(), hash);
        // a newer one applies
        assert_eq!(
            s.on_fetch(t0, body(&std_cfg(6))),
            SyncOutcome::Applied { revision: 6 }
        );
    }

    /// M4 through the real apply path: a permit held on the installed table is
    /// still counted after a new revision with the same route id and limit; a
    /// changed limit gets a fresh semaphore.
    #[test]
    fn apply_carries_admission_permits() {
        let f = fx();
        let table = TableHandle::new();
        let mut s = sync(&f, &table);
        let t0 = Instant::now();
        s.on_fetch(t0, body(&std_cfg(1)));
        let old = table.current().unwrap();
        let cap = Limits::default().max_calls_per_route as usize;
        let route_permit = old
            .route("r1")
            .unwrap()
            .sem
            .clone()
            .try_acquire_owned()
            .unwrap();
        let principal_permit = old
            .route("r1")
            .unwrap()
            .authenticate("tok-1")
            .unwrap()
            .sem
            .clone()
            .try_acquire_owned()
            .unwrap();

        // new revision (different verifier set, same route id and limits)
        let next = cfg(
            2,
            300,
            "gh",
            json!([{"key_id":"k1","verifier": v("tok-1")},{"key_id":"k2","verifier": v("tok-2")}]),
        );
        assert_eq!(
            s.on_fetch(t0, body(&next)),
            SyncOutcome::Applied { revision: 2 }
        );
        let new = table.current().unwrap();
        assert!(!std::sync::Arc::ptr_eq(&old, &new), "a new table was built");
        let r = new.route("r1").unwrap();
        assert_eq!(r.sem.available_permits(), cap - 1, "route permit lost");
        assert_eq!(
            r.authenticate("tok-1").unwrap().sem.available_permits(),
            Limits::default().max_calls_per_principal as usize - 1,
            "principal permit lost"
        );
        drop((route_permit, principal_permit));
        assert_eq!(r.sem.available_permits(), cap);

        // changed local limit: fresh semaphore, old permits not shared
        let _held = r.sem.clone().try_acquire_owned().unwrap();
        let lower = Limits {
            max_calls_per_route: 2,
            ..Limits::default()
        };
        let mut s2 = ConfigSync::new(
            "px-1",
            f.creds.clone(),
            lower,
            table.clone(),
            ConfigState::Expired,
        );
        assert_eq!(
            s2.on_fetch(t0, body(&std_cfg(1))),
            SyncOutcome::Applied { revision: 1 }
        );
        let fresh = table.current().unwrap();
        assert_eq!(fresh.route("r1").unwrap().sem.available_permits(), 2);
    }

    /// If the mark cannot be written, the new config is NOT applied.
    #[test]
    fn persist_failure_keeps_the_old_config() {
        let f = fx();
        let table = TableHandle::new();
        let mut s = sync(&f, &table);
        s.on_fetch(Instant::now(), body(&std_cfg(1)));
        let mut s = s.with_persister(Box::new(|_, _| false));
        let next = cfg(
            2,
            300,
            "gh",
            json!([{"key_id":"k2","verifier": v("tok-2")}]),
        );
        assert_eq!(
            s.on_fetch(Instant::now(), body(&next)),
            SyncOutcome::Kept(LastUpdateError::ApplyFailed)
        );
        assert!(authenticates(&table, "tok-1"));
        assert!(!authenticates(&table, "tok-2"));
        assert_eq!(s.applied_revision(), Some(1));
    }
}
