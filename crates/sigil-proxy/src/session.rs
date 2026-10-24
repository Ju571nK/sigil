//! Proxy-issued MCP sessions (T-12b2; control-plane.md §5.3, decisions.md M3,
//! validation.md D-04 "활성 세션").
//!
//! The proxy issues its own `Mcp-Session-Id` for every supported `initialize`,
//! even when the upstream is stateless, and binds it 1:1 to the principal and
//! route that created it, the route's [`Binding`] (upstream endpoint, credential
//! and scope) and the upstream's own session id, if it issued one. The upstream
//! id never reaches the client and the proxy id never reaches the upstream.
//!
//! * Ids are 256 bits from the OS CSPRNG, as 64 lowercase hex characters
//!   (visible ASCII). The table is keyed by the SHA-256 of the id, so the wire
//!   id is held only by the client. Nothing here prints or logs an id.
//! * Lookup answers one uniform [`NotFound`] for an unknown id, another
//!   principal's or route's id, an ended session and a session whose route now
//!   has another binding (the last also ends the session): no oracle.
//! * D-04 limits from [`Limits`]: total and per-principal sessions, counting
//!   `initialize` calls still in flight ([`Reservation`]); a full table refuses
//!   a new `initialize` and never evicts a live session. A session with no
//!   active call for `session_idle_secs` expires; one with an active call never
//!   does.
//! * When a session ends, the end hook runs with its number, so the relay can
//!   end the inventory chains and the held early cancels of that session.
//!   Ending a session sends nothing upstream: only a client DELETE does.
//!
//! Sessions live in memory only; a restart forgets them (clients re-initialize
//! after the 404).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use http::HeaderValue;
use sha2::{Digest, Sha256};
use tokio::time::Instant;

use crate::limits::Limits;
use crate::route::Binding;

/// Longest upstream `Mcp-Session-Id` accepted. // OPEN: not in D-04; the
/// protocol bounds only the alphabet (visible ASCII).
pub const MAX_UPSTREAM_SESSION_ID_BYTES: usize = 1024;

/// Idle sweeps run at most this often (and whenever the table is full).
const SWEEP_EVERY: Duration = Duration::from_secs(1);

/// The upstream's own session id: visible ASCII, bounded. Marked sensitive and
/// never printed.
#[derive(Clone)]
pub struct UpstreamSessionId(HeaderValue);

impl UpstreamSessionId {
    /// From the upstream's `initialize` response headers. `Ok(None)`: the
    /// upstream is stateless. `Err`: duplicated, empty, too long or outside
    /// 0x21-0x7E, so it cannot be used.
    pub fn from_response(h: &http::HeaderMap) -> Result<Option<UpstreamSessionId>, BadSessionId> {
        let mut it = h.get_all("mcp-session-id").iter();
        let Some(v) = it.next() else {
            return Ok(None);
        };
        if it.next().is_some() {
            return Err(BadSessionId);
        }
        let b = v.as_bytes();
        if b.is_empty()
            || b.len() > MAX_UPSTREAM_SESSION_ID_BYTES
            || !b.iter().all(|c| (0x21..=0x7e).contains(c))
        {
            return Err(BadSessionId);
        }
        let mut v = v.clone();
        v.set_sensitive(true);
        Ok(Some(UpstreamSessionId(v)))
    }

    pub fn header_value(&self) -> &HeaderValue {
        &self.0
    }
}

impl std::fmt::Debug for UpstreamSessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("UpstreamSessionId(<redacted>)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BadSessionId;

/// The proxy session id as the client presents it. `Debug` never shows it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Presented<'a> {
    Absent,
    /// More than one `Mcp-Session-Id` header.
    Duplicate,
    One(&'a [u8]),
}

impl std::fmt::Debug for Presented<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Presented::Absent => "Presented::Absent",
            Presented::Duplicate => "Presented::Duplicate",
            Presented::One(_) => "Presented::One(<redacted>)",
        })
    }
}

impl<'a> Presented<'a> {
    pub fn from_request(h: &'a http::HeaderMap) -> Presented<'a> {
        let mut it = h.get_all("mcp-session-id").iter();
        match (it.next(), it.next()) {
            (None, _) => Presented::Absent,
            (Some(_), Some(_)) => Presented::Duplicate,
            (Some(v), None) => Presented::One(v.as_bytes()),
        }
    }
}

/// Unknown, foreign, ended or rebound: one answer for all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotFound;

/// The table is at a D-04 session limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Full;

#[derive(Debug, Clone, Copy)]
pub struct SessionLimits {
    pub max_total: usize,
    pub max_per_principal: usize,
    pub idle: Duration,
}

impl SessionLimits {
    pub fn from_limits(l: &Limits) -> SessionLimits {
        SessionLimits {
            max_total: usize::try_from(l.max_sessions).unwrap_or(usize::MAX),
            max_per_principal: usize::try_from(l.max_sessions_per_principal).unwrap_or(usize::MAX),
            idle: Duration::from_secs(l.session_idle_secs),
        }
    }
}

struct SState {
    last_used: Instant,
    active: usize,
    ended: bool,
    /// The end hook ran. It waits for the last in-flight call of an ended
    /// session, so a late completion still finds the session's state.
    notified: bool,
}

/// One established session.
pub struct Session {
    no: u64,
    key: [u8; 32],
    principal: String,
    route: String,
    binding: Arc<Binding>,
    upstream: Option<UpstreamSessionId>,
    state: Mutex<SState>,
    /// Serialises client DELETEs of this session (one upstream DELETE at a time).
    pub(crate) delete_lock: tokio::sync::Mutex<()>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("no", &self.no)
            .finish_non_exhaustive()
    }
}

impl Session {
    /// Process-local number (never the wire id).
    pub fn no(&self) -> u64 {
        self.no
    }

    pub fn upstream(&self) -> Option<&UpstreamSessionId> {
        self.upstream.as_ref()
    }

    fn st(&self) -> std::sync::MutexGuard<'_, SState> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn is_ended(&self) -> bool {
        self.st().ended
    }
}

pub type EndHook = Arc<dyn Fn(u64) + Send + Sync>;

struct Inner {
    by_key: HashMap<[u8; 32], Arc<Session>>,
    /// Sessions plus reservations, per principal and in total.
    per_principal: HashMap<String, usize>,
    total: usize,
    last_sweep: Option<Instant>,
}

pub struct SessionTable {
    inner: Mutex<Inner>,
    limits: SessionLimits,
    next_no: AtomicU64,
    on_end: Mutex<Option<EndHook>>,
}

impl std::fmt::Debug for SessionTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionTable").finish_non_exhaustive()
    }
}

fn key_of(wire: &[u8]) -> [u8; 32] {
    Sha256::digest(wire).into()
}

fn new_wire_id() -> Option<String> {
    let mut b = [0u8; 32];
    getrandom::getrandom(&mut b).ok()?;
    let mut s = String::with_capacity(64);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    Some(s)
}

impl SessionTable {
    pub fn new(limits: SessionLimits) -> SessionTable {
        SessionTable {
            inner: Mutex::new(Inner {
                by_key: HashMap::new(),
                per_principal: HashMap::new(),
                total: 0,
                last_sweep: None,
            }),
            limits,
            next_no: AtomicU64::new(1),
            on_end: Mutex::new(None),
        }
    }

    /// Run `hook(session_no)` whenever a session ends.
    pub fn set_end_hook(&self, hook: EndHook) {
        *self.on_end.lock().unwrap_or_else(|p| p.into_inner()) = Some(hook);
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn ended(&self, nos: Vec<u64>) {
        if nos.is_empty() {
            return;
        }
        let hook = self
            .on_end
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        if let Some(h) = hook {
            for n in nos {
                h(n);
            }
        }
    }

    fn release(g: &mut Inner, principal: &str) {
        g.total = g.total.saturating_sub(1);
        if let Some(n) = g.per_principal.get_mut(principal) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                g.per_principal.remove(principal);
            }
        }
    }

    /// Remove `s` from the table (caller holds the lock). Returns its number if
    /// this call ended it and no call is in flight on it (otherwise the last
    /// [`ActiveCall`] to drop runs the end hook).
    fn end_locked(g: &mut Inner, s: &Arc<Session>) -> Option<u64> {
        let notify = {
            let mut st = s.st();
            if st.ended {
                return None;
            }
            st.ended = true;
            st.notified = st.active == 0;
            st.notified
        };
        if g.by_key.get(&s.key).is_some_and(|x| Arc::ptr_eq(x, s)) {
            g.by_key.remove(&s.key);
        }
        Self::release(g, &s.principal);
        notify.then_some(s.no)
    }

    fn sweep_locked(&self, g: &mut Inner, now: Instant, force: bool) -> Vec<u64> {
        if !force && g.last_sweep.is_some_and(|t| now < t + SWEEP_EVERY) {
            return Vec::new();
        }
        g.last_sweep = Some(now);
        let idle = self.limits.idle;
        let expired: Vec<Arc<Session>> = g
            .by_key
            .values()
            .filter(|s| {
                let st = s.st();
                st.active == 0 && now >= st.last_used + idle
            })
            .cloned()
            .collect();
        expired
            .iter()
            .filter_map(|s| Self::end_locked(g, s))
            .collect()
    }

    /// Reserve a slot for an `initialize` about to be sent. The slot counts
    /// against the limits until it becomes a session or is dropped.
    pub fn reserve(self: &Arc<Self>, principal: &str, now: Instant) -> Result<Reservation, Full> {
        let mut g = self.lock();
        let mut ended = self.sweep_locked(&mut g, now, false);
        let fits = |g: &Inner| {
            g.total < self.limits.max_total
                && g.per_principal.get(principal).copied().unwrap_or(0)
                    < self.limits.max_per_principal
        };
        if !fits(&g) {
            ended.extend(self.sweep_locked(&mut g, now, true));
        }
        let ok = fits(&g);
        if ok {
            g.total += 1;
            *g.per_principal.entry(principal.to_string()).or_insert(0) += 1;
        }
        drop(g);
        self.ended(ended);
        if !ok {
            return Err(Full);
        }
        Ok(Reservation {
            table: self.clone(),
            principal: principal.to_string(),
            held: true,
        })
    }

    /// Find the session `wire` of `principal` on `route` under `binding`, and
    /// count a call on it until the returned guard drops.
    pub fn lookup(
        self: &Arc<Self>,
        wire: &[u8],
        principal: &str,
        route: &str,
        binding: &Arc<Binding>,
        now: Instant,
    ) -> Result<ActiveCall, NotFound> {
        let key = key_of(wire);
        let mut g = self.lock();
        let mut ended = self.sweep_locked(&mut g, now, false);
        let found = g.by_key.get(&key).cloned();
        let result = match found {
            Some(s) if s.principal == principal && s.route == route => {
                if s.binding != *binding {
                    // The route was repointed: the old upstream session must
                    // never be sent to the new endpoint or credential.
                    ended.extend(Self::end_locked(&mut g, &s));
                    Err(NotFound)
                } else {
                    let mut st = s.st();
                    if st.ended || (st.active == 0 && now >= st.last_used + self.limits.idle) {
                        drop(st);
                        ended.extend(Self::end_locked(&mut g, &s));
                        Err(NotFound)
                    } else {
                        st.active += 1;
                        st.last_used = now;
                        drop(st);
                        Ok(ActiveCall {
                            table: self.clone(),
                            session: s,
                        })
                    }
                }
            }
            // Unknown, or another principal's or route's: the same answer.
            _ => Err(NotFound),
        };
        drop(g);
        self.ended(ended);
        result
    }

    /// End `s` (DELETE, upstream 404). Idempotent. Its in-flight calls finish.
    pub fn invalidate(&self, s: &Session) {
        let mut g = self.lock();
        let found = g.by_key.get(&s.key).cloned();
        let ended = match found {
            Some(x) if x.no == s.no => Self::end_locked(&mut g, &x),
            _ => None,
        };
        drop(g);
        self.ended(ended.into_iter().collect());
    }

    /// End every session (shutdown).
    pub fn end_all(&self) {
        let mut g = self.lock();
        let all: Vec<Arc<Session>> = g.by_key.values().cloned().collect();
        let ended: Vec<u64> = all
            .iter()
            .filter_map(|s| Self::end_locked(&mut g, s))
            .collect();
        drop(g);
        self.ended(ended);
    }

    /// Live sessions plus reservations.
    pub fn len(&self) -> usize {
        self.lock().total
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A slot held by an `initialize` in flight.
pub struct Reservation {
    table: Arc<SessionTable>,
    principal: String,
    held: bool,
}

impl Reservation {
    /// The upstream accepted the `initialize`: turn the slot into a session and
    /// return the wire id for the client (the only copy the proxy hands out).
    /// `None` only if the OS random source failed (the slot is released).
    pub fn establish(
        self,
        route: &str,
        binding: &Arc<Binding>,
        upstream: Option<UpstreamSessionId>,
        now: Instant,
    ) -> Option<(HeaderValue, Arc<Session>)> {
        self.establish_with_lease(route, binding, upstream, now, false)
            .map(|(h, s, _)| (h, s))
    }

    /// Establish an initialize session while atomically holding its first
    /// active call lease. The response stream can remain open without allowing
    /// idle expiry to race the initialize handler.
    pub fn establish_with_lease(
        mut self,
        route: &str,
        binding: &Arc<Binding>,
        upstream: Option<UpstreamSessionId>,
        now: Instant,
        leased: bool,
    ) -> Option<(HeaderValue, Arc<Session>, Option<ActiveCall>)> {
        let wire = new_wire_id()?;
        let mut hv = HeaderValue::from_str(&wire).ok()?;
        hv.set_sensitive(true);
        let s = Arc::new(Session {
            no: self.table.next_no.fetch_add(1, Ordering::Relaxed),
            key: key_of(wire.as_bytes()),
            principal: self.principal.clone(),
            route: route.to_string(),
            binding: binding.clone(),
            upstream,
            state: Mutex::new(SState {
                last_used: now,
                active: usize::from(leased),
                ended: false,
                notified: false,
            }),
            delete_lock: tokio::sync::Mutex::new(()),
        });
        let mut g = self.table.lock();
        g.by_key.insert(s.key, s.clone());
        drop(g);
        // The slot is now the session's.
        self.held = false;
        let lease = leased.then(|| ActiveCall {
            table: self.table.clone(),
            session: s.clone(),
        });
        Some((hv, s, lease))
    }
}

impl std::fmt::Debug for Reservation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Reservation").finish_non_exhaustive()
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if self.held {
            let mut g = self.table.lock();
            SessionTable::release(&mut g, &self.principal);
        }
    }
}

/// A call counted on a session. While one exists the session never expires.
pub struct ActiveCall {
    table: Arc<SessionTable>,
    session: Arc<Session>,
}

impl ActiveCall {
    pub fn session(&self) -> &Arc<Session> {
        &self.session
    }

    pub fn table(&self) -> &Arc<SessionTable> {
        &self.table
    }
}

impl Drop for ActiveCall {
    fn drop(&mut self) {
        let notify = {
            let mut st = self.session.st();
            st.active = st.active.saturating_sub(1);
            st.last_used = Instant::now();
            let n = st.ended && st.active == 0 && !st.notified;
            if n {
                st.notified = true;
            }
            n
        };
        if notify {
            self.table.ended(vec![self.session.no]);
        }
    }
}

impl std::fmt::Debug for ActiveCall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActiveCall")
            .field("session", &self.session.no)
            .finish()
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::bootstrap::Credential;
    use crate::route::{PrincipalSpec, RouteSpec, RouteTable};
    use sigil_proxy_api::Id;
    use std::collections::BTreeMap;
    use std::os::unix::fs::PermissionsExt;

    fn bindings() -> (Arc<Binding>, Arc<Binding>) {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("secret");
        std::fs::write(&p, "S").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        let creds = BTreeMap::from([(
            "r".to_string(),
            Credential {
                secret_file: p,
                upstream_origins: vec!["http://127.0.0.1:1".into(), "http://127.0.0.1:2".into()],
            },
        )]);
        let mk = |id: &str, url: &str| RouteSpec {
            route_id: Id::new(id).unwrap(),
            upstream_url: url.into(),
            credential_ref: "r".into(),
            principals: vec![PrincipalSpec::new(
                Id::new("p").unwrap(),
                vec![sigil_proxy_api::verifier_for("t").into()],
            )],
            allowed_origins: vec![],
            allow_private_destination: false,
            limits: Default::default(),
            scope: None,
        };
        let t = RouteTable::build(
            &[
                mk("a", "http://127.0.0.1:1/m"),
                mk("b", "http://127.0.0.1:2/m"),
            ],
            &creds,
            &Limits::default(),
        )
        .unwrap();
        (
            t.route("a").unwrap().binding().clone(),
            t.route("b").unwrap().binding().clone(),
        )
    }

    fn table(total: usize, per: usize, idle: u64) -> Arc<SessionTable> {
        Arc::new(SessionTable::new(SessionLimits {
            max_total: total,
            max_per_principal: per,
            idle: Duration::from_secs(idle),
        }))
    }

    fn open(
        t: &Arc<SessionTable>,
        p: &str,
        b: &Arc<Binding>,
        now: Instant,
    ) -> (String, Arc<Session>) {
        let (hv, s) = t
            .reserve(p, now)
            .unwrap()
            .establish("a", b, None, now)
            .unwrap();
        (hv.to_str().unwrap().to_string(), s)
    }

    #[test]
    fn ids_are_random_visible_ascii_and_never_stored() {
        let (a, _) = bindings();
        let t = table(8, 8, 60);
        let now = Instant::now();
        let (w1, s1) = open(&t, "p", &a, now);
        let (w2, _) = open(&t, "p", &a, now);
        assert_ne!(w1, w2);
        assert_eq!(w1.len(), 64);
        assert!(w1.bytes().all(|c| (0x21..=0x7e).contains(&c)));
        // only the digest is kept, and Debug shows the number only
        assert!(!format!("{s1:?}{t:?}").contains(&w1));
        assert!(t.lookup(w1.as_bytes(), "p", "a", &a, now).is_ok());
    }

    #[test]
    fn foreign_unknown_ended_and_rebound_are_one_answer() {
        let (a, b) = bindings();
        let t = table(8, 8, 60);
        let now = Instant::now();
        let (w, s) = open(&t, "p", &a, now);
        assert_eq!(t.lookup(b"nope", "p", "a", &a, now).unwrap_err(), NotFound);
        assert_eq!(
            t.lookup(w.as_bytes(), "q", "a", &a, now).unwrap_err(),
            NotFound
        );
        assert_eq!(
            t.lookup(w.as_bytes(), "p", "b", &a, now).unwrap_err(),
            NotFound
        );
        // a foreign lookup does not end the owner's session
        assert!(t.lookup(w.as_bytes(), "p", "a", &a, now).is_ok());
        t.invalidate(&s);
        assert_eq!(
            t.lookup(w.as_bytes(), "p", "a", &a, now).unwrap_err(),
            NotFound
        );
        // a changed binding ends the session for good
        let (w, _) = open(&t, "p", &a, now);
        assert_eq!(
            t.lookup(w.as_bytes(), "p", "a", &b, now).unwrap_err(),
            NotFound
        );
        assert_eq!(
            t.lookup(w.as_bytes(), "p", "a", &a, now).unwrap_err(),
            NotFound
        );
        assert!(t.is_empty());
    }

    #[test]
    fn limits_count_reservations_and_never_evict() {
        let (a, _) = bindings();
        let t = table(3, 2, 60);
        let now = Instant::now();
        let r1 = t.reserve("p", now).unwrap();
        let _s2 = open(&t, "p", &a, now);
        assert_eq!(t.reserve("p", now).unwrap_err(), Full, "per principal");
        let _q = open(&t, "q", &a, now);
        assert_eq!(t.reserve("x", now).unwrap_err(), Full, "total");
        drop(r1);
        assert!(
            t.reserve("x", now).is_ok(),
            "a dropped reservation frees its slot"
        );
    }

    #[test]
    fn idle_expiry_skips_sessions_with_active_calls() {
        let (a, _) = bindings();
        let t = table(8, 8, 10);
        let ended = Arc::new(Mutex::new(Vec::new()));
        let e2 = ended.clone();
        t.set_end_hook(Arc::new(move |n| e2.lock().unwrap().push(n)));
        let t0 = Instant::now();
        let (w1, s1) = open(&t, "p", &a, t0);
        let (w2, s2) = open(&t, "p", &a, t0);
        let call = t.lookup(w1.as_bytes(), "p", "a", &a, t0).unwrap();
        let later = t0 + Duration::from_secs(11);
        // s2 is idle and expires; s1 has an active call and stays
        assert!(t.lookup(w2.as_bytes(), "p", "a", &a, later).is_err());
        let again = t.lookup(w1.as_bytes(), "p", "a", &a, later).unwrap();
        assert_eq!(*ended.lock().unwrap(), vec![s2.no()]);
        drop((call, again));
        // once the calls ended, idleness counts from their end
        assert!(!s1.is_ended());
        let much_later = Instant::now() + Duration::from_secs(11);
        assert!(t.lookup(w1.as_bytes(), "p", "a", &a, much_later).is_err());
        assert_eq!(*ended.lock().unwrap(), vec![s2.no(), s1.no()]);
    }

    #[test]
    fn a_full_table_sweeps_idle_sessions_before_refusing() {
        let (a, _) = bindings();
        let t = table(1, 1, 5);
        let t0 = Instant::now();
        let _ = open(&t, "p", &a, t0);
        assert!(t.reserve("p", t0 + Duration::from_millis(1100)).is_err());
        assert!(t.reserve("p", t0 + Duration::from_secs(6)).is_ok());
    }

    #[test]
    fn upstream_session_ids_are_checked() {
        let mut h = http::HeaderMap::new();
        assert!(UpstreamSessionId::from_response(&h).unwrap().is_none());
        h.insert("mcp-session-id", HeaderValue::from_static("abc-123"));
        let u = UpstreamSessionId::from_response(&h).unwrap().unwrap();
        assert_eq!(format!("{u:?}"), "UpstreamSessionId(<redacted>)");
        h.append("mcp-session-id", HeaderValue::from_static("x"));
        assert!(UpstreamSessionId::from_response(&h).is_err(), "duplicate");
        for bad in ["a b", "a\tb", "\u{e9}", ""] {
            let mut h = http::HeaderMap::new();
            h.insert(
                "mcp-session-id",
                HeaderValue::from_bytes(bad.as_bytes()).unwrap(),
            );
            assert!(UpstreamSessionId::from_response(&h).is_err(), "{bad:?}");
        }
        let mut h = http::HeaderMap::new();
        let long = "a".repeat(MAX_UPSTREAM_SESSION_ID_BYTES + 1);
        h.insert("mcp-session-id", HeaderValue::from_str(&long).unwrap());
        assert!(UpstreamSessionId::from_response(&h).is_err());
    }

    #[test]
    fn the_end_hook_waits_for_the_last_call_in_flight() {
        let (a, _) = bindings();
        let t = table(4, 4, 600);
        let seen = Arc::new(Mutex::new(Vec::new()));
        let s2 = seen.clone();
        t.set_end_hook(Arc::new(move |n| s2.lock().unwrap().push(n)));
        let now = Instant::now();
        let (wire, s) = open(&t, "p", &a, now);
        let c1 = t.lookup(wire.as_bytes(), "p", "a", &a, now).unwrap();
        let c2 = t.lookup(wire.as_bytes(), "p", "a", &a, now).unwrap();
        t.invalidate(&s);
        // ended at once for new calls and for capacity
        assert!(t.lookup(wire.as_bytes(), "p", "a", &a, now).is_err());
        assert_eq!(t.len(), 0);
        drop(c1);
        assert!(seen.lock().unwrap().is_empty());
        drop(c2);
        assert_eq!(*seen.lock().unwrap(), vec![s.no()]);
        // and runs once
        t.invalidate(&s);
        assert_eq!(seen.lock().unwrap().len(), 1);
        // a session with nothing in flight ends at once
        let (_, s) = open(&t, "p", &a, now);
        t.invalidate(&s);
        assert_eq!(seen.lock().unwrap().last(), Some(&s.no()));
    }

    #[test]
    fn a_presented_id_never_shows_in_debug() {
        let mut h = http::HeaderMap::new();
        h.insert(
            "mcp-session-id",
            HeaderValue::from_static("canary-sid-7f3a"),
        );
        let p = Presented::from_request(&h);
        assert!(matches!(p, Presented::One(_)));
        let d = format!("{p:?}");
        assert!(!d.contains("canary"), "{d}");
    }
}
