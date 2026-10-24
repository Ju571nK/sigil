//! Cancel ordering (M3, contracts/README.md "Traffic와 내구성"; PX-006/013/015).
//!
//! A `notifications/cancelled` names the id of a client request. The proxy
//! decides by whether that request has been dispatched yet:
//!
//! | state of the target | cancel is | target |
//! |---|---|---|
//! | registered, not dispatched | NOT forwarded | never dispatched (`cancelled_before_dispatch`) |
//! | dispatched | forwarded, `cancel_requested` | waits for a response, then `cancel_no_response` |
//! | not seen yet | held in a bounded, short window; NOT forwarded | dispatch is refused if it arrives in the window |
//! | not seen, window passed | dropped, counted | unaffected |
//!
//! "Dispatch" is the instant the proxy starts writing the request to upstream.
//! The decision is a single compare-and-set on the target's state, so a cancel
//! and a dispatch racing each other have exactly one winner.
//!
//! Correlation is `(route, principal, proxy session, request id)` with exact
//! JSON value equality (README M3 `(session, requestId)`; T-12b2). The same id
//! in two sessions, principals or routes never matches. An `initialize` has no
//! session yet and is registered under its own call number, so no cancel can
//! ever name it (clients MUST NOT cancel `initialize`). When a session ends its
//! held early cancels are dropped and counted ([`CancelRegistry::drop_session`]).

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::watch;
use tokio::time::Instant;

use super::classify::RequestId;

/// How long a cancel for a not-yet-seen request id is held. // OPEN: "짧은 창
/// (수치는 D-04)" - D-04 has no value yet; this is a placeholder.
pub const EARLY_CANCEL_WINDOW: Duration = Duration::from_secs(2);

/// Entries held for not-yet-seen ids (PX-013: bounded).
pub const EARLY_CANCEL_CAPACITY: usize = 256;

/// How long a dispatched request whose cancel was forwarded may stay without a
/// response before it ends as `cancel_no_response`. // OPEN: D-04 value.
pub const CANCEL_RESPONSE_GRACE: Duration = Duration::from_secs(3);

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct CancelKey {
    pub route: String,
    pub principal: String,
    pub session: CancelScope,
    pub id: RequestId,
}

/// The id space a request id lives in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CancelScope {
    /// A proxy session (its process-local number).
    Session(u64),
    /// An `initialize` call, by its relay call number: a key no cancel can
    /// carry, since a cancel always belongs to a session.
    Initialize(u64),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum State {
    NotDispatched,
    Dispatched,
    CancelledBefore,
}

struct Entry {
    /// Relay-local call number of the target (for the observation).
    seq: u64,
    state: Mutex<(State, Option<Instant>)>,
    signal: watch::Sender<bool>,
}

/// What a `notifications/cancelled` found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CancelOutcome {
    /// The target is registered and was not dispatched; it now never will be.
    /// The cancel is not forwarded. The target's handler records it.
    BeforeDispatch,
    /// The target was already cancelled before dispatch (a repeat).
    AlreadyCancelled,
    /// The target is dispatched: forward the cancel and record
    /// `cancel_requested` for it.
    /// Carries the target's relay-local call number.
    AfterDispatch(u64),
    /// No such request yet; the cancel is held for the window. Not forwarded.
    Held,
}

struct Inner {
    inflight: HashMap<CancelKey, Arc<Entry>>,
    early: HashMap<CancelKey, Instant>,
    order: VecDeque<(CancelKey, Instant)>,
}

pub struct CancelRegistry {
    inner: Mutex<Inner>,
    window: Duration,
    capacity: usize,
    unmatched: AtomicU64,
}

impl Default for CancelRegistry {
    fn default() -> Self {
        Self::new(EARLY_CANCEL_WINDOW, EARLY_CANCEL_CAPACITY)
    }
}

impl CancelRegistry {
    pub fn new(window: Duration, capacity: usize) -> Self {
        CancelRegistry {
            inner: Mutex::new(Inner {
                inflight: HashMap::new(),
                early: HashMap::new(),
                order: VecDeque::new(),
            }),
            window,
            capacity: capacity.max(1),
            unmatched: AtomicU64::new(0),
        }
    }

    /// Cancels that matched no request: expired in the window or evicted by the
    /// capacity bound. A counter only (contracts/README.md M3): no content.
    pub fn unmatched_total(&self) -> u64 {
        self.unmatched.load(Ordering::Relaxed)
    }

    /// As [`CancelRegistry::unmatched_total`] after expiring entries due at `now`.
    pub fn unmatched_total_at(&self, now: Instant) -> u64 {
        let mut g = self.inner.lock().unwrap();
        self.expire(&mut g, now);
        self.unmatched.load(Ordering::Relaxed)
    }

    fn expire(&self, g: &mut Inner, now: Instant) {
        while let Some((k, at)) = g.order.front() {
            let live = g.early.get(k) == Some(at);
            if live && now < *at + self.window {
                break;
            }
            let (k, at) = g.order.pop_front().unwrap();
            if g.early.get(&k) == Some(&at) {
                g.early.remove(&k);
                self.unmatched.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Register a request that is about to be dispatched. If a cancel for the id
    /// is held, the registration starts out cancelled.
    /// `None` if a request with the same key is already in flight: the second
    /// one is refused rather than silently replacing the first (a cancel would
    /// otherwise address the wrong call).
    pub fn register(
        self: &Arc<Self>,
        key: CancelKey,
        seq: u64,
        now: Instant,
    ) -> Option<Registration> {
        let (signal, _) = watch::channel(false);
        let entry = Arc::new(Entry {
            seq,
            state: Mutex::new((State::NotDispatched, None)),
            signal,
        });
        let mut g = self.inner.lock().unwrap();
        self.expire(&mut g, now);
        if g.inflight.contains_key(&key) {
            return None;
        }
        let early = g.early.remove(&key).is_some();
        if early {
            entry.state.lock().unwrap().0 = State::CancelledBefore;
        }
        g.inflight.insert(key.clone(), entry.clone());
        drop(g);
        Some(Registration {
            registry: self.clone(),
            key,
            entry,
        })
    }

    /// Apply a `notifications/cancelled` for `key`.
    pub fn cancel(&self, key: &CancelKey, now: Instant) -> CancelOutcome {
        let mut g = self.inner.lock().unwrap();
        self.expire(&mut g, now);
        if let Some(entry) = g.inflight.get(key) {
            let mut st = entry.state.lock().unwrap();
            return match st.0 {
                State::NotDispatched => {
                    st.0 = State::CancelledBefore;
                    CancelOutcome::BeforeDispatch
                }
                State::CancelledBefore => CancelOutcome::AlreadyCancelled,
                State::Dispatched => {
                    st.1.get_or_insert(now);
                    // `send_replace` stores the value even with no receiver yet.
                    entry.signal.send_replace(true);
                    CancelOutcome::AfterDispatch(entry.seq)
                }
            };
        }
        // Not seen: hold it, bounded. A repeat keeps the first timestamp.
        if g.early.contains_key(key) {
            return CancelOutcome::Held;
        }
        while g.early.len() >= self.capacity {
            // Evict the oldest live entry (counts as unmatched).
            let Some((k, at)) = g.order.pop_front() else {
                break;
            };
            if g.early.get(&k) == Some(&at) {
                g.early.remove(&k);
                self.unmatched.fetch_add(1, Ordering::Relaxed);
            }
        }
        g.early.insert(key.clone(), now);
        g.order.push_back((key.clone(), now));
        CancelOutcome::Held
    }

    /// The session `session` ended: drop the cancels held for its ids (each
    /// counts as unmatched). Its in-flight requests keep their registrations.
    pub fn drop_session(&self, session: u64) {
        let mut g = self.inner.lock().unwrap();
        let before = g.early.len();
        g.early
            .retain(|k, _| k.session != CancelScope::Session(session));
        let dropped = before - g.early.len();
        if dropped > 0 {
            g.order
                .retain(|(k, _)| k.session != CancelScope::Session(session));
            self.unmatched.fetch_add(dropped as u64, Ordering::Relaxed);
        }
    }

    #[cfg(test)]
    fn inflight_len(&self) -> usize {
        self.inner.lock().unwrap().inflight.len()
    }
    #[cfg(test)]
    fn early_len(&self) -> usize {
        self.inner.lock().unwrap().early.len()
    }
}

/// A cancel won against dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cancelled;

/// A request registered for cancel correlation. Removed when dropped (when its
/// response body ends or the exchange fails).
pub struct Registration {
    registry: Arc<CancelRegistry>,
    key: CancelKey,
    entry: Arc<Entry>,
}

impl Registration {
    /// True if a cancel arrived before dispatch.
    pub fn is_cancelled(&self) -> bool {
        self.entry.state.lock().unwrap().0 == State::CancelledBefore
    }

    /// The dispatch decision: succeeds iff no cancel got there first. After
    /// `Ok` a cancel is forwarded instead of preventing the request.
    pub fn try_dispatch(&self) -> Result<(), Cancelled> {
        let mut st = self.entry.state.lock().unwrap();
        match st.0 {
            State::NotDispatched => {
                st.0 = State::Dispatched;
                Ok(())
            }
            State::Dispatched => Ok(()),
            State::CancelledBefore => Err(Cancelled),
        }
    }

    pub fn cancel_requested(&self) -> bool {
        self.entry.state.lock().unwrap().1.is_some()
    }

    /// A future that completes `grace` after a cancel is forwarded for this
    /// request. It borrows nothing, so a response body can hold it.
    pub fn grace_expired(
        &self,
        grace: Duration,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + Sync>> {
        let mut rx = self.entry.signal.subscribe();
        Box::pin(async move {
            if rx.wait_for(|v| *v).await.is_ok() {
                tokio::time::sleep(grace).await;
            } else {
                std::future::pending::<()>().await;
            }
        })
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        let mut g = self.registry.inner.lock().unwrap();
        if g.inflight
            .get(&self.key)
            .is_some_and(|e| Arc::ptr_eq(e, &self.entry))
        {
            g.inflight.remove(&self.key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(id: &str) -> CancelKey {
        CancelKey {
            route: "r".into(),
            principal: "p".into(),
            session: CancelScope::Session(1),
            id: RequestId::from_raw(id).unwrap(),
        }
    }

    fn reg() -> Arc<CancelRegistry> {
        Arc::new(CancelRegistry::new(Duration::from_secs(2), 4))
    }

    #[test]
    fn cancel_before_dispatch_prevents_dispatch() {
        let r = reg();
        let now = Instant::now();
        let x = r.register(key("4"), 1, now).unwrap();
        assert_eq!(r.cancel(&key("4"), now), CancelOutcome::BeforeDispatch);
        assert!(x.is_cancelled());
        assert!(x.try_dispatch().is_err());
        // a repeat is noted, not re-recorded
        assert_eq!(r.cancel(&key("4"), now), CancelOutcome::AlreadyCancelled);
        assert!(!x.cancel_requested());
    }

    #[test]
    fn cancel_after_dispatch_is_forwarded() {
        let r = reg();
        let now = Instant::now();
        let x = r.register(key("4"), 1, now).unwrap();
        assert!(x.try_dispatch().is_ok());
        assert_eq!(r.cancel(&key("4"), now), CancelOutcome::AfterDispatch(1));
        assert!(x.cancel_requested());
        assert!(
            x.try_dispatch().is_ok(),
            "a dispatched call stays dispatched"
        );
        // every further cancel is also forwarded
        assert_eq!(r.cancel(&key("4"), now), CancelOutcome::AfterDispatch(1));
    }

    #[test]
    fn early_cancel_within_the_window_stops_the_request() {
        let r = reg();
        let t0 = Instant::now();
        assert_eq!(r.cancel(&key("9"), t0), CancelOutcome::Held);
        let x = r
            .register(key("9"), 1, t0 + Duration::from_millis(1999))
            .unwrap();
        assert!(x.is_cancelled());
        assert!(x.try_dispatch().is_err());
        assert_eq!(r.early_len(), 0, "the held entry is consumed");
        assert_eq!(r.unmatched_total(), 0);
    }

    #[test]
    fn early_cancel_after_the_window_is_dropped_and_counted() {
        let r = reg();
        let t0 = Instant::now();
        assert_eq!(r.cancel(&key("9"), t0), CancelOutcome::Held);
        let x = r
            .register(key("9"), 1, t0 + Duration::from_secs(2))
            .unwrap();
        assert!(
            !x.is_cancelled(),
            "window passed: the request is unaffected"
        );
        assert!(x.try_dispatch().is_ok());
        assert_eq!(r.unmatched_total(), 1);
        assert_eq!(r.early_len(), 0);
    }

    #[test]
    fn unmatched_cancels_expire_without_any_later_request() {
        let r = reg();
        let t0 = Instant::now();
        r.cancel(&key("1"), t0);
        r.cancel(&key("2"), t0 + Duration::from_secs(1));
        assert_eq!(r.unmatched_total_at(t0 + Duration::from_millis(1500)), 0);
        assert_eq!(r.unmatched_total_at(t0 + Duration::from_millis(2500)), 1);
        assert_eq!(r.unmatched_total_at(t0 + Duration::from_secs(10)), 2);
        assert_eq!(r.early_len(), 0);
    }

    #[test]
    fn held_cancels_are_bounded() {
        let r = reg(); // capacity 4
        let t0 = Instant::now();
        for i in 0..10 {
            r.cancel(&key(&i.to_string()), t0);
        }
        assert_eq!(r.early_len(), 4);
        assert_eq!(r.unmatched_total(), 6, "evictions are counted");
        // the oldest were evicted; the newest are still held
        assert!(r.register(key("9"), 1, t0).unwrap().is_cancelled());
        assert!(!r.register(key("0"), 1, t0).unwrap().is_cancelled());
    }

    #[test]
    fn a_repeated_early_cancel_does_not_extend_the_window() {
        let r = reg();
        let t0 = Instant::now();
        r.cancel(&key("1"), t0);
        assert_eq!(
            r.cancel(&key("1"), t0 + Duration::from_millis(1900)),
            CancelOutcome::Held
        );
        assert!(!r
            .register(key("1"), 1, t0 + Duration::from_secs(2))
            .unwrap()
            .is_cancelled());
    }

    #[test]
    fn keys_separate_route_principal_and_json_type() {
        let r = reg();
        let now = Instant::now();
        let x = r.register(key("4"), 1, now).unwrap();
        let mut other = key("4");
        other.principal = "q".into();
        assert_eq!(r.cancel(&other, now), CancelOutcome::Held);
        let mut other = key("4");
        other.route = "s".into();
        assert_eq!(r.cancel(&other, now), CancelOutcome::Held);
        // "4" (string) and 4 (number) are different ids
        assert_eq!(r.cancel(&key("\"4\""), now), CancelOutcome::Held);
        assert!(!x.is_cancelled());
        assert_eq!(r.cancel(&key("4.0"), now), CancelOutcome::Held);
        assert!(!x.is_cancelled());
    }

    /// T-12b2: the same id in two sessions never matches; an `initialize` key
    /// is never matched; a session's end drops only its held cancels.
    #[test]
    fn sessions_separate_ids_and_initialize_is_never_cancelled() {
        let r = reg();
        let now = Instant::now();
        let a = r.register(key("4"), 1, now).unwrap();
        let mut in_b = key("4");
        in_b.session = CancelScope::Session(2);
        let b = r.register(in_b.clone(), 2, now).unwrap();
        a.try_dispatch().unwrap();
        b.try_dispatch().unwrap();
        assert_eq!(r.cancel(&in_b, now), CancelOutcome::AfterDispatch(2));
        assert!(b.cancel_requested() && !a.cancel_requested());
        // an initialize with id 0 lives under its own call number
        let mut init = key("0");
        init.session = CancelScope::Initialize(9);
        let i = r.register(init, 9, now).unwrap();
        assert_eq!(r.cancel(&key("0"), now), CancelOutcome::Held);
        assert!(!i.is_cancelled());
        // ending session 1 drops its held cancel ("0") but not session 2's
        let mut held_b = key("7");
        held_b.session = CancelScope::Session(2);
        assert_eq!(r.cancel(&held_b, now), CancelOutcome::Held);
        r.drop_session(1);
        assert_eq!(r.early_len(), 1);
        assert_eq!(r.unmatched_total(), 1);
        assert!(r.register(held_b, 3, now).unwrap().is_cancelled());
    }

    #[test]
    fn dropping_a_registration_forgets_it() {
        let r = reg();
        let now = Instant::now();
        let x = r.register(key("4"), 1, now).unwrap();
        assert_eq!(r.inflight_len(), 1);
        drop(x);
        assert_eq!(r.inflight_len(), 0);
        // a cancel after the response is just a held cancel now
        assert_eq!(r.cancel(&key("4"), now), CancelOutcome::Held);
    }

    #[test]
    fn a_second_request_with_an_in_flight_id_is_refused() {
        let r = reg();
        let now = Instant::now();
        let a = r.register(key("4"), 1, now).unwrap();
        assert!(
            r.register(key("4"), 2, now).is_none(),
            "no silent overwrite"
        );
        // the refused attempt changed nothing: a is still the target
        assert_eq!(r.cancel(&key("4"), now), CancelOutcome::BeforeDispatch);
        assert!(a.is_cancelled());
        // another principal or route is a different key
        let mut other = key("4");
        other.principal = "q".into();
        assert!(r.register(other, 3, now).is_some());
        // once the first is done the id can be used again
        drop(a);
        assert!(r.register(key("4"), 4, now).is_some());
    }

    /// Exactly one of {cancel stops dispatch, dispatch wins} for any interleaving.
    #[test]
    fn cancel_and_dispatch_have_one_winner() {
        for _ in 0..200 {
            let r = reg();
            let now = Instant::now();
            let x = Arc::new(r.register(key("4"), 1, now).unwrap());
            let (x2, r2) = (x.clone(), r.clone());
            let t = std::thread::spawn(move || r2.cancel(&key("4"), now));
            let dispatched = x2.try_dispatch().is_ok();
            let out = t.join().unwrap();
            match (dispatched, out) {
                (true, CancelOutcome::AfterDispatch(1)) => assert!(x.cancel_requested()),
                (false, CancelOutcome::BeforeDispatch) => assert!(x.is_cancelled()),
                other => panic!("inconsistent: {other:?}"),
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn grace_starts_when_a_cancel_is_forwarded() {
        let r = reg();
        let x = r.register(key("4"), 1, Instant::now()).unwrap();
        x.try_dispatch().unwrap();
        let mut g = x.grace_expired(Duration::from_secs(3));
        // no cancel yet: never completes
        assert!(tokio::time::timeout(Duration::from_secs(100), &mut g)
            .await
            .is_err());
        r.cancel(&key("4"), Instant::now());
        assert!(tokio::time::timeout(Duration::from_secs(2), &mut g)
            .await
            .is_err());
        assert!(tokio::time::timeout(Duration::from_secs(2), &mut g)
            .await
            .is_ok());
    }
}
