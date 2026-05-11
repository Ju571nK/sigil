//! Sender-side heartbeat fields.
//!
//! Spec §1.7 + §3.8.3 — sender adds backpressure visibility to the
//! shared heartbeat schema.

use parking_lot::RwLock;
use std::sync::Arc;
use time::OffsetDateTime;

#[derive(Clone, Debug, Default)]
pub struct SenderStats {
    pub lag_events: u64,
    pub lag_bytes: u64,
    pub oldest_unsent_age_s: u64,
    pub last_server_ack_at: Option<OffsetDateTime>,
    pub last_server_response_code: Option<u16>,
    pub client_cert_expires_at: Option<OffsetDateTime>,
}

pub type SharedStats = Arc<RwLock<SenderStats>>;

pub fn shared() -> SharedStats {
    Arc::new(RwLock::new(SenderStats::default()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn shared_starts_with_defaults() {
        let s = shared();
        let v = s.read();
        assert_eq!(v.lag_events, 0);
        assert!(v.last_server_ack_at.is_none());
    }

    #[test]
    fn writes_visible_to_readers() {
        let s = shared();
        {
            let mut w = s.write();
            w.lag_events = 5;
            w.last_server_response_code = Some(200);
            w.last_server_ack_at = Some(datetime!(2026-05-15 0:00 UTC));
        }
        let v = s.read();
        assert_eq!(v.lag_events, 5);
        assert_eq!(v.last_server_response_code, Some(200));
    }
}
