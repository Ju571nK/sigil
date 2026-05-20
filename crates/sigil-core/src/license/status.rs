//! License status state machine (pure). No I/O, no clock — `now`-derived
//! inputs are passed in by the caller (sigil-server).

use crate::license::LicenseDocument;
use serde::Serialize;
use time::OffsetDateTime;

/// Free-tier active-host limit when no valid license is present. Sized for the
/// target market. A valid license overrides this with its `max_hosts`.
pub const FREE_TIER_MAX_HOSTS: u32 = 200;

/// Outcome of loading + verifying the configured license at boot.
#[derive(Clone, Debug, PartialEq)]
pub enum LicenseState {
    /// No license path configured / file absent ⇒ free tier.
    Free,
    /// Verified, not expired.
    Valid(LicenseDocument),
    /// Verified signature but past `not_after` ⇒ free-tier fallback.
    Expired(LicenseDocument),
    /// Bad signature / unknown key / malformed ⇒ free-tier fallback.
    Invalid { reason: String },
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LicenseStatusState {
    Ok,
    OverLimit,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct LicenseStatus {
    pub state: LicenseStatusState,
    pub licensed: bool,
    pub expired: bool,
    pub effective_max_hosts: u32,
    pub current_host_count: u32,
    pub active_window_days: u32,
    pub customer_id: Option<String>,
    pub license_id: Option<String>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub not_after: Option<OffsetDateTime>,
}

/// Pure status computation. `active_count` and `window_days` are supplied by
/// the server (which knows the clock + fleet index).
pub fn compute_status(
    state: &LicenseState,
    active_count: u32,
    window_days: u32,
) -> LicenseStatus {
    let (effective_max, licensed, expired, customer_id, license_id, not_after) = match state {
        LicenseState::Valid(d) => (
            d.max_hosts,
            true,
            false,
            Some(d.customer_id.clone()),
            Some(d.license_id.clone()),
            Some(d.not_after),
        ),
        LicenseState::Expired(d) => (
            FREE_TIER_MAX_HOSTS,
            false,
            true,
            Some(d.customer_id.clone()),
            Some(d.license_id.clone()),
            Some(d.not_after),
        ),
        LicenseState::Free | LicenseState::Invalid { .. } => {
            (FREE_TIER_MAX_HOSTS, false, false, None, None, None)
        }
    };
    let state_enum = if active_count > effective_max {
        LicenseStatusState::OverLimit
    } else {
        LicenseStatusState::Ok
    };
    LicenseStatus {
        state: state_enum,
        licensed,
        expired,
        effective_max_hosts: effective_max,
        current_host_count: active_count,
        active_window_days: window_days,
        customer_id,
        license_id,
        not_after,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    fn doc(max: u32) -> LicenseDocument {
        LicenseDocument {
            license_id: "SIGIL-2026-ACME-a1b2c3".into(),
            customer_id: "ACME".into(),
            max_hosts: max,
            issued_at: datetime!(2026-05-01 0:00 UTC),
            not_after: datetime!(2027-01-01 0:00 UTC),
        }
    }

    #[test]
    fn free_under_limit_is_ok() {
        let s = compute_status(&LicenseState::Free, 199, 7);
        assert_eq!(s.state, LicenseStatusState::Ok);
        assert_eq!(s.effective_max_hosts, 200);
        assert!(!s.licensed);
        assert!(s.customer_id.is_none());
    }

    #[test]
    fn free_over_limit_is_over() {
        let s = compute_status(&LicenseState::Free, 201, 7);
        assert_eq!(s.state, LicenseStatusState::OverLimit);
    }

    #[test]
    fn free_exactly_at_limit_is_ok() {
        let s = compute_status(&LicenseState::Free, 200, 7);
        assert_eq!(s.state, LicenseStatusState::Ok);
    }

    #[test]
    fn valid_license_raises_limit() {
        let s = compute_status(&LicenseState::Valid(doc(1000)), 263, 7);
        assert_eq!(s.state, LicenseStatusState::Ok);
        assert_eq!(s.effective_max_hosts, 1000);
        assert!(s.licensed);
        assert_eq!(s.customer_id.as_deref(), Some("ACME"));
    }

    #[test]
    fn valid_license_over_its_own_limit_is_over() {
        let s = compute_status(&LicenseState::Valid(doc(1000)), 1001, 7);
        assert_eq!(s.state, LicenseStatusState::OverLimit);
    }

    #[test]
    fn expired_falls_back_to_free_and_flags_expired() {
        let s = compute_status(&LicenseState::Expired(doc(1000)), 250, 7);
        assert_eq!(s.effective_max_hosts, 200);
        assert_eq!(s.state, LicenseStatusState::OverLimit); // 250 > 200
        assert!(s.expired);
        assert!(!s.licensed);
        assert_eq!(s.customer_id.as_deref(), Some("ACME"));
    }

    #[test]
    fn invalid_falls_back_to_free() {
        let s = compute_status(&LicenseState::Invalid { reason: "bad sig".into() }, 50, 7);
        assert_eq!(s.effective_max_hosts, 200);
        assert_eq!(s.state, LicenseStatusState::Ok);
        assert!(!s.licensed);
        assert!(!s.expired);
    }
}
