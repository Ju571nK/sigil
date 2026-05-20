//! Boot-time license load + the audit-line builder. The loaded LicenseState
//! lives in AppState (read-only after boot). NEVER crashes the server: any
//! load/verify failure degrades to the free tier (measure-don't-block).

use sigil_core::audit::{AuditRecord, SignedAuditRecord};
use sigil_core::license::status::{LicenseState, LicenseStatus, LicenseStatusState};
use sigil_core::license::{verify_license_allow_expired, SignedLicense};
use std::path::Path;
use time::OffsetDateTime;

/// Default rolling window for active-host counting.
pub const DEFAULT_ACTIVE_WINDOW_DAYS: u32 = 7;

/// Load + verify the license at `path`. Takes `now` for testability.
/// Returns the LicenseState; logging is the caller's job (see `load_and_log`).
pub fn load_license(path: &Path, now: OffsetDateTime) -> LicenseState {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(_) => {
            return LicenseState::Invalid {
                reason: "license file unreadable".into(),
            }
        }
    };
    let env: SignedLicense = match serde_json::from_slice(&bytes) {
        Ok(e) => e,
        Err(e) => {
            return LicenseState::Invalid {
                reason: format!("parse: {e}"),
            }
        }
    };
    match verify_license_allow_expired(&env, now) {
        Ok((doc, false)) => LicenseState::Valid(doc),
        Ok((doc, true)) => LicenseState::Expired(doc),
        Err(e) => LicenseState::Invalid {
            reason: e.to_string(),
        },
    }
}

/// Resolve config into a LicenseState (None path ⇒ Free) and log one line.
pub fn load_and_log(path: Option<&Path>, now: OffsetDateTime) -> LicenseState {
    let state = match path {
        None => LicenseState::Free,
        Some(p) => load_license(p, now),
    };
    match &state {
        LicenseState::Free => tracing::info!("license: none configured; free tier"),
        LicenseState::Valid(d) => {
            tracing::info!(license_id = %d.license_id, customer = %d.customer_id, "license: valid")
        }
        LicenseState::Expired(d) => {
            tracing::warn!(license_id = %d.license_id, "license: EXPIRED; free-tier fallback")
        }
        LicenseState::Invalid { reason } => {
            tracing::warn!(%reason, "license: INVALID; free-tier fallback")
        }
    }
    state
}

/// Should we write an audit line given the previously-written state?
/// Always write when `last` is None (boot). Otherwise write on state change.
pub fn should_audit(last: Option<LicenseStatusState>, current: LicenseStatusState) -> bool {
    last != Some(current)
}

/// Read the last signed record from `audit_path` to resume the chain across
/// restarts. Returns `(next_seq, prev_hash)`. `None` ⇒ start at genesis
/// (file absent/empty, or last line not a SignedAuditRecord).
pub fn resume_chain(audit_path: &std::path::Path) -> Option<(u64, String)> {
    let body = std::fs::read_to_string(audit_path).ok()?;
    let last = body.lines().rev().find(|l| !l.trim().is_empty())?;
    let rec: SignedAuditRecord = serde_json::from_str(last).ok()?;
    Some((rec.record.seq + 1, rec.hash))
}

/// Build an unsigned `AuditRecord` from a computed status + chain position.
pub fn build_audit_record(
    status: &LicenseStatus,
    seq: u64,
    prev_hash: String,
    now: OffsetDateTime,
    server_version: &str,
) -> AuditRecord {
    let state = match status.state {
        LicenseStatusState::Ok => "ok",
        LicenseStatusState::OverLimit => "over_limit",
    };
    AuditRecord {
        v: 1,
        seq,
        ts: now
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap(),
        state: state.to_string(),
        licensed: status.licensed,
        expired: status.expired,
        effective_max_hosts: status.effective_max_hosts,
        current_host_count: status.current_host_count,
        active_window_days: status.active_window_days,
        customer_id: status.customer_id.clone(),
        license_id: status.license_id.clone(),
        server_version: server_version.to_string(),
        prev_hash,
    }
}

/// Append a single line to the audit log (creating the file if needed).
/// Append-only — never truncates. Best-effort: logs on I/O error, never panics.
pub fn append_audit_line(audit_path: &Path, line: &str) {
    use std::io::Write;
    match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(audit_path)
    {
        Ok(mut f) => {
            if let Err(e) = writeln!(f, "{line}") {
                tracing::warn!(%e, "license audit append failed");
            }
        }
        Err(e) => tracing::warn!(%e, "license audit open failed"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigil_core::license::status::{compute_status, LicenseStatusState};
    use time::macros::datetime;

    #[test]
    fn absent_path_is_free() {
        let s = load_and_log(None, datetime!(2026-06-01 0:00 UTC));
        assert_eq!(s, LicenseState::Free);
    }

    #[test]
    fn unreadable_path_is_invalid_not_panic() {
        let s = load_license(
            Path::new("/nonexistent/sigil/license-xyz.bundle"),
            datetime!(2026-06-01 0:00 UTC),
        );
        assert!(matches!(s, LicenseState::Invalid { .. }));
    }

    #[test]
    fn corrupt_file_is_invalid() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("license.bundle");
        std::fs::write(&p, b"not json").unwrap();
        let s = load_license(&p, datetime!(2026-06-01 0:00 UTC));
        assert!(matches!(s, LicenseState::Invalid { .. }));
    }

    #[test]
    fn build_audit_record_maps_status() {
        let status = compute_status(&LicenseState::Free, 263, 7);
        let r = build_audit_record(
            &status,
            0,
            "0".repeat(64),
            datetime!(2026-06-01 11:00 UTC),
            "0.1.0",
        );
        assert_eq!(r.seq, 0);
        assert_eq!(r.state, "over_limit");
        assert_eq!(r.current_host_count, 263);
        assert_eq!(r.effective_max_hosts, 200);
        assert_eq!(r.prev_hash, "0".repeat(64));
    }

    #[test]
    fn audits_on_boot_and_transition() {
        use LicenseStatusState::*;
        assert!(should_audit(None, Ok)); // boot
        assert!(!should_audit(Some(Ok), Ok)); // no change
        assert!(should_audit(Some(Ok), OverLimit)); // transition
        assert!(should_audit(Some(OverLimit), Ok)); // recovery
    }

    #[test]
    fn append_audit_line_is_append_only() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("license-audit.jsonl");
        append_audit_line(&p, "line-1");
        append_audit_line(&p, "line-2");
        let body = std::fs::read_to_string(&p).unwrap();
        assert_eq!(body, "line-1\nline-2\n");
    }
}
