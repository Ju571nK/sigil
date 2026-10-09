//! Read-only access to an existing signed, hash-chained audit log.
//!
//! Earlier releases appended records to `license-audit.jsonl` (next to the
//! high-water file). The server no longer writes new records, but a chain that
//! already exists on disk is still surfaced: its last line becomes
//! `/v1/meta.audit_head`, so a head recorded off-box can still be checked
//! against the file with `sigil-sign verify-audit`.

use sigil_core::audit::{AuditHead, SignedAuditRecord};
use std::path::{Path, PathBuf};

/// File name of the chain written by earlier releases. Kept so existing
/// deployments keep exposing their head; never created by this release.
pub const AUDIT_CHAIN_FILE_NAME: &str = "license-audit.jsonl";

/// Path of the existing audit chain inside the server's state directory.
pub fn chain_path(state_dir: &Path) -> PathBuf {
    state_dir.join(AUDIT_CHAIN_FILE_NAME)
}

/// Head of the chain at `path`, taken from its last non-empty line.
/// `None` when the file is absent/unreadable/empty or the last line is not a
/// `SignedAuditRecord`. Does not verify the chain; that is the job of
/// `sigil-sign verify-audit` against an externally-observed head.
pub fn read_head(path: &Path) -> Option<AuditHead> {
    let body = std::fs::read_to_string(path).ok()?;
    let last = body.lines().rev().find(|l| !l.trim().is_empty())?;
    let rec: SignedAuditRecord = serde_json::from_str(last).ok()?;
    Some(AuditHead {
        seq: rec.record.seq,
        hash: rec.hash,
        sig: rec.sig,
        pubkey_id: rec.pubkey_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../sigil-core/tests/fixtures/audit/legacy-chain-v1.jsonl"
    );

    #[test]
    fn head_of_existing_chain_is_last_line() {
        let head = read_head(Path::new(FIXTURE)).expect("fixture head");
        assert_eq!(head.seq, 2);
        assert_eq!(
            head.hash,
            "3f119e2fe76f1c3cbf8a267419db1cda7e137514d1ba48e3ddfa9d763c8c8df2"
        );
        assert_eq!(head.pubkey_id, "sigil-audit-fixt01");
    }

    #[test]
    fn trailing_blank_lines_are_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let p = chain_path(dir.path());
        let body = std::fs::read_to_string(FIXTURE).unwrap();
        std::fs::write(&p, format!("{body}\n\n  \n")).unwrap();
        assert_eq!(read_head(&p).unwrap().seq, 2);
    }

    #[test]
    fn absent_empty_or_garbage_is_none() {
        let dir = tempfile::tempdir().unwrap();
        let p = chain_path(dir.path());
        assert!(read_head(&p).is_none(), "absent");
        std::fs::write(&p, "").unwrap();
        assert!(read_head(&p).is_none(), "empty");
        std::fs::write(&p, "not json\n").unwrap();
        assert!(read_head(&p).is_none(), "garbage");
    }

    #[test]
    fn reading_does_not_create_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = chain_path(dir.path());
        let _ = read_head(&p);
        assert!(!p.exists());
    }
}
