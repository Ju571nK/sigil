//! #184 — signed enrollment audit log (`enrollment-audit.jsonl`).
//!
//! FAIL-CLOSED: if the signed append fails, the handler returns 500 and does NOT
//! return the cert. Each line is an ed25519-signed record over canonical+blake3
//! bytes, hash-chained to the prior line (same primitives as the license audit
//! in `sigil-core::audit`, but a distinct record shape). The appended line is
//! fsync'd before we report success.

use ed25519_dalek::Signer;
use serde::{Deserialize, Serialize};
use sigil_core::audit::GENESIS_PREV_HASH;
use sigil_core::policy::canonical::to_canonical_bytes;
use std::io::Write;
use std::path::Path;

/// The signed payload. Carries the enrollment decision plus the fingerprints
/// needed to investigate a mis-issuance.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EnrollmentAuditRecord {
    pub v: u8,
    pub seq: u64,
    pub ts: String,
    pub host_id: String,
    /// `outcome` ∈ {"issued","denied"}.
    pub decision: String,
    /// Internal reason (e.g. "ok", "token_expired", "host_mismatch", "sign_failed").
    pub reason: String,
    /// blake3 of the submitted CSR PEM bytes.
    pub csr_fingerprint: String,
    /// blake3 of the issued cert PEM bytes (empty when denied).
    pub cert_fingerprint: String,
    /// Issued cert serial hex (empty when denied).
    pub serial: String,
    /// not_after of the issued cert, rfc3339 (empty when denied).
    pub not_after: String,
    /// Caller (TLS peer) cert fingerprint — blake3 hex of the leaf DER, as
    /// plumbed by `tls_accept::PeerCertAcceptor` (#194). Empty when the
    /// request carried no peer identity (plain-HTTP dev mode).
    pub caller_fingerprint: String,
    pub prev_hash: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SignedEnrollmentRecord {
    #[serde(flatten)]
    pub record: EnrollmentAuditRecord,
    pub hash: String,
    pub sig: String,
    pub pubkey_id: String,
}

#[derive(Debug)]
pub enum AuditAppendError {
    Io(std::io::Error),
    Canonical(String),
}

impl std::fmt::Display for AuditAppendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditAppendError::Io(e) => write!(f, "io: {e}"),
            AuditAppendError::Canonical(e) => write!(f, "canonical: {e}"),
        }
    }
}

/// blake3 hex of arbitrary bytes (CSR/cert fingerprints).
pub fn fingerprint(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

/// Resume the chain from an existing jsonl file: returns (next_seq, prev_hash).
/// A missing/empty/corrupt-tail file starts a fresh genesis chain.
fn resume_chain(path: &Path) -> (u64, String) {
    let Ok(content) = std::fs::read_to_string(path) else {
        return (0, GENESIS_PREV_HASH.to_string());
    };
    let last = content.lines().rfind(|l| !l.trim().is_empty());
    match last.and_then(|l| serde_json::from_str::<SignedEnrollmentRecord>(l).ok()) {
        Some(s) => (s.record.seq + 1, s.hash),
        None => (0, GENESIS_PREV_HASH.to_string()),
    }
}

/// Build, sign, and durably append one enrollment record. fsync's the line.
/// FAIL-CLOSED: any error propagates so the handler can 500 and withhold the
/// cert.
#[allow(clippy::too_many_arguments)]
pub fn append(
    path: &Path,
    key: &crate::audit_key::AuditKey,
    host_id: &str,
    decision: &str,
    reason: &str,
    csr_fingerprint: &str,
    cert_fingerprint: &str,
    serial: &str,
    not_after: &str,
    caller_fingerprint: &str,
    ts: &str,
) -> Result<SignedEnrollmentRecord, AuditAppendError> {
    let (seq, prev_hash) = resume_chain(path);
    let record = EnrollmentAuditRecord {
        v: 1,
        seq,
        ts: ts.to_string(),
        host_id: host_id.to_string(),
        decision: decision.to_string(),
        reason: reason.to_string(),
        csr_fingerprint: csr_fingerprint.to_string(),
        cert_fingerprint: cert_fingerprint.to_string(),
        serial: serial.to_string(),
        not_after: not_after.to_string(),
        caller_fingerprint: caller_fingerprint.to_string(),
        prev_hash,
    };
    let canonical =
        to_canonical_bytes(&record).map_err(|e| AuditAppendError::Canonical(e.to_string()))?;
    let hash = blake3::hash(&canonical).to_hex().to_string();
    let sig = key.signing_key.sign(&canonical);
    let signed = SignedEnrollmentRecord {
        record,
        hash,
        sig: data_encoding::BASE64.encode(&sig.to_bytes()),
        pubkey_id: key.pubkey_id.clone(),
    };
    let line =
        serde_json::to_string(&signed).map_err(|e| AuditAppendError::Canonical(e.to_string()))?;

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(AuditAppendError::Io)?;
        }
    }
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(AuditAppendError::Io)?;
    f.write_all(line.as_bytes()).map_err(AuditAppendError::Io)?;
    f.write_all(b"\n").map_err(AuditAppendError::Io)?;
    f.sync_all().map_err(AuditAppendError::Io)?;
    Ok(signed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;

    fn key(dir: &Path) -> crate::audit_key::AuditKey {
        crate::audit_key::AuditKey::load_or_create(dir).unwrap()
    }

    fn verify_line(signed: &SignedEnrollmentRecord, k: &crate::audit_key::AuditKey) -> bool {
        let canonical = to_canonical_bytes(&signed.record).unwrap();
        if blake3::hash(&canonical).to_hex().to_string() != signed.hash {
            return false;
        }
        let raw = data_encoding::BASE64.decode(signed.sig.as_bytes()).unwrap();
        let arr: [u8; 64] = raw.as_slice().try_into().unwrap();
        let sig = ed25519_dalek::Signature::from_bytes(&arr);
        k.signing_key
            .verifying_key()
            .verify(&canonical, &sig)
            .is_ok()
    }

    #[test]
    fn append_two_chains_and_verifies() {
        let d = tempfile::tempdir().unwrap();
        let k = key(d.path());
        let p = d.path().join("enrollment-audit.jsonl");
        let a = append(
            &p,
            &k,
            "host-1",
            "issued",
            "ok",
            "csrfp",
            "certfp",
            "0a",
            "2026-07-01T00:00:00Z",
            "callerfp",
            "2026-06-23T00:00:00Z",
        )
        .unwrap();
        let b = append(
            &p,
            &k,
            "host-2",
            "denied",
            "token_expired",
            "csrfp2",
            "",
            "",
            "",
            "",
            "2026-06-23T00:01:00Z",
        )
        .unwrap();
        assert_eq!(a.record.seq, 0);
        assert_eq!(a.record.prev_hash, GENESIS_PREV_HASH);
        assert_eq!(a.record.caller_fingerprint, "callerfp");
        assert_eq!(b.record.caller_fingerprint, "");
        assert_eq!(b.record.seq, 1);
        assert_eq!(b.record.prev_hash, a.hash, "chain link");
        assert!(verify_line(&a, &k));
        assert!(verify_line(&b, &k));
        // two physical lines
        let n = std::fs::read_to_string(&p)
            .unwrap()
            .lines()
            .filter(|l| !l.trim().is_empty())
            .count();
        assert_eq!(n, 2);
    }
}
