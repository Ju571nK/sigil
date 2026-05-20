//! Tamper-evident license-audit log: per-record ed25519 signature + linear
//! blake3 hash-chain. Pure model + sign + verify — no file I/O, no RNG; the
//! caller (sigil-server) owns the key lifecycle. Mirrors the policy/license
//! signing pattern: ed25519 over `to_canonical_bytes`.
//!
//! HONEST LIMITATION: this fully defends against third-party tampering and
//! accidental corruption — any edit, reorder, deletion, or truncation breaks a
//! hash or the chain and is caught by `verify_chain`. It does NOT stop the box
//! operator (who holds the signing key) from rewriting the whole chain. The
//! operator is bound only for history *before any externally-observed head*
//! (e.g. a head read from `/v1/meta` and retained by an external party). The
//! signing key provides identity to pin, not secrecy. Push/transparency-log
//! anchoring is future work.

use crate::policy::canonical::to_canonical_bytes;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

/// `prev_hash` of the genesis record (seq 0): 64 hex zeros.
pub const GENESIS_PREV_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// The signed payload. `prev_hash` carries the chain link; `seq` is monotonic.
/// Does NOT contain its own hash/sig (those wrap it in `SignedAuditRecord`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AuditRecord {
    pub v: u8,
    pub seq: u64,
    pub ts: String,
    pub state: String,
    pub licensed: bool,
    pub expired: bool,
    pub effective_max_hosts: u32,
    pub current_host_count: u32,
    pub active_window_days: u32,
    pub customer_id: Option<String>,
    pub license_id: Option<String>,
    pub server_version: String,
    pub prev_hash: String,
}

/// One JSONL line: the record plus its hash, signature, and signer id.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SignedAuditRecord {
    #[serde(flatten)]
    pub record: AuditRecord,
    pub hash: String,
    pub sig: String,
    pub pubkey_id: String,
}

/// The latest verified position in the chain (exposed via `/v1/meta`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AuditHead {
    pub seq: u64,
    pub hash: String,
    pub sig: String,
    pub pubkey_id: String,
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum AuditError {
    #[error("signature verification failed at seq {0}")]
    BadSignature(u64),
    #[error("hash mismatch at seq {0}")]
    BadHash(u64),
    #[error("broken chain at seq {0}: prev_hash does not match prior line")]
    BrokenChain(u64),
    #[error("non-monotonic seq at line {index}: got {got}, expected {expected}")]
    NonMonotonicSeq {
        index: usize,
        got: u64,
        expected: u64,
    },
    #[error("malformed audit data: {0}")]
    Malformed(String),
}

/// Canonical bytes + their blake3 hex digest for a record.
fn canonical_and_hash(record: &AuditRecord) -> Result<(Vec<u8>, String), AuditError> {
    let canonical = to_canonical_bytes(record).map_err(|e| AuditError::Malformed(e.to_string()))?;
    let hash = blake3::hash(&canonical).to_hex().to_string();
    Ok((canonical, hash))
}

/// Build + sign one record. `hash` and `sig` both derive from
/// `to_canonical_bytes(&record)` (the SAME bytes `verify_*` re-derives).
pub fn sign_record(
    record: AuditRecord,
    signing_key: &SigningKey,
    pubkey_id: &str,
) -> Result<SignedAuditRecord, AuditError> {
    let (canonical, hash) = canonical_and_hash(&record)?;
    let sig = signing_key.sign(&canonical);
    Ok(SignedAuditRecord {
        record,
        hash,
        sig: data_encoding::BASE64.encode(&sig.to_bytes()),
        pubkey_id: pubkey_id.to_string(),
    })
}

/// Verify ONE record's hash + signature (not chain linkage).
pub fn verify_record(
    signed: &SignedAuditRecord,
    verifying_key: &VerifyingKey,
) -> Result<(), AuditError> {
    let seq = signed.record.seq;
    let (canonical, hash) = canonical_and_hash(&signed.record)?;
    if hash != signed.hash {
        return Err(AuditError::BadHash(seq));
    }
    let raw = data_encoding::BASE64
        .decode(signed.sig.as_bytes())
        .map_err(|_| AuditError::BadSignature(seq))?;
    let arr: [u8; 64] = raw
        .as_slice()
        .try_into()
        .map_err(|_| AuditError::BadSignature(seq))?;
    let sig = Signature::from_bytes(&arr);
    verifying_key
        .verify(&canonical, &sig)
        .map_err(|_| AuditError::BadSignature(seq))
}

/// Verify a full chain: per-record hash, optional signature, prev_hash linkage,
/// seq monotonicity. `verifying_key: None` => structure (hash + chain) only;
/// `Some` => also authenticity. Returns the head (last line) on success.
pub fn verify_chain(
    lines: &[SignedAuditRecord],
    verifying_key: Option<&VerifyingKey>,
) -> Result<AuditHead, AuditError> {
    if lines.is_empty() {
        return Err(AuditError::Malformed("empty chain".into()));
    }
    for (i, line) in lines.iter().enumerate() {
        let (_canonical, hash) = canonical_and_hash(&line.record)?;
        if hash != line.hash {
            return Err(AuditError::BadHash(line.record.seq));
        }
        if let Some(vk) = verifying_key {
            verify_record(line, vk)?;
        }
        if i == 0 {
            if line.record.seq != 0 {
                return Err(AuditError::NonMonotonicSeq {
                    index: 0,
                    got: line.record.seq,
                    expected: 0,
                });
            }
            if line.record.prev_hash != GENESIS_PREV_HASH {
                return Err(AuditError::BrokenChain(line.record.seq));
            }
        } else {
            let prev = &lines[i - 1];
            let expected = prev.record.seq + 1;
            if line.record.seq != expected {
                return Err(AuditError::NonMonotonicSeq {
                    index: i,
                    got: line.record.seq,
                    expected,
                });
            }
            if line.record.prev_hash != prev.hash {
                return Err(AuditError::BrokenChain(line.record.seq));
            }
        }
    }
    let last = &lines[lines.len() - 1];
    Ok(AuditHead {
        seq: last.record.seq,
        hash: last.hash.clone(),
        sig: last.sig.clone(),
        pubkey_id: last.pubkey_id.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::{OsRng, RngCore};

    fn keypair() -> (SigningKey, VerifyingKey) {
        let mut secret = [0u8; 32];
        OsRng.fill_bytes(&mut secret);
        let sk = SigningKey::from_bytes(&secret);
        let vk = sk.verifying_key();
        (sk, vk)
    }

    fn rec(seq: u64, prev_hash: &str) -> AuditRecord {
        AuditRecord {
            v: 1,
            seq,
            ts: "2026-06-01T00:00:00Z".into(),
            state: "ok".into(),
            licensed: true,
            expired: false,
            effective_max_hosts: 1000,
            current_host_count: 10,
            active_window_days: 7,
            customer_id: Some("ACME".into()),
            license_id: Some("SIGIL-2026-ACME-a1b2c3".into()),
            server_version: "0.1.0".into(),
            prev_hash: prev_hash.into(),
        }
    }

    fn signed_chain(sk: &SigningKey, n: u64) -> Vec<SignedAuditRecord> {
        let mut out = Vec::new();
        let mut prev = GENESIS_PREV_HASH.to_string();
        for seq in 0..n {
            let signed = sign_record(rec(seq, &prev), sk, "audit-k1").unwrap();
            prev = signed.hash.clone();
            out.push(signed);
        }
        out
    }

    #[test]
    fn genesis_record_round_trips() {
        let (sk, vk) = keypair();
        let signed = sign_record(rec(0, GENESIS_PREV_HASH), &sk, "audit-k1").unwrap();
        assert_eq!(signed.pubkey_id, "audit-k1");
        verify_record(&signed, &vk).unwrap();
        let head = verify_chain(&[signed], Some(&vk)).unwrap();
        assert_eq!(head.seq, 0);
    }

    #[test]
    fn multi_line_chain_verifies() {
        let (sk, vk) = keypair();
        let chain = signed_chain(&sk, 3);
        let head = verify_chain(&chain, Some(&vk)).unwrap();
        assert_eq!(head.seq, 2);
        assert_eq!(head.hash, chain[2].hash);
    }

    #[test]
    fn tampered_payload_is_bad_hash() {
        let (sk, vk) = keypair();
        let mut chain = signed_chain(&sk, 2);
        chain[1].record.current_host_count = 999_999;
        let err = verify_chain(&chain, Some(&vk)).unwrap_err();
        assert_eq!(err, AuditError::BadHash(1));
    }

    #[test]
    fn reorder_breaks_chain() {
        let (sk, vk) = keypair();
        let mut chain = signed_chain(&sk, 3);
        chain.swap(1, 2);
        let err = verify_chain(&chain, Some(&vk)).unwrap_err();
        assert_eq!(
            err,
            AuditError::NonMonotonicSeq {
                index: 1,
                got: 2,
                expected: 1
            }
        );
    }

    #[test]
    fn deleting_middle_breaks_chain() {
        let (sk, vk) = keypair();
        let mut chain = signed_chain(&sk, 3);
        chain.remove(1);
        let err = verify_chain(&chain, Some(&vk)).unwrap_err();
        assert_eq!(
            err,
            AuditError::NonMonotonicSeq {
                index: 1,
                got: 2,
                expected: 1
            }
        );
    }

    #[test]
    fn wrong_key_is_bad_signature() {
        let (sk, _vk) = keypair();
        let (_sk2, vk2) = keypair();
        let chain = signed_chain(&sk, 1);
        let err = verify_chain(&chain, Some(&vk2)).unwrap_err();
        assert_eq!(err, AuditError::BadSignature(0));
    }

    #[test]
    fn structure_only_skips_authenticity() {
        let (sk, _vk) = keypair();
        let chain = signed_chain(&sk, 2);
        let head = verify_chain(&chain, None).unwrap();
        assert_eq!(head.seq, 1);
    }

    #[test]
    fn non_genesis_first_line_breaks() {
        let (sk, vk) = keypair();
        let bad_prev = "ff".repeat(32);
        let signed = sign_record(rec(0, &bad_prev), &sk, "audit-k1").unwrap();
        let err = verify_chain(&[signed], Some(&vk)).unwrap_err();
        assert_eq!(err, AuditError::BrokenChain(0));
    }
}
