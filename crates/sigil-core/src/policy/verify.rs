//! 5-check signature verification chain for `SignedPolicyResponse`.
//!
//! Spec §3.8.2. The verifier is pure — no I/O, no state mutation, no event
//! emission. It returns either a `VerifiedPolicy` (caller may now atomically
//! advance `last_applied_policy_version` + write `policy.yaml`) or a
//! `VerifyError` (caller emits a `PolicySignatureInvalid` event).
//!
//! Order of checks is fixed by spec — the first failure short-circuits.
//!   1. pubkey active        → VerifyError::PubkeyUnknown / PubkeyInactive
//!   2. signature valid      → VerifyError::SignatureInvalid
//!   3. valid_until in future → VerifyError::Expired
//!   4. policy_version monotonic → VerifyError::VersionRegression
//!   5. parse                → VerifyError::ParseFailed

use crate::event::PolicySignatureInvalidReason;
use crate::policy::{
    canonical::{to_canonical_bytes, CanonicalError},
    pubkeys::{Keystore, KeystoreError},
    signed_envelope::SignedPolicyResponse,
    PolicyDocument,
};
use thiserror::Error;
use time::OffsetDateTime;

/// Successful verification result.
#[derive(Clone, Debug, PartialEq)]
pub struct VerifiedPolicy {
    /// The decoded YAML parsed into a `PolicyDocument`.
    pub policy: PolicyDocument,
    /// Echoed for the caller's atomic write step.
    pub policy_version: i64,
    /// Echoed for the caller's atomic write step (to be persisted on success).
    pub policy_bytes: Vec<u8>,
    /// Echoed for diagnostic logging.
    pub signing_pubkey_id: String,
}

/// Failure result. Each variant maps to a `PolicySignatureInvalidReason`.
#[derive(Debug, Error)]
pub enum VerifyError {
    /// Check 1: `signing_pubkey_id` not present in the keystore.
    #[error("pubkey unknown: {0}")]
    PubkeyUnknown(String),
    /// Check 1: keystore entry present but `now` is outside its validity window.
    #[error("pubkey inactive (outside validity window): {0}")]
    PubkeyInactive(String),
    /// Check 2: ed25519 verification failed against the canonical bytes.
    #[error("signature invalid")]
    SignatureInvalid,
    /// Check 3: envelope's `valid_until` is in the past.
    #[error("envelope expired")]
    Expired,
    /// Check 4: envelope's `policy_version` is not strictly greater than
    /// the agent's `last_applied_policy_version`.
    #[error("policy_version regression: envelope={envelope}, last_applied={last_applied}")]
    VersionRegression {
        /// Version claimed by the rejected envelope.
        envelope: i64,
        /// Agent's current persisted version.
        last_applied: i64,
    },
    /// Check 5: bytes did not parse to a `PolicyDocument`.
    #[error("policy bytes did not parse: {0}")]
    ParseFailed(String),
    /// Internal failure (keystore I/O, canonicalization). NOT a signature
    /// invalidity — the caller should NOT emit `PolicySignatureInvalid`,
    /// it should log + retry. Surfaced separately from the `Reason`.
    #[error("internal verifier error: {0}")]
    Internal(String),
}

impl VerifyError {
    /// Map to the wire-stable rejection reason. Returns `None` for `Internal`
    /// (which is not a signature invalidity).
    pub fn reason(&self) -> Option<PolicySignatureInvalidReason> {
        Some(match self {
            VerifyError::PubkeyUnknown(_) => PolicySignatureInvalidReason::PubkeyUnknown,
            VerifyError::PubkeyInactive(_) => PolicySignatureInvalidReason::PubkeyInactive,
            VerifyError::SignatureInvalid => PolicySignatureInvalidReason::SignatureInvalid,
            VerifyError::Expired => PolicySignatureInvalidReason::Expired,
            VerifyError::VersionRegression { .. } => {
                PolicySignatureInvalidReason::VersionRegression
            }
            VerifyError::ParseFailed(_) => PolicySignatureInvalidReason::ParseFailed,
            VerifyError::Internal(_) => return None,
        })
    }
}

impl From<KeystoreError> for VerifyError {
    fn from(e: KeystoreError) -> Self {
        VerifyError::Internal(format!("keystore: {e}"))
    }
}

impl From<CanonicalError> for VerifyError {
    fn from(e: CanonicalError) -> Self {
        VerifyError::Internal(format!("canonical: {e}"))
    }
}

/// Run the 5-check chain.
pub fn verify_envelope(
    keystore: &Keystore,
    response: &SignedPolicyResponse,
    now: OffsetDateTime,
    last_applied_policy_version: i64,
) -> Result<VerifiedPolicy, VerifyError> {
    use ed25519_dalek::{Signature, Verifier};

    // ─── Check 1: pubkey active ───────────────────────────────────────────
    let id = &response.signing_pubkey_id;
    let pk = match keystore.active_pubkey(id, now)? {
        Some(pk) => pk,
        None => {
            // Distinguish "id not present at all" from "id present but inactive".
            let id_known = keystore.pubkeys.iter().any(|e| &e.id == id);
            return if id_known {
                Err(VerifyError::PubkeyInactive(id.clone()))
            } else {
                Err(VerifyError::PubkeyUnknown(id.clone()))
            };
        }
    };

    // ─── Check 2: signature valid ────────────────────────────────────────
    let sig_bytes = match data_encoding::BASE64.decode(response.signature.as_bytes()) {
        Ok(b) => b,
        Err(_) => return Err(VerifyError::SignatureInvalid),
    };
    if sig_bytes.len() != 64 {
        return Err(VerifyError::SignatureInvalid);
    }
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&sig_bytes);
    let sig = Signature::from_bytes(&arr);

    let canonical = to_canonical_bytes(&response.signed_envelope)?;
    if pk.verify(&canonical, &sig).is_err() {
        return Err(VerifyError::SignatureInvalid);
    }

    // ─── Check 3: valid_until in future ──────────────────────────────────
    if now >= response.signed_envelope.valid_until {
        return Err(VerifyError::Expired);
    }

    // ─── Check 4: policy_version monotonic ───────────────────────────────
    let envelope_version = response.signed_envelope.policy_version;
    if envelope_version <= last_applied_policy_version {
        return Err(VerifyError::VersionRegression {
            envelope: envelope_version,
            last_applied: last_applied_policy_version,
        });
    }

    // ─── Check 5: decode + parse policy YAML ─────────────────────────────
    let policy_bytes = response
        .signed_envelope
        .decode_policy_bytes()
        .map_err(|e| VerifyError::ParseFailed(format!("base64: {e}")))?;
    let policy: PolicyDocument = serde_yaml::from_slice(&policy_bytes)
        .map_err(|e| VerifyError::ParseFailed(format!("yaml: {e}")))?;

    Ok(VerifiedPolicy {
        policy,
        policy_version: envelope_version,
        policy_bytes,
        signing_pubkey_id: response.signing_pubkey_id.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::canonical::to_canonical_bytes;
    use crate::policy::pubkeys::{Keystore, KeystoreEntry};
    use crate::policy::signed_envelope::{SignedEnvelope, SignedPolicyResponse};
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::{OsRng, RngCore};
    use time::macros::datetime;

    /// Fixture: a keystore + matching SigningKey for "k1" with a wide window.
    fn fixture(now: OffsetDateTime) -> (Keystore, SigningKey) {
        let mut secret = [0u8; 32];
        OsRng.fill_bytes(&mut secret);
        let sk = SigningKey::from_bytes(&secret);
        let pk_b64 = data_encoding::BASE64.encode(&sk.verifying_key().to_bytes());
        let store = Keystore {
            pubkeys: vec![KeystoreEntry {
                id: "k1".into(),
                ed25519_pubkey_b64: pk_b64,
                valid_from: now - time::Duration::days(30),
                valid_until: now + time::Duration::days(365),
            }],
        };
        (store, sk)
    }

    fn sign_response(
        sk: &SigningKey,
        envelope: SignedEnvelope,
        signing_pubkey_id: &str,
        now: OffsetDateTime,
    ) -> SignedPolicyResponse {
        let bytes = to_canonical_bytes(&envelope).unwrap();
        let sig = sk.sign(&bytes);
        SignedPolicyResponse {
            etag: blake3::hash(&bytes).to_hex().to_string(),
            signed_envelope: envelope,
            signature: data_encoding::BASE64.encode(&sig.to_bytes()),
            signing_pubkey_id: signing_pubkey_id.into(),
            applied_at: now,
        }
    }

    fn well_formed_envelope(version: i64, now: OffsetDateTime) -> SignedEnvelope {
        SignedEnvelope {
            policy_version: version,
            // base64("version: 1\nrules: []\n") — minimal valid policy YAML.
            policy_bytes_b64: data_encoding::BASE64.encode(b"version: 1\nrules: []\n"),
            valid_until: now + time::Duration::hours(24),
            issued_at: now,
        }
    }

    #[test]
    fn check1_unknown_pubkey_id_returns_pubkey_unknown() {
        let now = datetime!(2026-05-15 0:00 UTC);
        let (store, sk) = fixture(now);
        let env = well_formed_envelope(10, now);
        let mut resp = sign_response(&sk, env, "k1", now);
        resp.signing_pubkey_id = "k-does-not-exist".into();

        let r = verify_envelope(&store, &resp, now, 0);
        assert!(matches!(r, Err(VerifyError::PubkeyUnknown(_))));
    }

    #[test]
    fn check1_inactive_pubkey_returns_pubkey_inactive() {
        let now = datetime!(2026-05-15 0:00 UTC);
        let (mut store, sk) = fixture(now);
        store.pubkeys[0].valid_until = now - time::Duration::days(1);
        let env = well_formed_envelope(10, now);
        let resp = sign_response(&sk, env, "k1", now);

        let r = verify_envelope(&store, &resp, now, 0);
        assert!(matches!(r, Err(VerifyError::PubkeyInactive(_))));
    }

    #[test]
    fn check2_tampered_signature_returns_signature_invalid() {
        let now = datetime!(2026-05-15 0:00 UTC);
        let (store, sk) = fixture(now);
        let env = well_formed_envelope(10, now);
        let mut resp = sign_response(&sk, env, "k1", now);
        let mut sig_bytes = data_encoding::BASE64
            .decode(resp.signature.as_bytes())
            .unwrap();
        sig_bytes[0] ^= 0xff;
        resp.signature = data_encoding::BASE64.encode(&sig_bytes);

        let r = verify_envelope(&store, &resp, now, 0);
        assert!(matches!(r, Err(VerifyError::SignatureInvalid)));
    }

    #[test]
    fn check2_tampered_envelope_returns_signature_invalid() {
        let now = datetime!(2026-05-15 0:00 UTC);
        let (store, sk) = fixture(now);
        let env = well_formed_envelope(10, now);
        let mut resp = sign_response(&sk, env, "k1", now);
        resp.signed_envelope.policy_version = 999;

        let r = verify_envelope(&store, &resp, now, 0);
        assert!(matches!(r, Err(VerifyError::SignatureInvalid)));
    }

    #[test]
    fn check2_signature_with_wrong_length_is_signature_invalid_not_internal() {
        let now = datetime!(2026-05-15 0:00 UTC);
        let (store, sk) = fixture(now);
        let env = well_formed_envelope(10, now);
        let mut resp = sign_response(&sk, env, "k1", now);
        resp.signature = data_encoding::BASE64.encode(&[0u8; 32]);

        let r = verify_envelope(&store, &resp, now, 0);
        assert!(matches!(r, Err(VerifyError::SignatureInvalid)));
    }

    #[test]
    fn check2_signature_not_base64_is_signature_invalid_not_internal() {
        let now = datetime!(2026-05-15 0:00 UTC);
        let (store, sk) = fixture(now);
        let env = well_formed_envelope(10, now);
        let mut resp = sign_response(&sk, env, "k1", now);
        resp.signature = "not!base64!".into();

        let r = verify_envelope(&store, &resp, now, 0);
        assert!(matches!(r, Err(VerifyError::SignatureInvalid)));
    }

    #[test]
    fn each_error_variant_has_a_reason_except_internal() {
        assert_eq!(
            VerifyError::PubkeyUnknown("x".into()).reason(),
            Some(PolicySignatureInvalidReason::PubkeyUnknown)
        );
        assert_eq!(
            VerifyError::PubkeyInactive("x".into()).reason(),
            Some(PolicySignatureInvalidReason::PubkeyInactive)
        );
        assert_eq!(
            VerifyError::SignatureInvalid.reason(),
            Some(PolicySignatureInvalidReason::SignatureInvalid)
        );
        assert_eq!(
            VerifyError::Expired.reason(),
            Some(PolicySignatureInvalidReason::Expired)
        );
        assert_eq!(
            VerifyError::VersionRegression {
                envelope: 1,
                last_applied: 2
            }
            .reason(),
            Some(PolicySignatureInvalidReason::VersionRegression)
        );
        assert_eq!(
            VerifyError::ParseFailed("bad yaml".into()).reason(),
            Some(PolicySignatureInvalidReason::ParseFailed)
        );
        assert_eq!(VerifyError::Internal("io".into()).reason(), None);
    }

    #[test]
    fn check3_envelope_already_expired_returns_expired() {
        let now = datetime!(2026-05-15 0:00 UTC);
        let (store, sk) = fixture(now);
        let mut env = well_formed_envelope(10, now);
        env.valid_until = now - time::Duration::seconds(1);
        let resp = sign_response(&sk, env, "k1", now);

        let r = verify_envelope(&store, &resp, now, 0);
        assert!(matches!(r, Err(VerifyError::Expired)));
    }

    #[test]
    fn check3_envelope_at_exact_valid_until_is_expired() {
        let now = datetime!(2026-05-15 0:00 UTC);
        let (store, sk) = fixture(now);
        let mut env = well_formed_envelope(10, now);
        env.valid_until = now;
        let resp = sign_response(&sk, env, "k1", now);

        let r = verify_envelope(&store, &resp, now, 0);
        assert!(matches!(r, Err(VerifyError::Expired)));
    }

    #[test]
    fn check4_same_version_as_last_applied_returns_version_regression() {
        let now = datetime!(2026-05-15 0:00 UTC);
        let (store, sk) = fixture(now);
        let env = well_formed_envelope(10, now);
        let resp = sign_response(&sk, env, "k1", now);

        let r = verify_envelope(&store, &resp, now, 10);
        assert!(matches!(
            r,
            Err(VerifyError::VersionRegression {
                envelope: 10,
                last_applied: 10
            })
        ));
    }

    #[test]
    fn check4_lower_version_returns_version_regression() {
        let now = datetime!(2026-05-15 0:00 UTC);
        let (store, sk) = fixture(now);
        let env = well_formed_envelope(5, now);
        let resp = sign_response(&sk, env, "k1", now);

        let r = verify_envelope(&store, &resp, now, 10);
        assert!(matches!(
            r,
            Err(VerifyError::VersionRegression {
                envelope: 5,
                last_applied: 10
            })
        ));
    }

    #[test]
    fn check5_undecodable_base64_returns_parse_failed() {
        let now = datetime!(2026-05-15 0:00 UTC);
        let (store, sk) = fixture(now);
        let mut env = well_formed_envelope(10, now);
        env.policy_bytes_b64 = "not!base64!".into();
        let resp = sign_response(&sk, env, "k1", now);

        let r = verify_envelope(&store, &resp, now, 0);
        assert!(matches!(r, Err(VerifyError::ParseFailed(_))));
    }

    #[test]
    fn check5_invalid_yaml_returns_parse_failed() {
        let now = datetime!(2026-05-15 0:00 UTC);
        let (store, sk) = fixture(now);
        let mut env = well_formed_envelope(10, now);
        env.policy_bytes_b64 = data_encoding::BASE64.encode(b"\xff\xfe not yaml :::");
        let resp = sign_response(&sk, env, "k1", now);

        let r = verify_envelope(&store, &resp, now, 0);
        assert!(matches!(r, Err(VerifyError::ParseFailed(_))));
    }

    #[test]
    fn happy_path_returns_verified_policy() {
        let now = datetime!(2026-05-15 0:00 UTC);
        let (store, sk) = fixture(now);
        let env = well_formed_envelope(10, now);
        let resp = sign_response(&sk, env, "k1", now);

        let r = verify_envelope(&store, &resp, now, 9);
        let v = r.expect("happy path should succeed");
        assert_eq!(v.policy_version, 10);
        assert_eq!(v.signing_pubkey_id, "k1");
        assert_eq!(v.policy_bytes, b"version: 1\nrules: []\n");
    }

    #[test]
    fn checks_run_in_spec_order() {
        // An envelope failing check 3 + 4 + 5 → must report Expired (check 3).
        let now = datetime!(2026-05-15 0:00 UTC);
        let (store, sk) = fixture(now);
        let mut env = well_formed_envelope(1, now);
        env.valid_until = now - time::Duration::seconds(1);
        env.policy_bytes_b64 = "not!base64!".into();
        let resp = sign_response(&sk, env, "k1", now);

        let r = verify_envelope(&store, &resp, now, 100);
        assert!(matches!(r, Err(VerifyError::Expired)));
    }
}
