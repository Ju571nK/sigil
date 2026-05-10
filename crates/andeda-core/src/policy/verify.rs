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
    canonical::{CanonicalError},
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

/// Run the 5-check chain. The body is filled in by Tasks A5.3 + A5.4 — this
/// task only commits the skeleton + the type surface so downstream tasks
/// have something to import.
pub fn verify_envelope(
    keystore: &Keystore,
    response: &SignedPolicyResponse,
    now: OffsetDateTime,
    last_applied_policy_version: i64,
) -> Result<VerifiedPolicy, VerifyError> {
    // Body filled in by A5.3 + A5.4. Stub returns SignatureInvalid so the
    // skeleton compiles without claiming success.
    let _ = (keystore, response, now, last_applied_policy_version);
    Err(VerifyError::SignatureInvalid)
}

#[cfg(test)]
mod tests {
    use super::*;

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
            VerifyError::VersionRegression { envelope: 1, last_applied: 2 }.reason(),
            Some(PolicySignatureInvalidReason::VersionRegression)
        );
        assert_eq!(
            VerifyError::ParseFailed("bad yaml".into()).reason(),
            Some(PolicySignatureInvalidReason::ParseFailed)
        );
        assert_eq!(VerifyError::Internal("io".into()).reason(), None);
    }
}
