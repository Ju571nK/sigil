//! Signed-envelope types for the Phase 2 policy control plane.
//!
//! Spec §3.8.2: the envelope carries `policy_version`, `policy_bytes_b64`,
//! `valid_until`, `issued_at`. NO host_id field — the envelope is fleet-wide
//! and signed once for all hosts.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// The signed unit. Signature covers `canonical_json(SignedEnvelope)`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SignedEnvelope {
    /// Per-customer monotonic version counter (single integer for the whole fleet).
    pub policy_version: i64,
    /// YAML policy bytes, base64-encoded.
    pub policy_bytes_b64: String,
    /// Agent rejects if `now() >= valid_until`. RFC 3339.
    #[serde(with = "time::serde::rfc3339")]
    pub valid_until: OffsetDateTime,
    /// When the envelope was signed. Informational; not used in verification.
    #[serde(with = "time::serde::rfc3339")]
    pub issued_at: OffsetDateTime,
}

/// The wire shape returned by the control endpoint and handed to
/// `andeda-agent`'s `apply_policy` IPC.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SignedPolicyResponse {
    /// SHA-256(canonical_json(signed_envelope)) — used for ETag and caching.
    pub etag: String,
    /// The signed unit.
    pub signed_envelope: SignedEnvelope,
    /// ed25519 signature, base64-encoded.
    pub signature: String,
    /// Identifies which keystore entry was used to sign.
    pub signing_pubkey_id: String,
    /// Timestamp the server applied the envelope to its serving directory.
    /// Informational.
    #[serde(with = "time::serde::rfc3339")]
    pub applied_at: OffsetDateTime,
}

impl SignedEnvelope {
    /// Decode the embedded YAML policy bytes.
    pub fn decode_policy_bytes(&self) -> Result<Vec<u8>, data_encoding::DecodeError> {
        data_encoding::BASE64.decode(self.policy_bytes_b64.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    fn sample() -> SignedEnvelope {
        SignedEnvelope {
            policy_version: 42,
            policy_bytes_b64: "dmVyc2lvbjogMQo=".into(), // "version: 1\n"
            valid_until: datetime!(2026-06-15 0:00 UTC),
            issued_at: datetime!(2026-05-15 8:00 UTC),
        }
    }

    #[test]
    fn round_trips_through_serde_json() {
        let e = sample();
        let s = serde_json::to_string(&e).unwrap();
        let back: SignedEnvelope = serde_json::from_str(&s).unwrap();
        assert_eq!(e, back);
    }

    #[test]
    fn does_not_have_host_id_field() {
        let e = sample();
        let s = serde_json::to_string(&e).unwrap();
        assert!(
            !s.contains("host_id"),
            "spec §3.8.2: envelope MUST NOT include host_id"
        );
    }

    #[test]
    fn valid_until_serializes_as_rfc3339() {
        let e = sample();
        let s = serde_json::to_string(&e).unwrap();
        assert!(s.contains("\"valid_until\":\"2026-06-15T00:00:00Z\""));
    }

    #[test]
    fn decode_policy_bytes_returns_yaml_text() {
        let e = sample();
        let bytes = e.decode_policy_bytes().unwrap();
        assert_eq!(bytes, b"version: 1\n");
    }

    #[test]
    fn decode_rejects_invalid_base64() {
        let mut e = sample();
        e.policy_bytes_b64 = "not!base64!".into();
        assert!(e.decode_policy_bytes().is_err());
    }

    #[test]
    fn signed_policy_response_round_trips() {
        let r = SignedPolicyResponse {
            etag: "abc".into(),
            signed_envelope: sample(),
            signature: "sig".into(),
            signing_pubkey_id: "andeda-policy-2026-05".into(),
            applied_at: datetime!(2026-05-15 8:01 UTC),
        };
        let s = serde_json::to_string(&r).unwrap();
        let back: SignedPolicyResponse = serde_json::from_str(&s).unwrap();
        assert_eq!(r, back);
    }
}
