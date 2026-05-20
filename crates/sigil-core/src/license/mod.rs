//! Vendor-signed license verification. Sibling of `policy` — reuses the same
//! ed25519 + RFC 8785 canonical-JSON primitives, but the trust anchor is the
//! vendor's compiled-in pubkeys (NOT the operator's policy-signing keys), so
//! operators cannot self-issue a license.

pub mod status;

use crate::policy::canonical::to_canonical_bytes;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// Vendor-signed statement of agreed terms. Signed offline with the vendor
/// private key; verified against [`SIGIL_LICENSE_PUBKEYS`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LicenseDocument {
    /// Contract join key + identifier. Format: SIGIL-<year>-<CUST>-<rand6>.
    pub license_id: String,
    pub customer_id: String,
    pub max_hosts: u32,
    #[serde(with = "time::serde::rfc3339")]
    pub issued_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub not_after: OffsetDateTime,
}

/// The signed unit delivered to the server. Signature covers
/// `to_canonical_bytes(&license)`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SignedLicense {
    pub license: LicenseDocument,
    /// ed25519 signature over the canonical bytes of `license`, base64.
    pub signature: String,
    /// Which vendor key id signed this (matches an id in SIGIL_LICENSE_PUBKEYS).
    pub signing_pubkey_id: String,
}

/// Compiled-in vendor trust anchor. PUBLIC keys only — the private key never
/// exists in this repo. Each entry is `(key_id, "ed25519:<base64 pubkey>")`.
/// Multiple entries support rotation. Replaced via a new release, not config.
///
/// SHIPS EMPTY this phase: the vendor key ceremony (generate offline keypair,
/// paste the pubkey here) is an out-of-band step tracked in the issue. The
/// verification logic below is fully implemented and tested via an injected
/// test key (see `verify_license_allow_expired_with_keys`).
pub const SIGIL_LICENSE_PUBKEYS: &[(&str, &str)] = &[
    // ("sigil-license-2026", "ed25519:<base64 vendor pubkey v1>"),
];

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum LicenseError {
    #[error("signature verification failed")]
    BadSignature,
    #[error("unknown or unlisted signing key id: {0}")]
    UnknownKey(String),
    #[error("license expired at {0}")]
    Expired(OffsetDateTime),
    #[error("malformed license: {0}")]
    Malformed(String),
}

fn parse_vendor_key(entry: &str) -> Option<ed25519_dalek::VerifyingKey> {
    let b64 = entry.strip_prefix("ed25519:")?;
    let bytes = data_encoding::BASE64.decode(b64.as_bytes()).ok()?;
    let arr: [u8; 32] = bytes.try_into().ok()?;
    ed25519_dalek::VerifyingKey::from_bytes(&arr).ok()
}

/// Strict verify: valid signature from a listed vendor key AND not expired.
pub fn verify_license(
    env: &SignedLicense,
    now: OffsetDateTime,
) -> Result<LicenseDocument, LicenseError> {
    let (doc, expired) = verify_license_allow_expired(env, now)?;
    if expired {
        return Err(LicenseError::Expired(doc.not_after));
    }
    Ok(doc)
}

/// Verify signature + key, but report expiry as a flag instead of an error.
/// Used by the server so it can show the identity of an expired license.
pub fn verify_license_allow_expired(
    env: &SignedLicense,
    now: OffsetDateTime,
) -> Result<(LicenseDocument, bool), LicenseError> {
    verify_license_allow_expired_with_keys(env, now, SIGIL_LICENSE_PUBKEYS)
}

/// Core verifier with an explicit keyset (for tests / custom trust anchors).
pub fn verify_license_allow_expired_with_keys(
    env: &SignedLicense,
    now: OffsetDateTime,
    keys: &[(&str, &str)],
) -> Result<(LicenseDocument, bool), LicenseError> {
    use ed25519_dalek::{Signature, Verifier};

    // 1. resolve key id
    let key_entry = keys
        .iter()
        .find(|(id, _)| *id == env.signing_pubkey_id)
        .ok_or_else(|| LicenseError::UnknownKey(env.signing_pubkey_id.clone()))?;
    let vk = parse_vendor_key(key_entry.1)
        .ok_or_else(|| LicenseError::Malformed("vendor key unparseable".into()))?;

    // 2. signature over canonical bytes of the license document
    let sig_bytes = data_encoding::BASE64
        .decode(env.signature.as_bytes())
        .map_err(|_| LicenseError::BadSignature)?;
    let arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| LicenseError::BadSignature)?;
    let sig = Signature::from_bytes(&arr);
    let canonical =
        to_canonical_bytes(&env.license).map_err(|e| LicenseError::Malformed(e.to_string()))?;
    if vk.verify(&canonical, &sig).is_err() {
        return Err(LicenseError::BadSignature);
    }

    // 3. expiry as a flag
    let expired = now >= env.license.not_after;
    Ok((env.license.clone(), expired))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::{OsRng, RngCore};
    use time::macros::datetime;

    fn test_keypair() -> (SigningKey, String /* "ed25519:b64" */) {
        let mut secret = [0u8; 32];
        OsRng.fill_bytes(&mut secret);
        let sk = SigningKey::from_bytes(&secret);
        let entry = format!(
            "ed25519:{}",
            data_encoding::BASE64.encode(&sk.verifying_key().to_bytes())
        );
        (sk, entry)
    }

    fn doc(not_after: OffsetDateTime) -> LicenseDocument {
        LicenseDocument {
            license_id: "SIGIL-2026-ACME-a1b2c3".into(),
            customer_id: "ACME".into(),
            max_hosts: 1000,
            issued_at: datetime!(2026-05-01 0:00 UTC),
            not_after,
        }
    }

    fn sign(sk: &SigningKey, key_id: &str, license: LicenseDocument) -> SignedLicense {
        let canonical = to_canonical_bytes(&license).unwrap();
        let sig = sk.sign(&canonical);
        SignedLicense {
            license,
            signature: data_encoding::BASE64.encode(&sig.to_bytes()),
            signing_pubkey_id: key_id.into(),
        }
    }

    #[test]
    fn valid_license_verifies() {
        let (sk, entry) = test_keypair();
        let keys = [("vk1", entry.as_str())];
        let env = sign(&sk, "vk1", doc(datetime!(2027-01-01 0:00 UTC)));
        let (got, expired) =
            verify_license_allow_expired_with_keys(&env, datetime!(2026-06-01 0:00 UTC), &keys)
                .unwrap();
        assert!(!expired);
        assert_eq!(got.customer_id, "ACME");
        assert_eq!(got.max_hosts, 1000);
    }

    #[test]
    fn tampered_payload_is_bad_signature() {
        let (sk, entry) = test_keypair();
        let keys = [("vk1", entry.as_str())];
        let mut env = sign(&sk, "vk1", doc(datetime!(2027-01-01 0:00 UTC)));
        env.license.max_hosts = 999999; // tamper after signing
        let err = verify_license_allow_expired_with_keys(
            &env,
            datetime!(2026-06-01 0:00 UTC),
            &keys,
        )
        .unwrap_err();
        assert_eq!(err, LicenseError::BadSignature);
    }

    #[test]
    fn unknown_key_id_errors() {
        let (sk, entry) = test_keypair();
        let keys = [("vk1", entry.as_str())];
        let mut env = sign(&sk, "vk1", doc(datetime!(2027-01-01 0:00 UTC)));
        env.signing_pubkey_id = "nope".into();
        let err = verify_license_allow_expired_with_keys(
            &env,
            datetime!(2026-06-01 0:00 UTC),
            &keys,
        )
        .unwrap_err();
        assert_eq!(err, LicenseError::UnknownKey("nope".into()));
    }

    #[test]
    fn expired_flag_set_in_allow_expired() {
        let (sk, entry) = test_keypair();
        let keys = [("vk1", entry.as_str())];
        let env = sign(&sk, "vk1", doc(datetime!(2026-01-01 0:00 UTC)));
        let (_doc, expired) =
            verify_license_allow_expired_with_keys(&env, datetime!(2026-06-01 0:00 UTC), &keys)
                .unwrap();
        assert!(expired);
    }

    #[test]
    fn strict_verify_rejects_expired_via_with_keys_flag() {
        let (sk, entry) = test_keypair();
        let keys = [("vk1", entry.as_str())];
        let env = sign(&sk, "vk1", doc(datetime!(2026-01-01 0:00 UTC)));
        let (doc, expired) = verify_license_allow_expired_with_keys(
            &env,
            datetime!(2026-06-01 0:00 UTC),
            &keys,
        )
        .unwrap();
        assert!(expired);
        assert!(doc.not_after < datetime!(2026-06-01 0:00 UTC));
    }

    #[test]
    fn garbage_signature_is_bad_signature() {
        let (_sk, entry) = test_keypair();
        let keys = [("vk1", entry.as_str())];
        let env = SignedLicense {
            license: doc(datetime!(2027-01-01 0:00 UTC)),
            signature: "!!!notbase64!!!".into(),
            signing_pubkey_id: "vk1".into(),
        };
        let err = verify_license_allow_expired_with_keys(
            &env,
            datetime!(2026-06-01 0:00 UTC),
            &keys,
        )
        .unwrap_err();
        assert_eq!(err, LicenseError::BadSignature);
    }
}
