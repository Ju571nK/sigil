//! Wraps `sigil_core::policy::verify::verify_envelope` for CLI use.

use anyhow::{Context, Result};
use sigil_core::policy::pubkeys::Keystore;
use sigil_core::policy::signed_envelope::SignedPolicyResponse;
use sigil_core::policy::verify::{verify_envelope, VerifiedPolicy, VerifyError};
use std::path::Path;
use time::OffsetDateTime;

pub fn verify_file(
    signed_path: &Path,
    keystore_path: &Path,
    now: OffsetDateTime,
    last_applied: i64,
) -> Result<Result<VerifiedPolicy, VerifyError>> {
    let signed_bytes = std::fs::read(signed_path)
        .with_context(|| format!("read signed file {}", signed_path.display()))?;
    let response: SignedPolicyResponse = serde_json::from_slice(&signed_bytes)
        .with_context(|| format!("parse signed json {}", signed_path.display()))?;
    let keystore = Keystore::load_from_file(keystore_path)
        .with_context(|| format!("load keystore {}", keystore_path.display()))?;
    Ok(verify_envelope(&keystore, &response, now, last_applied))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::keygen;
    use crate::sign::{sign_to_file, SignArgs};
    use sigil_core::policy::pubkeys::KeystoreEntry;
    use tempfile::tempdir;
    use time::macros::datetime;

    fn write_keystore_for(
        dir: &Path,
        id: &str,
        pubkey_b64: &str,
        valid_from: OffsetDateTime,
        valid_until: OffsetDateTime,
    ) -> std::path::PathBuf {
        let store = Keystore {
            pubkeys: vec![KeystoreEntry {
                id: id.to_string(),
                ed25519_pubkey_b64: pubkey_b64.to_string(),
                valid_from,
                valid_until,
            }],
        };
        let p = dir.join("policy-signing-pubkeys.pem");
        std::fs::write(&p, serde_json::to_vec(&store).unwrap()).unwrap();
        p
    }

    #[test]
    fn keygen_sign_verify_e2e_succeeds() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("k.json");
        let key_file = keygen("k1", &key_path).unwrap();
        let yaml = dir.path().join("p.yaml");
        std::fs::write(&yaml, "version: 1\n").unwrap();
        let signed = dir.path().join("signed.json");
        sign_to_file(
            SignArgs {
                yaml_path: &yaml,
                key_file: &key_file,
                policy_version: 1,
                valid_until: datetime!(2027-01-01 0:00 UTC),
                now: datetime!(2026-05-15 0:00 UTC),
            },
            &signed,
        )
        .unwrap();

        let keystore = write_keystore_for(
            dir.path(),
            "k1",
            &key_file.ed25519_pubkey_b64,
            datetime!(2026-01-01 0:00 UTC),
            datetime!(2027-06-01 0:00 UTC),
        );

        let result = verify_file(&signed, &keystore, datetime!(2026-05-15 0:00 UTC), 0).unwrap();
        let verified = result.expect("verify should succeed");
        assert_eq!(verified.signing_pubkey_id, "k1");
        assert_eq!(verified.policy_version, 1);
    }

    #[test]
    fn verify_rejects_when_pubkey_missing_from_keystore() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("k.json");
        let key_file = keygen("k1", &key_path).unwrap();
        let yaml = dir.path().join("p.yaml");
        std::fs::write(&yaml, "x: 1\n").unwrap();
        let signed = dir.path().join("signed.json");
        sign_to_file(
            SignArgs {
                yaml_path: &yaml,
                key_file: &key_file,
                policy_version: 1,
                valid_until: datetime!(2027-01-01 0:00 UTC),
                now: datetime!(2026-05-15 0:00 UTC),
            },
            &signed,
        )
        .unwrap();
        // Empty keystore.
        let store = Keystore { pubkeys: vec![] };
        let keystore = dir.path().join("policy-signing-pubkeys.pem");
        std::fs::write(&keystore, serde_json::to_vec(&store).unwrap()).unwrap();

        let result = verify_file(&signed, &keystore, datetime!(2026-05-15 0:00 UTC), 0).unwrap();
        assert!(matches!(result, Err(VerifyError::PubkeyUnknown(_))));
    }
}
