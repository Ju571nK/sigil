//! Sign one YAML payload into a `SignedPolicyResponse` JSON file.

use crate::keygen::SigningKeyFile;
use anyhow::{Context, Result};
use ed25519_dalek::Signer;
use sigil_core::policy::canonical::to_canonical_bytes;
use sigil_core::policy::signed_envelope::{SignedEnvelope, SignedPolicyResponse};
use std::path::Path;
use time::OffsetDateTime;

pub struct SignArgs<'a> {
    pub yaml_path: &'a Path,
    pub key_file: &'a SigningKeyFile,
    pub policy_version: i64,
    pub valid_until: OffsetDateTime,
    pub now: OffsetDateTime,
}

/// Read the YAML, build + sign the envelope, and return the response.
pub fn sign(args: SignArgs<'_>) -> Result<SignedPolicyResponse> {
    let yaml_bytes = std::fs::read(args.yaml_path)
        .with_context(|| format!("read yaml {}", args.yaml_path.display()))?;

    let envelope = SignedEnvelope {
        policy_version: args.policy_version,
        policy_bytes_b64: data_encoding::BASE64.encode(&yaml_bytes),
        valid_until: args.valid_until,
        issued_at: args.now,
    };

    let canonical = to_canonical_bytes(&envelope).context("canonicalize envelope")?;
    let sk = args.key_file.signing_key().context("decode signing key")?;
    let signature = sk.sign(&canonical);

    // ETag is opaque to verify (used only for HTTP If-None-Match caching).
    // Use blake3 over the canonical bytes — already in the workspace deps and
    // collision-resistant for the cache-tag use case.
    let etag = blake3::hash(&canonical).to_hex().to_string();

    Ok(SignedPolicyResponse {
        etag,
        signed_envelope: envelope,
        signature: data_encoding::BASE64.encode(&signature.to_bytes()),
        signing_pubkey_id: args.key_file.id.clone(),
        applied_at: args.now,
    })
}

/// Convenience wrapper: sign and write the JSON to `out`.
pub fn sign_to_file(args: SignArgs<'_>, out: &Path) -> Result<SignedPolicyResponse> {
    let resp = sign(args)?;
    let bytes = serde_json::to_vec_pretty(&resp).context("serialize response")?;
    if let Some(parent) = out.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create dir {}", parent.display()))?;
        }
    }
    std::fs::write(out, &bytes).with_context(|| format!("write {}", out.display()))?;
    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::keygen;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    use tempfile::tempdir;
    use time::macros::datetime;

    fn write_yaml(dir: &Path, name: &str, body: &str) -> std::path::PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, body).unwrap();
        p
    }

    #[test]
    fn signed_envelope_round_trips_signature() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("k.json");
        let key_file = keygen("k1", &key_path).unwrap();
        let yaml_path = write_yaml(dir.path(), "p.yaml", "version: 1\n");

        let resp = sign(SignArgs {
            yaml_path: &yaml_path,
            key_file: &key_file,
            policy_version: 7,
            valid_until: datetime!(2027-01-01 0:00 UTC),
            now: datetime!(2026-05-15 0:00 UTC),
        })
        .unwrap();

        // Reconstruct verifier from the keystore-style pubkey.
        let pk_bytes = data_encoding::BASE64
            .decode(key_file.ed25519_pubkey_b64.as_bytes())
            .unwrap();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&pk_bytes);
        let pk = VerifyingKey::from_bytes(&arr).unwrap();

        let sig_bytes = data_encoding::BASE64
            .decode(resp.signature.as_bytes())
            .unwrap();
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);
        let sig = Signature::from_bytes(&sig_arr);

        let canonical = to_canonical_bytes(&resp.signed_envelope).unwrap();
        assert!(pk.verify(&canonical, &sig).is_ok());
    }

    #[test]
    fn sign_to_file_writes_loadable_json() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("k.json");
        let key_file = keygen("k", &key_path).unwrap();
        let yaml_path = write_yaml(dir.path(), "p.yaml", "x: 1\n");
        let out = dir.path().join("signed.json");
        sign_to_file(
            SignArgs {
                yaml_path: &yaml_path,
                key_file: &key_file,
                policy_version: 1,
                valid_until: datetime!(2027-01-01 0:00 UTC),
                now: datetime!(2026-05-15 0:00 UTC),
            },
            &out,
        )
        .unwrap();
        let bytes = std::fs::read(&out).unwrap();
        let _back: SignedPolicyResponse = serde_json::from_slice(&bytes).unwrap();
    }

    #[test]
    fn etag_is_64_hex_chars() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("k.json");
        let key_file = keygen("k", &key_path).unwrap();
        let yaml_path = write_yaml(dir.path(), "p.yaml", "x: 1\n");
        let resp = sign(SignArgs {
            yaml_path: &yaml_path,
            key_file: &key_file,
            policy_version: 1,
            valid_until: datetime!(2027-01-01 0:00 UTC),
            now: datetime!(2026-05-15 0:00 UTC),
        })
        .unwrap();
        assert_eq!(resp.etag.len(), 64);
        assert!(resp.etag.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
