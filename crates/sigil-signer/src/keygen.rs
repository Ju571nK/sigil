//! ed25519 keypair generation + on-disk format.

use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::path::Path;
use time::OffsetDateTime;

/// On-disk JSON shape for a signing keypair. Compatible with the agent's
/// keystore format for the `ed25519_pubkey_b64` field — operator copies
/// that one field into `policy-signing-pubkeys.pem` to enable verification.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SigningKeyFile {
    pub id: String,
    pub ed25519_secret_b64: String,
    pub ed25519_pubkey_b64: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

impl SigningKeyFile {
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = std::fs::read(path)
            .with_context(|| format!("read signing key file {}", path.display()))?;
        serde_json::from_slice(&bytes)
            .with_context(|| format!("parse signing key file {}", path.display()))
    }

    /// Decode the raw 32-byte secret and return an `ed25519_dalek::SigningKey`.
    pub fn signing_key(&self) -> Result<SigningKey> {
        let raw = data_encoding::BASE64
            .decode(self.ed25519_secret_b64.as_bytes())
            .context("decode ed25519_secret_b64")?;
        if raw.len() != 32 {
            anyhow::bail!("ed25519 secret must be 32 bytes, got {}", raw.len());
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&raw);
        Ok(SigningKey::from_bytes(&arr))
    }
}

/// Generate a fresh ed25519 keypair, write the JSON file, return it.
pub fn keygen(id: &str, out: &Path) -> Result<SigningKeyFile> {
    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);
    let sk = SigningKey::from_bytes(&secret);
    let pk = sk.verifying_key();
    let file = SigningKeyFile {
        id: id.to_string(),
        ed25519_secret_b64: data_encoding::BASE64.encode(&secret),
        ed25519_pubkey_b64: data_encoding::BASE64.encode(&pk.to_bytes()),
        created_at: OffsetDateTime::now_utc(),
    };
    let bytes = serde_json::to_vec_pretty(&file).context("serialize signing key")?;
    if let Some(parent) = out.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create dir {}", parent.display()))?;
        }
    }
    std::fs::write(out, &bytes).with_context(|| format!("write {}", out.display()))?;
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn keygen_writes_loadable_file_with_matching_pubkey() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("k.json");
        let written = keygen("k1", &path).unwrap();
        let loaded = SigningKeyFile::load(&path).unwrap();
        assert_eq!(loaded.id, "k1");
        assert_eq!(loaded.ed25519_pubkey_b64, written.ed25519_pubkey_b64);

        let sk = loaded.signing_key().unwrap();
        let pk_from_sk = data_encoding::BASE64.encode(&sk.verifying_key().to_bytes());
        assert_eq!(pk_from_sk, loaded.ed25519_pubkey_b64);
    }

    #[test]
    fn keygen_secret_is_32_bytes_base64() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("k.json");
        let f = keygen("k", &path).unwrap();
        let raw = data_encoding::BASE64
            .decode(f.ed25519_secret_b64.as_bytes())
            .unwrap();
        assert_eq!(raw.len(), 32);
    }

    #[test]
    fn keygen_creates_parent_dir() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nested").join("k.json");
        keygen("k", &path).unwrap();
        assert!(path.exists());
    }
}
