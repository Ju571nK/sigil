//! Policy-signing pubkey keystore.
//!
//! Spec §3.8.2 "Pubkey distribution and rotation": the file is a small
//! JSON document at `/etc/andeda/policy-signing-pubkeys.pem` (the `.pem`
//! suffix is preserved for operator familiarity but the contents are JSON
//! with embedded base64 ed25519 pubkeys).

use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;
use time::OffsetDateTime;

/// Top-level keystore document.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Keystore {
    /// One or more signing pubkeys, each with its own validity window.
    pub pubkeys: Vec<KeystoreEntry>,
}

/// A single pubkey entry in the keystore.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct KeystoreEntry {
    /// Identifier the server stamps into `signing_pubkey_id` on every signed
    /// response. Stable across the entry's lifetime.
    pub id: String,
    /// 32-byte ed25519 public key, base64-encoded.
    pub ed25519_pubkey_b64: String,
    /// Entry is "active" when `valid_from <= now < valid_until`.
    #[serde(with = "time::serde::rfc3339")]
    pub valid_from: OffsetDateTime,
    /// See `valid_from`.
    #[serde(with = "time::serde::rfc3339")]
    pub valid_until: OffsetDateTime,
}

/// Errors produced by keystore loading and lookup.
#[derive(Debug, Error)]
pub enum KeystoreError {
    /// I/O failure reading the keystore file.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// JSON parse error.
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    /// Base64 decode error on a pubkey.
    #[error("invalid base64 pubkey for id {id}")]
    InvalidPubkeyEncoding {
        /// Entry id that failed to decode.
        id: String,
    },
    /// ed25519 pubkey was not 32 bytes.
    #[error("invalid ed25519 pubkey length for id {id}: expected 32 bytes, got {len}")]
    InvalidPubkeyLength {
        /// Entry id.
        id: String,
        /// Actual byte length found.
        len: usize,
    },
}

impl Keystore {
    /// Load and parse the keystore from the given path.
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, KeystoreError> {
        let bytes = std::fs::read(path)?;
        let store: Keystore = serde_json::from_slice(&bytes)?;
        Ok(store)
    }

    /// Look up a pubkey by id. Returns the parsed `VerifyingKey` ONLY if
    /// the entry is currently active (`valid_from <= now < valid_until`).
    /// Returns `None` if the id is unknown OR the entry is expired/not-yet-valid.
    pub fn active_pubkey(
        &self,
        id: &str,
        now: OffsetDateTime,
    ) -> Result<Option<VerifyingKey>, KeystoreError> {
        for entry in &self.pubkeys {
            if entry.id != id {
                continue;
            }
            if now < entry.valid_from || now >= entry.valid_until {
                return Ok(None);
            }
            let raw = data_encoding::BASE64
                .decode(entry.ed25519_pubkey_b64.as_bytes())
                .map_err(|_| KeystoreError::InvalidPubkeyEncoding { id: id.to_string() })?;
            if raw.len() != 32 {
                return Err(KeystoreError::InvalidPubkeyLength {
                    id: id.to_string(),
                    len: raw.len(),
                });
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&raw);
            let key = VerifyingKey::from_bytes(&arr).map_err(|_| {
                KeystoreError::InvalidPubkeyEncoding { id: id.to_string() }
            })?;
            return Ok(Some(key));
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::OsRng;
    use tempfile::tempdir;
    use time::macros::datetime;

    fn write_keystore(dir: &tempfile::TempDir, store: &Keystore) -> std::path::PathBuf {
        let path = dir.path().join("policy-signing-pubkeys.pem");
        std::fs::write(&path, serde_json::to_vec(store).unwrap()).unwrap();
        path
    }

    fn fresh_pubkey_b64() -> (SigningKey, String) {
        use rand_core::RngCore;
        let mut secret = [0u8; 32];
        OsRng.fill_bytes(&mut secret);
        let sk = SigningKey::from_bytes(&secret);
        let pk_bytes = sk.verifying_key().to_bytes();
        (sk, data_encoding::BASE64.encode(&pk_bytes))
    }

    #[test]
    fn empty_keystore_returns_none_for_any_lookup() {
        let dir = tempdir().unwrap();
        let store = Keystore { pubkeys: vec![] };
        let path = write_keystore(&dir, &store);
        let loaded = Keystore::load_from_file(&path).unwrap();
        assert!(loaded.active_pubkey("anything", datetime!(2026-05-15 0:00 UTC)).unwrap().is_none());
    }

    #[test]
    fn active_window_returns_pubkey() {
        let dir = tempdir().unwrap();
        let (_sk, pk_b64) = fresh_pubkey_b64();
        let store = Keystore {
            pubkeys: vec![KeystoreEntry {
                id: "k1".into(),
                ed25519_pubkey_b64: pk_b64,
                valid_from: datetime!(2026-05-01 0:00 UTC),
                valid_until: datetime!(2027-05-01 0:00 UTC),
            }],
        };
        let path = write_keystore(&dir, &store);
        let loaded = Keystore::load_from_file(&path).unwrap();
        let now = datetime!(2026-05-15 0:00 UTC);
        let key = loaded.active_pubkey("k1", now).unwrap();
        assert!(key.is_some());
    }

    #[test]
    fn expired_entry_returns_none() {
        let dir = tempdir().unwrap();
        let (_sk, pk_b64) = fresh_pubkey_b64();
        let store = Keystore {
            pubkeys: vec![KeystoreEntry {
                id: "expired".into(),
                ed25519_pubkey_b64: pk_b64,
                valid_from: datetime!(2025-01-01 0:00 UTC),
                valid_until: datetime!(2025-06-01 0:00 UTC),
            }],
        };
        let path = write_keystore(&dir, &store);
        let loaded = Keystore::load_from_file(&path).unwrap();
        assert!(loaded.active_pubkey("expired", datetime!(2026-01-01 0:00 UTC)).unwrap().is_none());
    }

    #[test]
    fn future_entry_returns_none() {
        let dir = tempdir().unwrap();
        let (_sk, pk_b64) = fresh_pubkey_b64();
        let store = Keystore {
            pubkeys: vec![KeystoreEntry {
                id: "future".into(),
                ed25519_pubkey_b64: pk_b64,
                valid_from: datetime!(2027-01-01 0:00 UTC),
                valid_until: datetime!(2028-01-01 0:00 UTC),
            }],
        };
        let path = write_keystore(&dir, &store);
        let loaded = Keystore::load_from_file(&path).unwrap();
        assert!(loaded.active_pubkey("future", datetime!(2026-01-01 0:00 UTC)).unwrap().is_none());
    }

    #[test]
    fn unknown_id_returns_none() {
        let dir = tempdir().unwrap();
        let (_sk, pk_b64) = fresh_pubkey_b64();
        let store = Keystore {
            pubkeys: vec![KeystoreEntry {
                id: "real".into(),
                ed25519_pubkey_b64: pk_b64,
                valid_from: datetime!(2026-05-01 0:00 UTC),
                valid_until: datetime!(2027-05-01 0:00 UTC),
            }],
        };
        let path = write_keystore(&dir, &store);
        let loaded = Keystore::load_from_file(&path).unwrap();
        assert!(loaded.active_pubkey("missing", datetime!(2026-05-15 0:00 UTC)).unwrap().is_none());
    }

    #[test]
    fn invalid_base64_returns_error() {
        let dir = tempdir().unwrap();
        let store = Keystore {
            pubkeys: vec![KeystoreEntry {
                id: "bad".into(),
                ed25519_pubkey_b64: "not!valid!base64!".into(),
                valid_from: datetime!(2026-05-01 0:00 UTC),
                valid_until: datetime!(2027-05-01 0:00 UTC),
            }],
        };
        let path = write_keystore(&dir, &store);
        let loaded = Keystore::load_from_file(&path).unwrap();
        let res = loaded.active_pubkey("bad", datetime!(2026-05-15 0:00 UTC));
        assert!(matches!(res, Err(KeystoreError::InvalidPubkeyEncoding { .. })));
    }

    #[test]
    fn wrong_length_pubkey_returns_error() {
        let dir = tempdir().unwrap();
        // 31 bytes — too short.
        let short = data_encoding::BASE64.encode(&[0u8; 31]);
        let store = Keystore {
            pubkeys: vec![KeystoreEntry {
                id: "short".into(),
                ed25519_pubkey_b64: short,
                valid_from: datetime!(2026-05-01 0:00 UTC),
                valid_until: datetime!(2027-05-01 0:00 UTC),
            }],
        };
        let path = write_keystore(&dir, &store);
        let loaded = Keystore::load_from_file(&path).unwrap();
        let res = loaded.active_pubkey("short", datetime!(2026-05-15 0:00 UTC));
        assert!(matches!(res, Err(KeystoreError::InvalidPubkeyLength { len: 31, .. })));
    }

    #[test]
    fn signature_round_trip_validates() {
        // End-to-end: keystore lookup → verify a signed message.
        use ed25519_dalek::Verifier;
        let (sk, pk_b64) = fresh_pubkey_b64();
        let store = Keystore {
            pubkeys: vec![KeystoreEntry {
                id: "rt".into(),
                ed25519_pubkey_b64: pk_b64,
                valid_from: datetime!(2026-01-01 0:00 UTC),
                valid_until: datetime!(2027-01-01 0:00 UTC),
            }],
        };
        let now = datetime!(2026-05-15 0:00 UTC);
        let pk = store.active_pubkey("rt", now).unwrap().unwrap();
        let msg = b"hello canonical world";
        let sig = sk.sign(msg);
        assert!(pk.verify(msg, &sig).is_ok());
    }
}
