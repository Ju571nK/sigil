//! #184 — enrollment token store.
//!
//! On-disk JSON: `{ "tokens": [ { token_hash, host_id, expires_at, used_at } ] }`.
//! Tokens are 32 random bytes (OsRng), URL-safe base64; only `blake3(plaintext)`
//! hex is stored — the plaintext is returned once by the CLI and never persisted.
//!
//! Single-use is enforced by stamping `used_at`. The read-modify-write is
//! protected by a cross-process advisory flock (see `lock.rs`) so the CLI's
//! `issue()` and the server's `check`/`mark_used` can't lose a write. Writes are
//! atomic (tmp+rename) preserving 0600.
//!
//! The handler splits redeem into `check` (verify only) and `mark_used` (stamp)
//! so the spec's commit order holds: validate → reserve(token) → sign → … . In
//! practice the handler RESERVES before signing by calling `mark_used` up front;
//! `check` is the pre-validate. Both take the flock.

use super::lock::FileLock;
use serde::{Deserialize, Serialize};
use std::path::Path;
use time::OffsetDateTime;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TokenStore {
    pub tokens: Vec<TokenEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenEntry {
    /// `blake3(plaintext).to_hex()`.
    pub token_hash: String,
    pub host_id: String,
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option", default)]
    pub used_at: Option<OffsetDateTime>,
}

/// Redeem failure reasons. The HTTP layer collapses Expired/Used/HostMismatch/
/// NotFound into a single generic `enrollment_denied` (no token-state leak); the
/// specific reason is logged/audited internally.
#[derive(Debug, PartialEq, Eq)]
pub enum RedeemErr {
    NotFound,
    Expired,
    Used,
    HostMismatch,
    Io(String),
}

impl std::fmt::Display for RedeemErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RedeemErr::NotFound => write!(f, "not_found"),
            RedeemErr::Expired => write!(f, "expired"),
            RedeemErr::Used => write!(f, "used"),
            RedeemErr::HostMismatch => write!(f, "host_mismatch"),
            RedeemErr::Io(e) => write!(f, "io: {e}"),
        }
    }
}

/// blake3 hex digest of a plaintext token.
pub fn hash_token(plaintext: &str) -> String {
    blake3::hash(plaintext.as_bytes()).to_hex().to_string()
}

impl TokenStore {
    fn read(path: &Path) -> Result<TokenStore, RedeemErr> {
        match std::fs::read(path) {
            Ok(b) => serde_json::from_slice(&b)
                .map_err(|e| RedeemErr::Io(format!("parse token store: {e}"))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(TokenStore::default()),
            Err(e) => Err(RedeemErr::Io(format!("read token store: {e}"))),
        }
    }

    /// Atomic write (tmp in same dir + rename), 0600.
    fn write_atomic(path: &Path, store: &TokenStore) -> Result<(), RedeemErr> {
        let bytes = serde_json::to_vec_pretty(store)
            .map_err(|e| RedeemErr::Io(format!("serialize: {e}")))?;
        write_atomic_0600(path, &bytes).map_err(|e| RedeemErr::Io(format!("write: {e}")))
    }

    /// Issue a fresh token for `host_id` with the given expiry. Returns the
    /// plaintext (URL-safe base64) ONCE; only the hash is stored. Takes the
    /// cross-process flock for the whole read-modify-write.
    pub fn issue(
        path: &Path,
        host_id: &str,
        expires_at: OffsetDateTime,
        _now: OffsetDateTime,
    ) -> Result<String, RedeemErr> {
        let _lock = FileLock::acquire_exclusive(path)
            .map_err(|e| RedeemErr::Io(format!("lock: {e}")))?;
        let plaintext = generate_token();
        let mut store = Self::read(path)?;
        store.tokens.push(TokenEntry {
            token_hash: hash_token(&plaintext),
            host_id: host_id.to_string(),
            expires_at,
            used_at: None,
        });
        Self::write_atomic(path, &store)?;
        Ok(plaintext)
    }

    /// Verify a token WITHOUT consuming it: must exist, be unused, unexpired,
    /// and bound to `host_id`. Order of checks intentionally returns the most
    /// specific reason for internal logging. Takes the flock (consistent read).
    pub fn check(
        path: &Path,
        plaintext: &str,
        host_id: &str,
        now: OffsetDateTime,
    ) -> Result<(), RedeemErr> {
        let _lock = FileLock::acquire_exclusive(path)
            .map_err(|e| RedeemErr::Io(format!("lock: {e}")))?;
        let store = Self::read(path)?;
        let hash = hash_token(plaintext);
        let entry = store
            .tokens
            .iter()
            .find(|t| t.token_hash == hash)
            .ok_or(RedeemErr::NotFound)?;
        if entry.used_at.is_some() {
            return Err(RedeemErr::Used);
        }
        if now > entry.expires_at {
            return Err(RedeemErr::Expired);
        }
        if entry.host_id != host_id {
            return Err(RedeemErr::HostMismatch);
        }
        Ok(())
    }

    /// Durably stamp `used_at` (reserve the token) under the flock. Re-validates
    /// existence + unused so a concurrent stamp can't double-spend. This is the
    /// reserve-before-sign step in the handler's commit order.
    pub fn mark_used(
        path: &Path,
        plaintext: &str,
        host_id: &str,
        now: OffsetDateTime,
    ) -> Result<(), RedeemErr> {
        let _lock = FileLock::acquire_exclusive(path)
            .map_err(|e| RedeemErr::Io(format!("lock: {e}")))?;
        let mut store = Self::read(path)?;
        let hash = hash_token(plaintext);
        let entry = store
            .tokens
            .iter_mut()
            .find(|t| t.token_hash == hash)
            .ok_or(RedeemErr::NotFound)?;
        if entry.used_at.is_some() {
            return Err(RedeemErr::Used);
        }
        if now > entry.expires_at {
            return Err(RedeemErr::Expired);
        }
        if entry.host_id != host_id {
            return Err(RedeemErr::HostMismatch);
        }
        entry.used_at = Some(now);
        Self::write_atomic(path, &store)?;
        Ok(())
    }
}

/// 32 bytes OsRng → URL-safe base64 (no padding).
fn generate_token() -> String {
    use rand_core::{OsRng, RngCore};
    let mut b = [0u8; 32];
    OsRng.fill_bytes(&mut b);
    data_encoding::BASE64URL_NOPAD.encode(&b)
}

/// Atomic write via tmp-in-same-dir + rename, mode 0600.
fn write_atomic_0600(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let mut tmp = tempfile::Builder::new()
        .prefix(".tokens-")
        .tempfile_in(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = tmp
            .as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600));
    }
    tmp.write_all(bytes)?;
    tmp.as_file().sync_all()?;
    tmp.persist(path)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::Duration;

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_900_000_000).unwrap()
    }

    #[test]
    fn issue_stores_hash_not_plaintext() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("t.json");
        let now = now();
        let tok = TokenStore::issue(&p, "host-1", now + Duration::hours(1), now).unwrap();
        let disk = std::fs::read_to_string(&p).unwrap();
        assert!(!disk.contains(&tok), "plaintext must never hit disk");
        assert!(disk.contains(&hash_token(&tok)), "hash must be stored");
    }

    #[test]
    fn check_then_mark_used_single_use() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("t.json");
        let now = now();
        let tok = TokenStore::issue(&p, "host-1", now + Duration::hours(1), now).unwrap();
        assert!(TokenStore::check(&p, &tok, "host-1", now).is_ok());
        assert!(TokenStore::mark_used(&p, &tok, "host-1", now).is_ok());
        // reused → Used (both check and mark_used)
        assert_eq!(
            TokenStore::check(&p, &tok, "host-1", now),
            Err(RedeemErr::Used)
        );
        assert_eq!(
            TokenStore::mark_used(&p, &tok, "host-1", now),
            Err(RedeemErr::Used)
        );
    }

    #[test]
    fn expired_token_rejected() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("t.json");
        let now = now();
        let tok = TokenStore::issue(&p, "host-3", now - Duration::seconds(1), now).unwrap();
        assert_eq!(
            TokenStore::check(&p, &tok, "host-3", now),
            Err(RedeemErr::Expired)
        );
    }

    #[test]
    fn host_mismatch_rejected() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("t.json");
        let now = now();
        let tok = TokenStore::issue(&p, "host-2", now + Duration::hours(1), now).unwrap();
        assert_eq!(
            TokenStore::check(&p, &tok, "host-X", now),
            Err(RedeemErr::HostMismatch)
        );
    }

    #[test]
    fn unknown_token_not_found() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("t.json");
        let now = now();
        let _ = TokenStore::issue(&p, "host-1", now + Duration::hours(1), now).unwrap();
        assert_eq!(
            TokenStore::check(&p, "bogus", "host-1", now),
            Err(RedeemErr::NotFound)
        );
    }
}
