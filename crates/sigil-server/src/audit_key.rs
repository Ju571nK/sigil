//! Server audit-signing key: auto-generate on first boot, persist (0600),
//! reuse across boots. Lives next to `license-audit.jsonl`. measure-don't-block:
//! ANY failure returns `None` (audit signing disabled) — never panics.

use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::path::Path;
use time::OffsetDateTime;

const KEY_FILE_NAME: &str = "audit-signing.key";

#[derive(Serialize, Deserialize)]
struct AuditKeyFile {
    id: String,
    ed25519_secret_b64: String,
    ed25519_pubkey_b64: String,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
}

/// In-memory audit key: the decoded signing key + its public identity.
pub struct AuditKey {
    pub signing_key: SigningKey,
    pub pubkey_id: String,
    pub pubkey_b64: String,
}

impl AuditKey {
    /// Load `<dir>/audit-signing.key`, or generate + persist a fresh one.
    /// Returns `None` on any I/O/parse failure (signing disabled, never panics).
    pub fn load_or_create(dir: &Path) -> Option<AuditKey> {
        let path = dir.join(KEY_FILE_NAME);
        if let Ok(bytes) = std::fs::read(&path) {
            match serde_json::from_slice::<AuditKeyFile>(&bytes)
                .ok()
                .and_then(into_key)
            {
                Some(k) => return Some(k),
                None => tracing::warn!(
                    path = %path.display(),
                    "audit key file unreadable/corrupt; regenerating"
                ),
            }
        }
        generate_and_persist(&path)
    }
}

fn into_key(f: AuditKeyFile) -> Option<AuditKey> {
    let raw = data_encoding::BASE64
        .decode(f.ed25519_secret_b64.as_bytes())
        .ok()?;
    let arr: [u8; 32] = raw.as_slice().try_into().ok()?;
    Some(AuditKey {
        signing_key: SigningKey::from_bytes(&arr),
        pubkey_id: f.id,
        pubkey_b64: f.ed25519_pubkey_b64,
    })
}

fn random_suffix() -> String {
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut bytes = [0u8; 6];
    OsRng.fill_bytes(&mut bytes);
    bytes
        .iter()
        .map(|b| CHARS[(*b as usize) % CHARS.len()] as char)
        .collect()
}

fn generate_and_persist(path: &Path) -> Option<AuditKey> {
    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);
    let sk = SigningKey::from_bytes(&secret);
    let pubkey_b64 = data_encoding::BASE64.encode(&sk.verifying_key().to_bytes());
    let id = format!("sigil-audit-{}", random_suffix());
    let file = AuditKeyFile {
        id: id.clone(),
        ed25519_secret_b64: data_encoding::BASE64.encode(&secret),
        ed25519_pubkey_b64: pubkey_b64.clone(),
        created_at: OffsetDateTime::now_utc(),
    };
    let bytes = serde_json::to_vec_pretty(&file).ok()?;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).ok()?;
        }
    }
    std::fs::write(path, &bytes).ok()?;
    set_permissions_0600(path);
    Some(AuditKey {
        signing_key: sk,
        pubkey_id: id,
        pubkey_b64,
    })
}

#[cfg(unix)]
fn set_permissions_0600(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}
#[cfg(not(unix))]
fn set_permissions_0600(_path: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_then_reuses() {
        let dir = tempfile::tempdir().unwrap();
        let k1 = AuditKey::load_or_create(dir.path()).unwrap();
        assert!(k1.pubkey_id.starts_with("sigil-audit-"));
        let k2 = AuditKey::load_or_create(dir.path()).unwrap();
        assert_eq!(k1.pubkey_id, k2.pubkey_id);
        assert_eq!(k1.pubkey_b64, k2.pubkey_b64);
    }

    #[test]
    fn pubkey_b64_decodes_to_32_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let k = AuditKey::load_or_create(dir.path()).unwrap();
        let raw = data_encoding::BASE64
            .decode(k.pubkey_b64.as_bytes())
            .unwrap();
        assert_eq!(raw.len(), 32);
    }

    #[test]
    fn corrupt_file_regenerates() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(KEY_FILE_NAME), b"not json").unwrap();
        let k = AuditKey::load_or_create(dir.path()).unwrap();
        assert!(k.pubkey_id.starts_with("sigil-audit-"));
    }

    #[test]
    fn unwritable_dir_is_none_not_panic() {
        let dir = tempfile::tempdir().unwrap();
        let blocker = dir.path().join("blocker");
        std::fs::write(&blocker, b"x").unwrap();
        let keydir = blocker.join("nope");
        assert!(AuditKey::load_or_create(&keydir).is_none());
    }
}
