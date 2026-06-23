//! Optional `hosts.json` allowlist.
//!
//! Format: `{"hosts": ["host-a", "host-b", ...]}`. Absent file ⇒ no
//! restriction (every authenticated host is accepted).

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;
use thiserror::Error;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct HostAllowlistFile {
    pub hosts: Vec<String>,
}

#[derive(Debug, Error)]
pub enum AllowlistError {
    #[error("read {path}: {source}")]
    Io {
        path: std::path::PathBuf,
        source: std::io::Error,
    },
    #[error("json parse {path}: {source}")]
    Parse {
        path: std::path::PathBuf,
        source: serde_json::Error,
    },
}

/// Load the allowlist into a set. `None` path or absent file ⇒ `Ok(None)`
/// (no restriction). A present-but-broken file is a hard error.
pub fn load(path: Option<&Path>) -> Result<Option<HashSet<String>>, AllowlistError> {
    let Some(path) = path else {
        return Ok(None);
    };
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(AllowlistError::Io {
                path: path.to_path_buf(),
                source,
            })
        }
    };
    let file: HostAllowlistFile =
        serde_json::from_slice(&bytes).map_err(|source| AllowlistError::Parse {
            path: path.to_path_buf(),
            source,
        })?;
    Ok(Some(file.hosts.into_iter().collect()))
}

/// Returns `true` if `host_id` is permitted given `allowlist` (`None` ⇒ all permitted).
pub fn permits(allowlist: &Option<HashSet<String>>, host_id: &str) -> bool {
    match allowlist {
        None => true,
        Some(set) => set.contains(host_id),
    }
}

/// #184 — atomically add `host_id` to the on-disk allowlist file. Idempotent:
/// a host already present is a no-op success. Creates the file (with just this
/// host) if absent. Write is atomic (tmp-in-same-dir + rename). Does NOT touch
/// the in-memory set — the enroll handler updates that separately.
pub fn add_host_atomic(path: &Path, host_id: &str) -> Result<(), AllowlistError> {
    let mut file: HostAllowlistFile = match std::fs::read(path) {
        Ok(b) => serde_json::from_slice(&b).map_err(|source| AllowlistError::Parse {
            path: path.to_path_buf(),
            source,
        })?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => HostAllowlistFile::default(),
        Err(source) => {
            return Err(AllowlistError::Io {
                path: path.to_path_buf(),
                source,
            })
        }
    };
    if file.hosts.iter().any(|h| h == host_id) {
        return Ok(()); // idempotent
    }
    file.hosts.push(host_id.to_string());
    let bytes = serde_json::to_vec_pretty(&file).map_err(|source| AllowlistError::Parse {
        path: path.to_path_buf(),
        source,
    })?;
    write_atomic(path, &bytes).map_err(|source| AllowlistError::Io {
        path: path.to_path_buf(),
        source,
    })
}

/// Atomic write: tmp file in the same directory, then rename over `path`.
fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let mut tmp = tempfile::Builder::new()
        .prefix(".hosts-")
        .tempfile_in(dir)?;
    tmp.write_all(bytes)?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(std::io::Error::other)?;
    // #184 P2: fsync the PARENT directory so the rename survives a crash.
    // Directory fsync is best-effort (unsupported on some platforms) — ignore.
    if let Ok(f) = std::fs::File::open(dir) {
        let _ = f.sync_all();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn none_path_permits_everything() {
        let al = load(None).unwrap();
        assert!(al.is_none());
        assert!(permits(&al, "anything"));
    }

    #[test]
    fn absent_file_permits_everything() {
        let dir = tempdir().unwrap();
        let al = load(Some(&dir.path().join("missing.json"))).unwrap();
        assert!(al.is_none());
        assert!(permits(&al, "anything"));
    }

    #[test]
    fn present_file_restricts() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("hosts.json");
        std::fs::write(&p, r#"{"hosts":["a","b"]}"#).unwrap();
        let al = load(Some(&p)).unwrap();
        assert!(al.is_some());
        assert!(permits(&al, "a"));
        assert!(permits(&al, "b"));
        assert!(!permits(&al, "c"));
    }

    #[test]
    fn broken_file_is_error() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("hosts.json");
        std::fs::write(&p, "not json").unwrap();
        assert!(load(Some(&p)).is_err());
    }

    #[test]
    fn add_host_atomic_creates_file_when_absent() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("hosts.json");
        add_host_atomic(&p, "host-a").unwrap();
        let al = load(Some(&p)).unwrap().unwrap();
        assert!(al.contains("host-a"));
    }

    #[test]
    fn add_host_atomic_appends_and_is_idempotent() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("hosts.json");
        std::fs::write(&p, r#"{"hosts":["existing"]}"#).unwrap();
        add_host_atomic(&p, "host-b").unwrap();
        add_host_atomic(&p, "host-b").unwrap(); // idempotent: no dup
        let al = load(Some(&p)).unwrap().unwrap();
        assert!(al.contains("existing"));
        assert!(al.contains("host-b"));
        // exactly two hosts (no duplicate)
        let raw = std::fs::read_to_string(&p).unwrap();
        let f: HostAllowlistFile = serde_json::from_str(&raw).unwrap();
        assert_eq!(f.hosts.len(), 2);
    }
}
