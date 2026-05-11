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
}
