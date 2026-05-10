//! sender.yaml schema + loader.
//!
//! Spec §3.8.3 + §3.6 (filesystem ACL).

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Duration;
use thiserror::Error;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct SenderConfig {
    /// HTTPS URL of `andeda-server-gateway`. e.g., `https://andeda.example.com`.
    pub server_base_url: String,
    /// Path to client cert (PEM).
    pub client_cert_path: PathBuf,
    /// Path to client private key (PEM).
    pub client_key_path: PathBuf,
    /// Path to CA bundle that signs the server cert (PEM).
    pub server_ca_path: PathBuf,
    /// Path to the agent's events directory (where JSONL spool lives).
    pub events_dir: PathBuf,
    /// Path where `sender-offset.json` is persisted.
    pub offset_path: PathBuf,
    /// Path to the agent's control IPC (Unix socket on unix; pipe name on Windows).
    pub agent_control: PathBuf,
    /// Path to host-side dead-letter spool dir.
    pub dead_letter_dir: PathBuf,
    /// Maximum events per batch (spec default 256).
    #[serde(default = "default_max_batch_events")]
    pub max_batch_events: usize,
    /// Maximum batch bytes (spec default 1 MiB = 1048576).
    #[serde(default = "default_max_batch_bytes")]
    pub max_batch_bytes: usize,
    /// Policy poll interval (spec default 5min).
    #[serde(default = "default_policy_poll_secs", with = "serde_duration_secs")]
    pub policy_poll_interval: Duration,
}

fn default_max_batch_events() -> usize { 256 }
fn default_max_batch_bytes() -> usize { 1024 * 1024 }
fn default_policy_poll_secs() -> Duration { Duration::from_secs(300) }

mod serde_duration_secs {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u64(d.as_secs())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        let secs = u64::deserialize(d)?;
        Ok(Duration::from_secs(secs))
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("read {path}: {source}")]
    Read { path: PathBuf, source: std::io::Error },
    #[error("yaml parse {path}: {source}")]
    Parse { path: PathBuf, source: serde_yaml::Error },
}

impl SenderConfig {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let bytes = std::fs::read(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        serde_yaml::from_slice(&bytes).map_err(|source| ConfigError::Parse {
            path: path.to_path_buf(),
            source,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn write(path: &Path, body: &str) {
        std::fs::write(path, body).unwrap();
    }

    #[test]
    fn loads_minimal_config_with_defaults() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("sender.yaml");
        write(&p, r#"
server_base_url: "https://andeda.example.com"
client_cert_path: "/etc/andeda/client.crt"
client_key_path: "/etc/andeda/client.key"
server_ca_path: "/etc/andeda/server-ca.pem"
events_dir: "/var/log/andeda/events"
offset_path: "/var/lib/andeda/sender-offset.json"
agent_control: "/var/run/andeda/control.sock"
dead_letter_dir: "/var/log/andeda/dead-letter"
"#);
        let cfg = SenderConfig::load(&p).unwrap();
        assert_eq!(cfg.server_base_url, "https://andeda.example.com");
        assert_eq!(cfg.max_batch_events, 256);
        assert_eq!(cfg.max_batch_bytes, 1024 * 1024);
        assert_eq!(cfg.policy_poll_interval.as_secs(), 300);
    }

    #[test]
    fn loads_overrides() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("sender.yaml");
        write(&p, r#"
server_base_url: "https://x"
client_cert_path: "/a"
client_key_path: "/b"
server_ca_path: "/c"
events_dir: "/d"
offset_path: "/e"
agent_control: "/f"
dead_letter_dir: "/g"
max_batch_events: 64
max_batch_bytes: 65536
policy_poll_interval: 30
"#);
        let cfg = SenderConfig::load(&p).unwrap();
        assert_eq!(cfg.max_batch_events, 64);
        assert_eq!(cfg.max_batch_bytes, 65536);
        assert_eq!(cfg.policy_poll_interval.as_secs(), 30);
    }

    #[test]
    fn missing_file_is_read_error() {
        let p = std::path::Path::new("/nonexistent/sender.yaml");
        let err = SenderConfig::load(p).unwrap_err();
        assert!(matches!(err, ConfigError::Read { .. }));
    }
}
