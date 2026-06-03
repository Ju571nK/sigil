//! sender.yaml schema + loader.
//!
//! Spec §3.8.3 + §3.6 (filesystem ACL).

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Duration;
use thiserror::Error;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct SenderConfig {
    /// HTTPS URL of `sigil-server-gateway`. e.g., `https://sigil.example.com`.
    pub server_base_url: String,
    /// Path to client cert (PEM). Optional: omit (with `client_key_path`) to
    /// run without an mTLS client identity — e.g. against a plain-HTTP dev
    /// server. mTLS is the recommended production posture.
    #[serde(default)]
    pub client_cert_path: Option<PathBuf>,
    /// Path to client private key (PEM). Required iff `client_cert_path` is set.
    #[serde(default)]
    pub client_key_path: Option<PathBuf>,
    /// Path to CA bundle that signs the server cert (PEM). Optional: when set,
    /// the server cert is pinned to this CA (built-in roots disabled);
    /// otherwise the platform's built-in roots are used.
    #[serde(default)]
    pub server_ca_path: Option<PathBuf>,
    /// Path to the agent's events directory (where JSONL spool lives). The
    /// sender only *reads* this (the agent owns it `root:sigil`), so it is
    /// reachable by the `sigil` group.
    pub events_dir: PathBuf,
    /// Path where `sender-offset.json` is persisted. Sender-owned and writable;
    /// defaults to the sender's own state dir (`/var/lib/sigil-sender`) so the
    /// non-root sender (#10 slice 2) can write it without touching the agent's
    /// `root:sigil` `/var/lib/sigil`.
    #[serde(default = "default_offset_path")]
    pub offset_path: PathBuf,
    /// Path to the agent's control IPC (Unix socket on unix; pipe name on Windows).
    pub agent_control: PathBuf,
    /// Path to host-side dead-letter spool dir. Sender-owned and writable;
    /// defaults to the sender's own log dir (`/var/log/sigil-sender`).
    #[serde(default = "default_dead_letter_dir")]
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
    /// This host's id — MUST equal the agent's host_id (the agent's state.db
    /// UUID). The server rejects events whose host_id != the batch envelope
    /// host_id. Overridable at runtime by the SIGIL_HOST_ID env var.
    #[serde(default)]
    pub host_id: Option<String>,
}

fn default_offset_path() -> PathBuf {
    PathBuf::from("/var/lib/sigil-sender/sender-offset.json")
}
fn default_dead_letter_dir() -> PathBuf {
    PathBuf::from("/var/log/sigil-sender/dead-letter")
}
fn default_max_batch_events() -> usize {
    256
}
fn default_max_batch_bytes() -> usize {
    1024 * 1024
}
fn default_policy_poll_secs() -> Duration {
    Duration::from_secs(300)
}

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
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("yaml parse {path}: {source}")]
    Parse {
        path: PathBuf,
        source: serde_yaml::Error,
    },
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
        write(
            &p,
            r#"
server_base_url: "https://sigil.example.com"
client_cert_path: "/etc/sigil/client.crt"
client_key_path: "/etc/sigil/client.key"
server_ca_path: "/etc/sigil/server-ca.pem"
events_dir: "/var/log/sigil/events"
offset_path: "/var/lib/sigil/sender-offset.json"
agent_control: "/var/run/sigil/control.sock"
dead_letter_dir: "/var/log/sigil/dead-letter"
"#,
        );
        let cfg = SenderConfig::load(&p).unwrap();
        assert_eq!(cfg.server_base_url, "https://sigil.example.com");
        assert_eq!(cfg.max_batch_events, 256);
        assert_eq!(cfg.max_batch_bytes, 1024 * 1024);
        assert_eq!(cfg.policy_poll_interval.as_secs(), 300);
    }

    #[test]
    fn writable_paths_default_to_sender_owned_dirs_when_omitted() {
        // #10 slice 2: when offset_path / dead_letter_dir are omitted, they
        // default to the sender's own state/log dirs so the non-root sender can
        // write them without touching the agent's root:sigil dirs.
        let dir = tempdir().unwrap();
        let p = dir.path().join("sender.yaml");
        write(
            &p,
            r#"
server_base_url: "https://sigil.example.com"
client_cert_path: "/etc/sigil/client.crt"
client_key_path: "/etc/sigil/client.key"
server_ca_path: "/etc/sigil/server-ca.pem"
events_dir: "/var/log/sigil/events"
agent_control: "/var/run/sigil/control.sock"
"#,
        );
        let cfg = SenderConfig::load(&p).unwrap();
        assert_eq!(
            cfg.offset_path,
            PathBuf::from("/var/lib/sigil-sender/sender-offset.json")
        );
        assert_eq!(
            cfg.dead_letter_dir,
            PathBuf::from("/var/log/sigil-sender/dead-letter")
        );
    }

    #[test]
    fn loads_overrides() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("sender.yaml");
        write(
            &p,
            r#"
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
"#,
        );
        let cfg = SenderConfig::load(&p).unwrap();
        assert_eq!(cfg.max_batch_events, 64);
        assert_eq!(cfg.max_batch_bytes, 65536);
        assert_eq!(cfg.policy_poll_interval.as_secs(), 30);
    }

    #[test]
    fn certs_absent_parses_to_none() {
        // A plain-HTTP / no-mTLS config: the three cert paths may be omitted.
        let dir = tempdir().unwrap();
        let p = dir.path().join("sender.yaml");
        write(
            &p,
            r#"
server_base_url: "http://127.0.0.1:8443"
events_dir: "/d"
offset_path: "/e"
agent_control: "/f"
dead_letter_dir: "/g"
"#,
        );
        let cfg = SenderConfig::load(&p).unwrap();
        assert!(cfg.client_cert_path.is_none());
        assert!(cfg.client_key_path.is_none());
        assert!(cfg.server_ca_path.is_none());
    }

    #[test]
    fn missing_file_is_read_error() {
        let p = std::path::Path::new("/nonexistent/sender.yaml");
        let err = SenderConfig::load(p).unwrap_err();
        assert!(matches!(err, ConfigError::Read { .. }));
    }

    #[test]
    fn host_id_present_parses_to_some() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("sender.yaml");
        write(
            &p,
            r#"
server_base_url: "https://sigil.example.com"
client_cert_path: "/etc/sigil/client.crt"
client_key_path: "/etc/sigil/client.key"
server_ca_path: "/etc/sigil/server-ca.pem"
events_dir: "/var/log/sigil/events"
offset_path: "/var/lib/sigil/sender-offset.json"
agent_control: "/var/run/sigil/control.sock"
dead_letter_dir: "/var/log/sigil/dead-letter"
host_id: "abc-123"
"#,
        );
        let cfg = SenderConfig::load(&p).unwrap();
        assert_eq!(cfg.host_id, Some("abc-123".to_string()));
    }

    #[test]
    fn host_id_absent_parses_to_none() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("sender.yaml");
        write(
            &p,
            r#"
server_base_url: "https://sigil.example.com"
client_cert_path: "/etc/sigil/client.crt"
client_key_path: "/etc/sigil/client.key"
server_ca_path: "/etc/sigil/server-ca.pem"
events_dir: "/var/log/sigil/events"
offset_path: "/var/lib/sigil/sender-offset.json"
agent_control: "/var/run/sigil/control.sock"
dead_letter_dir: "/var/log/sigil/dead-letter"
"#,
        );
        let cfg = SenderConfig::load(&p).unwrap();
        assert_eq!(cfg.host_id, None);
    }
}
