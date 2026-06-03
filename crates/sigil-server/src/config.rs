//! `server.yaml` schema + loader.

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use thiserror::Error;

/// License configuration block (optional). Absent ⇒ free tier.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct LicenseConfig {
    /// Path to the SignedLicense bundle (JSON). Absent ⇒ free tier.
    #[serde(default)]
    pub path: Option<PathBuf>,
    /// Rolling window for "active host" counting. Absent ⇒ DEFAULT_ACTIVE_WINDOW_DAYS.
    #[serde(default)]
    pub active_window_days: Option<u32>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ServerConfig {
    /// Address to bind. e.g. `0.0.0.0:8443`.
    pub bind: SocketAddr,
    /// PEM server cert. If set (together with `tls_key_path`), the server
    /// runs mTLS; `client_ca_path` is then required.
    #[serde(default)]
    pub tls_cert_path: Option<PathBuf>,
    /// PEM server private key.
    #[serde(default)]
    pub tls_key_path: Option<PathBuf>,
    /// PEM bundle of CAs whose client certs are trusted (mTLS).
    #[serde(default)]
    pub client_ca_path: Option<PathBuf>,
    /// Directory where accepted events are written (per-host subdirs).
    pub events_out_dir: PathBuf,
    /// Path to the operator-signed policy bundle (`SignedPolicyResponse` JSON,
    /// produced by `sigil-sign`). Absent file ⇒ `GET /v1/policy` returns 404.
    pub policy_bundle_path: PathBuf,
    /// Path to the signed pack-set bundle (`SignedPolicyResponse`-shaped JSON,
    /// produced by `sigil-sign`). Absent ⇒ `GET /v1/rule-packs` returns 404.
    #[serde(default)]
    pub rule_packs_bundle_path: Option<std::path::PathBuf>,
    /// Optional allowlist of `host_id`s. Absent ⇒ accept all authenticated hosts.
    #[serde(default)]
    pub host_allowlist_path: Option<PathBuf>,
    /// Path to the persisted per-host high-water-sequence map (for dedup
    /// across restarts). Defaults to `<events_out_dir>/.high-water.json`.
    #[serde(default)]
    pub high_water_path: Option<PathBuf>,
    /// Optional license configuration. Absent ⇒ free tier (no enforcement).
    #[serde(default)]
    pub license: Option<LicenseConfig>,
}

impl ServerConfig {
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

    /// Effective high-water path: explicit, or `<events_out_dir>/.high-water.json`.
    pub fn high_water_path(&self) -> PathBuf {
        self.high_water_path
            .clone()
            .unwrap_or_else(|| self.events_out_dir.join(".high-water.json"))
    }

    /// True iff a full mTLS triple is configured.
    pub fn mtls_enabled(&self) -> bool {
        self.tls_cert_path.is_some() && self.tls_key_path.is_some() && self.client_ca_path.is_some()
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn loads_minimal_config() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("server.yaml");
        std::fs::write(
            &p,
            r#"
bind: "127.0.0.1:8443"
events_out_dir: "/var/lib/sigil-server/events"
policy_bundle_path: "/var/lib/sigil-server/signed-policy.json"
"#,
        )
        .unwrap();
        let cfg = ServerConfig::load(&p).unwrap();
        assert_eq!(cfg.bind.port(), 8443);
        assert!(!cfg.mtls_enabled());
        assert!(cfg.host_allowlist_path.is_none());
        assert_eq!(
            cfg.high_water_path(),
            PathBuf::from("/var/lib/sigil-server/events/.high-water.json")
        );
    }

    #[test]
    fn mtls_enabled_when_full_triple_present() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("server.yaml");
        std::fs::write(
            &p,
            r#"
bind: "0.0.0.0:8443"
tls_cert_path: "/etc/sigil-server/server.crt"
tls_key_path: "/etc/sigil-server/server.key"
client_ca_path: "/etc/sigil-server/client-ca.pem"
events_out_dir: "/d/events"
policy_bundle_path: "/d/signed-policy.json"
host_allowlist_path: "/d/hosts.json"
"#,
        )
        .unwrap();
        let cfg = ServerConfig::load(&p).unwrap();
        assert!(cfg.mtls_enabled());
        assert!(cfg.host_allowlist_path.is_some());
    }

    #[test]
    fn missing_file_is_read_error() {
        let err = ServerConfig::load(Path::new("/nonexistent/server.yaml")).unwrap_err();
        assert!(matches!(err, ConfigError::Read { .. }));
    }

    #[test]
    fn parses_optional_license_block() {
        let yaml = r#"
bind: "127.0.0.1:8443"
events_out_dir: "/var/lib/sigil-server/events"
policy_bundle_path: "/var/lib/sigil-server/signed-policy.json"
license:
  path: /etc/sigil/license.bundle
  active_window_days: 14
"#;
        let cfg: ServerConfig = serde_yaml::from_str(yaml).unwrap();
        let lic = cfg.license.expect("license block present");
        assert_eq!(
            lic.path.as_deref(),
            Some(std::path::Path::new("/etc/sigil/license.bundle"))
        );
        assert_eq!(lic.active_window_days, Some(14));
    }

    #[test]
    fn license_block_absent_is_none() {
        let yaml = r#"
bind: "127.0.0.1:8443"
events_out_dir: "/var/lib/sigil-server/events"
policy_bundle_path: "/var/lib/sigil-server/signed-policy.json"
"#;
        let cfg: ServerConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(cfg.license.is_none());
    }
}
