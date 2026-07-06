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
    /// Directory of operator-populated, signed agent release artifacts
    /// (tarballs/zips, `.deb`/`.rpm`, `SHA256SUMS`, `build-manifest.json`).
    /// Absent ⇒ `GET /v1/artifacts*` returns 404 (feature off). #182
    #[serde(default)]
    pub artifacts_dir: Option<PathBuf>,
    /// #184 — operator-provided INTERMEDIATE CA cert (PEM). Returned in the
    /// enroll chain and used to sign host CSRs. Root stays offline. Absent ⇒
    /// enrollment off (404).
    #[serde(default)]
    pub enroll_ca_cert_path: Option<PathBuf>,
    /// #184 — intermediate CA private key (PEM, 0600). Online signing key.
    /// Absent ⇒ enrollment off.
    #[serde(default)]
    pub enroll_ca_key_path: Option<PathBuf>,
    /// #184 — enrollment token store (JSON, blake3-hashed tokens).
    /// Absent ⇒ enrollment off.
    #[serde(default)]
    pub enroll_tokens_path: Option<PathBuf>,
    /// #194.1 — optional allowlist of TLS client-cert fingerprints (blake3 hex
    /// of the leaf cert DER) permitted to call `POST /v1/enroll` (the
    /// PMS/issuer box). Absent ⇒ any mTLS fleet member may redeem an enroll
    /// token (pre-#194 behavior). Present-but-empty ⇒ deny-all.
    #[serde(default)]
    pub enroll_issuer_fingerprints: Option<Vec<String>>,
    /// #184 — issued client-cert validity in days (default 30; short by design,
    /// re-enroll replaces revocation in the MVP).
    #[serde(default)]
    pub enroll_cert_days: Option<u32>,
    /// Optional allowlist of `host_id`s. Absent ⇒ accept all authenticated hosts.
    /// REQUIRED for enrollment (#184): without it, auto-add is meaningless, so
    /// enrollment stays off (404) when this is unset.
    #[serde(default)]
    pub host_allowlist_path: Option<PathBuf>,
    /// #194.2 — when true, `POST /v1/events` additionally requires the TLS
    /// client cert to match the envelope `host_id` (subject CN == host_id, or
    /// host_id ∈ SAN DNS). Requires mTLS: the server refuses to start if this
    /// is set without the full TLS triple. Default false (pre-#194 behavior).
    #[serde(default)]
    pub events_require_cert_host_match: bool,
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
        let cfg: Self = serde_yaml::from_slice(&bytes).map_err(|source| ConfigError::Parse {
            path: path.to_path_buf(),
            source,
        })?;
        cfg.validate(path)?;
        Ok(cfg)
    }

    /// Cross-field boot validation. #194.2: `events_require_cert_host_match`
    /// is meaningless over plain HTTP (there is no client cert to match), so
    /// setting it without the full mTLS triple is a refuse-to-start error —
    /// never a silently-ignored gate.
    fn validate(&self, path: &Path) -> Result<(), ConfigError> {
        if self.events_require_cert_host_match && !self.mtls_enabled() {
            return Err(ConfigError::Invalid {
                path: path.to_path_buf(),
                reason: "events_require_cert_host_match requires mTLS \
                         (tls_cert_path + tls_key_path + client_ca_path)"
                    .to_string(),
            });
        }
        Ok(())
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
    #[error("invalid config {path}: {reason}")]
    Invalid { path: PathBuf, reason: String },
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    /// The shipped `config/server.example.yaml` must stay in sync with the
    /// `ServerConfig` schema: uncomment every documented setting and it must
    /// still deserialize (guards against a typo'd or renamed key in the docs).
    #[test]
    fn example_config_matches_schema() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../config/server.example.yaml"
        );
        let raw = std::fs::read_to_string(path).expect("read example yaml");
        let mut out = String::new();
        for line in raw.lines() {
            let t = line.trim_start();
            // Uncomment lines that document a setting (`# key:`, `#   - item`,
            // nested `# path:` / `# active_window_days:`); drop prose comments.
            let is_setting = t
                .strip_prefix('#')
                .map(|r| {
                    let r = r.trim_start();
                    r.starts_with("- ")
                        || r.split_once(':').is_some_and(|(k, _)| {
                            !k.is_empty() && k.chars().all(|c| c.is_ascii_lowercase() || c == '_')
                        })
                })
                .unwrap_or(false);
            if let Some(stripped) = line.strip_prefix("# ").or_else(|| line.strip_prefix('#')) {
                if is_setting {
                    out.push_str(stripped);
                    out.push('\n');
                }
                // else: prose comment — skip
            } else {
                out.push_str(line);
                out.push('\n');
            }
        }
        let cfg: ServerConfig = serde_yaml::from_str(&out).unwrap_or_else(|e| {
            panic!("example yaml (all keys uncommented) must parse: {e}\n---\n{out}")
        });
        // Spot-check the #184/#194 keys are present and typed as expected.
        assert!(cfg.enroll_ca_cert_path.is_some());
        assert!(cfg.enroll_issuer_fingerprints.is_some());
        assert!(cfg.events_require_cert_host_match);
        assert!(cfg.artifacts_dir.is_some());
    }

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

    /// #194.1 — enroll_issuer_fingerprints parses; absent stays None.
    #[test]
    fn parses_enroll_issuer_fingerprints() {
        let yaml = r#"
bind: "127.0.0.1:8443"
events_out_dir: "/d/events"
policy_bundle_path: "/d/signed-policy.json"
enroll_issuer_fingerprints:
  - "aabb01"
  - "ccdd02"
"#;
        let cfg: ServerConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(
            cfg.enroll_issuer_fingerprints,
            Some(vec!["aabb01".to_string(), "ccdd02".to_string()])
        );

        let yaml_absent = r#"
bind: "127.0.0.1:8443"
events_out_dir: "/d/events"
policy_bundle_path: "/d/signed-policy.json"
"#;
        let cfg: ServerConfig = serde_yaml::from_str(yaml_absent).unwrap();
        assert_eq!(cfg.enroll_issuer_fingerprints, None);
    }

    /// #194.2 — events_require_cert_host_match parses; default false.
    #[test]
    fn parses_events_require_cert_host_match() {
        let yaml = r#"
bind: "127.0.0.1:8443"
tls_cert_path: "/e/server.crt"
tls_key_path: "/e/server.key"
client_ca_path: "/e/client-ca.pem"
events_out_dir: "/d/events"
policy_bundle_path: "/d/signed-policy.json"
events_require_cert_host_match: true
"#;
        let cfg: ServerConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(cfg.events_require_cert_host_match);

        let yaml_absent = r#"
bind: "127.0.0.1:8443"
events_out_dir: "/d/events"
policy_bundle_path: "/d/signed-policy.json"
"#;
        let cfg: ServerConfig = serde_yaml::from_str(yaml_absent).unwrap();
        assert!(!cfg.events_require_cert_host_match, "default is false");
    }

    /// #194.2 — the flag without mTLS is a refuse-to-start config error; with
    /// the full mTLS triple the same config loads.
    #[test]
    fn cert_host_match_without_mtls_refuses_to_load() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("server.yaml");
        std::fs::write(
            &p,
            r#"
bind: "127.0.0.1:8443"
events_out_dir: "/d/events"
policy_bundle_path: "/d/signed-policy.json"
events_require_cert_host_match: true
"#,
        )
        .unwrap();
        let err = ServerConfig::load(&p).unwrap_err();
        assert!(
            matches!(err, ConfigError::Invalid { .. }),
            "flag without mTLS must refuse to start, got: {err}"
        );

        std::fs::write(
            &p,
            r#"
bind: "127.0.0.1:8443"
tls_cert_path: "/e/server.crt"
tls_key_path: "/e/server.key"
client_ca_path: "/e/client-ca.pem"
events_out_dir: "/d/events"
policy_bundle_path: "/d/signed-policy.json"
events_require_cert_host_match: true
"#,
        )
        .unwrap();
        let cfg = ServerConfig::load(&p).unwrap();
        assert!(cfg.events_require_cert_host_match && cfg.mtls_enabled());
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
