//! #184 — enrollment state: intermediate CA paths + boot validation + mint
//! serialization.
//!
//! Boot validation (codex-hardened rev2) — ALL must pass or the feature is
//! DISABLED (returns None ⇒ every `/v1/enroll` route 404s):
//!   1. cert + key + tokens paths all configured AND host_allowlist configured.
//!   2. openssl resolvable (absolute path captured once).
//!   3. CA cert is `CA:TRUE` (basicConstraints).
//!   4. CA key matches the cert (modulus / pubkey agreement, via openssl).
//!   5. (unix) CA key file mode is NOT looser than 0600.

pub mod audit;
pub mod lock;
pub mod sign;
pub mod tokens;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;

/// Default issued client-cert validity. Short by design (re-enroll replaces
/// revocation in the MVP).
const DEFAULT_CERT_DAYS: u32 = 30;

pub struct EnrollState {
    pub ca_cert_path: PathBuf,
    pub ca_key_path: PathBuf,
    pub tokens_path: PathBuf,
    /// `<events_out_dir parent>/enrollment-audit.jsonl` — set by build_state.
    pub audit_path: PathBuf,
    /// Absolute path to the openssl binary, resolved once at boot.
    pub openssl_path: PathBuf,
    pub cert_days: u32,
    /// Serializes the whole mint critical section:
    /// CN-check → reserve(token) → sign → allowlist → audit.
    pub mint: Mutex<()>,
}

impl EnrollState {
    /// Construct + validate. Returns `None` (feature off) unless every gate
    /// passes. `allowlist_configured` reflects whether `host_allowlist_path` is
    /// set — required, since auto-add is the point of enrollment.
    #[allow(clippy::too_many_arguments)]
    pub fn load(
        ca_cert: Option<&Path>,
        ca_key: Option<&Path>,
        tokens: Option<&Path>,
        allowlist_configured: bool,
        cert_days: Option<u32>,
        audit_path: PathBuf,
    ) -> Option<EnrollState> {
        let (cert, key, toks) = (ca_cert?, ca_key?, tokens?);
        if !allowlist_configured {
            tracing::warn!(
                "enroll: host_allowlist_path not configured; enrollment disabled (allowlist is required)"
            );
            return None;
        }
        if !cert.is_file() || !key.is_file() {
            tracing::warn!("enroll: ca cert/key missing on disk; enrollment disabled");
            return None;
        }
        let openssl = match sign::resolve_openssl() {
            Some(p) => p,
            None => {
                tracing::warn!("enroll: openssl not found on PATH; enrollment disabled");
                return None;
            }
        };
        if !key_mode_ok(key) {
            tracing::error!(
                path = %key.display(),
                "enroll: CA key file mode is looser than 0600; enrollment disabled"
            );
            return None;
        }
        if !ca_cert_is_ca(&openssl, cert) {
            tracing::error!(
                path = %cert.display(),
                "enroll: configured CA cert is not CA:TRUE; enrollment disabled"
            );
            return None;
        }
        if !key_matches_cert(&openssl, cert, key) {
            tracing::error!("enroll: CA key does not match CA cert; enrollment disabled");
            return None;
        }
        tracing::info!(
            cert = %cert.display(),
            "enroll: enabled (intermediate CA validated)"
        );
        Some(EnrollState {
            ca_cert_path: cert.to_path_buf(),
            ca_key_path: key.to_path_buf(),
            tokens_path: toks.to_path_buf(),
            audit_path,
            openssl_path: openssl,
            cert_days: cert_days.unwrap_or(DEFAULT_CERT_DAYS),
            mint: Mutex::new(()),
        })
    }
}

/// (unix) True iff the key file mode has NO group/other permission bits.
#[cfg(unix)]
fn key_mode_ok(key: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::metadata(key) {
        Ok(m) => m.permissions().mode() & 0o077 == 0,
        Err(_) => false,
    }
}
#[cfg(not(unix))]
fn key_mode_ok(_key: &Path) -> bool {
    true
}

/// Verify the cert advertises `CA:TRUE` via `openssl x509 -text`.
fn ca_cert_is_ca(openssl: &Path, cert: &Path) -> bool {
    let out = Command::new(openssl)
        .env_remove("OPENSSL_CONF")
        .arg("x509")
        .arg("-in")
        .arg(cert)
        .args(["-noout", "-text"])
        .output();
    match out {
        Ok(o) if o.status.success() => {
            String::from_utf8_lossy(&o.stdout)
                .to_lowercase()
                .contains("ca:true")
        }
        _ => false,
    }
}

/// Verify the private key matches the cert by comparing public-key hashes.
/// Algorithm-agnostic: `-pubkey` from cert and from key must be byte-identical.
fn key_matches_cert(openssl: &Path, cert: &Path, key: &Path) -> bool {
    let cert_pub = Command::new(openssl)
        .env_remove("OPENSSL_CONF")
        .arg("x509")
        .arg("-in")
        .arg(cert)
        .args(["-noout", "-pubkey"])
        .output();
    let key_pub = Command::new(openssl)
        .env_remove("OPENSSL_CONF")
        .arg("pkey")
        .arg("-in")
        .arg(key)
        .args(["-pubout"])
        .output();
    match (cert_pub, key_pub) {
        (Ok(c), Ok(k)) if c.status.success() && k.status.success() => {
            !c.stdout.is_empty() && c.stdout == k.stdout
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_none_when_any_path_absent() {
        let s = EnrollState::load(
            Some(&PathBuf::from("/x.crt")),
            None,
            Some(&PathBuf::from("/t.json")),
            true,
            None,
            PathBuf::from("/tmp/a.jsonl"),
        );
        assert!(s.is_none());
    }

    #[test]
    fn load_none_when_allowlist_absent() {
        // even with all CA paths "present" as strings, no allowlist ⇒ off
        let s = EnrollState::load(
            Some(&PathBuf::from("/x.crt")),
            Some(&PathBuf::from("/x.key")),
            Some(&PathBuf::from("/t.json")),
            false,
            None,
            PathBuf::from("/tmp/a.jsonl"),
        );
        assert!(s.is_none());
    }

    #[test]
    fn load_none_when_cert_missing_on_disk() {
        let d = tempfile::tempdir().unwrap();
        let s = EnrollState::load(
            Some(&d.path().join("nope.crt")),
            Some(&d.path().join("nope.key")),
            Some(&d.path().join("t.json")),
            true,
            None,
            d.path().join("a.jsonl"),
        );
        assert!(s.is_none());
    }

    /// Full positive: a real CA:TRUE cert+matching key, 0600, validates.
    #[test]
    fn load_some_with_valid_intermediate_ca() {
        let Some(openssl) = sign::resolve_openssl() else {
            eprintln!("openssl not present; skipping");
            return;
        };
        let d = tempfile::tempdir().unwrap();
        let (cert, key) = make_ca(&openssl, d.path());
        let toks = d.path().join("t.json");
        let s = EnrollState::load(
            Some(&cert),
            Some(&key),
            Some(&toks),
            true,
            Some(30),
            d.path().join("a.jsonl"),
        );
        assert!(s.is_some(), "valid CA should enable enrollment");
        assert_eq!(s.unwrap().cert_days, 30);
    }

    /// A non-CA (CA:FALSE) cert must be rejected.
    #[test]
    fn load_none_when_cert_not_ca() {
        let Some(openssl) = sign::resolve_openssl() else {
            return;
        };
        let d = tempfile::tempdir().unwrap();
        let (cert, key) = make_leaf_cert(&openssl, d.path());
        let s = EnrollState::load(
            Some(&cert),
            Some(&key),
            Some(&d.path().join("t.json")),
            true,
            None,
            d.path().join("a.jsonl"),
        );
        assert!(s.is_none(), "CA:FALSE cert must disable enrollment");
    }

    fn make_ca(openssl: &Path, dir: &Path) -> (PathBuf, PathBuf) {
        let key = dir.join("ca.key");
        let crt = dir.join("ca.crt");
        run(openssl, &["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", key.to_str().unwrap()]);
        run(
            openssl,
            &[
                "req", "-x509", "-new", "-key", key.to_str().unwrap(), "-days", "3650",
                "-subj", "/CN=test-ca", "-addext", "basicConstraints=critical,CA:TRUE",
                "-out", crt.to_str().unwrap(),
            ],
        );
        set_0600(&key);
        (crt, key)
    }

    fn make_leaf_cert(openssl: &Path, dir: &Path) -> (PathBuf, PathBuf) {
        let key = dir.join("leaf.key");
        let crt = dir.join("leaf.crt");
        run(openssl, &["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", key.to_str().unwrap()]);
        run(
            openssl,
            &[
                "req", "-x509", "-new", "-key", key.to_str().unwrap(), "-days", "3650",
                "-subj", "/CN=leaf", "-addext", "basicConstraints=critical,CA:FALSE",
                "-out", crt.to_str().unwrap(),
            ],
        );
        set_0600(&key);
        (crt, key)
    }

    fn run(openssl: &Path, args: &[&str]) {
        let o = Command::new(openssl).args(args).output().unwrap();
        assert!(o.status.success(), "openssl {args:?}: {}", String::from_utf8_lossy(&o.stderr));
    }

    #[cfg(unix)]
    fn set_0600(p: &Path) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    #[cfg(not(unix))]
    fn set_0600(_p: &Path) {}
}
