//! #184 — enrollment state: intermediate CA paths + boot validation + mint
//! serialization.
//!
//! Boot validation (codex-hardened rev3) — ALL must pass or the feature is
//! DISABLED (returns None ⇒ every `/v1/enroll` route 404s):
//!   0. mTLS is configured on the server (the full TLS triple). Token-only cert
//!      minting must never be reachable over cleartext HTTP. (fix A)
//!   1. cert + key + tokens paths all configured AND host_allowlist configured.
//!   2. the host_allowlist file EXISTS and loads as a restrictive `Some(set)`
//!      (possibly empty). A missing/permit-all allowlist disables enrollment so
//!      a token-minted host can never bypass the allowlist gate. (fix B)
//!   3. openssl resolvable (absolute path captured once).
//!   4. CA cert is `CA:TRUE` (basicConstraints).
//!   5. CA key matches the cert (modulus / pubkey agreement, via openssl).
//!   6. (unix) CA key file mode is NOT looser than 0600.

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
    /// #194.1 — optional allowlist of caller (TLS client-cert) fingerprints
    /// permitted to enroll, normalized to lowercase hex at load. `None` ⇒ any
    /// mTLS fleet member may redeem a token; `Some([])` ⇒ deny-all.
    pub issuer_fingerprints: Option<Vec<String>>,
    /// Serializes the whole mint critical section:
    /// issuer-check → CN-check → reserve(token) → sign → allowlist → audit.
    pub mint: Mutex<()>,
}

impl EnrollState {
    /// Construct + validate. Returns `None` (feature off) unless every gate
    /// passes. `allowlist_path` is the on-disk `hosts.json` path — required,
    /// since auto-add is the point of enrollment, and it MUST load as a
    /// restrictive `Some(set)`. `mtls_enabled` reflects the server's TLS triple;
    /// enrollment is refused over cleartext HTTP.
    #[allow(clippy::too_many_arguments)]
    pub fn load(
        ca_cert: Option<&Path>,
        ca_key: Option<&Path>,
        tokens: Option<&Path>,
        allowlist_path: Option<&Path>,
        mtls_enabled: bool,
        cert_days: Option<u32>,
        audit_path: PathBuf,
        issuer_fingerprints: Option<Vec<String>>,
    ) -> Option<EnrollState> {
        // fix A: never expose token-only cert minting over cleartext HTTP.
        if !mtls_enabled {
            if ca_cert.is_some() || ca_key.is_some() || tokens.is_some() {
                tracing::warn!(
                    "enroll: enrollment paths set but server mTLS is not configured; enrollment disabled (token-only minting must not be reachable over cleartext HTTP)"
                );
            }
            return None;
        }
        let (cert, key, toks) = (ca_cert?, ca_key?, tokens?);
        let Some(allowlist_path) = allowlist_path else {
            tracing::warn!(
                "enroll: host_allowlist_path not configured; enrollment disabled (allowlist is required)"
            );
            return None;
        };
        // fix B: the allowlist file MUST exist and load as a restrictive set
        // (possibly empty). A missing/permit-all allowlist ⇒ disable enrollment,
        // never leave it on with a permit-all allowlist.
        match crate::allowlist::load(Some(allowlist_path)) {
            Ok(Some(_set)) => {}
            Ok(None) => {
                tracing::warn!(
                    path = %allowlist_path.display(),
                    "enroll: host_allowlist file missing (permit-all); enrollment disabled (a restrictive allowlist is required)"
                );
                return None;
            }
            Err(e) => {
                tracing::warn!(
                    path = %allowlist_path.display(),
                    error = %e,
                    "enroll: host_allowlist file unloadable; enrollment disabled"
                );
                return None;
            }
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
        // #194.1 — normalize issuer fingerprints to lowercase hex once, at
        // boot, and VALIDATE them (codex review): a blake3 fingerprint is
        // exactly 64 hex chars, so a typo'd entry can never match anything —
        // it would silently lock the operator out. Malformed entries disable
        // enrollment loudly instead. Duplicates are removed. `Some([])` is
        // kept as-is: deny-all, so an empty list in the config surfaces
        // immediately rather than silently disabling the gate.
        let issuer_fingerprints = match issuer_fingerprints {
            None => None,
            Some(list) => {
                let mut norm: Vec<String> = Vec::with_capacity(list.len());
                for raw in &list {
                    let f = raw.trim().to_ascii_lowercase();
                    if f.len() != 64 || !f.bytes().all(|b| b.is_ascii_hexdigit()) {
                        tracing::error!(
                            entry = %raw,
                            "enroll: enroll_issuer_fingerprints entry is not 64 hex chars \
                             (blake3 of the client cert DER); enrollment disabled"
                        );
                        return None;
                    }
                    if !norm.contains(&f) {
                        norm.push(f);
                    }
                }
                Some(norm)
            }
        };
        match issuer_fingerprints.as_deref() {
            Some([]) => tracing::warn!(
                "enroll: enroll_issuer_fingerprints is EMPTY — every /v1/enroll caller will be denied"
            ),
            Some(list) => tracing::info!(
                entries = list.len(),
                "enroll: issuer cert-fingerprint binding enabled (#194.1)"
            ),
            None => {}
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
            issuer_fingerprints,
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
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout)
            .to_lowercase()
            .contains("ca:true"),
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

    /// Write a restrictive (empty) allowlist file so the fix-B gate passes.
    fn write_allowlist(dir: &Path) -> PathBuf {
        let p = dir.join("hosts.json");
        std::fs::write(&p, r#"{"hosts":[]}"#).unwrap();
        p
    }

    #[test]
    fn load_none_when_any_path_absent() {
        let d = tempfile::tempdir().unwrap();
        let al = write_allowlist(d.path());
        let s = EnrollState::load(
            Some(&PathBuf::from("/x.crt")),
            None,
            Some(&PathBuf::from("/t.json")),
            Some(&al),
            true, // mtls on
            None,
            PathBuf::from("/tmp/a.jsonl"),
            None,
        );
        assert!(s.is_none());
    }

    #[test]
    fn load_none_when_allowlist_absent() {
        // even with all CA paths "present" as strings, no allowlist path ⇒ off
        let s = EnrollState::load(
            Some(&PathBuf::from("/x.crt")),
            Some(&PathBuf::from("/x.key")),
            Some(&PathBuf::from("/t.json")),
            None,
            true, // mtls on
            None,
            PathBuf::from("/tmp/a.jsonl"),
            None,
        );
        assert!(s.is_none());
    }

    /// fix A: enrollment paths set but server mTLS not configured ⇒ disabled.
    #[test]
    fn load_none_when_mtls_disabled() {
        let d = tempfile::tempdir().unwrap();
        let al = write_allowlist(d.path());
        let s = EnrollState::load(
            Some(&PathBuf::from("/x.crt")),
            Some(&PathBuf::from("/x.key")),
            Some(&PathBuf::from("/t.json")),
            Some(&al),
            false, // mtls OFF ⇒ must refuse
            None,
            d.path().join("a.jsonl"),
            None,
        );
        assert!(s.is_none(), "no mTLS ⇒ enrollment must be disabled");
    }

    /// fix A (full positive control): a real valid CA enrolls ONLY with mTLS on;
    /// flipping mTLS off disables it.
    #[test]
    fn load_none_when_mtls_disabled_even_with_valid_ca() {
        let Some(openssl) = sign::resolve_openssl() else {
            return;
        };
        let d = tempfile::tempdir().unwrap();
        let (cert, key) = make_ca(&openssl, d.path());
        let al = write_allowlist(d.path());
        let toks = d.path().join("t.json");
        let s = EnrollState::load(
            Some(&cert),
            Some(&key),
            Some(&toks),
            Some(&al),
            false, // mtls OFF
            Some(30),
            d.path().join("a.jsonl"),
            None,
        );
        assert!(s.is_none(), "valid CA still disabled when mTLS is off");
    }

    /// fix B: allowlist path configured but the FILE is missing ⇒ enrollment
    /// disabled (never permit-all under enrollment).
    #[test]
    fn load_none_when_allowlist_file_missing() {
        let Some(openssl) = sign::resolve_openssl() else {
            return;
        };
        let d = tempfile::tempdir().unwrap();
        let (cert, key) = make_ca(&openssl, d.path());
        let toks = d.path().join("t.json");
        let missing = d.path().join("hosts.json"); // never created
        let s = EnrollState::load(
            Some(&cert),
            Some(&key),
            Some(&toks),
            Some(&missing),
            true, // mtls on
            Some(30),
            d.path().join("a.jsonl"),
            None,
        );
        assert!(
            s.is_none(),
            "missing allowlist file (permit-all) ⇒ enrollment disabled"
        );
    }

    #[test]
    fn load_none_when_cert_missing_on_disk() {
        let d = tempfile::tempdir().unwrap();
        let al = write_allowlist(d.path());
        let s = EnrollState::load(
            Some(&d.path().join("nope.crt")),
            Some(&d.path().join("nope.key")),
            Some(&d.path().join("t.json")),
            Some(&al),
            true,
            None,
            d.path().join("a.jsonl"),
            None,
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
        let al = write_allowlist(d.path());
        let toks = d.path().join("t.json");
        let s = EnrollState::load(
            Some(&cert),
            Some(&key),
            Some(&toks),
            Some(&al),
            true,
            Some(30),
            d.path().join("a.jsonl"),
            None,
        );
        assert!(s.is_some(), "valid CA should enable enrollment");
        assert_eq!(s.unwrap().cert_days, 30);
    }

    /// #194.1 — issuer fingerprints are normalized (trim + lowercase) at load;
    /// absent stays `None`; an empty list is preserved (deny-all).
    #[test]
    fn load_normalizes_issuer_fingerprints() {
        let Some(openssl) = sign::resolve_openssl() else {
            return;
        };
        let d = tempfile::tempdir().unwrap();
        let (cert, key) = make_ca(&openssl, d.path());
        let al = write_allowlist(d.path());
        let toks = d.path().join("t.json");
        let load = |issuers: Option<Vec<String>>| {
            EnrollState::load(
                Some(&cert),
                Some(&key),
                Some(&toks),
                Some(&al),
                true,
                Some(30),
                d.path().join("a.jsonl"),
                issuers,
            )
        };
        let hexfp = "AB".repeat(32); // 64 hex chars, uppercase
        let s = load(Some(vec![format!("  {hexfp}  "), hexfp.to_lowercase()])).unwrap();
        assert_eq!(
            s.issuer_fingerprints,
            Some(vec!["ab".repeat(32)]),
            "trimmed + lowercased + deduped"
        );
        let s = load(Some(vec![])).unwrap();
        assert_eq!(s.issuer_fingerprints, Some(vec![]), "empty kept = deny-all");
        let s = load(None).unwrap();
        assert_eq!(s.issuer_fingerprints, None, "absent stays permissive");
        // codex review — malformed entries (wrong length / non-hex) can never
        // match a blake3 fingerprint; they disable enrollment loudly instead
        // of silently locking the operator out.
        assert!(
            load(Some(vec!["abcdef0123".to_string()])).is_none(),
            "short entry rejected"
        );
        assert!(
            load(Some(vec!["zz".repeat(32)])).is_none(),
            "non-hex entry rejected"
        );
    }

    /// A non-CA (CA:FALSE) cert must be rejected.
    #[test]
    fn load_none_when_cert_not_ca() {
        let Some(openssl) = sign::resolve_openssl() else {
            return;
        };
        let d = tempfile::tempdir().unwrap();
        let (cert, key) = make_leaf_cert(&openssl, d.path());
        let al = write_allowlist(d.path());
        let s = EnrollState::load(
            Some(&cert),
            Some(&key),
            Some(&d.path().join("t.json")),
            Some(&al),
            true,
            None,
            d.path().join("a.jsonl"),
            None,
        );
        assert!(s.is_none(), "CA:FALSE cert must disable enrollment");
    }

    fn make_ca(openssl: &Path, dir: &Path) -> (PathBuf, PathBuf) {
        let key = dir.join("ca.key");
        let crt = dir.join("ca.crt");
        run(
            openssl,
            &[
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-out",
                key.to_str().unwrap(),
            ],
        );
        run(
            openssl,
            &[
                "req",
                "-x509",
                "-new",
                "-key",
                key.to_str().unwrap(),
                "-days",
                "3650",
                "-subj",
                "/CN=test-ca",
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-out",
                crt.to_str().unwrap(),
            ],
        );
        set_0600(&key);
        (crt, key)
    }

    fn make_leaf_cert(openssl: &Path, dir: &Path) -> (PathBuf, PathBuf) {
        let key = dir.join("leaf.key");
        let crt = dir.join("leaf.crt");
        run(
            openssl,
            &[
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-out",
                key.to_str().unwrap(),
            ],
        );
        run(
            openssl,
            &[
                "req",
                "-x509",
                "-new",
                "-key",
                key.to_str().unwrap(),
                "-days",
                "3650",
                "-subj",
                "/CN=leaf",
                "-addext",
                "basicConstraints=critical,CA:FALSE",
                "-out",
                crt.to_str().unwrap(),
            ],
        );
        set_0600(&key);
        (crt, key)
    }

    fn run(openssl: &Path, args: &[&str]) {
        let o = Command::new(openssl).args(args).output().unwrap();
        assert!(
            o.status.success(),
            "openssl {args:?}: {}",
            String::from_utf8_lossy(&o.stderr)
        );
    }

    #[cfg(unix)]
    fn set_0600(p: &Path) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    #[cfg(not(unix))]
    fn set_0600(_p: &Path) {}
}
