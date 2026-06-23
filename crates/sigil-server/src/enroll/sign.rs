//! #184 — CSR signing via `openssl` shell-out (argv only, never a shell string).
//!
//! The operator-provided intermediate CA signs the host CSR. We do NOT trust
//! the CSR's extensions: a FIXED profile ext file pins `CA:FALSE`, clientAuth
//! EKU, `digitalSignature,keyEncipherment` keyUsage and an explicit
//! `subjectAltName=DNS:<host_id>`. `-copy_extensions` is never passed (default
//! is no-copy). Serial is a random 128-bit value via `-set_serial` (no `.srl`
//! file → no serial race / symlink games). After signing we RE-PARSE the issued
//! cert and reject (no cert returned) on CA:TRUE, serverAuth EKU, any SAN other
//! than the host_id, or unexpected critical extensions.
//!
//! `openssl` is resolved to an absolute path once at boot; signing runs with a
//! controlled env (`OPENSSL_CONF` cleared) so a hostile config can't redirect
//! the profile. All temp files live in a private 0700 dir with 0600 files
//! (tempfile), cleaned up on every exit path (Drop).

use rand_core::{OsRng, RngCore};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

/// CSR PEM size cap (defense against oversized untrusted input).
pub const MAX_CSR_BYTES: usize = 16 * 1024;

#[derive(Debug)]
pub enum SignError {
    Io(std::io::Error),
    /// openssl ran but rejected/failed; carries stderr for internal logging.
    Openssl(String),
    /// CSR is malformed / too large / no CN — maps to 400 externally.
    BadCsr(String),
    /// The ISSUED cert failed post-sign inspection — maps to 500 (no cert out).
    BadIssued(String),
}

impl std::fmt::Display for SignError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignError::Io(e) => write!(f, "io: {e}"),
            SignError::Openssl(s) => write!(f, "openssl: {s}"),
            SignError::BadCsr(s) => write!(f, "bad csr: {s}"),
            SignError::BadIssued(s) => write!(f, "bad issued cert: {s}"),
        }
    }
}

/// Resolve the absolute path to `openssl` once (PATH lookup). `None` ⇒ openssl
/// not found; the caller disables enrollment. Done at boot so request-time
/// signing never consults `$PATH` (no PATH-hijack window).
pub fn resolve_openssl() -> Option<PathBuf> {
    // Probe candidates: explicit common locations first, then a `version` run.
    for cand in [
        "/usr/bin/openssl",
        "/opt/homebrew/bin/openssl",
        "/usr/local/bin/openssl",
    ] {
        let p = Path::new(cand);
        if p.is_file() {
            return Some(p.to_path_buf());
        }
    }
    // Fall back to PATH resolution via a controlled `openssl version` probe.
    // `which`-style: ask the shell-free Command if a bare `openssl` runs.
    match Command::new("openssl").arg("version").output() {
        Ok(o) if o.status.success() => Some(PathBuf::from("openssl")),
        _ => None,
    }
}

/// Build a Command for openssl with a controlled environment: clear
/// `OPENSSL_CONF` so a hostile/leftover config can't inject extensions or
/// redirect the engine. argv only — never a shell string.
fn openssl_cmd(openssl: &Path) -> Command {
    let mut c = Command::new(openssl);
    c.env_remove("OPENSSL_CONF");
    c
}

/// Extract + validate the CSR subject CN. `openssl req -verify` is the
/// trusted-input parse boundary; we also size-cap and PEM-header check first.
pub fn csr_cn(openssl: &Path, csr_pem: &str) -> Result<String, SignError> {
    if csr_pem.len() > MAX_CSR_BYTES {
        return Err(SignError::BadCsr("csr too large".into()));
    }
    if !csr_pem.contains("BEGIN CERTIFICATE REQUEST") {
        return Err(SignError::BadCsr("not a PEM CSR".into()));
    }
    let dir = private_tempdir().map_err(SignError::Io)?;
    let p = dir.path().join("c.csr");
    write_0600(&p, csr_pem.as_bytes())?;
    let out = openssl_cmd(openssl)
        .arg("req")
        .arg("-in")
        .arg(&p)
        .args(["-noout", "-subject", "-verify"])
        .output()
        .map_err(SignError::Io)?;
    if !out.status.success() {
        return Err(SignError::BadCsr("openssl rejected csr".into()));
    }
    let s = String::from_utf8_lossy(&out.stdout);
    extract_cn(&s).ok_or_else(|| SignError::BadCsr("no CN in subject".into()))
}

/// Sign the CSR with the intermediate CA, enforcing a fixed client-cert
/// profile pinned to `host_id`. Returns the leaf cert PEM. Post-sign
/// inspection rejects any deviation (CA:TRUE / serverAuth / extra SAN).
pub fn sign_csr(
    openssl: &Path,
    ca_cert: &Path,
    ca_key: &Path,
    csr_pem: &str,
    host_id: &str,
    days: u32,
) -> Result<String, SignError> {
    if csr_pem.len() > MAX_CSR_BYTES {
        return Err(SignError::BadCsr("csr too large".into()));
    }
    let dir = private_tempdir().map_err(SignError::Io)?;
    let csr = dir.path().join("c.csr");
    let ext = dir.path().join("c.ext");
    let out = dir.path().join("c.crt");
    write_0600(&csr, csr_pem.as_bytes())?;
    // Explicit SAN pinned to host_id; no wildcards, no copy_extensions.
    let ext_body = format!(
        "basicConstraints=critical,CA:FALSE\n\
         keyUsage=critical,digitalSignature,keyEncipherment\n\
         extendedKeyUsage=clientAuth\n\
         subjectAltName=DNS:{host_id}\n"
    );
    write_0600(&ext, ext_body.as_bytes())?;

    let serial = random_serial_hex();
    let st = openssl_cmd(openssl)
        .arg("x509")
        .arg("-req")
        .arg("-in")
        .arg(&csr)
        .arg("-CA")
        .arg(ca_cert)
        .arg("-CAkey")
        .arg(ca_key)
        .arg("-set_serial")
        .arg(format!("0x{serial}"))
        .args(["-days", &days.to_string()])
        .arg("-extfile")
        .arg(&ext)
        .arg("-out")
        .arg(&out)
        .output()
        .map_err(SignError::Io)?;
    if !st.status.success() {
        return Err(SignError::Openssl(
            String::from_utf8_lossy(&st.stderr).into_owned(),
        ));
    }
    let cert = std::fs::read_to_string(&out).map_err(SignError::Io)?;
    inspect_issued(openssl, &cert, host_id)?;
    Ok(cert)
}

/// Re-parse the issued cert (`openssl x509 -text`) and reject any deviation
/// from the intended client-cert profile. Fail-closed: any parse failure ⇒
/// reject.
fn inspect_issued(openssl: &Path, cert_pem: &str, host_id: &str) -> Result<(), SignError> {
    let dir = private_tempdir().map_err(SignError::Io)?;
    let p = dir.path().join("issued.crt");
    write_0600(&p, cert_pem.as_bytes())?;
    let out = openssl_cmd(openssl)
        .arg("x509")
        .arg("-in")
        .arg(&p)
        .args(["-noout", "-text"])
        .output()
        .map_err(SignError::Io)?;
    if !out.status.success() {
        return Err(SignError::BadIssued("could not parse issued cert".into()));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let lc = text.to_lowercase();
    // basicConstraints CA must be FALSE.
    if lc.contains("ca:true") {
        return Err(SignError::BadIssued("issued cert is a CA".into()));
    }
    // No serverAuth EKU.
    if lc.contains("tls web server authentication") || lc.contains("serverauth") {
        return Err(SignError::BadIssued(
            "issued cert has serverAuth EKU".into(),
        ));
    }
    // clientAuth EKU must be present.
    if !(lc.contains("tls web client authentication") || lc.contains("clientauth")) {
        return Err(SignError::BadIssued(
            "issued cert missing clientAuth EKU".into(),
        ));
    }
    // fix D: a SAN section MUST be present and contain EXACTLY one entry,
    // `DNS:<host_id>` (case-insensitive). Modern verifiers key on the SAN, so a
    // no-SAN or multi-SAN cert is rejected fail-closed.
    let sans = extract_san_entries(&text)
        .ok_or_else(|| SignError::BadIssued("issued cert has no SAN".into()))?;
    if sans.len() != 1 {
        return Err(SignError::BadIssued(format!(
            "issued cert SAN must have exactly one entry, got {}",
            sans.len()
        )));
    }
    let host_lc = host_id.to_lowercase();
    let e = sans[0].trim();
    let dns = e
        .strip_prefix("DNS:")
        .map(|s| s.to_lowercase())
        .unwrap_or_default();
    if dns != host_lc {
        return Err(SignError::BadIssued(format!("unexpected SAN entry: {e}")));
    }
    Ok(())
}

/// Derive (serial_hex, not_after_rfc-ish) from the ISSUED cert by re-parsing it
/// with openssl (`-serial`, `-enddate`). Best-effort: empty strings on failure
/// (the cert was already validated by `sign_csr`'s inspection). Values are taken
/// from the issued cert, never assumed.
pub fn issued_meta(openssl: &Path, cert_pem: &str) -> (String, String) {
    let Ok(dir) = private_tempdir() else {
        return (String::new(), String::new());
    };
    let p = dir.path().join("issued.crt");
    if write_0600(&p, cert_pem.as_bytes()).is_err() {
        return (String::new(), String::new());
    }
    let serial = openssl_cmd(openssl)
        .arg("x509")
        .arg("-in")
        .arg(&p)
        .args(["-noout", "-serial"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .trim()
                .strip_prefix("serial=")
                .unwrap_or("")
                .to_string()
        })
        .unwrap_or_default();
    let not_after = openssl_cmd(openssl)
        .arg("x509")
        .arg("-in")
        .arg(&p)
        .args(["-noout", "-enddate"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .trim()
                .strip_prefix("notAfter=")
                .unwrap_or("")
                .to_string()
        })
        .unwrap_or_default();
    (serial, not_after)
}

/// Parse the `X509v3 Subject Alternative Name:` value into ALL entries.
///
/// The value follows the header on one or more indented continuation lines and
/// may contain multiple comma-separated entries (e.g. `DNS:a, DNS:b`). We collect
/// every continuation line (more-indented than the header) until the next
/// extension header / less-indented line, then split on commas. Returning only
/// the first line (the old bug) let a wrapped/extra entry like `DNS:evil` slip
/// past the post-sign SAN check. Returns `None` only if no SAN header is found.
fn extract_san_entries(text: &str) -> Option<Vec<String>> {
    let lines: Vec<&str> = text.lines().collect();
    let mut i = 0;
    while i < lines.len() {
        if lines[i].contains("Subject Alternative Name") {
            let header_indent = indent_of(lines[i]);
            let mut value = String::new();
            let mut j = i + 1;
            while j < lines.len() {
                let line = lines[j];
                // A blank or less/equally-indented line ends the SAN value
                // (next extension or section). Continuation lines are strictly
                // more indented than the header.
                if line.trim().is_empty() || indent_of(line) <= header_indent {
                    break;
                }
                if !value.is_empty() {
                    value.push(',');
                }
                value.push_str(line.trim());
                j += 1;
            }
            return Some(
                value
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect(),
            );
        }
        i += 1;
    }
    None
}

/// Number of leading whitespace chars (openssl indents extension values).
fn indent_of(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

/// 128-bit random serial as lowercase hex (no leading `0x`). Top bit cleared so
/// the DER INTEGER is unambiguously positive regardless of openssl handling.
fn random_serial_hex() -> String {
    let mut b = [0u8; 16];
    OsRng.fill_bytes(&mut b);
    b[0] &= 0x7f;
    b[0] |= 0x40; // ensure non-zero high byte → stable 16-byte serial
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// A private 0700 temp dir (tempfile picks an unpredictable name with O_EXCL).
fn private_tempdir() -> std::io::Result<tempfile::TempDir> {
    let d = tempfile::Builder::new().prefix("sigil-enroll-").tempdir()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700));
    }
    Ok(d)
}

fn write_0600(p: &Path, b: &[u8]) -> Result<(), SignError> {
    let mut f = std::fs::File::create(p).map_err(SignError::Io)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = f.set_permissions(std::fs::Permissions::from_mode(0o600));
    }
    f.write_all(b).map_err(SignError::Io)?;
    f.flush().map_err(SignError::Io)
}

fn extract_cn(output: &str) -> Option<String> {
    // `openssl req -noout -subject -verify` mixes the verify status message
    // with the subject line, and which STREAM the verify message lands on is
    // version-dependent: OpenSSL 3.5.1 prints "Certificate request
    // self-signature verify OK" to STDOUT (ahead of the subject), while other
    // builds send it to stderr. So scan all lines for the `subject=` line
    // specifically rather than assuming stdout begins with it.
    // Subject formats also vary:
    //   "subject=/C=US/CN=host-1"   (legacy, slash-separated)
    //   "subject=CN=host-1"         (3.x, no leading slash)
    //   "subject=CN = host-1"       (3.x with spaces)
    let line = output
        .lines()
        .map(str::trim)
        .find(|l| l.starts_with("subject="))?;
    let body = line.strip_prefix("subject=").unwrap_or(line).trim();
    body.split([',', '/'])
        .find_map(|f| {
            let f = f.trim();
            // Accept "CN=v" and "CN = v" (split key/value on the first '=').
            let (k, v) = f.split_once('=')?;
            if k.trim() == "CN" {
                Some(v.trim().to_string())
            } else {
                None
            }
        })
        .filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn openssl() -> PathBuf {
        resolve_openssl().expect("openssl must be installed for enroll tests")
    }

    /// Build a self-signed intermediate-style CA (CA:TRUE) at <dir>/ca.crt + ca.key.
    fn make_ca(dir: &Path) -> (PathBuf, PathBuf) {
        let key = dir.join("ca.key");
        let crt = dir.join("ca.crt");
        let ssl = openssl();
        let st = Command::new(&ssl)
            .args([
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-out",
            ])
            .arg(&key)
            .output()
            .unwrap();
        assert!(
            st.status.success(),
            "genpkey: {}",
            String::from_utf8_lossy(&st.stderr)
        );
        let st = Command::new(&ssl)
            .args(["req", "-x509", "-new", "-key"])
            .arg(&key)
            .args([
                "-days",
                "3650",
                "-subj",
                "/CN=test-int-ca",
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-out",
            ])
            .arg(&crt)
            .output()
            .unwrap();
        assert!(
            st.status.success(),
            "req x509: {}",
            String::from_utf8_lossy(&st.stderr)
        );
        (crt, key)
    }

    /// Generate a host key + CSR with the given CN. Returns the CSR PEM string.
    fn make_csr(dir: &Path, cn: &str) -> String {
        let key = dir.join("host.key");
        let csr = dir.join("host.csr");
        let ssl = openssl();
        let st = Command::new(&ssl)
            .args([
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-out",
            ])
            .arg(&key)
            .output()
            .unwrap();
        assert!(st.status.success());
        let st = Command::new(&ssl)
            .args(["req", "-new", "-key"])
            .arg(&key)
            .args(["-subj", &format!("/CN={cn}"), "-out"])
            .arg(&csr)
            .output()
            .unwrap();
        assert!(
            st.status.success(),
            "req new: {}",
            String::from_utf8_lossy(&st.stderr)
        );
        std::fs::read_to_string(&csr).unwrap()
    }

    fn openssl_verify(dir: &Path, ca: &Path, leaf_pem: &str) -> bool {
        let leaf = dir.join("leaf.crt");
        std::fs::write(&leaf, leaf_pem).unwrap();
        let st = Command::new(openssl())
            .arg("verify")
            .arg("-CAfile")
            .arg(ca)
            .arg(&leaf)
            .output()
            .unwrap();
        st.status.success()
    }

    fn cert_has_client_auth(dir: &Path, leaf_pem: &str) -> bool {
        let leaf = dir.join("leaf2.crt");
        std::fs::write(&leaf, leaf_pem).unwrap();
        let out = Command::new(openssl())
            .arg("x509")
            .arg("-in")
            .arg(&leaf)
            .args(["-noout", "-text"])
            .output()
            .unwrap();
        let t = String::from_utf8_lossy(&out.stdout).to_lowercase();
        t.contains("tls web client authentication")
    }

    #[test]
    fn sign_csr_produces_clientauth_cert_for_cn() {
        let d = tempfile::tempdir().unwrap();
        let ssl = openssl();
        let (ca_cert, ca_key) = make_ca(d.path());
        let csr = make_csr(d.path(), "host-1");
        let cn = csr_cn(&ssl, &csr).unwrap();
        assert_eq!(cn, "host-1");
        let cert = sign_csr(&ssl, &ca_cert, &ca_key, &csr, "host-1", 30).unwrap();
        assert!(cert.contains("BEGIN CERTIFICATE"));
        assert!(
            openssl_verify(d.path(), &ca_cert, &cert),
            "leaf must verify vs CA"
        );
        assert!(
            cert_has_client_auth(d.path(), &cert),
            "must have clientAuth EKU"
        );
    }

    #[test]
    fn csr_cn_rejects_non_pem() {
        let ssl = openssl();
        assert!(matches!(
            csr_cn(&ssl, "not a csr"),
            Err(SignError::BadCsr(_))
        ));
    }

    #[test]
    fn csr_cn_rejects_oversize() {
        let ssl = openssl();
        let big = format!(
            "-----BEGIN CERTIFICATE REQUEST-----\n{}",
            "A".repeat(MAX_CSR_BYTES + 1)
        );
        assert!(matches!(csr_cn(&ssl, &big), Err(SignError::BadCsr(_))));
    }

    #[test]
    fn random_serial_is_16_bytes_positive() {
        let s = random_serial_hex();
        assert_eq!(s.len(), 32, "16 bytes => 32 hex chars");
        let first = u8::from_str_radix(&s[0..2], 16).unwrap();
        assert!(first & 0x80 == 0, "top bit cleared (positive)");
        assert!(first != 0, "high byte non-zero");
    }

    // fix E: a single-line, single-entry SAN parses to exactly one entry.
    #[test]
    fn extract_san_single_entry() {
        let text = "        X509v3 extensions:\n\
                    \x20           X509v3 Subject Alternative Name: \n\
                    \x20               DNS:host-1\n\
                    \x20       Signature Algorithm: sha256WithRSAEncryption\n";
        let sans = extract_san_entries(text).expect("SAN present");
        assert_eq!(sans, vec!["DNS:host-1".to_string()]);
    }

    // fix E: two comma-separated entries on one value line are BOTH parsed, so
    // the fix-D check sees count != 1 and rejects.
    #[test]
    fn extract_san_multi_entry_same_line() {
        let text = "            X509v3 Subject Alternative Name: \n\
                    \x20               DNS:host-1, DNS:evil\n\
                    \x20       Signature Algorithm: x\n";
        let sans = extract_san_entries(text).expect("SAN present");
        assert_eq!(sans, vec!["DNS:host-1".to_string(), "DNS:evil".to_string()]);
    }

    // fix E: a second entry WRAPPED onto a continuation line is also collected.
    #[test]
    fn extract_san_multi_entry_wrapped() {
        let text = "            X509v3 Subject Alternative Name: \n\
                    \x20               DNS:host-1,\n\
                    \x20               DNS:evil\n\
                    \x20       Signature Algorithm: x\n";
        let sans = extract_san_entries(text).expect("SAN present");
        assert_eq!(sans, vec!["DNS:host-1".to_string(), "DNS:evil".to_string()]);
    }

    #[test]
    fn extract_san_absent_is_none() {
        let text = "        X509v3 extensions:\n\
                    \x20           X509v3 Basic Constraints: critical\n\
                    \x20               CA:FALSE\n";
        assert!(extract_san_entries(text).is_none());
    }

    // fix D + E end-to-end: an issued cert carrying TWO SANs (DNS:host_id +
    // DNS:evil) must be rejected, not pass because the first entry matched.
    #[test]
    fn inspect_issued_rejects_multi_san() {
        let d = tempfile::tempdir().unwrap();
        let ssl = openssl();
        let (ca_cert, ca_key) = make_ca(d.path());
        // Sign a cert with a hostile two-entry SAN using a raw ext file (bypasses
        // sign_csr's pinned single-SAN profile to simulate a CA that emitted two).
        let key = d.path().join("h.key");
        let csr = d.path().join("h.csr");
        let ext = d.path().join("h.ext");
        let crt = d.path().join("h.crt");
        Command::new(&ssl)
            .args([
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-out",
            ])
            .arg(&key)
            .output()
            .unwrap();
        Command::new(&ssl)
            .args(["req", "-new", "-key"])
            .arg(&key)
            .args(["-subj", "/CN=host-1", "-out"])
            .arg(&csr)
            .output()
            .unwrap();
        std::fs::write(
            &ext,
            "basicConstraints=critical,CA:FALSE\n\
             extendedKeyUsage=clientAuth\n\
             subjectAltName=DNS:host-1,DNS:evil\n",
        )
        .unwrap();
        let st = Command::new(&ssl)
            .args(["x509", "-req", "-in"])
            .arg(&csr)
            .arg("-CA")
            .arg(&ca_cert)
            .arg("-CAkey")
            .arg(&ca_key)
            .args(["-set_serial", "0x42", "-days", "30", "-extfile"])
            .arg(&ext)
            .arg("-out")
            .arg(&crt)
            .output()
            .unwrap();
        assert!(
            st.status.success(),
            "{}",
            String::from_utf8_lossy(&st.stderr)
        );
        let cert = std::fs::read_to_string(&crt).unwrap();
        let r = inspect_issued(&ssl, &cert, "host-1");
        assert!(
            matches!(r, Err(SignError::BadIssued(_))),
            "multi-SAN cert must be rejected, got {r:?}"
        );
    }

    // fix D: a cert with NO SAN must be rejected (modern verifiers require it).
    #[test]
    fn inspect_issued_rejects_no_san() {
        let d = tempfile::tempdir().unwrap();
        let ssl = openssl();
        let (ca_cert, ca_key) = make_ca(d.path());
        let key = d.path().join("n.key");
        let csr = d.path().join("n.csr");
        let ext = d.path().join("n.ext");
        let crt = d.path().join("n.crt");
        Command::new(&ssl)
            .args([
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-out",
            ])
            .arg(&key)
            .output()
            .unwrap();
        Command::new(&ssl)
            .args(["req", "-new", "-key"])
            .arg(&key)
            .args(["-subj", "/CN=host-1", "-out"])
            .arg(&csr)
            .output()
            .unwrap();
        // No subjectAltName in the ext file at all.
        std::fs::write(
            &ext,
            "basicConstraints=critical,CA:FALSE\nextendedKeyUsage=clientAuth\n",
        )
        .unwrap();
        let st = Command::new(&ssl)
            .args(["x509", "-req", "-in"])
            .arg(&csr)
            .arg("-CA")
            .arg(&ca_cert)
            .arg("-CAkey")
            .arg(&ca_key)
            .args(["-set_serial", "0x43", "-days", "30", "-extfile"])
            .arg(&ext)
            .arg("-out")
            .arg(&crt)
            .output()
            .unwrap();
        assert!(
            st.status.success(),
            "{}",
            String::from_utf8_lossy(&st.stderr)
        );
        let cert = std::fs::read_to_string(&crt).unwrap();
        let r = inspect_issued(&ssl, &cert, "host-1");
        assert!(
            matches!(r, Err(SignError::BadIssued(_))),
            "no-SAN cert must be rejected, got {r:?}"
        );
    }

    #[test]
    fn extract_cn_handles_variants() {
        assert_eq!(extract_cn("subject=CN=host-1").as_deref(), Some("host-1"));
        assert_eq!(extract_cn("subject=CN = host-2").as_deref(), Some("host-2"));
        assert_eq!(
            extract_cn("subject=/C=US/CN=host-3/O=acme").as_deref(),
            Some("host-3")
        );
        assert_eq!(extract_cn("subject=O=acme"), None);
        // OpenSSL 3.5.1 (Rocky 9): the `-verify` status prints to STDOUT ahead
        // of the subject line — the subject= line must still be found. Caught by
        // real-hardware enroll e2e.
        assert_eq!(
            extract_cn(
                "Certificate request self-signature verify OK\nsubject=CN=597ec667-b843-47dc-af1a-276dc547283e\n"
            )
            .as_deref(),
            Some("597ec667-b843-47dc-af1a-276dc547283e")
        );
    }
}
