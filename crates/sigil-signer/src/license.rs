//! Build + sign a `LicenseDocument` into a `SignedLicense` bundle.
//! Mirrors `sign.rs` (policy signing): build struct → canonical bytes →
//! ed25519 sign → base64. The vendor PRIVATE key comes from the SigningKeyFile
//! at `--key`; it is never embedded here.

use crate::keygen::SigningKeyFile;
use anyhow::{Context, Result};
use ed25519_dalek::Signer;
use rand_core::{OsRng, RngCore};
use sigil_core::license::{LicenseDocument, SignedLicense};
use sigil_core::policy::canonical::to_canonical_bytes;
use std::path::Path;
use time::OffsetDateTime;

pub struct LicenseArgs<'a> {
    pub key_file: &'a SigningKeyFile,
    pub customer_id: String,
    pub max_hosts: u32,
    pub valid_days: u32,
    /// Optional explicit id; auto-generated when None.
    pub license_id: Option<String>,
    pub now: OffsetDateTime,
}

/// Build the LicenseDocument and sign it. Signature covers
/// `to_canonical_bytes(&license)` — the SAME bytes `verify_license` checks.
pub fn build_and_sign(args: LicenseArgs<'_>) -> Result<SignedLicense> {
    let license_id = args
        .license_id
        .clone()
        .unwrap_or_else(|| generate_license_id(&args.customer_id, args.now));
    let license = LicenseDocument {
        license_id,
        customer_id: args.customer_id.clone(),
        max_hosts: args.max_hosts,
        issued_at: args.now,
        not_after: args.now + time::Duration::days(args.valid_days as i64),
    };
    let canonical = to_canonical_bytes(&license).context("canonicalize license")?;
    let sk = args.key_file.signing_key().context("decode signing key")?;
    let signature = sk.sign(&canonical);
    Ok(SignedLicense {
        license,
        signature: data_encoding::BASE64.encode(&signature.to_bytes()),
        signing_pubkey_id: args.key_file.id.clone(),
    })
}

/// Sign and write the JSON bundle to `out` (pretty). Mirrors sign::sign_to_file.
pub fn sign_to_file(args: LicenseArgs<'_>, out: &Path) -> Result<SignedLicense> {
    let signed = build_and_sign(args)?;
    let bytes = serde_json::to_vec_pretty(&signed).context("serialize signed license")?;
    if let Some(parent) = out.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create dir {}", parent.display()))?;
        }
    }
    std::fs::write(out, &bytes).with_context(|| format!("write {}", out.display()))?;
    Ok(signed)
}

/// `SIGIL-<year>-<CUST>-<rand6>`. CUST = customer_id uppercased, non-alnum
/// stripped, truncated to 12 (fallback "CUST"). rand6 = 6 chars [a-z0-9].
fn generate_license_id(customer_id: &str, now: OffsetDateTime) -> String {
    let cust: String = customer_id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .take(12)
        .collect();
    let cust = if cust.is_empty() { "CUST".to_string() } else { cust };
    format!("SIGIL-{}-{}-{}", now.year(), cust, random_suffix())
}

fn random_suffix() -> String {
    // Non-cryptographic id suffix; modulo bias is irrelevant here (the
    // signature, not the id, is what authenticates a license).
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut bytes = [0u8; 6];
    OsRng.fill_bytes(&mut bytes);
    bytes
        .iter()
        .map(|b| CHARS[(*b as usize) % CHARS.len()] as char)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::keygen;
    use sigil_core::license::verify_license_allow_expired_with_keys;
    use time::macros::datetime;

    fn args_for<'a>(kf: &'a SigningKeyFile, now: OffsetDateTime) -> LicenseArgs<'a> {
        LicenseArgs {
            key_file: kf,
            customer_id: "ACME".into(),
            max_hosts: 1000,
            valid_days: 365,
            license_id: None,
            now,
        }
    }

    #[test]
    fn signed_license_verifies_with_matching_pubkey() {
        let dir = tempfile::tempdir().unwrap();
        let kf = keygen("sigil-license-2026", &dir.path().join("vendor.key")).unwrap();
        let now = datetime!(2026-06-01 0:00 UTC);
        let signed = build_and_sign(args_for(&kf, now)).unwrap();

        // Verifier expects "ed25519:<base64>" entries keyed by id.
        let entry = format!("ed25519:{}", kf.ed25519_pubkey_b64);
        let keys = [(kf.id.as_str(), entry.as_str())];
        let (doc, expired) =
            verify_license_allow_expired_with_keys(&signed, now, &keys).unwrap();
        assert!(!expired);
        assert_eq!(doc.customer_id, "ACME");
        assert_eq!(doc.max_hosts, 1000);
    }

    #[test]
    fn signing_pubkey_id_is_key_file_id() {
        let dir = tempfile::tempdir().unwrap();
        let kf = keygen("sigil-license-2026", &dir.path().join("vendor.key")).unwrap();
        let now = datetime!(2026-06-01 0:00 UTC);
        let signed = build_and_sign(args_for(&kf, now)).unwrap();
        assert_eq!(signed.signing_pubkey_id, "sigil-license-2026");
    }

    #[test]
    fn not_after_is_now_plus_valid_days() {
        let dir = tempfile::tempdir().unwrap();
        let kf = keygen("k", &dir.path().join("vendor.key")).unwrap();
        let now = datetime!(2026-06-01 0:00 UTC);
        let signed = build_and_sign(args_for(&kf, now)).unwrap();
        assert_eq!(signed.license.not_after, now + time::Duration::days(365));
    }

    #[test]
    fn auto_license_id_matches_format() {
        let id = generate_license_id("ACME", datetime!(2026-06-01 0:00 UTC));
        assert!(id.starts_with("SIGIL-2026-ACME-"), "got: {id}");
        let parts: Vec<&str> = id.split('-').collect();
        assert_eq!(parts.len(), 4, "got: {id}");
        assert_eq!(parts[0], "SIGIL");
        let suffix = parts[3];
        assert_eq!(suffix.len(), 6, "got: {id}");
        assert!(
            suffix.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()),
            "got: {id}"
        );
    }

    #[test]
    fn empty_customer_id_falls_back_to_cust() {
        let id = generate_license_id("!!!", datetime!(2026-06-01 0:00 UTC));
        assert!(id.starts_with("SIGIL-2026-CUST-"), "got: {id}");
    }

    #[test]
    fn explicit_license_id_passes_through() {
        let dir = tempfile::tempdir().unwrap();
        let kf = keygen("k", &dir.path().join("vendor.key")).unwrap();
        let now = datetime!(2026-06-01 0:00 UTC);
        let mut a = args_for(&kf, now);
        a.license_id = Some("SIGIL-2026-ACME-zzzzzz".into());
        let signed = build_and_sign(a).unwrap();
        assert_eq!(signed.license.license_id, "SIGIL-2026-ACME-zzzzzz");
    }

    #[test]
    fn sign_to_file_round_trips_from_disk() {
        let dir = tempfile::tempdir().unwrap();
        let kf = keygen("k", &dir.path().join("vendor.key")).unwrap();
        let now = datetime!(2026-06-01 0:00 UTC);
        let out = dir.path().join("acme.license.json");
        let signed = sign_to_file(args_for(&kf, now), &out).unwrap();
        let from_disk: SignedLicense =
            serde_json::from_slice(&std::fs::read(&out).unwrap()).unwrap();
        assert_eq!(from_disk, signed);
    }
}
