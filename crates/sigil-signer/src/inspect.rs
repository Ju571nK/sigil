//! Pretty-print metadata of a signed envelope file (no signature check).

use anyhow::{Context, Result};
use sigil_core::policy::signed_envelope::SignedPolicyResponse;
use std::path::Path;

pub struct InspectReport {
    pub signing_pubkey_id: String,
    pub policy_version: i64,
    pub valid_until: time::OffsetDateTime,
    pub issued_at: time::OffsetDateTime,
    pub applied_at: time::OffsetDateTime,
    pub etag: String,
    pub policy_bytes_len: usize,
    pub signature_b64_len: usize,
}

pub fn inspect_file(path: &Path) -> Result<InspectReport> {
    let bytes =
        std::fs::read(path).with_context(|| format!("read signed file {}", path.display()))?;
    let r: SignedPolicyResponse = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse signed json {}", path.display()))?;
    let policy_bytes_len = data_encoding::BASE64
        .decode(r.signed_envelope.policy_bytes_b64.as_bytes())
        .map(|b| b.len())
        .unwrap_or(0);
    Ok(InspectReport {
        signing_pubkey_id: r.signing_pubkey_id,
        policy_version: r.signed_envelope.policy_version,
        valid_until: r.signed_envelope.valid_until,
        issued_at: r.signed_envelope.issued_at,
        applied_at: r.applied_at,
        etag: r.etag,
        policy_bytes_len,
        signature_b64_len: r.signature.len(),
    })
}

pub fn print_report(report: &InspectReport) {
    println!("signing_pubkey_id : {}", report.signing_pubkey_id);
    println!("policy_version    : {}", report.policy_version);
    println!("valid_until       : {}", report.valid_until);
    println!("issued_at         : {}", report.issued_at);
    println!("applied_at        : {}", report.applied_at);
    println!("etag              : {}", report.etag);
    println!(
        "policy_bytes      : {} bytes (decoded)",
        report.policy_bytes_len
    );
    println!("signature_b64     : {} chars", report.signature_b64_len);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::keygen;
    use crate::sign::{sign_to_file, SignArgs};
    use tempfile::tempdir;
    use time::macros::datetime;

    #[test]
    fn inspect_reports_envelope_metadata() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("k.json");
        let key_file = keygen("k1", &key_path).unwrap();
        let yaml = dir.path().join("p.yaml");
        std::fs::write(&yaml, "version: 1\nfoo: bar\n").unwrap();
        let signed = dir.path().join("signed.json");
        sign_to_file(
            SignArgs {
                yaml_path: &yaml,
                key_file: &key_file,
                policy_version: 42,
                valid_until: datetime!(2027-06-15 0:00 UTC),
                now: datetime!(2026-05-15 0:00 UTC),
            },
            &signed,
        )
        .unwrap();

        let r = inspect_file(&signed).unwrap();
        assert_eq!(r.signing_pubkey_id, "k1");
        assert_eq!(r.policy_version, 42);
        assert_eq!(r.valid_until, datetime!(2027-06-15 0:00 UTC));
        assert_eq!(r.policy_bytes_len, b"version: 1\nfoo: bar\n".len());
    }
}
