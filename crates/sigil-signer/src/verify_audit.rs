//! `sigil-sign verify-audit`: independently verify a signed audit-chain file
//! against the OSS verifier in sigil-core. Authenticity requires the externally
//! observed pubkey (the file alone cannot establish trust in a key).

use anyhow::{anyhow, Context, Result};
use sigil_core::audit::{verify_chain, SignedAuditRecord};
use std::path::Path;

pub struct VerifyAuditArgs<'a> {
    pub file: &'a Path,
    pub pubkey: Option<String>,
    pub expect_head: Option<String>,
}

pub enum VerifyAuditOutcome {
    Ok {
        seq: u64,
        hash: String,
        pubkey_id: String,
        lines: usize,
        authenticity_checked: bool,
    },
    Failed(String),
}

fn parse_pubkey(entry: &str) -> Result<ed25519_dalek::VerifyingKey> {
    let b64 = entry
        .strip_prefix("ed25519:")
        .context("pubkey must start with ed25519:")?;
    let bytes = data_encoding::BASE64
        .decode(b64.as_bytes())
        .context("decode pubkey base64")?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("pubkey must be 32 bytes"))?;
    ed25519_dalek::VerifyingKey::from_bytes(&arr).context("parse ed25519 pubkey")
}

pub fn verify_audit(args: VerifyAuditArgs<'_>) -> Result<VerifyAuditOutcome> {
    let body = std::fs::read_to_string(args.file)
        .with_context(|| format!("read {}", args.file.display()))?;
    let mut lines = Vec::new();
    for (i, l) in body.lines().enumerate() {
        if l.trim().is_empty() {
            continue;
        }
        let rec: SignedAuditRecord = serde_json::from_str(l)
            .with_context(|| format!("parse line {} as SignedAuditRecord", i + 1))?;
        lines.push(rec);
    }
    let vk = match &args.pubkey {
        Some(p) => Some(parse_pubkey(p)?),
        None => None,
    };
    let authenticity_checked = vk.is_some();
    match verify_chain(&lines, vk.as_ref()) {
        Ok(head) => {
            if let Some(expected) = &args.expect_head {
                if &head.hash != expected {
                    return Ok(VerifyAuditOutcome::Failed(format!(
                        "head hash mismatch: computed {} != expected {}",
                        head.hash, expected
                    )));
                }
            }
            Ok(VerifyAuditOutcome::Ok {
                seq: head.seq,
                hash: head.hash,
                pubkey_id: head.pubkey_id,
                lines: lines.len(),
                authenticity_checked,
            })
        }
        Err(e) => Ok(VerifyAuditOutcome::Failed(e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::keygen;
    use sigil_core::audit::{sign_record, AuditRecord, GENESIS_PREV_HASH};

    fn rec(seq: u64, prev_hash: &str) -> AuditRecord {
        AuditRecord {
            v: 1,
            seq,
            ts: "2026-06-01T00:00:00Z".into(),
            state: "ok".into(),
            licensed: true,
            expired: false,
            effective_max_hosts: 1000,
            current_host_count: 10,
            active_window_days: 7,
            customer_id: Some("ACME".into()),
            license_id: Some("SIGIL-2026-ACME-a1b2c3".into()),
            server_version: "0.1.0".into(),
            prev_hash: prev_hash.into(),
        }
    }

    fn write_chain(dir: &std::path::Path) -> (std::path::PathBuf, String) {
        let kf = keygen("audit-test", &dir.join("audit.key")).unwrap();
        let sk = kf.signing_key().unwrap();
        let mut prev = GENESIS_PREV_HASH.to_string();
        let mut body = String::new();
        for seq in 0..2 {
            let signed = sign_record(rec(seq, &prev), &sk, &kf.id).unwrap();
            prev = signed.hash.clone();
            body.push_str(&serde_json::to_string(&signed).unwrap());
            body.push('\n');
        }
        let path = dir.join("license-audit.jsonl");
        std::fs::write(&path, body).unwrap();
        (path, format!("ed25519:{}", kf.ed25519_pubkey_b64))
    }

    #[test]
    fn happy_path_with_pubkey() {
        let dir = tempfile::tempdir().unwrap();
        let (path, pubkey) = write_chain(dir.path());
        let out = verify_audit(VerifyAuditArgs {
            file: &path,
            pubkey: Some(pubkey),
            expect_head: None,
        })
        .unwrap();
        match out {
            VerifyAuditOutcome::Ok {
                seq,
                lines,
                authenticity_checked,
                ..
            } => {
                assert_eq!(seq, 1);
                assert_eq!(lines, 2);
                assert!(authenticity_checked);
            }
            VerifyAuditOutcome::Failed(m) => panic!("expected Ok, got {m}"),
        }
    }

    #[test]
    fn tampered_file_fails() {
        let dir = tempfile::tempdir().unwrap();
        let (path, pubkey) = write_chain(dir.path());
        let mut body = std::fs::read_to_string(&path).unwrap();
        body = body.replacen("\"current_host_count\":10", "\"current_host_count\":11", 1);
        std::fs::write(&path, body).unwrap();
        let out = verify_audit(VerifyAuditArgs {
            file: &path,
            pubkey: Some(pubkey),
            expect_head: None,
        })
        .unwrap();
        assert!(matches!(out, VerifyAuditOutcome::Failed(_)));
    }

    #[test]
    fn expect_head_mismatch_fails() {
        let dir = tempfile::tempdir().unwrap();
        let (path, pubkey) = write_chain(dir.path());
        let out = verify_audit(VerifyAuditArgs {
            file: &path,
            pubkey: Some(pubkey),
            expect_head: Some("deadbeef".into()),
        })
        .unwrap();
        assert!(matches!(out, VerifyAuditOutcome::Failed(_)));
    }
}
