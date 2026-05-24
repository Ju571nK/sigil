//! Phase 3c — vendor-signed build manifest 검증. license 의 sibling: 같은
//! ed25519 + RFC 8785 canonical-JSON primitive 를 쓰고, trust anchor 는
//! 컴파일드인 SIGIL_BUILD_PUBKEYS (이 slice 는 빈 채로 ship).

use crate::policy::canonical::to_canonical_bytes;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use time::OffsetDateTime;

/// 이 interpreter 가 지원하는 manifest 포맷 버전.
pub const MANIFEST_SCHEMA_VERSION: u8 = 1;

/// 컴파일드인 vendor trust anchor — PUBLIC 키만. 이 slice 는 빈 채 ship.
/// `(key_id, "ed25519:<base64 pubkey>")`.
pub const SIGIL_BUILD_PUBKEYS: &[(&str, &str)] = &[];

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ArtifactEntry {
    pub name: String,
    pub target: String,
    pub blake3: String, // 소문자 64-char hex
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BuildManifest {
    pub schema_version: u8,
    pub git_sha: String,
    pub run_url: String,
    #[serde(with = "time::serde::rfc3339")]
    pub built_at: OffsetDateTime,
    pub artifacts: Vec<ArtifactEntry>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SignedBuildManifest {
    pub manifest: BuildManifest,
    /// ed25519 signature over to_canonical_bytes(&manifest), base64.
    pub signature: String,
    pub signing_pubkey_id: String,
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum ManifestError {
    #[error("signature verification failed")]
    BadSignature,
    #[error("unknown or unlisted signing key id: {0}")]
    UnknownKey(String),
    #[error("malformed manifest: {0}")]
    Malformed(String),
}

impl BuildManifest {
    /// (name,target) 매칭 entry. verify 가 중복을 거부하므로 first-match 로 충분.
    pub fn artifact(&self, name: &str, target: &str) -> Option<&ArtifactEntry> {
        self.artifacts.iter().find(|a| a.name == name && a.target == target)
    }
}

/// license::parse_vendor_key 와 동일 로직(그쪽은 private 이라 import 불가 — 복제).
fn parse_build_key(entry: &str) -> Option<ed25519_dalek::VerifyingKey> {
    let b64 = entry.strip_prefix("ed25519:")?;
    let bytes = data_encoding::BASE64.decode(b64.as_bytes()).ok()?;
    let arr: [u8; 32] = bytes.try_into().ok()?;
    ed25519_dalek::VerifyingKey::from_bytes(&arr).ok()
}

fn is_lower_hex_64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// 컴파일드인 SIGIL_BUILD_PUBKEYS 로 검증. anchor 가 비어있으면 항상 UnknownKey.
pub fn verify_manifest(signed: &SignedBuildManifest) -> Result<BuildManifest, ManifestError> {
    verify_manifest_with_keys(signed, SIGIL_BUILD_PUBKEYS)
}

/// 명시 keyset 으로 검증(테스트/커스텀 trust anchor). owned manifest 반환.
pub fn verify_manifest_with_keys(
    signed: &SignedBuildManifest,
    keys: &[(&str, &str)],
) -> Result<BuildManifest, ManifestError> {
    use ed25519_dalek::{Signature, Verifier};
    let m = &signed.manifest;

    if m.schema_version != MANIFEST_SCHEMA_VERSION {
        return Err(ManifestError::Malformed(format!(
            "unsupported schema_version {}", m.schema_version
        )));
    }
    let mut seen: HashSet<(&str, &str)> = HashSet::new();
    for a in &m.artifacts {
        if !is_lower_hex_64(&a.blake3) {
            return Err(ManifestError::Malformed(format!(
                "artifact {}/{}: blake3 not lowercase 64-hex", a.name, a.target
            )));
        }
        if !seen.insert((a.name.as_str(), a.target.as_str())) {
            return Err(ManifestError::Malformed(format!(
                "duplicate artifact entry {}/{}", a.name, a.target
            )));
        }
    }
    let key_entry = keys
        .iter()
        .find(|(id, _)| *id == signed.signing_pubkey_id)
        .ok_or_else(|| ManifestError::UnknownKey(signed.signing_pubkey_id.clone()))?;
    let vk = parse_build_key(key_entry.1)
        .ok_or_else(|| ManifestError::Malformed("build key unparseable".into()))?;
    let sig_bytes = data_encoding::BASE64
        .decode(signed.signature.as_bytes())
        .map_err(|_| ManifestError::BadSignature)?;
    let arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| ManifestError::BadSignature)?;
    let sig = Signature::from_bytes(&arr);
    let canonical = to_canonical_bytes(m).map_err(|e| ManifestError::Malformed(e.to_string()))?;
    if vk.verify(&canonical, &sig).is_err() {
        return Err(ManifestError::BadSignature);
    }
    Ok(m.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::{OsRng, RngCore};
    use time::macros::datetime;

    fn test_keypair() -> (SigningKey, String) {
        let mut secret = [0u8; 32];
        OsRng.fill_bytes(&mut secret);
        let sk = SigningKey::from_bytes(&secret);
        let entry = format!("ed25519:{}", data_encoding::BASE64.encode(&sk.verifying_key().to_bytes()));
        (sk, entry)
    }
    fn manifest_with(artifacts: Vec<ArtifactEntry>) -> BuildManifest {
        BuildManifest {
            schema_version: MANIFEST_SCHEMA_VERSION,
            git_sha: "abc123".into(),
            run_url: "https://ci/run/1".into(),
            built_at: datetime!(2026-05-24 0:00 UTC),
            artifacts,
        }
    }
    fn entry(name: &str) -> ArtifactEntry {
        ArtifactEntry { name: name.into(), target: "x86_64-apple-darwin".into(), blake3: "a".repeat(64) }
    }
    fn sign(sk: &SigningKey, id: &str, m: BuildManifest) -> SignedBuildManifest {
        let canonical = to_canonical_bytes(&m).unwrap();
        let sig = sk.sign(&canonical);
        SignedBuildManifest { manifest: m, signature: data_encoding::BASE64.encode(&sig.to_bytes()), signing_pubkey_id: id.into() }
    }

    #[test]
    fn valid_manifest_verifies() {
        let (sk, e) = test_keypair();
        let keys = [("bk1", e.as_str())];
        let signed = sign(&sk, "bk1", manifest_with(vec![entry("sigil")]));
        let got = verify_manifest_with_keys(&signed, &keys).unwrap();
        assert_eq!(got.artifacts[0].name, "sigil");
    }
    #[test]
    fn tampered_payload_is_bad_signature() {
        let (sk, e) = test_keypair();
        let keys = [("bk1", e.as_str())];
        let mut signed = sign(&sk, "bk1", manifest_with(vec![entry("sigil")]));
        signed.manifest.git_sha = "deadbeef".into();
        assert_eq!(verify_manifest_with_keys(&signed, &keys).unwrap_err(), ManifestError::BadSignature);
    }
    #[test]
    fn unknown_key_id() {
        let (sk, e) = test_keypair();
        let keys = [("other", e.as_str())];
        let signed = sign(&sk, "bk1", manifest_with(vec![entry("sigil")]));
        assert!(matches!(verify_manifest_with_keys(&signed, &keys).unwrap_err(), ManifestError::UnknownKey(_)));
    }
    #[test]
    fn bad_schema_version_is_malformed() {
        let (sk, e) = test_keypair();
        let keys = [("bk1", e.as_str())];
        let mut m = manifest_with(vec![entry("sigil")]);
        m.schema_version = 99;
        let signed = sign(&sk, "bk1", m);
        assert!(matches!(verify_manifest_with_keys(&signed, &keys).unwrap_err(), ManifestError::Malformed(_)));
    }
    #[test]
    fn bad_hex_is_malformed() {
        let (sk, e) = test_keypair();
        let keys = [("bk1", e.as_str())];
        let mut bad = entry("sigil"); bad.blake3 = "XYZ".into();
        let signed = sign(&sk, "bk1", manifest_with(vec![bad]));
        assert!(matches!(verify_manifest_with_keys(&signed, &keys).unwrap_err(), ManifestError::Malformed(_)));
    }
    #[test]
    fn duplicate_entry_is_malformed() {
        let (sk, e) = test_keypair();
        let keys = [("bk1", e.as_str())];
        let signed = sign(&sk, "bk1", manifest_with(vec![entry("sigil"), entry("sigil")]));
        assert!(matches!(verify_manifest_with_keys(&signed, &keys).unwrap_err(), ManifestError::Malformed(_)));
    }
    #[test]
    fn artifact_lookup_hit_and_miss() {
        let m = manifest_with(vec![entry("sigil")]);
        assert!(m.artifact("sigil", "x86_64-apple-darwin").is_some());
        assert!(m.artifact("sigil", "aarch64-unknown-linux-gnu").is_none());
        assert!(m.artifact("sigil-sender", "x86_64-apple-darwin").is_none());
    }
    #[test]
    fn empty_anchor_yields_unknown_key() {
        let (sk, _e) = test_keypair();
        let signed = sign(&sk, "bk1", manifest_with(vec![entry("sigil")]));
        assert!(matches!(verify_manifest_with_keys(&signed, &[]).unwrap_err(), ManifestError::UnknownKey(_)));
    }
}
