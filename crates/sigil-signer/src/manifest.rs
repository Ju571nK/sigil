//! Build + sign a BuildManifest into a SignedBuildManifest. Mirrors license.rs:
//! per-artifact blake3 -> canonical bytes -> ed25519 sign -> base64.

use crate::keygen::SigningKeyFile;
use anyhow::{bail, Context, Result};
use ed25519_dalek::Signer;
use sigil_core::manifest::{ArtifactEntry, BuildManifest, SignedBuildManifest, MANIFEST_SCHEMA_VERSION};
use sigil_core::policy::canonical::to_canonical_bytes;
use std::path::{Path, PathBuf};
use time::OffsetDateTime;

pub struct ArtifactSpec {
    pub name: String,
    pub target: String,
    pub file: PathBuf,
}

pub struct ManifestArgs<'a> {
    pub key_file: &'a SigningKeyFile,
    pub git_sha: String,
    pub run_url: String,
    pub artifacts: Vec<ArtifactSpec>,
    pub now: OffsetDateTime,
}

/// "name=<n>,target=<t>,file=<p>" 1개를 ArtifactSpec 으로 파싱. 누락/미지 키는 에러.
pub fn parse_artifact_spec(s: &str) -> Result<ArtifactSpec> {
    let (mut name, mut target, mut file) = (None, None, None);
    for part in s.split(',') {
        let (k, v) = part
            .split_once('=')
            .with_context(|| format!("artifact spec part missing '=': {part}"))?;
        match k.trim() {
            "name" => name = Some(v.to_string()),
            "target" => target = Some(v.to_string()),
            "file" => file = Some(PathBuf::from(v)),
            other => bail!("unknown artifact key '{other}' (expected name/target/file)"),
        }
    }
    Ok(ArtifactSpec {
        name: name.context("artifact spec missing name=")?,
        target: target.context("artifact spec missing target=")?,
        file: file.context("artifact spec missing file=")?,
    })
}

pub fn build_and_sign(args: ManifestArgs<'_>) -> Result<SignedBuildManifest> {
    let mut artifacts = Vec::new();
    for spec in &args.artifacts {
        let bytes = std::fs::read(&spec.file)
            .with_context(|| format!("read artifact {}", spec.file.display()))?;
        artifacts.push(ArtifactEntry {
            name: spec.name.clone(),
            target: spec.target.clone(),
            blake3: blake3::hash(&bytes).to_hex().to_string(),
        });
    }
    let manifest = BuildManifest {
        schema_version: MANIFEST_SCHEMA_VERSION,
        git_sha: args.git_sha.clone(),
        run_url: args.run_url.clone(),
        built_at: args.now,
        artifacts,
    };
    let canonical = to_canonical_bytes(&manifest).context("canonicalize manifest")?;
    let sk = args.key_file.signing_key().context("decode signing key")?;
    let signature = sk.sign(&canonical);
    Ok(SignedBuildManifest {
        manifest,
        signature: data_encoding::BASE64.encode(&signature.to_bytes()),
        signing_pubkey_id: args.key_file.id.clone(),
    })
}

pub fn sign_to_file(args: ManifestArgs<'_>, out: &Path) -> Result<SignedBuildManifest> {
    let signed = build_and_sign(args)?;
    let bytes = serde_json::to_vec_pretty(&signed).context("serialize signed manifest")?;
    if let Some(parent) = out.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).with_context(|| format!("create dir {}", parent.display()))?;
        }
    }
    std::fs::write(out, &bytes).with_context(|| format!("write {}", out.display()))?;
    Ok(signed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::keygen;
    use sigil_core::manifest::verify_manifest_with_keys;
    use std::io::Write;
    use time::macros::datetime;

    fn tmpfile(dir: &Path, name: &str, body: &[u8]) -> PathBuf {
        let p = dir.join(name);
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(body).unwrap();
        p
    }

    #[test]
    fn signed_manifest_verifies_and_hashes_each_file() {
        let dir = tempfile::tempdir().unwrap();
        let kf = keygen("sigil-build-2026", &dir.path().join("build.key")).unwrap();
        let f1 = tmpfile(dir.path(), "sigil", b"binary-one");
        let args = ManifestArgs {
            key_file: &kf,
            git_sha: "abc123".into(),
            run_url: "https://ci/run/1".into(),
            artifacts: vec![ArtifactSpec { name: "sigil".into(), target: "x86_64-apple-darwin".into(), file: f1 }],
            now: datetime!(2026-05-24 0:00 UTC),
        };
        let signed = build_and_sign(args).unwrap();
        let expected = blake3::hash(b"binary-one").to_hex().to_string();
        assert_eq!(signed.manifest.artifacts[0].blake3, expected);
        assert_eq!(signed.signing_pubkey_id, "sigil-build-2026");
        let entry = format!("ed25519:{}", kf.ed25519_pubkey_b64);
        let keys = [(kf.id.as_str(), entry.as_str())];
        assert!(verify_manifest_with_keys(&signed, &keys).is_ok());
    }

    #[test]
    fn parse_artifact_spec_ok() {
        let s = parse_artifact_spec("name=sigil,target=x86_64-apple-darwin,file=/tmp/sigil").unwrap();
        assert_eq!(s.name, "sigil");
        assert_eq!(s.target, "x86_64-apple-darwin");
        assert_eq!(s.file, PathBuf::from("/tmp/sigil"));
    }
    #[test]
    fn parse_artifact_spec_missing_key_errors() {
        assert!(parse_artifact_spec("name=sigil,target=x").is_err());
        assert!(parse_artifact_spec("name=sigil,bogus=1,file=/x").is_err());
    }

    #[test]
    fn sign_to_file_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let kf = keygen("k", &dir.path().join("build.key")).unwrap();
        let f1 = tmpfile(dir.path(), "sigil", b"x");
        let out = dir.path().join("build-manifest.json");
        let args = ManifestArgs {
            key_file: &kf, git_sha: "s".into(), run_url: "".into(),
            artifacts: vec![ArtifactSpec { name: "sigil".into(), target: "t".into(), file: f1 }],
            now: datetime!(2026-05-24 0:00 UTC),
        };
        let signed = sign_to_file(args, &out).unwrap();
        let from_disk: SignedBuildManifest = serde_json::from_slice(&std::fs::read(&out).unwrap()).unwrap();
        assert_eq!(from_disk, signed);
    }
}
