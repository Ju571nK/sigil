//! Targeted deployment v2 contract (#230). Verification is not activation.
//!
//! This module performs no I/O and never advances a watermark. Callers must
//! serialize verification with commit, compile the effective policy, and commit
//! both artifacts and the replay checkpoint together before acknowledging apply.

use super::{parse, to_canonical_bytes, Keystore, PolicyDocument};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

pub const SCHEMA_VERSION: u32 = 2;
pub const SIGNATURE_DOMAIN: &[u8] = b"sigil.targeted-deployment.v2\0";
pub const MAX_MANIFEST_BYTES: usize = 16 * 1024;
pub const MAX_ARTIFACT_BYTES: usize = 4 * 1024 * 1024;
/// Keep integers exactly representable by JSON consumers using IEEE-754.
pub const MAX_SEQUENCE: i64 = (1_i64 << 53) - 1;
const MAX_TIMESTAMP: i64 = 253_402_300_799; // 9999-12-31T23:59:59Z

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    Policy,
    RulePacks,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactDescriptor {
    pub kind: ArtifactKind,
    /// Lowercase, 64-character BLAKE3 digest of the exact YAML bytes.
    pub blake3: String,
    pub size_bytes: u32,
}

impl ArtifactDescriptor {
    pub fn from_bytes(kind: ArtifactKind, bytes: &[u8]) -> Result<Self, DeploymentError> {
        if bytes.is_empty() || bytes.len() > MAX_ARTIFACT_BYTES {
            return Err(DeploymentError::ArtifactSize(kind));
        }
        Ok(Self {
            kind,
            blake3: blake3::hash(bytes).to_hex().to_string(),
            size_bytes: bytes.len() as u32,
        })
    }

    fn validate(&self, kind: ArtifactKind) -> Result<(), DeploymentError> {
        if self.kind != kind {
            return Err(DeploymentError::ArtifactKind(kind));
        }
        if self.size_bytes == 0 || self.size_bytes as usize > MAX_ARTIFACT_BYTES {
            return Err(DeploymentError::ArtifactSize(kind));
        }
        if !valid_digest(&self.blake3) {
            return Err(DeploymentError::InvalidField("artifact.blake3"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentManifest {
    pub schema_version: u32,
    /// Non-nil UUID in lowercase hyphenated form.
    pub deployment_id: String,
    /// Exact enrolled identity, never a query parameter or a name lookup.
    pub target_host_id: String,
    pub sequence: i64,
    pub policy: ArtifactDescriptor,
    pub rule_packs: ArtifactDescriptor,
    /// UTC Unix seconds, no fractions; valid on [issued_at, valid_until).
    pub issued_at: i64,
    pub valid_until: i64,
    /// Included in the signature, unlike the legacy envelope's key hint.
    pub signing_pubkey_id: String,
}

impl DeploymentManifest {
    pub fn validate(&self) -> Result<(), DeploymentError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(DeploymentError::UnsupportedSchema(self.schema_version));
        }
        let id = uuid::Uuid::parse_str(&self.deployment_id)
            .map_err(|_| DeploymentError::InvalidField("deployment_id"))?;
        if id.is_nil() || id.hyphenated().to_string() != self.deployment_id {
            return Err(DeploymentError::InvalidField("deployment_id"));
        }
        if !valid_identifier(&self.target_host_id) {
            return Err(DeploymentError::InvalidField("target_host_id"));
        }
        if !valid_identifier(&self.signing_pubkey_id) {
            return Err(DeploymentError::InvalidField("signing_pubkey_id"));
        }
        if !(1..=MAX_SEQUENCE).contains(&self.sequence) {
            return Err(DeploymentError::InvalidField("sequence"));
        }
        if !(0..=MAX_TIMESTAMP).contains(&self.issued_at)
            || self.valid_until <= self.issued_at
            || self.valid_until > MAX_TIMESTAMP
        {
            return Err(DeploymentError::InvalidField("validity"));
        }
        self.policy.validate(ArtifactKind::Policy)?;
        self.rule_packs.validate(ArtifactKind::RulePacks)
    }

    /// Shared server/signer/agent encoding. Do not sign reserialized raw JSON.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, DeploymentError> {
        self.validate()?;
        let canonical =
            to_canonical_bytes(self).map_err(|e| DeploymentError::Internal(e.to_string()))?;
        let mut bytes = Vec::with_capacity(SIGNATURE_DOMAIN.len() + canonical.len());
        bytes.extend_from_slice(SIGNATURE_DOMAIN);
        bytes.extend_from_slice(&canonical);
        Ok(bytes)
    }

    /// BLAKE3 of the domain-prefixed signing bytes, not of the wire response.
    pub fn digest(&self) -> Result<String, DeploymentError> {
        Ok(blake3::hash(&self.signing_bytes()?).to_hex().to_string())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedDeploymentManifest {
    pub manifest: DeploymentManifest,
    /// Standard padded base64 Ed25519 signature (64 decoded bytes).
    pub signature: String,
}

impl SignedDeploymentManifest {
    /// Bound allocation and reject duplicate/unknown fields before verification.
    pub fn from_json(bytes: &[u8]) -> Result<Self, DeploymentError> {
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err(DeploymentError::ManifestTooLarge);
        }
        let signed: Self =
            serde_json::from_slice(bytes).map_err(|e| DeploymentError::Wire(e.to_string()))?;
        signed.manifest.validate()?;
        Ok(signed)
    }
}

/// Trusted local state, NOT supplied by the server alongside a manifest.
/// Missing/corrupt state after enrollment is an error, not `Legacy { 0, 0 }`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReplayState {
    /// First v2 sequence must exceed both persisted legacy watermarks.
    Legacy {
        policy_version: i64,
        rule_packs_version: i64,
    },
    /// The checkpoint must be committed atomically with both artifacts.
    Targeted {
        host_id: String,
        sequence: i64,
        manifest_digest: String,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationDisposition {
    New,
    /// Same committed intent, not permission to skip runtime recovery/expiry.
    Retry,
}

/// An authenticated manifest. This does NOT mean the deployment is applied.
#[derive(Debug)]
pub struct VerifiedManifest {
    manifest: DeploymentManifest,
    digest: String,
    disposition: VerificationDisposition,
}

impl VerifiedManifest {
    pub fn manifest(&self) -> &DeploymentManifest {
        &self.manifest
    }
    pub fn digest(&self) -> &str {
        &self.digest
    }
    pub fn disposition(&self) -> VerificationDisposition {
        self.disposition
    }

    /// Check both exact byte streams and the existing core policy grammar.
    /// Agent-specific regex/rubric compilation and merge validation still follow.
    pub fn verify_artifacts(
        &self,
        policy: &[u8],
        rule_packs: &[u8],
    ) -> Result<(PolicyDocument, PolicyDocument), DeploymentError> {
        let policy_doc = verify_artifact(&self.manifest.policy, policy)?;
        let packs_doc = verify_artifact(&self.manifest.rule_packs, rule_packs)?;
        Ok((policy_doc, packs_doc))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DeploymentError {
    #[error("deployment manifest exceeds size limit")]
    ManifestTooLarge,
    #[error("invalid deployment JSON: {0}")]
    Wire(String),
    #[error("unsupported deployment schema: {0}")]
    UnsupportedSchema(u32),
    #[error("invalid deployment field: {0}")]
    InvalidField(&'static str),
    #[error("unknown signing key")]
    UnknownKey,
    #[error("inactive signing key")]
    InactiveKey,
    #[error("invalid deployment signature")]
    SignatureInvalid,
    #[error("deployment target does not match enrolled host")]
    TargetMismatch,
    #[error("deployment is not yet valid")]
    NotYetValid,
    #[error("deployment expired")]
    Expired,
    #[error("invalid local replay state")]
    InvalidReplayState,
    #[error("deployment sequence regression or conflicting retry")]
    Replay,
    #[error("incorrect artifact kind for {0:?}")]
    ArtifactKind(ArtifactKind),
    #[error("incorrect or excessive artifact size for {0:?}")]
    ArtifactSize(ArtifactKind),
    #[error("artifact digest mismatch for {0:?}")]
    ArtifactDigest(ArtifactKind),
    #[error("invalid {kind:?} policy document: {detail}")]
    ArtifactParse { kind: ArtifactKind, detail: String },
    #[error("internal deployment verifier error: {0}")]
    Internal(String),
}

/// Verify against independently obtained enrolled identity and durable state.
/// No network identity authentication or anti-rollback persistence happens here.
pub fn verify_manifest(
    keystore: &Keystore,
    signed: &SignedDeploymentManifest,
    expected_host_id: &str,
    now: OffsetDateTime,
    state: &ReplayState,
) -> Result<VerifiedManifest, DeploymentError> {
    let manifest = &signed.manifest;
    let bytes = manifest.signing_bytes()?;
    let id = &manifest.signing_pubkey_id;
    let matches = keystore
        .pubkeys
        .iter()
        .filter(|entry| &entry.id == id)
        .count();
    if matches == 0 {
        return Err(DeploymentError::UnknownKey);
    }
    if matches != 1 {
        return Err(DeploymentError::Internal("ambiguous signing key ID".into()));
    }
    let key = keystore
        .active_pubkey(id, now)
        .map_err(|e| DeploymentError::Internal(e.to_string()))?
        .ok_or(DeploymentError::InactiveKey)?;
    if signed.signature.len() != 88 {
        return Err(DeploymentError::SignatureInvalid);
    }
    let signature = data_encoding::BASE64
        .decode(signed.signature.as_bytes())
        .map_err(|_| DeploymentError::SignatureInvalid)?;
    let signature = ed25519_dalek::Signature::from_slice(&signature)
        .map_err(|_| DeploymentError::SignatureInvalid)?;
    key.verify_strict(&bytes, &signature)
        .map_err(|_| DeploymentError::SignatureInvalid)?;
    if manifest.target_host_id != expected_host_id {
        return Err(DeploymentError::TargetMismatch);
    }
    if now.unix_timestamp() < manifest.issued_at {
        return Err(DeploymentError::NotYetValid);
    }
    if now.unix_timestamp() >= manifest.valid_until {
        return Err(DeploymentError::Expired);
    }
    let digest = blake3::hash(&bytes).to_hex().to_string();
    let disposition = match state {
        ReplayState::Legacy {
            policy_version,
            rule_packs_version,
        } => {
            if *policy_version < 0 || *rule_packs_version < 0 {
                return Err(DeploymentError::InvalidReplayState);
            }
            if manifest.sequence <= *policy_version.max(rule_packs_version) {
                return Err(DeploymentError::Replay);
            }
            VerificationDisposition::New
        }
        ReplayState::Targeted {
            host_id,
            sequence,
            manifest_digest,
        } => {
            if host_id != expected_host_id
                || !(1..=MAX_SEQUENCE).contains(sequence)
                || !valid_digest(manifest_digest)
            {
                return Err(DeploymentError::InvalidReplayState);
            }
            if manifest.sequence < *sequence
                || (manifest.sequence == *sequence && digest != *manifest_digest)
            {
                return Err(DeploymentError::Replay);
            }
            if manifest.sequence == *sequence {
                VerificationDisposition::Retry
            } else {
                VerificationDisposition::New
            }
        }
    };
    Ok(VerifiedManifest {
        manifest: manifest.clone(),
        digest,
        disposition,
    })
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn verify_artifact(
    descriptor: &ArtifactDescriptor,
    bytes: &[u8],
) -> Result<PolicyDocument, DeploymentError> {
    if bytes.len() > MAX_ARTIFACT_BYTES || bytes.len() != descriptor.size_bytes as usize {
        return Err(DeploymentError::ArtifactSize(descriptor.kind));
    }
    if blake3::hash(bytes).to_hex().as_str() != descriptor.blake3 {
        return Err(DeploymentError::ArtifactDigest(descriptor.kind));
    }
    let yaml = std::str::from_utf8(bytes).map_err(|e| DeploymentError::ArtifactParse {
        kind: descriptor.kind,
        detail: e.to_string(),
    })?;
    parse(yaml).map_err(|e| DeploymentError::ArtifactParse {
        kind: descriptor.kind,
        detail: e.to_string(),
    })
}
