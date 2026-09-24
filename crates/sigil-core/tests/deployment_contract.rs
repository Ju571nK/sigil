use ed25519_dalek::{Signer, SigningKey};
use sigil_core::policy::deployment::*;
use sigil_core::policy::{to_canonical_bytes, Keystore, KeystoreEntry};
use time::{macros::datetime, OffsetDateTime};

const POLICY: &[u8] = b"version: 1\ntargets: []\n";
const PACKS: &[u8] = b"version: 1\nrule_packs: []\n";
type ManifestMutation = Box<dyn Fn(&mut DeploymentManifest)>;

fn now() -> OffsetDateTime {
    datetime!(2026-09-23 0:00 UTC)
}

// Public test seed only; never use this key for production signing.
fn key() -> SigningKey {
    SigningKey::from_bytes(&[7; 32])
}

fn store() -> Keystore {
    Keystore {
        pubkeys: vec![KeystoreEntry {
            id: "fixture-key".into(),
            ed25519_pubkey_b64: data_encoding::BASE64.encode(&key().verifying_key().to_bytes()),
            valid_from: now() - time::Duration::days(1),
            valid_until: now() + time::Duration::days(2),
        }],
    }
}

fn manifest() -> DeploymentManifest {
    DeploymentManifest {
        schema_version: 2,
        deployment_id: "01234567-89ab-4cde-8fab-0123456789ab".into(),
        target_host_id: "host-a".into(),
        sequence: 42,
        policy: ArtifactDescriptor::from_bytes(ArtifactKind::Policy, POLICY).unwrap(),
        rule_packs: ArtifactDescriptor::from_bytes(ArtifactKind::RulePacks, PACKS).unwrap(),
        issued_at: now().unix_timestamp(),
        valid_until: (now() + time::Duration::days(1)).unix_timestamp(),
        signing_pubkey_id: "fixture-key".into(),
    }
}

fn sign(manifest: DeploymentManifest) -> SignedDeploymentManifest {
    let signature =
        data_encoding::BASE64.encode(&key().sign(&manifest.signing_bytes().unwrap()).to_bytes());
    SignedDeploymentManifest {
        manifest,
        signature,
    }
}

fn legacy() -> ReplayState {
    ReplayState::Legacy {
        policy_version: 0,
        rule_packs_version: 0,
    }
}

fn verify(signed: &SignedDeploymentManifest) -> Result<VerifiedManifest, DeploymentError> {
    verify_manifest(&store(), signed, "host-a", now(), &legacy())
}

fn checkpoint(signed: &SignedDeploymentManifest) -> ReplayState {
    ReplayState::Targeted {
        host_id: signed.manifest.target_host_id.clone(),
        sequence: signed.manifest.sequence,
        manifest_digest: signed.manifest.digest().unwrap(),
    }
}

#[test]
fn golden_contract() {
    let signed = sign(manifest());
    let verified = verify(&signed).unwrap();
    assert_eq!(verified.disposition(), VerificationDisposition::New);
    verified.verify_artifacts(POLICY, PACKS).unwrap();
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/targeted-deployment-v2.json")).unwrap();
    assert_eq!(
        fixture,
        serde_json::json!({
            "signed": signed,
            "public_key": store().pubkeys[0].ed25519_pubkey_b64,
            "signing_bytes_utf8": String::from_utf8(manifest().signing_bytes().unwrap()).unwrap(),
            "manifest_digest": verified.digest(),
            "policy_utf8": std::str::from_utf8(POLICY).unwrap(),
            "rule_packs_utf8": std::str::from_utf8(PACKS).unwrap(),
        })
    );
}

#[test]
fn json_order_and_whitespace_do_not_change_signature() {
    let signed = sign(manifest());
    let wire = serde_json::to_vec_pretty(&signed).unwrap();
    let parsed = SignedDeploymentManifest::from_json(&wire).unwrap();
    verify(&parsed).unwrap();
    let sorted = to_canonical_bytes(&signed).unwrap();
    assert_ne!(wire, sorted);
    assert_eq!(
        SignedDeploymentManifest::from_json(&sorted).unwrap(),
        parsed
    );
}

#[test]
fn rejects_unknown_duplicate_missing_and_legacy_fields() {
    let wire = serde_json::to_string(&sign(manifest())).unwrap();
    for bad in [
        wire.replacen("{", "{\"extra\":1,", 1),
        wire.replace(
            "\"schema_version\":2",
            "\"schema_version\":2,\"schema_version\":2",
        ),
        wire.replace(
            "\"target_host_id\":\"host-a\"",
            "\"target_host_id\":\"host-a\",\"target_host_id\":\"host-b\"",
        ),
        wire.replace(
            "\"kind\":\"policy\"",
            "\"kind\":\"policy\",\"kind\":\"rule_packs\"",
        ),
        wire.replace("\"sequence\":42,", ""),
        wire.replace("\"sequence\":42", "\"sequence\":42.0"),
        wire.replace("\"kind\":\"policy\"", "\"kind\":\"executable\""),
        wire.replace("\"size_bytes\":23", "\"extra\":1,\"size_bytes\":23"),
        r#"{"signed_envelope":{},"signature":"x","signing_pubkey_id":"fixture-key"}"#.into(),
    ] {
        assert!(
            SignedDeploymentManifest::from_json(bad.as_bytes()).is_err(),
            "accepted {bad}"
        );
    }
}

#[test]
fn manifest_and_artifact_limits_are_enforced() {
    assert!(matches!(
        SignedDeploymentManifest::from_json(&vec![b' '; MAX_MANIFEST_BYTES + 1]),
        Err(DeploymentError::ManifestTooLarge)
    ));
    for bytes in [vec![], vec![0; MAX_ARTIFACT_BYTES + 1]] {
        assert!(ArtifactDescriptor::from_bytes(ArtifactKind::Policy, &bytes).is_err());
    }
    let verified = verify(&sign(manifest())).unwrap();
    for bytes in [vec![], vec![0; MAX_ARTIFACT_BYTES + 1]] {
        assert!(matches!(
            verified.verify_artifacts(&bytes, PACKS),
            Err(DeploymentError::ArtifactSize(ArtifactKind::Policy))
        ));
    }
}

#[test]
fn malformed_manifest_fields_are_rejected() {
    let mutations: Vec<ManifestMutation> = vec![
        Box::new(|m| m.schema_version = 1),
        Box::new(|m| m.schema_version = 3),
        Box::new(|m| m.deployment_id = uuid::Uuid::nil().to_string()),
        Box::new(|m| m.deployment_id = m.deployment_id.to_uppercase()),
        Box::new(|m| m.target_host_id.clear()),
        Box::new(|m| m.target_host_id = " host-a".into()),
        Box::new(|m| m.target_host_id = "a\nb".into()),
        Box::new(|m| m.target_host_id = "a".repeat(257)),
        Box::new(|m| m.signing_pubkey_id.clear()),
        Box::new(|m| m.sequence = 0),
        Box::new(|m| m.sequence = -1),
        Box::new(|m| m.sequence = MAX_SEQUENCE + 1),
        Box::new(|m| m.issued_at = -1),
        Box::new(|m| m.valid_until = m.issued_at),
        Box::new(|m| m.valid_until = i64::MAX),
        Box::new(|m| m.policy.blake3 = m.policy.blake3.to_uppercase()),
        Box::new(|m| m.policy.blake3 = "z".repeat(64)),
        Box::new(|m| m.policy.size_bytes = 0),
        Box::new(|m| m.rule_packs.size_bytes = MAX_ARTIFACT_BYTES as u32 + 1),
        Box::new(|m| m.policy.kind = ArtifactKind::RulePacks),
        Box::new(|m| m.rule_packs.kind = ArtifactKind::Policy),
    ];
    for (index, mutate) in mutations.iter().enumerate() {
        let mut m = manifest();
        mutate(&mut m);
        assert!(m.signing_bytes().is_err(), "mutation {index} accepted");
    }
}

#[test]
fn signature_covers_every_manifest_field() {
    let signed = sign(manifest());
    let mutations: Vec<ManifestMutation> = vec![
        Box::new(|m| m.deployment_id = "01234567-89ab-4cde-8fab-0123456789ac".into()),
        Box::new(|m| m.target_host_id = "host-b".into()),
        Box::new(|m| m.sequence += 1),
        Box::new(|m| m.issued_at -= 1),
        Box::new(|m| m.valid_until += 1),
        Box::new(|m| m.policy.blake3 = "0".repeat(64)),
        Box::new(|m| m.rule_packs.blake3 = "0".repeat(64)),
        Box::new(|m| m.policy.size_bytes += 1),
        Box::new(|m| m.rule_packs.size_bytes += 1),
        Box::new(|m| m.signing_pubkey_id = "alias-key".into()),
    ];
    let mut keys = store();
    let mut alias = keys.pubkeys[0].clone();
    alias.id = "alias-key".into();
    keys.pubkeys.push(alias);
    for mutate in mutations {
        let mut bad = signed.clone();
        mutate(&mut bad.manifest);
        assert!(matches!(
            verify_manifest(&keys, &bad, "host-a", now(), &legacy()),
            Err(DeploymentError::SignatureInvalid)
        ));
    }
}

#[test]
fn signature_requires_v2_domain_and_strict_encoding() {
    let mut signed = sign(manifest());
    signed.signature = data_encoding::BASE64.encode(
        &key()
            .sign(&to_canonical_bytes(&signed.manifest).unwrap())
            .to_bytes(),
    );
    assert!(matches!(
        verify(&signed),
        Err(DeploymentError::SignatureInvalid)
    ));
    for sig in [
        String::new(),
        "!".repeat(88),
        data_encoding::BASE64.encode(&[0; 64]),
        "A".repeat(MAX_MANIFEST_BYTES),
    ] {
        signed.signature = sig;
        assert!(matches!(
            verify(&signed),
            Err(DeploymentError::SignatureInvalid)
        ));
    }
}

#[test]
fn rejects_unknown_inactive_wrong_and_ambiguous_keys() {
    let signed = sign(manifest());
    let mut keys = store();
    keys.pubkeys.clear();
    assert!(matches!(
        verify_manifest(&keys, &signed, "host-a", now(), &legacy()),
        Err(DeploymentError::UnknownKey)
    ));
    for at in [
        now() - time::Duration::days(2),
        now() + time::Duration::days(2),
    ] {
        assert!(matches!(
            verify_manifest(&store(), &signed, "host-a", at, &legacy()),
            Err(DeploymentError::InactiveKey)
        ));
    }
    keys = store();
    keys.pubkeys[0].ed25519_pubkey_b64 =
        data_encoding::BASE64.encode(&SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes());
    assert!(matches!(
        verify_manifest(&keys, &signed, "host-a", now(), &legacy()),
        Err(DeploymentError::SignatureInvalid)
    ));
    keys = store();
    keys.pubkeys.push(keys.pubkeys[0].clone());
    assert!(matches!(
        verify_manifest(&keys, &signed, "host-a", now(), &legacy()),
        Err(DeploymentError::Internal(_))
    ));
}

#[test]
fn rejects_other_hosts_and_exact_expiry_boundary() {
    let signed = sign(manifest());
    for host in ["host-b", "HOST-A", "", "host-a "] {
        assert!(matches!(
            verify_manifest(&store(), &signed, host, now(), &legacy()),
            Err(DeploymentError::TargetMismatch)
        ));
    }
    assert!(matches!(
        verify_manifest(
            &store(),
            &signed,
            "host-a",
            now() - time::Duration::nanoseconds(1),
            &legacy()
        ),
        Err(DeploymentError::NotYetValid)
    ));
    let end = now() + time::Duration::days(1);
    verify_manifest(
        &store(),
        &signed,
        "host-a",
        end - time::Duration::nanoseconds(1),
        &legacy(),
    )
    .unwrap();
    assert!(matches!(
        verify_manifest(&store(), &signed, "host-a", end, &legacy()),
        Err(DeploymentError::Expired)
    ));
}

#[test]
fn migration_exceeds_both_legacy_watermarks() {
    let signed = sign(manifest());
    for (policy_version, rule_packs_version) in [(42, 1), (1, 42), (43, 50), (0, i64::MAX)] {
        assert!(matches!(
            verify_manifest(
                &store(),
                &signed,
                "host-a",
                now(),
                &ReplayState::Legacy {
                    policy_version,
                    rule_packs_version
                }
            ),
            Err(DeploymentError::Replay)
        ));
    }
    assert!(matches!(
        verify_manifest(
            &store(),
            &signed,
            "host-a",
            now(),
            &ReplayState::Legacy {
                policy_version: -1,
                rule_packs_version: 0
            }
        ),
        Err(DeploymentError::InvalidReplayState)
    ));
}

#[test]
fn retry_requires_same_digest_but_still_checks_expiry_and_artifacts() {
    let signed = sign(manifest());
    let state = checkpoint(&signed);
    let verified = verify_manifest(&store(), &signed, "host-a", now(), &state).unwrap();
    assert_eq!(verified.disposition(), VerificationDisposition::Retry);
    assert!(verified.verify_artifacts(POLICY, b"damaged").is_err());
    assert!(matches!(
        verify_manifest(
            &store(),
            &signed,
            "host-a",
            now() + time::Duration::days(1),
            &state
        ),
        Err(DeploymentError::Expired)
    ));
    let mut changed = manifest();
    changed.valid_until += 1;
    assert!(matches!(
        verify_manifest(&store(), &sign(changed), "host-a", now(), &state),
        Err(DeploymentError::Replay)
    ));
    for (seq, succeeds) in [(41, false), (43, true)] {
        let mut m = manifest();
        m.sequence = seq;
        let result = verify_manifest(&store(), &sign(m), "host-a", now(), &state);
        assert_eq!(result.is_ok(), succeeds);
        if let Ok(v) = result {
            assert_eq!(v.disposition(), VerificationDisposition::New);
        }
    }
}

#[test]
fn rejects_corrupt_or_different_identity_checkpoint() {
    let signed = sign(manifest());
    for (host, seq, digest) in [
        ("host-b", 42, "0".repeat(64)),
        ("host-a", 0, "0".repeat(64)),
        ("host-a", MAX_SEQUENCE + 1, "0".repeat(64)),
        ("host-a", 42, "bad".into()),
    ] {
        let state = ReplayState::Targeted {
            host_id: host.into(),
            sequence: seq,
            manifest_digest: digest,
        };
        assert!(matches!(
            verify_manifest(&store(), &signed, "host-a", now(), &state),
            Err(DeploymentError::InvalidReplayState)
        ));
    }
}

#[test]
fn checks_both_artifacts_and_core_parse_semantics() {
    let verified = verify(&sign(manifest())).unwrap();
    let mut changed = POLICY.to_vec();
    changed[0] = b'x';
    assert!(matches!(
        verified.verify_artifacts(&changed, PACKS),
        Err(DeploymentError::ArtifactDigest(ArtifactKind::Policy))
    ));
    let mut changed = PACKS.to_vec();
    changed[0] = b'x';
    assert!(matches!(
        verified.verify_artifacts(POLICY, &changed),
        Err(DeploymentError::ArtifactDigest(ArtifactKind::RulePacks))
    ));
    assert!(verified.verify_artifacts(PACKS, POLICY).is_err());
    for bad in [b"version: 99\n".as_slice(), b"[", b"\xff", b"version: 1\nhook_deny_rules:\n- id: same\n  match: {kind: bash, command: {kind: exists}}\n- id: same\n  match: {kind: bash, command: {kind: exists}}\n"] {
        let mut m = manifest();
        m.rule_packs = ArtifactDescriptor::from_bytes(ArtifactKind::RulePacks, bad).unwrap();
        let verified = verify(&sign(m)).unwrap();
        assert!(matches!(verified.verify_artifacts(POLICY, bad), Err(DeploymentError::ArtifactParse { kind: ArtifactKind::RulePacks, .. })));
    }
}

#[test]
fn missing_artifact_and_duplicate_outer_fields_are_rejected() {
    let signed = sign(manifest());
    let wire = serde_json::to_string(&signed).unwrap();
    let duplicate = format!("{{\"signature\":\"{}\",{}", signed.signature, &wire[1..]);
    assert!(SignedDeploymentManifest::from_json(duplicate.as_bytes()).is_err());
    for field in ["policy", "rule_packs"] {
        let mut value = serde_json::to_value(&signed).unwrap();
        value["manifest"].as_object_mut().unwrap().remove(field);
        assert!(SignedDeploymentManifest::from_json(&serde_json::to_vec(&value).unwrap()).is_err());
    }
}

#[test]
fn two_hosts_cannot_exchange_valid_manifests() {
    for (host, other) in [("host-a", "host-b"), ("host-b", "host-a")] {
        let mut m = manifest();
        m.target_host_id = host.into();
        let signed = sign(m);
        verify_manifest(&store(), &signed, host, now(), &legacy()).unwrap();
        assert!(matches!(
            verify_manifest(&store(), &signed, other, now(), &legacy()),
            Err(DeploymentError::TargetMismatch)
        ));
    }
}

#[test]
fn rollback_content_requires_new_sequence_and_new_signature() {
    let original = sign(manifest());
    let changed_policy = b"version: 1\ntargets: []\n# revision B\n";
    let mut next = manifest();
    next.sequence += 1;
    next.policy = ArtifactDescriptor::from_bytes(ArtifactKind::Policy, changed_policy).unwrap();
    let next = sign(next);
    verify_manifest(&store(), &next, "host-a", now(), &checkpoint(&original))
        .unwrap()
        .verify_artifacts(changed_policy, PACKS)
        .unwrap();
    let state = checkpoint(&next);
    assert!(matches!(
        verify_manifest(&store(), &original, "host-a", now(), &state),
        Err(DeploymentError::Replay)
    ));
    let mut rollback = manifest();
    rollback.sequence += 2;
    rollback.deployment_id = "01234567-89ab-4cde-8fab-0123456789ac".into();
    let verified = verify_manifest(&store(), &sign(rollback), "host-a", now(), &state).unwrap();
    assert_eq!(verified.disposition(), VerificationDisposition::New);
    verified.verify_artifacts(POLICY, PACKS).unwrap();
}
