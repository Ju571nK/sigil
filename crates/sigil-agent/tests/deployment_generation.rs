use ed25519_dalek::{Signer, SigningKey};
use sigil_agent::deployment::{CoordinatorError, DeploymentCoordinator};
use sigil_core::policy::deployment::{ArtifactDescriptor, ArtifactKind, SignedDeploymentManifest};
use sigil_core::policy::deployment_store::DeploymentStore;
use sigil_core::policy::{HostIdStrategy, Keystore, KeystoreEntry};
use std::sync::Arc;
use time::{macros::datetime, OffsetDateTime};

const POLICY: &[u8] = b"version: 1\ntargets: []\n";
const PACKS: &[u8] = b"version: 1\nrule_packs: []\n";
fn now() -> OffsetDateTime {
    datetime!(2026-09-23 0:00 UTC)
}

fn keys() -> Arc<Keystore> {
    Arc::new(Keystore {
        pubkeys: vec![KeystoreEntry {
            id: "fixture-key".into(),
            ed25519_pubkey_b64: data_encoding::BASE64
                .encode(&SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes()),
            valid_from: now() - time::Duration::days(1),
            valid_until: now() + time::Duration::days(2),
        }],
    })
}

fn signed(sequence: i64, policy: &[u8], packs: &[u8]) -> SignedDeploymentManifest {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../sigil-core/tests/fixtures/targeted-deployment-v2.json"
    ))
    .unwrap();
    let mut signed: SignedDeploymentManifest =
        serde_json::from_value(fixture["signed"].clone()).unwrap();
    signed.manifest.sequence = sequence;
    signed.manifest.policy = ArtifactDescriptor::from_bytes(ArtifactKind::Policy, policy).unwrap();
    signed.manifest.rule_packs =
        ArtifactDescriptor::from_bytes(ArtifactKind::RulePacks, packs).unwrap();
    signed.signature = data_encoding::BASE64.encode(
        &SigningKey::from_bytes(&[7; 32])
            .sign(&signed.manifest.signing_bytes().unwrap())
            .to_bytes(),
    );
    signed
}

fn setup() -> (tempfile::TempDir, DeploymentCoordinator) {
    let dir = tempfile::tempdir().unwrap();
    let store =
        DeploymentStore::initialize(&dir.path().join("deployment.db"), "host-a", 0, 0).unwrap();
    let coordinator =
        DeploymentCoordinator::open(store, keys(), HostIdStrategy::MachineId, now()).unwrap();
    (dir, coordinator)
}

fn pack_yaml(selector: &str, regex: &str, version: u32) -> Vec<u8> {
    format!("version: 1\nrule_packs:\n- id: example\n  pack_version: {version}\n  tool: codex\n  scope: {{kind: user_global}}\n  watched_paths: []\n  rules:\n  - id: rule\n    on_file: /tmp/sigil-deployment-test.json\n    format: json\n    selector: '{selector}'\n    matcher: {{kind: regex, pattern: '{regex}'}}\n    emit: {{kind: sandbox_disabled}}\n").into_bytes()
}

#[test]
fn commit_and_restart_preserve_manifest_and_compiled_generation() {
    let (dir, coordinator) = setup();
    assert!(coordinator.snapshot(now()).unwrap().is_none());
    let generation = coordinator
        .commit(&signed(42, POLICY, PACKS), POLICY, PACKS, now)
        .unwrap();
    assert_eq!(generation.manifest.sequence, 42);
    assert!(!generation.effective.targets.is_empty());
    drop(coordinator);
    let store =
        DeploymentStore::open_existing(&dir.path().join("deployment.db"), "host-a").unwrap();
    let recovered =
        DeploymentCoordinator::open(store, keys(), HostIdStrategy::MachineId, now()).unwrap();
    let recovered = recovered.snapshot(now()).unwrap().unwrap();
    assert_eq!(generation.manifest_digest, recovered.manifest_digest);
    assert_eq!(generation.effective, recovered.effective);
    assert_eq!(generation.rubric.weights, recovered.rubric.weights);
}

#[test]
fn bundle_override_matches_existing_final_policy_semantics() {
    let (_dir, coordinator) = setup();
    let policy = b"version: 1\nrubric_overrides: {sandbox_disabled: 7.0}\nhook_deny_rules:\n- id: shared\n  match: {kind: bash, command: {kind: equals, value: from-policy}}\n";
    let packs = b"version: 1\nhook_deny_rules:\n- id: shared\n  match: {kind: bash, command: {kind: equals, value: from-bundle}}\n";
    let generation = coordinator
        .commit(&signed(42, policy, packs), policy, packs, now)
        .unwrap();
    assert_eq!(generation.rubric.weights["sandbox_disabled"], 7.0);
    assert!(generation
        .evaluator
        .evaluate_bash_preview("from-policy")
        .is_none());
    assert_eq!(
        generation
            .evaluator
            .evaluate_bash_preview("from-bundle")
            .unwrap()
            .0,
        "shared"
    );
    let merged = sigil_core::policy::merge(
        sigil_core::policy::defaults().unwrap(),
        Some(sigil_core::policy::parse(std::str::from_utf8(policy).unwrap()).unwrap()),
        Some(sigil_core::policy::parse(std::str::from_utf8(packs).unwrap()).unwrap()),
        sigil_core::policy::current_platform(),
    )
    .unwrap();
    assert_eq!(generation.effective, merged);
}

#[test]
fn invalid_compilation_never_changes_disk_or_current_snapshot() {
    let (dir, coordinator) = setup();
    let original = coordinator
        .commit(&signed(42, POLICY, PACKS), POLICY, PACKS, now)
        .unwrap();
    for packs in [
        pack_yaml("not-a-selector", ".*", 1),
        pack_yaml("$.x", "[", 1),
        pack_yaml("$.x", ".*", 99),
        b"version: 1\nhook_deny_rules:\n- id: bad\n  match: {kind: bash, command: {kind: regex, pattern: '['}}\n".to_vec(),
    ] {
        assert!(coordinator.commit(&signed(43, POLICY, &packs), POLICY, &packs, now).is_err());
        assert!(Arc::ptr_eq(&original, &coordinator.snapshot(now()).unwrap().unwrap()));
    }
    drop(coordinator);
    let store =
        DeploymentStore::open_existing(&dir.path().join("deployment.db"), "host-a").unwrap();
    let recovered =
        DeploymentCoordinator::open(store, keys(), HostIdStrategy::MachineId, now()).unwrap();
    assert_eq!(
        recovered
            .snapshot(now())
            .unwrap()
            .unwrap()
            .manifest
            .sequence,
        42
    );
}

#[test]
fn rejects_identity_changes_bad_globs_and_invalid_rubric() {
    let (_dir, coordinator) = setup();
    for policy in [
        "version: 1\nhost_id_strategy: hostname\n",
        "version: 1\nrubric_overrides: {sandbox_disabled: .nan}\n",
        "version: 1\nrubric_overrides: {sandbox_disabled: -1.0}\n",
        "version: 1\nrubric_overrides: {unknown_reason: 1.0}\n",
        "version: 1\ntargets:\n- id: bad\n  description: invalid glob\n  tier: standard\n  platform: any\n  paths: ['[']\n",
    ] {
        assert!(coordinator.commit(&signed(42, policy.as_bytes(), PACKS), policy.as_bytes(), PACKS, now).is_err(), "accepted {policy}");
        assert!(coordinator.snapshot(now()).unwrap().is_none());
    }
}

#[test]
fn bad_policy_cannot_be_hidden_by_valid_bundle_override() {
    let (_dir, coordinator) = setup();
    let policy = pack_yaml("$.x", "[", 1);
    let packs = pack_yaml("$.x", ".*", 1);
    assert!(coordinator
        .commit(&signed(42, &policy, &packs), &policy, &packs, now)
        .is_err());
    assert!(coordinator.snapshot(now()).unwrap().is_none());

    let policy = b"version: 1\nhook_deny_rules:\n- id: shared\n  match: {kind: bash, command: {kind: regex, pattern: '['}}\n";
    let packs = b"version: 1\nhook_deny_rules:\n- id: shared\n  match: {kind: bash, command: {kind: exists}}\n";
    assert!(coordinator
        .commit(&signed(42, policy, packs), policy, packs, now)
        .is_err());
    assert!(coordinator.snapshot(now()).unwrap().is_none());
}

#[test]
fn expired_generation_is_not_reported_as_current_or_recovered() {
    let (dir, coordinator) = setup();
    coordinator
        .commit(&signed(42, POLICY, PACKS), POLICY, PACKS, now)
        .unwrap();
    let later = now() + time::Duration::days(1);
    assert!(matches!(
        coordinator.snapshot(later),
        Err(CoordinatorError::Expired)
    ));
    drop(coordinator);
    let store =
        DeploymentStore::open_existing(&dir.path().join("deployment.db"), "host-a").unwrap();
    assert!(DeploymentCoordinator::open(store, keys(), HostIdStrategy::MachineId, later).is_err());
}

#[test]
fn concurrent_readers_observe_one_complete_generation() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let (_dir, coordinator) = setup();
    let coordinator = Arc::new(coordinator);
    let make_policy = |sequence| {
        format!("version: 1\nrubric_overrides: {{sandbox_disabled: {sequence}.0}}\nhook_deny_rules:\n- id: generation\n  match: {{kind: bash, command: {{kind: equals, value: generation-{sequence}}}}}\n").into_bytes()
    };
    let policy = make_policy(42);
    coordinator
        .commit(&signed(42, &policy, PACKS), &policy, PACKS, now)
        .unwrap();
    let done = Arc::new(AtomicBool::new(false));
    let reader = {
        let coordinator = coordinator.clone();
        let done = done.clone();
        std::thread::spawn(move || loop {
            let generation = coordinator.snapshot(now()).unwrap().unwrap();
            let sequence = generation.manifest.sequence;
            assert_eq!(
                generation.rubric.weights["sandbox_disabled"],
                sequence as f32
            );
            assert!(generation
                .evaluator
                .evaluate_bash_preview(&format!("generation-{sequence}"))
                .is_some());
            if done.load(Ordering::Acquire) {
                break;
            }
            std::thread::yield_now();
        })
    };
    for sequence in 43..=48 {
        let policy = make_policy(sequence);
        coordinator
            .commit(&signed(sequence, &policy, PACKS), &policy, PACKS, now)
            .unwrap();
    }
    done.store(true, Ordering::Release);
    reader.join().unwrap();
    assert_eq!(
        coordinator
            .snapshot(now())
            .unwrap()
            .unwrap()
            .manifest
            .sequence,
        48
    );
}
