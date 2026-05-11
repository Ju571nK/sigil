//! Drives the `sigil-sign` binary directly: keygen → sign → verify roundtrip
//! ends with verify exiting 0 and inspect printing the right metadata.

use std::process::Command;
use tempfile::tempdir;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_sigil-sign")
}

#[test]
fn keygen_sign_verify_inspect_roundtrip_via_cli() {
    let dir = tempdir().unwrap();
    let key_path = dir.path().join("k.json");
    let yaml_path = dir.path().join("p.yaml");
    let signed_path = dir.path().join("signed.json");
    let keystore_path = dir.path().join("policy-signing-pubkeys.pem");

    std::fs::write(&yaml_path, "version: 1\nfoo: bar\n").unwrap();

    // 1. keygen
    let out = Command::new(bin())
        .args(["keygen", "--id", "k1", "--out"])
        .arg(&key_path)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "keygen failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Build a keystore that includes the freshly-generated pubkey.
    let key_bytes = std::fs::read(&key_path).unwrap();
    let key_json: serde_json::Value = serde_json::from_slice(&key_bytes).unwrap();
    let pubkey_b64 = key_json["ed25519_pubkey_b64"].as_str().unwrap();
    let store = serde_json::json!({
        "pubkeys": [{
            "id": "k1",
            "ed25519_pubkey_b64": pubkey_b64,
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_until": "2027-12-31T00:00:00Z"
        }]
    });
    std::fs::write(&keystore_path, serde_json::to_vec(&store).unwrap()).unwrap();

    // 2. sign
    let out = Command::new(bin())
        .args(["sign", "--in"])
        .arg(&yaml_path)
        .arg("--key")
        .arg(&key_path)
        .args(["--policy-version", "7"])
        .args(["--valid-until", "2027-06-15T00:00:00Z"])
        .arg("--out")
        .arg(&signed_path)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "sign failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // 3. verify (now within keystore validity window AND envelope validity)
    let out = Command::new(bin())
        .args(["verify", "--in"])
        .arg(&signed_path)
        .arg("--keystore")
        .arg(&keystore_path)
        .args(["--now", "2026-06-15T00:00:00Z"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "verify failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    // 4. inspect
    let out = Command::new(bin())
        .args(["inspect", "--in"])
        .arg(&signed_path)
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("signing_pubkey_id : k1"));
    assert!(stdout.contains("policy_version    : 7"));
    assert!(stdout.contains("valid_until       : 2027-06-15"));
}

#[test]
fn verify_fails_when_keystore_missing_pubkey() {
    let dir = tempdir().unwrap();
    let key_path = dir.path().join("k.json");
    let yaml_path = dir.path().join("p.yaml");
    let signed_path = dir.path().join("signed.json");
    let keystore_path = dir.path().join("policy-signing-pubkeys.pem");

    std::fs::write(&yaml_path, "version: 1\n").unwrap();

    Command::new(bin())
        .args(["keygen", "--id", "k1", "--out"])
        .arg(&key_path)
        .output()
        .unwrap();

    Command::new(bin())
        .args(["sign", "--in"])
        .arg(&yaml_path)
        .arg("--key")
        .arg(&key_path)
        .args(["--policy-version", "1"])
        .args(["--valid-until", "2027-06-15T00:00:00Z"])
        .arg("--out")
        .arg(&signed_path)
        .output()
        .unwrap();

    // Empty keystore.
    std::fs::write(&keystore_path, br#"{"pubkeys":[]}"#).unwrap();

    let out = Command::new(bin())
        .args(["verify", "--in"])
        .arg(&signed_path)
        .arg("--keystore")
        .arg(&keystore_path)
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "verify should fail with empty keystore"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("FAIL") || stderr.contains("pubkey unknown"));
}
