//! CLI side-effect tests (#112): `install --agent antigravity` is static-posture-only
//! by default (no bundle written, agy never invoked) and rejects --enforce; only
//! --force performs the (legacy / no-op-on-current-agy) bundle install.
#![cfg(unix)]
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

// Fake `agy` that records each invocation by touching a marker file.
fn write_fake_agy(home: &Path) -> PathBuf {
    let bin = home.join(".local/bin");
    fs::create_dir_all(&bin).unwrap();
    let agy = bin.join("agy");
    let marker = home.join("agy-invoked.marker");
    fs::write(
        &agy,
        format!("#!/bin/sh\necho called >> {}\nexit 0\n", marker.display()),
    )
    .unwrap();
    fs::set_permissions(&agy, fs::Permissions::from_mode(0o755)).unwrap();
    marker
}

fn staging(home: &Path) -> PathBuf {
    home.join(".local/state/sigil/antigravity-plugin/sigil-hook")
}

#[test]
fn antigravity_install_no_force_is_static_only_noop() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path();
    let marker = write_fake_agy(home);
    let out = Command::new(env!("CARGO_BIN_EXE_sigil-hook"))
        .args(["install", "--agent", "antigravity", "--write"])
        .env("HOME", home)
        .env_remove("XDG_STATE_HOME")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "stderr: {stderr}");
    assert!(stderr.contains("NOT installed"), "stderr: {stderr}");
    assert!(!staging(home).exists(), "no bundle should be written");
    assert!(!marker.exists(), "agy must not be invoked");
}

#[test]
fn antigravity_install_force_writes_bundle_and_calls_agy() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path();
    let marker = write_fake_agy(home);
    let out = Command::new(env!("CARGO_BIN_EXE_sigil-hook"))
        .args(["install", "--agent", "antigravity", "--write", "--force"])
        .env("HOME", home)
        .env_remove("XDG_STATE_HOME")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        staging(home).join("hooks/hooks.json").exists(),
        "bundle written under --force"
    );
    assert!(marker.exists(), "agy invoked under --force");
}

#[test]
fn antigravity_enforce_is_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path();
    write_fake_agy(home);
    let out = Command::new(env!("CARGO_BIN_EXE_sigil-hook"))
        .args(["install", "--agent", "antigravity", "--enforce"])
        .env("HOME", home)
        .env_remove("XDG_STATE_HOME")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "stderr: {stderr}");
    assert!(
        stderr.contains("enforce is not available"),
        "stderr: {stderr}"
    );
}
