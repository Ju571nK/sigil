//! CLI side-effect tests for `install --agent antigravity`.
//!
//! #112 made this static-posture-only because agy 1.0.7/1.0.8 did not fire
//! command hooks. #202 re-verified on agy 1.1.7: the hook at the shared
//! `~/.gemini/config/hooks.json` fires and an explicit deny blocks the call, so
//! the default install now registers there. The legacy `agy plugin install`
//! bundle is a *different* mechanism that has not been re-probed, and stays
//! behind `--force`.
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

fn hooks_file(home: &Path) -> PathBuf {
    home.join(".gemini/config/hooks.json")
}

fn run(home: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_sigil-hook"))
        .args(args)
        .env("HOME", home)
        .env_remove("XDG_STATE_HOME")
        .output()
        .unwrap()
}

#[test]
fn install_registers_in_the_shared_hooks_file_not_the_plugin_bundle() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path();
    let marker = write_fake_agy(home);

    let out = run(home, &["install", "--agent", "antigravity", "--write"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "stderr: {stderr}");

    let v: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(hooks_file(home)).unwrap()).unwrap();
    // The nested wrapper is required — a bare top-level `PreToolUse` does not
    // load on agy (#202).
    let arr = v["hooks"]["PreToolUse"]
        .as_array()
        .unwrap_or_else(|| panic!("expected nested hooks.PreToolUse, got {v}"));
    assert_eq!(arr.len(), 1, "{v}");
    assert!(
        v["PreToolUse"].is_null(),
        "must not write the bare shape: {v}"
    );

    assert!(!staging(home).exists(), "default install writes no bundle");
    assert!(!marker.exists(), "default install must not invoke agy");
}

/// The file is shared with agy's own `/hooks` TUI, so registration is additive
/// and uninstall takes only Sigil's entry.
#[test]
fn install_and_uninstall_leave_foreign_hooks_alone() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path();
    write_fake_agy(home);
    fs::create_dir_all(hooks_file(home).parent().unwrap()).unwrap();
    fs::write(
        hooks_file(home),
        r#"{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"/other/tool"}]}]}}"#,
    )
    .unwrap();

    assert!(run(home, &["install", "--agent", "antigravity", "--write"])
        .status
        .success());
    let v: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(hooks_file(home)).unwrap()).unwrap();
    assert_eq!(v["hooks"]["PreToolUse"].as_array().unwrap().len(), 2, "{v}");

    assert!(
        run(home, &["uninstall", "--agent", "antigravity", "--write"])
            .status
            .success()
    );
    let v: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(hooks_file(home)).unwrap()).unwrap();
    let left = v["hooks"]["PreToolUse"].as_array().unwrap();
    assert_eq!(left.len(), 1, "foreign hook must survive: {v}");
    assert_eq!(left[0]["hooks"][0]["command"], "/other/tool");
}

/// #202 measured the deny path working, so enforce is no longer refused.
#[test]
fn enforce_registers_the_deny_command() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path();
    write_fake_agy(home);

    let out = run(
        home,
        &["install", "--agent", "antigravity", "--enforce", "--write"],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "stderr: {stderr}");

    let text = fs::read_to_string(hooks_file(home)).unwrap();
    assert!(text.contains("--enforce"), "{text}");
    // agy is fail-open, so the registered command must carry an explicit
    // on-failure mode rather than relying on the exit code.
    assert!(text.contains("--on-failure"), "{text}");
}

#[test]
fn force_still_writes_the_legacy_plugin_bundle() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path();
    let marker = write_fake_agy(home);
    let out = run(
        home,
        &["install", "--agent", "antigravity", "--write", "--force"],
    );
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
    // And it says plainly that this path is unverified rather than implying
    // protection.
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("legacy"), "stderr: {stderr}");
}

/// The hooks file is shared with agy. If it does not parse, registration must
/// refuse rather than start from `{}` and silently delete the user's hooks.
#[test]
fn malformed_shared_file_is_not_overwritten() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path();
    write_fake_agy(home);
    fs::create_dir_all(hooks_file(home).parent().unwrap()).unwrap();
    let original = r#"{"hooks":{"PreToolUse":[{"matcher":"*",]}}"#; // trailing comma / bad
    fs::write(hooks_file(home), original).unwrap();

    let out = run(home, &["install", "--agent", "antigravity", "--write"]);
    assert!(!out.status.success(), "must not claim success");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("not valid JSON"), "stderr: {stderr}");
    assert_eq!(
        fs::read_to_string(hooks_file(home)).unwrap(),
        original,
        "the file must be left exactly as it was"
    );
}

/// An empty file holds nothing to lose, so it is treated as an empty document
/// rather than an error.
#[test]
fn empty_shared_file_registers_normally() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path();
    write_fake_agy(home);
    fs::create_dir_all(hooks_file(home).parent().unwrap()).unwrap();
    fs::write(hooks_file(home), "  \n").unwrap();

    let out = run(home, &["install", "--agent", "antigravity", "--write"]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(hooks_file(home)).unwrap()).unwrap();
    assert_eq!(v["hooks"]["PreToolUse"].as_array().unwrap().len(), 1, "{v}");
}

/// Valid JSON in an unexpected shape is still live data. Coercing it — which is
/// what the merge helper does on its own — would delete the user's hooks.
#[test]
fn wrong_shaped_but_valid_json_is_refused_not_coerced() {
    for original in [
        // PreToolUse as an object rather than an array
        r#"{"hooks":{"PreToolUse":{"matcher":"*","hooks":[{"type":"command","command":"/other"}]}}}"#,
        // hooks as a string
        r#"{"hooks":"user data"}"#,
        // root as an array
        r#"[1,2,3]"#,
    ] {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        write_fake_agy(home);
        fs::create_dir_all(hooks_file(home).parent().unwrap()).unwrap();
        fs::write(hooks_file(home), original).unwrap();

        let out = run(home, &["install", "--agent", "antigravity", "--write"]);
        assert!(!out.status.success(), "must refuse: {original}");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains("unexpected shape"), "stderr: {stderr}");
        assert_eq!(
            fs::read_to_string(hooks_file(home)).unwrap(),
            original,
            "file must be untouched"
        );
    }
}

/// The legacy bundle registers an observe-only command, so asking for enforce
/// through it must fail loudly rather than return a hook that never denies.
#[test]
fn force_plus_enforce_is_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path();
    let marker = write_fake_agy(home);
    let out = run(
        home,
        &[
            "install",
            "--agent",
            "antigravity",
            "--enforce",
            "--write",
            "--force",
        ],
    );
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("cannot enforce"), "stderr: {stderr}");
    assert!(!marker.exists(), "agy must not be invoked");
    assert!(!staging(home).exists(), "no bundle written");
}

/// Install writes a baseline for antigravity, so verify has to be able to read
/// it — otherwise the command that checks registrations rejects the agent whose
/// registration it just recorded.
#[test]
fn verify_accepts_antigravity_after_install() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path();
    write_fake_agy(home);
    assert!(run(home, &["install", "--agent", "antigravity", "--write"])
        .status
        .success());

    let out = run(home, &["verify", "--agent", "antigravity"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("unsupported --agent"),
        "verify must know this agent: {stderr}"
    );
}
