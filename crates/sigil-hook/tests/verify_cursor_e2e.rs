//! CLI e2e (#120): install Cursor enforce → verify clean → tamper failClosed →
//! verify detects fail_mode_drift (exit 2) → delete an event entry → verify
//! detects entry_missing (exit 2) → unknown agent → usage error (exit 1).
#![cfg(unix)]
use std::process::Command;

fn sigil(home: &std::path::Path, state: &std::path::Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_sigil-hook"))
        .args(args)
        .env("HOME", home)
        .env("XDG_STATE_HOME", state)
        .output()
        .unwrap()
}

#[test]
fn cursor_verify_roundtrip_and_tamper() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path();
    let state = home.join("state");
    let hooks = home.join(".cursor/hooks.json");

    // install enforce closed → writes both events (+failClosed) AND the per-agent baseline
    let out = sigil(
        home,
        &state,
        &[
            "install",
            "--agent",
            "cursor",
            "--enforce",
            "--on-failure",
            "closed",
            "--write",
        ],
    );
    assert!(
        out.status.success(),
        "install failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // hooks.json and baseline must both exist after install
    assert!(
        hooks.exists(),
        "hooks.json must be written by install --write"
    );
    assert!(
        state.join("sigil/hook-registration-cursor.json").exists(),
        "baseline must be written by install --write"
    );

    // clean verify → exit 0
    let v = sigil(home, &state, &["verify", "--agent", "cursor"]);
    assert_eq!(
        v.status.code(),
        Some(0),
        "clean verify must exit 0: stdout={} stderr={}",
        String::from_utf8_lossy(&v.stdout),
        String::from_utf8_lossy(&v.stderr)
    );

    // tamper: flip ONLY beforeShellExecution[0].failClosed → false; command intact,
    // beforeMCPExecution untouched. PASS 1/2 don't fire (both entries present, command
    // hash matches); PASS 3 fires on the shell event → fail_mode_drift.
    let raw = std::fs::read_to_string(&hooks).unwrap();
    let mut j: serde_json::Value = serde_json::from_str(&raw).unwrap();
    j["hooks"]["beforeShellExecution"][0]["failClosed"] = serde_json::json!(false);
    std::fs::write(&hooks, serde_json::to_string(&j).unwrap()).unwrap();

    let v = sigil(home, &state, &["verify", "--agent", "cursor"]);
    assert_eq!(
        v.status.code(),
        Some(2),
        "fail-mode drift must exit 2: stdout={} stderr={}",
        String::from_utf8_lossy(&v.stdout),
        String::from_utf8_lossy(&v.stderr)
    );
    assert!(
        String::from_utf8_lossy(&v.stdout).contains("fail_mode_drift"),
        "stdout must contain 'fail_mode_drift', got: {}",
        String::from_utf8_lossy(&v.stdout)
    );

    // tamper harder: wipe beforeMCPExecution to []. beforeShellExecution still holds
    // the prior-tamper entry, but the MCP event is now empty → PASS 1 short-circuits on
    // the missing MCP entry → entry_missing (precedence over the lingering shell drift).
    let raw = std::fs::read_to_string(&hooks).unwrap();
    let mut j: serde_json::Value = serde_json::from_str(&raw).unwrap();
    j["hooks"]["beforeMCPExecution"] = serde_json::json!([]);
    std::fs::write(&hooks, serde_json::to_string(&j).unwrap()).unwrap();

    let v = sigil(home, &state, &["verify", "--agent", "cursor"]);
    assert_eq!(
        v.status.code(),
        Some(2),
        "entry_missing must exit 2: stdout={} stderr={}",
        String::from_utf8_lossy(&v.stdout),
        String::from_utf8_lossy(&v.stderr)
    );
    assert!(
        String::from_utf8_lossy(&v.stdout).contains("entry_missing"),
        "stdout must contain 'entry_missing', got: {}",
        String::from_utf8_lossy(&v.stdout)
    );

    // unknown agent → usage error (exit 1), not a drift code
    let v = sigil(home, &state, &["verify", "--agent", "bogus"]);
    assert_eq!(
        v.status.code(),
        Some(1),
        "unknown agent must exit 1 (usage error): stdout={} stderr={}",
        String::from_utf8_lossy(&v.stdout),
        String::from_utf8_lossy(&v.stderr)
    );
    // lock the usage path itself, not just the exit code: cmd_verify emits
    // "sigil-hook verify: unsupported --agent '...'" to stderr.
    assert!(
        String::from_utf8_lossy(&v.stderr).contains("unsupported"),
        "bogus agent stderr: {}",
        String::from_utf8_lossy(&v.stderr)
    );
}

/// Completes the exit-code matrix (0 clean / 2 drift / 1 usage / 3 absent):
/// with no install, no baseline exists on disk → BaselineAbsent → exit 3.
#[test]
fn cursor_verify_baseline_absent_exits_3() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path();
    let state = home.join("state");
    // no install → no baseline on disk
    let v = sigil(home, &state, &["verify", "--agent", "cursor"]);
    assert_eq!(
        v.status.code(),
        Some(3),
        "missing baseline must exit 3 (baseline_absent): {}",
        String::from_utf8_lossy(&v.stdout)
    );
}
