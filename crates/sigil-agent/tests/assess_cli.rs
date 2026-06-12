//! Integration tests for `sigil assess` — cold-disk pre-flight verdict CLI.
//!
//! These tests cover the exit-code matrix and fail-closed behaviors described
//! in #149 Task 6.
//!
//! # Test strategy
//!
//! Heavy-lifting of exit-code mapping and input-validation is exercised in
//! unit tests inside `assess_cli.rs` (fast + deterministic). The integration
//! tests here run the real `sigil` binary via `CARGO_BIN_EXE_sigil` and cover
//! the observable contract:
//!   - `--command "ls -la"` → exit 0, JSON body has `"decision":"allow"`
//!   - `--command "rm -rf /tmp/x"` → exit 2, `"decision":"deny"`
//!   - `--command` + `--mcp-config` simultaneously → exit 1 (usage error)
//!   - command > 16 384 bytes → exit 1 (fail-closed oversize check)
//!   - `--mcp-stdin` with non-object JSON → exit 1 (fail-closed malformed MCP)
//!
//! The `--fail-on-warn` path is covered in the unit tests in `assess_cli.rs`.

#![cfg(feature = "operator-cli")]

use std::io::Write;
use std::process::{Command, Stdio};

fn sigil_bin() -> &'static str {
    env!("CARGO_BIN_EXE_sigil")
}

// ── helper: run `sigil assess` with extra args; optionally pipe `stdin_data` ──

fn run_assess(extra_args: &[&str], stdin_data: Option<&[u8]>) -> std::process::Output {
    let mut cmd = Command::new(sigil_bin());
    cmd.arg("assess");
    for a in extra_args {
        cmd.arg(a);
    }
    if stdin_data.is_some() {
        cmd.stdin(Stdio::piped());
    }
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let mut child = cmd.spawn().expect("failed to spawn sigil");
    if let Some(data) = stdin_data {
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(data)
            .expect("write stdin");
    }
    child.wait_with_output().expect("failed to wait")
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 1 — safe command → exit 0, decision=allow
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn assess_safe_command_exit_0() {
    let out = run_assess(&["--command", "ls", "--arg", "-la"], None);
    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout);

    assert_eq!(
        code,
        0,
        "ls -la should exit 0 (allow); stdout={stdout}\nstderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    // The JSON must be present and contain "decision":"allow"
    assert!(
        stdout.contains("\"decision\""),
        "stdout missing 'decision' field: {stdout}"
    );
    assert!(
        stdout.contains("\"allow\""),
        "stdout missing 'allow' decision: {stdout}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 2 — destructive command → exit 2, decision=deny
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn assess_destructive_command_exit_2() {
    let out = run_assess(
        &["--command", "rm", "--arg", "-rf", "--arg", "/tmp/x"],
        None,
    );
    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout);

    assert_eq!(
        code,
        2,
        "rm -rf /tmp/x should exit 2 (deny); stdout={stdout}\nstderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("\"deny\""),
        "stdout missing 'deny' decision: {stdout}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 3 — --command AND --mcp-config simultaneously → exit 1 (usage error)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn assess_command_xor_mcp_usage_error() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), b"{}").unwrap();

    let mcp_config_str = tmp.path().to_str().unwrap().to_string();
    let out = run_assess(&["--command", "ls", "--mcp-config", &mcp_config_str], None);
    let code = out.status.code().unwrap_or(-1);
    assert_eq!(
        code,
        1,
        "both --command and --mcp-config should exit 1; \
         stdout={}\nstderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 4 — command > 16 384 bytes → exit 1 (fail-closed oversize)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn assess_oversize_command_exit_1() {
    let big_command = "a".repeat(16_385);
    let out = run_assess(&["--command", &big_command], None);
    let code = out.status.code().unwrap_or(-1);
    assert_eq!(
        code,
        1,
        "oversize command should exit 1; \
         stdout={}\nstderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 5 — --mcp-stdin with non-object JSON → exit 1 (fail-closed)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn assess_invalid_mcp_json_exit_1() {
    // A JSON array is valid JSON but not an object — must be rejected as
    // malformed input (fail-closed: never produce Allow for unexpected shapes).
    let out = run_assess(
        &["--mcp-stdin", "--mcp-name", "bad-server"],
        Some(b"[1,2,3]"),
    );
    let code = out.status.code().unwrap_or(-1);
    assert_eq!(
        code,
        1,
        "--mcp-stdin with non-object JSON should exit 1; \
         stdout={}\nstderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 6 — neither --command nor --mcp-* → exit 1 (usage error)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn assess_no_input_mode_exit_1() {
    let out = run_assess(&[], None);
    let code = out.status.code().unwrap_or(-1);
    assert_eq!(
        code,
        1,
        "no input mode should exit 1; \
         stdout={}\nstderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 7 — mcp-stdin with empty JSON object → exit 0 or 2 (valid MCP, not exit 1)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn assess_mcp_stdin_empty_object_is_valid_input() {
    // An empty JSON object {} is a valid (if sparse) MCP definition — should NOT
    // exit 1. It may exit 0 (allow) or 2 (deny) depending on policy.
    let out = run_assess(
        &["--mcp-stdin", "--mcp-name", "minimal-server"],
        Some(b"{}"),
    );
    let code = out.status.code().unwrap_or(-1);
    assert!(
        code == 0 || code == 2,
        "empty-object MCP definition should exit 0 or 2, not {code}; \
         stdout={}\nstderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("\"decision\""),
        "stdout must contain a decision: {stdout}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 8 — mcp-stdin with MCP null JSON → exit 1 (fail-closed)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn assess_mcp_stdin_null_json_exit_1() {
    let out = run_assess(&["--mcp-stdin", "--mcp-name", "null-server"], Some(b"null"));
    let code = out.status.code().unwrap_or(-1);
    assert_eq!(
        code,
        1,
        "--mcp-stdin with null JSON should exit 1 (fail-closed); \
         stdout={}\nstderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}
