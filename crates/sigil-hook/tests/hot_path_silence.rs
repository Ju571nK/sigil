//! Integration test: the sigil-hook binary must exit 0 and produce no output
//! (stdout or stderr) even when fed garbage/invalid input on stdin.
//!
//! Covers both the fail-open invariant (spec §7: exit 0 so the agent's tool
//! call is never blocked) and the silence invariant (the panic hook suppresses
//! output, and normal parse failures are also silent).

use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn garbage_stdin_exits_zero_with_no_output() {
    // Feed clearly-invalid UTF-8 bytes to sigil-hook claude-code.
    // The binary must: (a) exit with status 0, (b) write nothing to stdout,
    // (c) write nothing to stderr.
    let mut child = Command::new(env!("CARGO_BIN_EXE_sigil-hook"))
        .arg("claude-code")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn sigil-hook");

    // Write invalid UTF-8 followed by clearly non-JSON garbage.
    if let Some(mut stdin) = child.stdin.take() {
        let garbage: &[u8] = b"\xFF\xFE not json at all \x00\x80";
        let _ = stdin.write_all(garbage);
        // Drop closes stdin so the process sees EOF.
    }

    let output = child
        .wait_with_output()
        .expect("failed to wait for sigil-hook");

    assert!(
        output.status.success(),
        "sigil-hook must exit 0 on garbage input; got: {:?}",
        output.status
    );
    assert!(
        output.stdout.is_empty(),
        "sigil-hook must produce no stdout; got: {:?}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        output.stderr.is_empty(),
        "sigil-hook must produce no stderr; got: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn not_json_string_exits_zero_with_no_output() {
    // Also test with a plain ASCII non-JSON string to confirm the json parse
    // failure path is also silent.
    let mut child = Command::new(env!("CARGO_BIN_EXE_sigil-hook"))
        .arg("claude-code")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn sigil-hook");

    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(b"not json");
    }

    let output = child
        .wait_with_output()
        .expect("failed to wait for sigil-hook");

    assert!(
        output.status.success(),
        "sigil-hook must exit 0 on non-JSON input; got: {:?}",
        output.status
    );
    assert!(
        output.stdout.is_empty(),
        "sigil-hook must produce no stdout on non-JSON input; got: {:?}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        output.stderr.is_empty(),
        "sigil-hook must produce no stderr on non-JSON input; got: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
}
