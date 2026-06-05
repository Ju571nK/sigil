//! E2E (#100): `sigil-hook codex --enforce` against a stub decide server.
#![cfg(unix)]
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::process::{Command, Stdio};
use std::time::Duration;

/// One-shot stub: accept one connection, read the request line, reply with a
/// fixed verdict. `deny` chooses the verdict.
fn spawn_stub(socket: std::path::PathBuf, deny: bool) {
    std::thread::spawn(move || {
        let listener = UnixListener::bind(&socket).unwrap();
        if let Ok((mut s, _)) = listener.accept() {
            let mut line = String::new();
            BufReader::new(s.try_clone().unwrap())
                .read_line(&mut line)
                .unwrap();
            // Build the response with the EXACT verified wire shape.
            // HookDecisionResponse { protocol_version, request_id, verdict: HookVerdict { decision, enforcement_mode } }
            // Decision is serde(tag = "kind", rename_all = "snake_case"):
            //   Deny { rule_id, reason } → {"kind":"deny","rule_id":"...","reason":"..."}
            //   Allow → {"kind":"allow"}
            let decision = if deny {
                r#"{"kind":"deny","rule_id":"no-rm","reason":"destructive"}"#
            } else {
                r#"{"kind":"allow"}"#
            };
            let resp = format!(
                r#"{{"protocol_version":2,"request_id":"00000000-0000-0000-0000-000000000000","verdict":{{"decision":{decision},"enforcement_mode":"enforce"}}}}"#
            );
            writeln!(s, "{resp}").unwrap();
        }
    });
}

fn run_codex_enforce(socket: &std::path::Path, stdin_json: &str) -> (String, i32) {
    let exe = env!("CARGO_BIN_EXE_sigil-hook");
    let mut child = Command::new(exe)
        .args(["codex", "--enforce", "--on-failure", "open"])
        .env("SIGIL_HOOK_DECIDE_SOCKET", socket)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin_json.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        out.status.code().unwrap_or(-1),
    )
}

/// Poll until the stub's listening socket appears (guards the bind race between
/// the spawned stub thread and the hook process connecting).
fn wait_for_socket(path: &std::path::Path) {
    for _ in 0..50 {
        if path.exists() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Build a codex Bash stdin payload.
/// Codex reuses the Claude Code hook shape: `tool_name` + `tool_input.command`.
/// Verified against adapters/codex.rs normalize():
///   - top-level key "tool_name" → tool dispatch
///   - top-level key "tool_input" → nested object
///   - "tool_input"."command" → Bash command string (HookAction::Bash branch)
// NOTE: cmd must not contain `"` or `\` — interpolated raw into JSON (fine for the simple test commands here).
fn bash_stdin(cmd: &str) -> String {
    format!(r#"{{"tool_name":"Bash","tool_input":{{"command":"{cmd}"}}}}"#)
}

#[test]
fn codex_deny_emits_permission_decision_json() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("hook-decide.sock");
    spawn_stub(socket.clone(), true);
    wait_for_socket(&socket);
    let (stdout, code) = run_codex_enforce(&socket, &bash_stdin("rm -rf /"));
    assert_eq!(code, 0, "hook must always exit 0");
    assert!(
        stdout.contains("\"permissionDecision\":\"deny\""),
        "got: {stdout}"
    );
    assert!(stdout.contains("no-rm"));
}

#[test]
fn codex_allow_is_silent() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("hook-decide.sock");
    spawn_stub(socket.clone(), false);
    wait_for_socket(&socket);
    let (stdout, code) = run_codex_enforce(&socket, &bash_stdin("ls -la"));
    assert_eq!(code, 0);
    assert!(
        stdout.trim().is_empty(),
        "allow must print nothing, got: {stdout}"
    );
}

#[test]
fn codex_missing_socket_fails_open() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("absent.sock"); // never bound
    let (stdout, code) = run_codex_enforce(&socket, &bash_stdin("rm -rf /"));
    assert_eq!(code, 0);
    assert!(
        stdout.trim().is_empty(),
        "fail-open (on_failure=open) → allow, no output"
    );
}
