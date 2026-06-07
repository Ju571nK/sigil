//! E2E (#100): `sigil-hook cursor --enforce` against a stub decide server.
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

/// Run `sigil-hook cursor --enforce --on-failure <mode>` with the given stdin.
fn run_cursor_enforce(
    socket: &std::path::Path,
    on_failure: &str,
    stdin_json: &str,
) -> (String, i32) {
    let exe = env!("CARGO_BIN_EXE_sigil-hook");
    let mut child = Command::new(exe)
        .args(["cursor", "--enforce", "--on-failure", on_failure])
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

fn wait_for_socket(path: &std::path::Path) {
    for _ in 0..50 {
        if path.exists() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Cursor `beforeShellExecution` stdin: top-level `command`, snake_case keys.
fn shell_stdin(cmd: &str) -> String {
    format!(
        r#"{{"hook_event_name":"beforeShellExecution","command":"{cmd}","conversation_id":"c","generation_id":"g","cwd":"/x"}}"#
    )
}

#[test]
fn cursor_deny_emits_permission_deny_json() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("hook-decide.sock");
    spawn_stub(socket.clone(), true);
    wait_for_socket(&socket);
    let (stdout, code) = run_cursor_enforce(&socket, "open", &shell_stdin("rm -rf /"));
    assert_eq!(code, 0, "hook must always exit 0");
    assert!(stdout.contains("\"permission\":\"deny\""), "got: {stdout}");
    assert!(stdout.contains("no-rm"), "got: {stdout}");
}

#[test]
fn cursor_allow_emits_permission_allow() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("hook-decide.sock");
    spawn_stub(socket.clone(), false);
    wait_for_socket(&socket);
    let (stdout, code) = run_cursor_enforce(&socket, "open", &shell_stdin("ls -la"));
    assert_eq!(code, 0);
    assert!(
        stdout.contains("\"permission\":\"allow\""),
        "allow must be explicit, got: {stdout}"
    );
    assert!(
        !stdout.contains("\"permission\":\"deny\""),
        "allow must not deny, got: {stdout}"
    );
}

#[test]
fn cursor_missing_socket_open_fails_open() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("absent.sock"); // never bound
    let (stdout, code) = run_cursor_enforce(&socket, "open", &shell_stdin("rm -rf /"));
    assert_eq!(code, 0);
    assert!(
        stdout.contains("\"permission\":\"allow\""),
        "fail-open now emits explicit allow, got: {stdout}"
    );
}

#[test]
fn cursor_missing_socket_closed_emits_deny() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("absent.sock"); // never bound
    let (stdout, code) = run_cursor_enforce(&socket, "closed", &shell_stdin("rm -rf /"));
    assert_eq!(code, 0);
    assert!(
        stdout.contains("\"permission\":\"deny\""),
        "fail-closed → deny, got: {stdout}"
    );
}
