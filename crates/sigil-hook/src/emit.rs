use std::path::Path;
use std::time::Duration;

/// Best-effort one-line emit. NEVER returns Err for a normal failure (agent
/// down, reset, pipe broken) — those are success from the agent's POV.
///
/// `write_timeout` is applied via `set_write_timeout` on the stream.
/// NOTE: `UnixStream::connect()` itself is NOT separately bounded — the
/// caller's process watchdog (`arm_watchdog`) is the backstop for a stuck
/// connect.
#[cfg(unix)]
pub fn send_envelope(socket: &Path, line: &str, write_timeout: Duration) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::net::UnixStream;
    let stream = match UnixStream::connect(socket) {
        Ok(s) => s,
        Err(_) => return Ok(()), // agent down / socket missing → silent success
    };
    stream.set_write_timeout(Some(write_timeout)).ok();
    let mut stream = stream;
    let _ = stream.write_all(line.as_bytes());
    let _ = stream.write_all(b"\n");
    Ok(())
}

/// Non-unix stub. The agent's IPC on Windows is a named pipe (see `control.rs`'s
/// `#[cfg(windows)]` path); Stage 1 does not wire a named-pipe hook emit yet, so
/// the emit is a no-op here (fail-open, consistent with a down agent). Named-pipe
/// emit is a follow-up.
#[cfg(not(unix))]
pub fn send_envelope(_socket: &Path, _line: &str, _write_timeout: Duration) -> std::io::Result<()> {
    Ok(())
}

/// Spawn a watchdog that hard-exits 0 after `budget`, so even a pathological
/// blocking stdin read cannot stall the agent's tool call.
pub fn arm_watchdog(budget: Duration) {
    std::thread::spawn(move || {
        std::thread::sleep(budget);
        std::process::exit(0);
    });
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    #[test]
    fn emit_to_missing_socket_is_ok() {
        let path = std::path::Path::new("/nonexistent/sigil/hook.sock");
        assert!(send_envelope(path, "{\"x\":1}", std::time::Duration::from_millis(150)).is_ok());
    }
}
