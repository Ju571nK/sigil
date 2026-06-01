use std::io::Write;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

/// Best-effort one-line emit. NEVER returns Err for a normal failure (agent
/// down, reset, pipe broken) — those are success from the agent's POV.
pub fn send_envelope(socket: &Path, line: &str, connect_timeout: Duration) -> std::io::Result<()> {
    let stream = match UnixStream::connect(socket) {
        Ok(s) => s,
        Err(_) => return Ok(()), // agent down / socket missing → silent success
    };
    stream.set_write_timeout(Some(connect_timeout)).ok();
    let mut stream = stream;
    let _ = stream.write_all(line.as_bytes());
    let _ = stream.write_all(b"\n");
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn emit_to_missing_socket_is_ok() {
        let path = std::path::Path::new("/nonexistent/sigil/hook.sock");
        assert!(send_envelope(path, "{\"x\":1}", std::time::Duration::from_millis(150)).is_ok());
    }
}
