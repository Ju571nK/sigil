//! Stage 2 (#100): hook-side synchronous decision transport. Blocking std
//! sockets (the hook is a short-lived process; no tokio). Any failure → None
//! so the caller falls back to its local on_failure mode.
use sigil_core::hook_proto::{HookDecisionRequest, HookVerdict};
use std::path::Path;
use std::time::Duration;

// called by the claude-code enforce path (Task 9)
#[cfg(unix)]
pub fn request_verdict(
    socket: &Path,
    req: &HookDecisionRequest,
    deadline: Duration,
) -> Option<HookVerdict> {
    // unix-only imports kept local so the non-unix stub doesn't trip unused-import.
    use sigil_core::hook_proto::HookDecisionResponse;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;
    let stream = UnixStream::connect(socket).ok()?;
    stream.set_read_timeout(Some(deadline)).ok()?;
    stream.set_write_timeout(Some(deadline)).ok()?;
    // set_*_timeout is a socket-level option (SO_RCVTIMEO/SO_SNDTIMEO); try_clone inherits it on the dup'd fd.
    let mut w = stream.try_clone().ok()?;
    let mut line = serde_json::to_string(req).ok()?;
    line.push('\n');
    w.write_all(line.as_bytes()).ok()?;
    w.flush().ok()?;
    let mut resp = String::new();
    // Single-line response; read_line completes in one syscall on a domain socket, so deadline-per-read is acceptable for slice 1.
    BufReader::new(stream).read_line(&mut resp).ok()?;
    let parsed: HookDecisionResponse = serde_json::from_str(resp.trim()).ok()?;
    Some(parsed.verdict)
}

// called by the claude-code enforce path (Task 9)
#[cfg(not(unix))]
pub fn request_verdict(
    _socket: &Path,
    _req: &HookDecisionRequest,
    _deadline: Duration,
) -> Option<HookVerdict> {
    None // Windows enforce is out of scope (slice 1): always fall back to on_failure.
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    #[test]
    fn missing_socket_returns_none() {
        let req = sample_req();
        let v = request_verdict(
            Path::new("/nonexistent/sigil/hook-decide.sock"),
            &req,
            Duration::from_millis(100),
        );
        assert!(v.is_none());
    }
    fn sample_req() -> HookDecisionRequest {
        use sigil_core::hook_proto::*;
        HookDecisionRequest {
            protocol_version: HOOK_PROTOCOL_VERSION,
            request_id: uuid::Uuid::nil(),
            sent_at_unix_ms: 0,
            invocation: HookInvocation {
                agent: sigil_core::event::AiTool::ClaudeCode,
                agent_session_id: None,
                tool_use_id: None,
                action: HookAction::Bash {
                    command_hash: "ab".repeat(32),
                    command_preview: Some("x".into()),
                },
                capture_level: CaptureLevel::Redacted,
                capture_status: CaptureStatus::Ok,
                cwd: None,
            },
            deadline_ms: 100,
        }
    }
}
