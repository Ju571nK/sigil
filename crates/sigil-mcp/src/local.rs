//! Local-mode upstream: talks to a co-located `sigil-agent` over its control
//! socket instead of the fleet read API. Read-only — fetches the AI Guard
//! report via [`Request::DoctorAiGuardReport`]. The transport mirrors
//! `sigil-agent`'s `control_client::query_unix`: connect, write one
//! newline-terminated JSON request, shut down the write half so the agent sees
//! EOF, then read one newline-terminated JSON `Response`.
//!
//! Consumed by [`crate::local_tools::SigilLocal`]; `main` builds it via
//! [`LocalUpstream::from_cfg`] in local mode.

use crate::config::LocalConfig;
use rmcp::ErrorData as McpError;
use sigil_core::assess::AssessInput;
use sigil_core::control_proto::{AssessVerdict, DoctorAiGuardReport, Request, Response};
use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum LocalError {
    #[error(
        "local mode: cannot reach the sigil-agent control socket at {0}: {1}. \
         Start a local agent, set SIGIL_AGENT_CONTROL_SOCKET, or set SIGIL_SERVER_BASE_URL for fleet mode."
    )]
    Connect(String, String),
    /// The socket's peer is neither root nor this user — likely a different
    /// local user impersonating the agent. We refuse to report its data rather
    /// than surface a posture we can't trust (#57).
    #[error(
        "local mode: refusing to trust the control socket at {socket}: its peer runs as uid {peer}, \
         not root or this user (uid {self_uid}). Another local user may have created a fake socket."
    )]
    UntrustedPeer {
        socket: String,
        peer: u32,
        self_uid: u32,
    },
    #[error("agent error: {0}")]
    Agent(String),
    #[error("agent returned no AI Guard report (built without operator-cli?)")]
    Empty,
    #[error("agent returned no assess verdict (built without operator-cli?)")]
    EmptyVerdict,
}

/// The control socket is trusted only if its peer is root (the system agent) or
/// the same user as this process (the individual-developer case). Any other
/// local user owning the socket is treated as a spoofing attempt (#57).
#[cfg(unix)]
fn peer_trusted(peer_euid: u32, self_uid: u32) -> bool {
    peer_euid == 0 || peer_euid == self_uid
}

impl From<LocalError> for McpError {
    fn from(e: LocalError) -> Self {
        McpError::internal_error(e.to_string(), None)
    }
}

#[derive(Clone)]
pub struct LocalUpstream {
    socket: PathBuf,
}

impl LocalUpstream {
    /// Construct directly from a socket path. Test-only: `main` builds via
    /// [`LocalUpstream::from_cfg`]; this is exercised by the canned-agent tests
    /// here and in `local_tools`.
    #[cfg(all(test, unix))]
    pub fn new(socket: PathBuf) -> Self {
        Self { socket }
    }

    pub fn from_cfg(cfg: &LocalConfig) -> Self {
        Self {
            socket: cfg.socket.clone(),
        }
    }

    pub async fn doctor_report(&self) -> Result<DoctorAiGuardReport, LocalError> {
        let resp = self.query(&Request::DoctorAiGuardReport).await?;
        if let Some(err) = resp.error {
            return Err(LocalError::Agent(err));
        }
        resp.doctor_ai_guard.ok_or(LocalError::Empty)
    }

    /// Ask the running `sigil-agent` to evaluate a proposed command or MCP
    /// server definition against its LIVE loaded policy. Phase 3b.9 (#149).
    #[allow(dead_code)] // consumed by sigil-mcp tool wiring in a follow-on task
    pub async fn assess(&self, input: AssessInput) -> Result<AssessVerdict, LocalError> {
        let resp = self.query(&Request::Assess { input }).await?;
        if let Some(err) = resp.error {
            return Err(LocalError::Agent(err));
        }
        resp.assess_verdict.ok_or(LocalError::EmptyVerdict)
    }

    /// Build a `Connect` error tagged with the socket path.
    fn conn(&self, detail: impl std::fmt::Display) -> LocalError {
        LocalError::Connect(self.socket.display().to_string(), detail.to_string())
    }

    /// Verify the connected peer is root or this user before trusting any data
    /// it sends. Closes the spoofing gap where another local user could bind a
    /// fake control socket at a predictable path (#57). Uses tokio's portable
    /// peer-credential lookup (SO_PEERCRED on Linux, getpeereid on macOS).
    #[cfg(unix)]
    fn verify_peer(&self, cred: tokio::net::unix::UCred) -> Result<(), LocalError> {
        let peer = cred.uid();
        // SAFETY: getuid is always safe and cannot fail.
        let self_uid = unsafe { libc::getuid() };
        if !peer_trusted(peer, self_uid) {
            return Err(LocalError::UntrustedPeer {
                socket: self.socket.display().to_string(),
                peer,
                self_uid,
            });
        }
        Ok(())
    }

    #[cfg(unix)]
    async fn query(&self, req: &Request) -> Result<Response, LocalError> {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        use tokio::net::UnixStream;
        let stream = UnixStream::connect(&self.socket)
            .await
            .map_err(|e| self.conn(e))?;
        // Authenticate the peer before sending or trusting anything.
        let cred = stream.peer_cred().map_err(|e| self.conn(e))?;
        self.verify_peer(cred)?;
        let (rd, mut wr) = stream.into_split();
        let mut bytes = serde_json::to_vec(req).map_err(|e| self.conn(e))?;
        bytes.push(b'\n');
        wr.write_all(&bytes).await.map_err(|e| self.conn(e))?;
        wr.shutdown().await.ok();
        let mut line = String::new();
        BufReader::new(rd)
            .read_line(&mut line)
            .await
            .map_err(|e| self.conn(e))?;
        serde_json::from_str(line.trim()).map_err(|e| self.conn(format!("malformed reply: {e}")))
    }

    // Local mode reads the agent's Unix control socket. Windows uses a named
    // pipe for that socket; wiring sigil-mcp to it is tracked separately (the
    // spec scopes local mode to Unix for v1). On Windows, use fleet mode
    // (SIGIL_SERVER_BASE_URL). This stub keeps the crate compiling there.
    #[cfg(not(unix))]
    async fn query(&self, req: &Request) -> Result<Response, LocalError> {
        let _ = req;
        Err(self.conn(
            "local mode is only supported on Unix in v1; \
             set SIGIL_SERVER_BASE_URL to use fleet mode on this platform",
        ))
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use sigil_core::assess::{AssessInput, AssessVerdict, Decision};
    use sigil_core::control_proto::{DoctorAiGuardReport, PerRepoSummary, Response};
    use sigil_core::event::AiGuardBucket;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    #[test]
    fn peer_trusted_accepts_root_and_self_rejects_others() {
        assert!(peer_trusted(0, 501), "root agent is trusted");
        assert!(peer_trusted(501, 501), "same user is trusted");
        assert!(
            !peer_trusted(1001, 501),
            "a different local user is rejected"
        );
    }

    #[tokio::test]
    async fn doctor_report_round_trips_against_canned_agent() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("control.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let srv = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (rd, mut wr) = stream.into_split();
            let mut line = String::new();
            BufReader::new(rd).read_line(&mut line).await.unwrap();
            assert_eq!(line.trim(), r#"{"cmd":"doctor_ai_guard_report"}"#);
            let resp = Response {
                ok: true,
                stats: None,
                apply_policy: None,
                policy_status: None,
                targets: None,
                risk: None,
                error: None,
                doctor_ai_guard: Some(DoctorAiGuardReport {
                    parsers: vec![],
                    rule_packs: vec![],
                    ext_scripts: Default::default(),
                    per_repo: PerRepoSummary {
                        continue_dev: 0,
                        claude_code: 2,
                        codex: 0,
                    },
                    latest_risk: vec![],
                    effective_rubric: vec![],
                    unknown_override_keys: vec![],
                }),
                assess_verdict: None,
            };
            let mut bytes = serde_json::to_vec(&resp).unwrap();
            bytes.push(b'\n');
            wr.write_all(&bytes).await.unwrap();
        });
        let up = LocalUpstream::new(socket);
        let rep = up.doctor_report().await.unwrap();
        assert_eq!(rep.per_repo.claude_code, 2);
        srv.await.unwrap();
    }

    #[tokio::test]
    async fn errors_when_socket_absent() {
        let dir = tempfile::tempdir().unwrap();
        let up = LocalUpstream::new(dir.path().join("nope.sock"));
        assert!(up.doctor_report().await.is_err());
    }

    /// TDD (#149): canned in-process server returns a known AssessVerdict;
    /// client must deserialize it and round-trip the verdict correctly.
    #[tokio::test]
    async fn assess_round_trips_against_canned_agent() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("assess_control.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let srv = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (rd, mut wr) = stream.into_split();
            let mut line = String::new();
            BufReader::new(rd).read_line(&mut line).await.unwrap();
            // Verify the wire verb is "assess"
            let trimmed = line.trim();
            assert!(
                trimmed.contains("\"cmd\":\"assess\""),
                "expected assess cmd, got: {trimmed}"
            );
            assert!(
                trimmed.contains("\"kind\":\"command\""),
                "expected command kind, got: {trimmed}"
            );
            let resp = Response {
                ok: true,
                stats: None,
                apply_policy: None,
                policy_status: None,
                targets: None,
                risk: None,
                error: None,
                doctor_ai_guard: None,
                assess_verdict: Some(AssessVerdict {
                    bucket: AiGuardBucket::High,
                    score: 4.0,
                    reasons: vec![],
                    deny_match: None,
                    decision: Decision::Deny,
                }),
            };
            let mut bytes = serde_json::to_vec(&resp).unwrap();
            bytes.push(b'\n');
            wr.write_all(&bytes).await.unwrap();
        });
        let up = LocalUpstream::new(socket);
        let input = AssessInput::Command {
            command: "rm".into(),
            args: vec!["-rf".into(), "/tmp/x".into()],
        };
        let verdict = up.assess(input).await.unwrap();
        assert_eq!(verdict.decision, Decision::Deny);
        assert_eq!(verdict.bucket, AiGuardBucket::High);
        assert_eq!(verdict.score, 4.0);
        srv.await.unwrap();
    }
}
