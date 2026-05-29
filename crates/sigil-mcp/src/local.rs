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
use sigil_core::control_proto::{DoctorAiGuardReport, Request, Response};
use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum LocalError {
    #[error(
        "local mode: no sigil-agent control socket at {0}: {1}. \
         Start a local agent, set SIGIL_AGENT_CONTROL_SOCKET, or set SIGIL_SERVER_BASE_URL for fleet mode."
    )]
    Connect(String, String),
    #[error("agent error: {0}")]
    Agent(String),
    #[error("agent returned no AI Guard report (built without operator-cli?)")]
    Empty,
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
    #[cfg(test)]
    pub fn new(socket: PathBuf) -> Self {
        Self { socket }
    }

    pub fn from_cfg(cfg: &LocalConfig) -> Self {
        Self {
            socket: cfg.socket.clone(),
        }
    }

    pub async fn doctor_report(&self) -> Result<DoctorAiGuardReport, LocalError> {
        let resp = self
            .query(&Request::DoctorAiGuardReport)
            .await
            .map_err(|e| LocalError::Connect(self.socket.display().to_string(), e.to_string()))?;
        if let Some(err) = resp.error {
            return Err(LocalError::Agent(err));
        }
        resp.doctor_ai_guard.ok_or(LocalError::Empty)
    }

    async fn query(&self, req: &Request) -> anyhow::Result<Response> {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        use tokio::net::UnixStream;
        let stream = UnixStream::connect(&self.socket).await?;
        let (rd, mut wr) = stream.into_split();
        let mut bytes = serde_json::to_vec(req)?;
        bytes.push(b'\n');
        wr.write_all(&bytes).await?;
        wr.shutdown().await.ok();
        let mut line = String::new();
        BufReader::new(rd).read_line(&mut line).await?;
        Ok(serde_json::from_str(line.trim())?)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use sigil_core::control_proto::{DoctorAiGuardReport, PerRepoSummary, Response};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

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
}
