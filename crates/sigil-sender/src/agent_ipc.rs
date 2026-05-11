//! IPC client: connects to sigil-agent's control socket/pipe and
//! invokes `apply_policy`.

use crate::wire::SignedPolicyResponse;
use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;

#[derive(Serialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
enum AgentRequest<'a> {
    ApplyPolicy { response: &'a SignedPolicyResponse },
}

#[derive(Deserialize, Debug)]
pub struct AgentResponse {
    pub ok: bool,
    pub apply_policy: Option<ApplyPolicyResult>,
    pub error: Option<String>,
}

#[derive(Deserialize, Debug)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ApplyPolicyResult {
    Accepted { applied_policy_version: i64 },
    Rejected { reason: String },
}

#[derive(Debug, Error)]
pub enum IpcError {
    #[error("connect {path}: {source}")]
    Connect {
        path: std::path::PathBuf,
        source: std::io::Error,
    },
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("response parse: {0}")]
    Parse(#[from] serde_json::Error),
}

#[cfg(unix)]
pub async fn apply_policy(
    socket_path: &Path,
    response: &SignedPolicyResponse,
) -> Result<AgentResponse, IpcError> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixStream;
    let stream = UnixStream::connect(socket_path)
        .await
        .map_err(|source| IpcError::Connect {
            path: socket_path.to_path_buf(),
            source,
        })?;
    let (rd, mut wr) = stream.into_split();
    let req = AgentRequest::ApplyPolicy { response };
    let mut req_bytes = serde_json::to_vec(&req)?;
    req_bytes.push(b'\n');
    wr.write_all(&req_bytes).await?;
    wr.shutdown().await.ok();
    let mut buf = String::new();
    BufReader::new(rd).read_line(&mut buf).await?;
    let parsed: AgentResponse = serde_json::from_str(buf.trim())?;
    Ok(parsed)
}

#[cfg(windows)]
pub async fn apply_policy(
    pipe_name: &Path,
    response: &SignedPolicyResponse,
) -> Result<AgentResponse, IpcError> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::windows::named_pipe::ClientOptions;
    let pipe_str = pipe_name.to_string_lossy().to_string();
    let mut client = ClientOptions::new()
        .open(pipe_str.as_str())
        .map_err(|source| IpcError::Connect {
            path: pipe_name.to_path_buf(),
            source,
        })?;
    let req = AgentRequest::ApplyPolicy { response };
    let mut req_bytes = serde_json::to_vec(&req)?;
    req_bytes.push(b'\n');
    client.write_all(&req_bytes).await?;
    client.flush().await?;
    let mut buf = String::new();
    BufReader::new(&mut client).read_line(&mut buf).await?;
    let parsed: AgentResponse = serde_json::from_str(buf.trim())?;
    Ok(parsed)
}
