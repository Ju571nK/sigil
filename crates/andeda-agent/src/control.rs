//! Control IPC: UDS on Unix, Named Pipe on Windows.
//!
//! Phase 1 supports a single command: `{"cmd":"stats"}` returning the current
//! Heartbeat-equivalent payload as JSON.

use andeda_core::stats::{Stats, StatsSnapshot};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "cmd", rename_all = "lowercase")]
pub enum Request {
    Stats,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Response {
    pub ok: bool,
    pub stats: Option<StatsSnapshot>,
    pub error: Option<String>,
}

#[cfg(unix)]
pub async fn serve(socket_path: &Path, stats: Arc<Stats>) -> std::io::Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixListener;

    if socket_path.exists() {
        let _ = std::fs::remove_file(socket_path);
    }
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let listener = UnixListener::bind(socket_path)?;
    tracing::info!(path = ?socket_path, "control IPC listening");
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = ?e, "control IPC accept failed");
                continue;
            }
        };
        let stats = stats.clone();
        tokio::spawn(async move {
            let (rd, mut wr) = stream.into_split();
            let mut reader = BufReader::new(rd);
            let mut line = String::new();
            if reader.read_line(&mut line).await.is_err() {
                return;
            }
            let resp = match serde_json::from_str::<Request>(line.trim()) {
                Ok(Request::Stats) => Response {
                    ok: true,
                    stats: Some(stats.snapshot()),
                    error: None,
                },
                Err(e) => Response {
                    ok: false,
                    stats: None,
                    error: Some(e.to_string()),
                },
            };
            if let Ok(json) = serde_json::to_string(&resp) {
                let _ = wr.write_all(json.as_bytes()).await;
                let _ = wr.write_all(b"\n").await;
            }
        });
    }
}

#[cfg(windows)]
pub async fn serve(pipe_name: &str, stats: Arc<Stats>) -> std::io::Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::windows::named_pipe::ServerOptions;

    loop {
        let server = ServerOptions::new()
            .first_pipe_instance(false)
            .access_inbound(true)
            .access_outbound(true)
            .create(pipe_name)?;
        server.connect().await?;
        let stats = stats.clone();
        tokio::spawn(async move {
            let (rd, mut wr) = tokio::io::split(server);
            let mut reader = BufReader::new(rd);
            let mut line = String::new();
            if reader.read_line(&mut line).await.is_err() {
                return;
            }
            let resp = match serde_json::from_str::<Request>(line.trim()) {
                Ok(Request::Stats) => Response {
                    ok: true,
                    stats: Some(stats.snapshot()),
                    error: None,
                },
                Err(e) => Response {
                    ok: false,
                    stats: None,
                    error: Some(e.to_string()),
                },
            };
            if let Ok(json) = serde_json::to_string(&resp) {
                let _ = wr.write_all(json.as_bytes()).await;
                let _ = wr.write_all(b"\n").await;
            }
        });
    }
}
