//! Tiny synchronous client for the agent's control IPC. Used by `sigil show
//! stats|policy-status|targets` and `sigil reload`.

use crate::control::{Request, Response};

/// Connect to the running daemon, send `req`, return its `Response`. Wraps
/// `query_async` with a current-thread tokio runtime so sync `main`/CLI
/// contexts can use it without an `.await`.
pub fn query(req: &Request) -> anyhow::Result<Response> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(query_async(req))
}

async fn query_async(req: &Request) -> anyhow::Result<Response> {
    #[cfg(unix)]
    {
        let socket = crate::control::default_control_socket();
        query_unix(&socket, req).await.map_err(|e| {
            anyhow::anyhow!(
                "cannot reach the sigil daemon at {}: {e} (is `sigil run` running?)",
                socket.display()
            )
        })
    }
    #[cfg(windows)]
    {
        let pipe = crate::control::default_control_pipe_name();
        query_windows(&pipe, req).await.map_err(|e| {
            anyhow::anyhow!(
                "cannot reach the sigil daemon at {pipe}: {e} (is `sigil run` running?)"
            )
        })
    }
}

#[cfg(unix)]
pub(crate) async fn query_unix(
    socket: &std::path::Path,
    req: &Request,
) -> anyhow::Result<Response> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixStream;
    let stream = UnixStream::connect(socket).await?;
    let (rd, mut wr) = stream.into_split();
    let mut bytes = serde_json::to_vec(req)?;
    bytes.push(b'\n');
    wr.write_all(&bytes).await?;
    wr.shutdown().await.ok();
    let mut line = String::new();
    BufReader::new(rd).read_line(&mut line).await?;
    Ok(serde_json::from_str(line.trim())?)
}

#[cfg(windows)]
pub(crate) async fn query_windows(pipe_name: &str, req: &Request) -> anyhow::Result<Response> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::windows::named_pipe::ClientOptions;
    let mut client = ClientOptions::new().open(pipe_name)?;
    let mut bytes = serde_json::to_vec(req)?;
    bytes.push(b'\n');
    client.write_all(&bytes).await?;
    client.flush().await?;
    let mut line = String::new();
    BufReader::new(&mut client).read_line(&mut line).await?;
    Ok(serde_json::from_str(line.trim())?)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::control::Response;
    use sigil_core::stats::StatsSnapshot;
    use std::collections::BTreeMap;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    #[tokio::test]
    async fn query_unix_round_trips_stats_against_a_canned_server() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("control.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (rd, mut wr) = stream.into_split();
            let mut line = String::new();
            BufReader::new(rd).read_line(&mut line).await.unwrap();
            assert_eq!(line.trim(), r#"{"cmd":"stats"}"#);
            let resp = Response {
                ok: true,
                stats: Some(StatsSnapshot {
                    events_emitted_total: 7,
                    channel_stall_events_total: 1,
                    events_by_kind: BTreeMap::new(),
                    hash_p50_ms: 0,
                    hash_p99_ms: 0,
                }),
                apply_policy: None,
                policy_status: None,
                targets: None,
                risk: None,
                #[cfg(feature = "operator-cli")]
                doctor_ai_guard: None,
                error: None,
            };
            let mut bytes = serde_json::to_vec(&resp).unwrap();
            bytes.push(b'\n');
            wr.write_all(&bytes).await.unwrap();
        });

        let resp = query_unix(&socket, &Request::Stats).await.unwrap();
        let snap = resp.stats.unwrap();
        assert_eq!(snap.events_emitted_total, 7);
        assert_eq!(snap.channel_stall_events_total, 1);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn query_unix_errors_when_socket_absent() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("nope.sock");
        assert!(query_unix(&socket, &Request::Stats).await.is_err());
    }

    #[cfg(feature = "operator-cli")]
    #[tokio::test]
    async fn query_unix_round_trips_targets_against_a_canned_server() {
        use crate::control::{TargetSummary, TargetsPayload};
        use sigil_core::policy::Tier;
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("control.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (rd, mut wr) = stream.into_split();
            let mut line = String::new();
            BufReader::new(rd).read_line(&mut line).await.unwrap();
            assert_eq!(line.trim(), r#"{"cmd":"targets"}"#);
            let resp = Response {
                ok: true,
                stats: None,
                apply_policy: None,
                policy_status: None,
                targets: Some(TargetsPayload {
                    targets: vec![TargetSummary {
                        id: "etc-shadow".to_string(),
                        tier: Tier::Critical,
                        globs: vec!["/etc/shadow".to_string()],
                    }],
                }),
                risk: None,
                doctor_ai_guard: None,
                error: None,
            };
            let mut bytes = serde_json::to_vec(&resp).unwrap();
            bytes.push(b'\n');
            wr.write_all(&bytes).await.unwrap();
        });

        let resp = query_unix(&socket, &Request::Targets).await.unwrap();
        let payload = resp.targets.unwrap();
        assert_eq!(payload.targets.len(), 1);
        assert_eq!(payload.targets[0].id, "etc-shadow");
        assert_eq!(payload.targets[0].tier, Tier::Critical);
        assert_eq!(payload.targets[0].globs, vec!["/etc/shadow".to_string()]);
        server.await.unwrap();
    }
}
