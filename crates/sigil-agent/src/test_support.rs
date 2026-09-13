//! TestAgent — spawns a daemon under a tempdir for integration tests.

use crate::runtime::{self, RuntimeConfig};
use std::path::PathBuf;
use tempfile::TempDir;
use tokio::task::JoinHandle;

pub struct TestAgent {
    pub td: TempDir,
    pub events_dir: PathBuf,
    pub state_db: PathBuf,
    pub policy_file: PathBuf,
    pub control_socket: PathBuf,
    pub control_pipe_name: String,
    pub join: JoinHandle<()>,
}

pub struct TestAgentBuilder {
    policy_yaml: String,
    poll_watcher: bool,
    /// JSON bytes of a policy-signing keystore the agent should load. `None` →
    /// no keystore (Phase 1 mode; `apply_policy` rejects every envelope).
    keystore_json: Option<Vec<u8>>,
}

impl Default for TestAgentBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl TestAgentBuilder {
    pub fn new() -> Self {
        Self {
            policy_yaml: String::new(),
            poll_watcher: false,
            keystore_json: None,
        }
    }

    pub fn policy(mut self, yaml: &str) -> Self {
        self.policy_yaml = yaml.to_string();
        self
    }

    pub fn poll_watcher(mut self, enabled: bool) -> Self {
        self.poll_watcher = enabled;
        self
    }

    /// Give the agent a policy-signing keystore (JSON, as produced by
    /// `serde_json::to_vec(&sigil_core::policy::pubkeys::Keystore { .. })`), so
    /// `apply_policy` requests signed by a matching key are accepted.
    pub fn keystore_json(mut self, json: Vec<u8>) -> Self {
        self.keystore_json = Some(json);
        self
    }

    pub async fn start(self) -> TestAgent {
        let td = TempDir::new().expect("tempdir");
        let events_dir = td.path().join("events");
        let state_db = td.path().join("state.db");
        let policy_file = td.path().join("policy.yaml");
        std::fs::write(&policy_file, &self.policy_yaml).unwrap();
        let control_socket = td.path().join("control.sock");
        let control_pipe_name = format!(r"\\.\pipe\sigil-test-{}", uuid::Uuid::new_v4().simple());
        let keystore_path = self.keystore_json.as_ref().map(|json| {
            let p = td.path().join("policy-signing-pubkeys.pem");
            std::fs::write(&p, json).unwrap();
            p
        });
        let cfg = RuntimeConfig {
            policy_path: Some(policy_file.clone()),
            state_db_path: state_db.clone(),
            events_dir: events_dir.clone(),
            control_socket: control_socket.clone(),
            control_pipe_name: control_pipe_name.clone(),
            poll_watcher: self.poll_watcher,
            keystore_path,
        };
        let mut join = tokio::spawn(async move {
            let code = runtime::run(cfg).await.expect("test agent runtime failed");
            assert_eq!(code, 0, "test agent exited abnormally");
        });
        // Watch registration precedes control startup. Require a real response
        // on both transports; a fixed Windows settle delay races startup (#228).
        let secs = std::env::var("SIGIL_TEST_IPC_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(20);
        let ready = tokio::select! {
            ready = wait_for_control(&control_socket, &control_pipe_name, std::time::Duration::from_secs(secs)) => ready,
            result = &mut join => panic!("test agent exited before control IPC was ready: {result:?}"),
        };
        if !ready {
            join.abort();
            let _ = join.await;
            panic!("test agent control IPC was not ready within {secs} seconds");
        }
        // Small settle window for the OS watcher to start delivering events.
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        TestAgent {
            td,
            events_dir,
            state_db,
            policy_file,
            control_socket,
            control_pipe_name,
            join,
        }
    }
}

async fn wait_for_control(
    _socket: &std::path::Path,
    _pipe: &str,
    timeout: std::time::Duration,
) -> bool {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    tokio::time::timeout(timeout, async {
        loop {
            #[cfg(unix)]
            let connection = tokio::net::UnixStream::connect(_socket).await;
            #[cfg(windows)]
            let connection = tokio::net::windows::named_pipe::ClientOptions::new().open(_pipe);
            if let Ok(stream) = connection {
                let request = async {
                    let mut reader = BufReader::new(stream);
                    reader.get_mut().write_all(b"{\"cmd\":\"stats\"}\n").await?;
                    let mut line = String::new();
                    reader.read_line(&mut line).await?;
                    Ok::<_, std::io::Error>(
                        serde_json::from_str::<crate::control::Response>(&line)
                            .is_ok_and(|response| response.ok),
                    )
                };
                if matches!(
                    tokio::time::timeout(std::time::Duration::from_secs(1), request).await,
                    Ok(Ok(true))
                ) {
                    return;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .is_ok()
}

impl TestAgent {
    pub fn read_all_events(&self) -> Vec<serde_json::Value> {
        let mut out = Vec::new();
        let Ok(entries) = std::fs::read_dir(&self.events_dir) else {
            return out;
        };
        let mut paths: Vec<_> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("jsonl"))
            .collect();
        paths.sort();
        for p in paths {
            let s = std::fs::read_to_string(&p).unwrap_or_default();
            for line in s.lines() {
                if line.is_empty() {
                    continue;
                }
                if let Ok(v) = serde_json::from_str(line) {
                    out.push(v);
                }
            }
        }
        out
    }

    pub async fn wait_for_event<F: Fn(&serde_json::Value) -> bool>(
        &self,
        pred: F,
        timeout: std::time::Duration,
    ) -> Option<serde_json::Value> {
        let deadline = std::time::Instant::now() + timeout;
        while std::time::Instant::now() < deadline {
            for ev in self.read_all_events() {
                if pred(&ev) {
                    return Some(ev);
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        None
    }

    /// Send an `apply_policy` request over the agent's control socket; returns
    /// the raw JSON response line. (Unix only — the control IPC is a UDS there;
    /// the Windows named-pipe client path isn't needed by any test yet.)
    #[cfg(unix)]
    pub async fn apply_policy(
        &self,
        resp: &sigil_core::policy::signed_envelope::SignedPolicyResponse,
    ) -> String {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        use tokio::net::UnixStream;
        let req = serde_json::json!({
            "cmd": "apply_policy",
            "response": serde_json::to_value(resp).expect("serialize SignedPolicyResponse"),
        });
        let mut bytes = serde_json::to_vec(&req).unwrap();
        bytes.push(b'\n');
        let stream = UnixStream::connect(&self.control_socket)
            .await
            .expect("connect control socket");
        let (rd, mut wr) = stream.into_split();
        wr.write_all(&bytes).await.unwrap();
        wr.shutdown().await.ok();
        let mut line = String::new();
        BufReader::new(rd).read_line(&mut line).await.unwrap();
        line
    }

    /// Send an arbitrary control request as a JSON `Value` and return the
    /// parsed JSON response. Used by operator-introspection tests to drive
    /// `policy_status` / `targets` / `reload_policy` without going through the
    /// typed `Request` enum. (Unix only — same reason as `apply_policy`.)
    #[cfg(unix)]
    pub async fn control(&self, req: &serde_json::Value) -> serde_json::Value {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        use tokio::net::UnixStream;
        let mut bytes = serde_json::to_vec(req).unwrap();
        bytes.push(b'\n');
        let stream = UnixStream::connect(&self.control_socket)
            .await
            .expect("connect control socket");
        let (rd, mut wr) = stream.into_split();
        wr.write_all(&bytes).await.unwrap();
        wr.shutdown().await.ok();
        let mut line = String::new();
        BufReader::new(rd).read_line(&mut line).await.unwrap();
        serde_json::from_str(line.trim()).expect("response is valid JSON")
    }
}

#[cfg(test)]
mod readiness_tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    #[tokio::test]
    async fn waits_for_delayed_listener_instead_of_a_fixed_settle_delay() {
        let td = TempDir::new().unwrap();
        let socket = td.path().join("control.sock");
        let pipe = format!(r"\\.\pipe\sigil-ready-{}", uuid::Uuid::new_v4().simple());
        let (start_tx, start_rx) = tokio::sync::oneshot::channel();
        #[cfg(unix)]
        let endpoint = socket.clone();
        #[cfg(windows)]
        let endpoint = pipe.clone();
        let server = tokio::spawn(async move {
            start_rx.await.unwrap();
            #[cfg(unix)]
            let stream = {
                let listener = tokio::net::UnixListener::bind(endpoint).unwrap();
                listener.accept().await.unwrap().0
            };
            #[cfg(windows)]
            let stream = {
                let server = tokio::net::windows::named_pipe::ServerOptions::new()
                    .create(endpoint)
                    .unwrap();
                server.connect().await.unwrap();
                server
            };
            let mut reader = BufReader::new(stream);
            let mut request = String::new();
            reader.read_line(&mut request).await.unwrap();
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&request).unwrap()["cmd"],
                "stats"
            );
            reader
                .get_mut()
                .write_all(b"{\"ok\":true}\n")
                .await
                .unwrap();
            reader.get_mut().flush().await.unwrap();
        });
        let ready = wait_for_control(&socket, &pipe, Duration::from_secs(5));
        tokio::pin!(ready);
        assert!(tokio::time::timeout(Duration::from_millis(300), &mut ready)
            .await
            .is_err());
        start_tx.send(()).unwrap();
        assert!(ready.await);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn missing_listener_has_a_bounded_readiness_deadline() {
        let td = TempDir::new().unwrap();
        let pipe = format!(r"\\.\pipe\sigil-absent-{}", uuid::Uuid::new_v4().simple());
        assert!(
            !wait_for_control(
                &td.path().join("absent.sock"),
                &pipe,
                Duration::from_millis(50)
            )
            .await
        );
    }
}
