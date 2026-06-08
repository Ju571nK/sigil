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
            keystore_json: None,
        }
    }

    pub fn policy(mut self, yaml: &str) -> Self {
        self.policy_yaml = yaml.to_string();
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
            poll_watcher: false,
            keystore_path,
        };
        let join = tokio::spawn(async move {
            let _ = runtime::run(cfg).await;
        });
        // Wait until the control IPC is listening: the runtime registers every
        // watch root *before* opening the control listener, so the socket file
        // appearing means all watchers are live. Under the heavy parallel load
        // of `cargo test --workspace`, the runtime can take several seconds to
        // bind — a too-short deadline lets `start()` return before the socket
        // exists, so a later `control()`/`apply_policy()` connect fails (#108).
        // Budget generously (override via `SIGIL_TEST_IPC_TIMEOUT_SECS`); the
        // loop returns as soon as the socket appears, so headroom is free.
        #[cfg(unix)]
        {
            let secs = std::env::var("SIGIL_TEST_IPC_TIMEOUT_SECS")
                .ok()
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(20);
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(secs);
            while !control_socket.exists() && std::time::Instant::now() < deadline {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        }
        // Small settle window for the OS watcher to start delivering events.
        // (On Windows the control IPC is a named pipe with no socket file, so we
        // skip the readiness poll above — ReadDirectoryChangesW registration is
        // synchronous and fast — and rely on this settle window.)
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
