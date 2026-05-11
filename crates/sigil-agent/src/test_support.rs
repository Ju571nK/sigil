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
        }
    }

    pub fn policy(mut self, yaml: &str) -> Self {
        self.policy_yaml = yaml.to_string();
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
        let cfg = RuntimeConfig {
            policy_path: Some(policy_file.clone()),
            state_db_path: state_db.clone(),
            events_dir: events_dir.clone(),
            control_socket: control_socket.clone(),
            control_pipe_name: control_pipe_name.clone(),
            poll_watcher: false,
        };
        let join = tokio::spawn(async move {
            let _ = runtime::run(cfg).await;
        });
        // Wait until the control IPC is listening: the runtime registers every
        // watch root *before* opening the control listener, so the socket file
        // appearing means all watchers are live. (On Windows the IPC is a named
        // pipe with no socket file, so this just runs out the deadline — fine,
        // ReadDirectoryChangesW registration is synchronous and fast.)
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        while !control_socket.exists() && std::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
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
}
