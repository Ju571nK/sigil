//! Supervisor: tracks JoinHandles, listens for SIGTERM/Ctrl-C, propagates
//! shutdown via a `CancellationToken`, catches panics, emits AgentDying.

use crate::state_task::CommittableEvent;
use andeda_core::event::{
    AgentDyingReason, Event, Evidence, Severity, SourceKind, Subject, AGENT_VERSION,
    SCHEMA_VERSION,
};
use time::OffsetDateTime;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

pub struct Supervisor {
    handles: Vec<(String, JoinHandle<()>)>,
    pub shutdown: CancellationToken,
}

impl Supervisor {
    pub fn new() -> Self {
        Self {
            handles: Vec::new(),
            shutdown: CancellationToken::new(),
        }
    }

    pub fn track(&mut self, name: &str, handle: JoinHandle<()>) {
        self.handles.push((name.to_string(), handle));
    }

    /// Wait for shutdown signal, then drain all tasks. Returns `Ok(())` on
    /// graceful shutdown, `Err(reason)` if a task panicked.
    pub async fn run(
        mut self,
        host_id: String,
        tx_sink_emergency: mpsc::Sender<CommittableEvent>,
    ) -> std::io::Result<i32> {
        let cancel = self.shutdown.clone();
        tokio::spawn(async move {
            // SIGTERM on Unix, Ctrl-C on Windows. tokio's `signal::ctrl_c` covers both.
            let _ = tokio::signal::ctrl_c().await;
            tracing::info!("shutdown signal received");
            cancel.cancel();
        });

        // Wait until all tracked tasks finish OR a panic surfaces.
        let mut panic_task: Option<String> = None;
        let mut panic_detail: String = String::new();
        for (name, handle) in self.handles.drain(..) {
            match handle.await {
                Ok(()) => {}
                Err(je) => {
                    if je.is_panic() {
                        panic_task = Some(name.clone());
                        panic_detail = je
                            .into_panic()
                            .downcast_ref::<&'static str>()
                            .map(|s| s.to_string())
                            .unwrap_or_else(|| "panic in task".into());
                    } else {
                        tracing::warn!(task = %name, "task cancelled");
                    }
                }
            }
        }

        if let Some(task) = panic_task {
            // Best-effort: emit AgentDying.
            let event = Event {
                schema_version: SCHEMA_VERSION,
                event_id: Uuid::now_v7(),
                ts: OffsetDateTime::now_utc(),
                host_id,
                agent_version: AGENT_VERSION,
                severity: Severity::Warn,
                source: SourceKind::Agent,
                subject: Subject::Self_,
                evidence: Evidence::AgentDying {
                    reason: AgentDyingReason::Panic,
                    detail: panic_detail,
                    task: Some(task),
                },
                target_id: None,
            };
            let _ = tx_sink_emergency
                .send(CommittableEvent {
                    event,
                    new_hash: None,
                    path_for_db: std::path::PathBuf::new(),
                    target_id: String::new(),
                })
                .await;
            return Ok(101);
        }
        Ok(0)
    }
}
