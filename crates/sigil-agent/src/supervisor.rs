//! Supervise tasks concurrently and bound graceful pipeline draining.

use crate::state_task::CommittableEvent;
use sigil_core::event::{
    AgentDyingReason, Event, Evidence, Severity, SourceKind, Subject, AGENT_VERSION, SCHEMA_VERSION,
};
use std::{io, time::Duration};
use time::OffsetDateTime;
use tokio::sync::mpsc;
use tokio::task::{AbortHandle, JoinHandle, JoinSet};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);

struct AbortOnDrop(AbortHandle);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

type Completion = (String, Result<io::Result<()>, tokio::task::JoinError>);

#[derive(Default)]
pub struct Supervisor {
    tasks: JoinSet<Completion>,
    pub shutdown: CancellationToken,
}

impl Supervisor {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn track(&mut self, name: &str, handle: JoinHandle<()>) {
        let guard = AbortOnDrop(handle.abort_handle());
        let name = name.to_owned();
        self.tasks.spawn(async move {
            let _guard = guard;
            (name, handle.await.map(|()| Ok(())))
        });
    }

    pub fn track_result(&mut self, name: &str, handle: JoinHandle<io::Result<()>>) {
        let guard = AbortOnDrop(handle.abort_handle());
        let name = name.to_owned();
        self.tasks.spawn(async move {
            let _guard = guard;
            (name, handle.await)
        });
    }

    /// Stop producers on SIGINT/SIGTERM (Ctrl-C on Windows), then let channel
    /// closure drain the pipeline. A weak emergency sender cannot pin the sink.
    pub async fn run(
        self,
        host_id: String,
        tx_sink_emergency: mpsc::WeakSender<CommittableEvent>,
    ) -> io::Result<i32> {
        self.drain(
            host_id,
            tx_sink_emergency,
            SHUTDOWN_TIMEOUT,
            shutdown_signal(),
        )
        .await
    }

    async fn drain(
        mut self,
        host_id: String,
        tx_sink_emergency: mpsc::WeakSender<CommittableEvent>,
        timeout: Duration,
        signal: impl std::future::Future<Output = io::Result<()>>,
    ) -> io::Result<i32> {
        tokio::pin!(signal);
        let deadline = tokio::time::sleep(timeout);
        tokio::pin!(deadline);
        let mut draining = false;
        let mut exit_code = 0;
        while !self.tasks.is_empty() {
            tokio::select! {
                biased;
                _ = self.shutdown.cancelled(), if !draining => {
                    draining = true;
                    deadline.as_mut().reset(tokio::time::Instant::now() + timeout);
                }
                result = &mut signal, if !draining => {
                    if let Err(error) = result {
                        tracing::error!(%error, "shutdown signal registration failed");
                        exit_code = 1;
                    }
                    tracing::info!("shutdown signal received");
                    self.shutdown.cancel();
                }
                _ = &mut deadline, if draining => {
                    tracing::error!(remaining = self.tasks.len(), "graceful shutdown timed out; drain incomplete");
                    self.tasks.shutdown().await;
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "graceful shutdown timed out"));
                }
                done = self.tasks.join_next() => {
                    let (name, result) = done.expect("nonempty task set").map_err(io::Error::other)?;
                    match result {
                        Ok(Ok(())) => {}
                        Ok(Err(error)) => {
                            tracing::error!(task = %name, %error, "task failed");
                            exit_code = exit_code.max(1);
                            self.shutdown.cancel();
                        }
                        Err(error) => {
                            tracing::error!(task = %name, %error, "task terminated abnormally");
                            exit_code = 101;
                            self.shutdown.cancel();
                            if error.is_panic() {
                                if let Some(tx) = tx_sink_emergency.upgrade() {
                                    let _ = tx.try_send(panic_event(&host_id, name, error.to_string()));
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(exit_code)
    }
}

async fn shutdown_signal() -> io::Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut interrupt = signal(SignalKind::interrupt())?;
        let mut terminate = signal(SignalKind::terminate())?;
        tokio::select! {
            _ = interrupt.recv() => {},
            _ = terminate.recv() => {},
        }
        Ok(())
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await
}

fn panic_event(host_id: &str, task: String, detail: String) -> CommittableEvent {
    CommittableEvent {
        event: Event {
            schema_version: SCHEMA_VERSION,
            event_id: Uuid::now_v7(),
            ts: OffsetDateTime::now_utc(),
            host_id: host_id.to_owned(),
            agent_version: AGENT_VERSION.to_string(),
            severity: Severity::Warn,
            source: SourceKind::Agent,
            subject: Subject::Self_,
            evidence: Evidence::AgentDying {
                reason: AgentDyingReason::Panic,
                detail,
                task: Some(task),
            },
            target_id: None,
        },
        new_hash: None,
        path_for_db: std::path::PathBuf::new(),
        target_id: String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn later_panic_cancels_earlier_task_and_emits_before_sink_closes() {
        let mut sup = Supervisor::new();
        let cancel = sup.shutdown.clone();
        let (tx, mut rx) = mpsc::channel::<CommittableEvent>(8);
        let weak = tx.downgrade();
        sup.track(
            "producer",
            tokio::spawn(async move {
                cancel.cancelled().await;
                drop(tx);
            }),
        );
        sup.track("panic", tokio::spawn(async { panic!("test panic") }));
        let reader = tokio::spawn(async move {
            let event = rx.recv().await.unwrap();
            assert!(matches!(event.event.evidence, Evidence::AgentDying { .. }));
            assert!(rx.recv().await.is_none());
        });
        assert_eq!(
            sup.drain(
                "test".into(),
                weak,
                Duration::from_secs(1),
                std::future::pending()
            )
            .await
            .unwrap(),
            101
        );
        reader.await.unwrap();
    }

    #[tokio::test]
    async fn cancellation_drains_a_full_channel_without_emergency_sender_pin() {
        let mut sup = Supervisor::new();
        let cancel = sup.shutdown.clone();
        let (tx, mut rx) = mpsc::channel(1);
        let weak = tx.downgrade();
        sup.track(
            "producer",
            tokio::spawn(async move {
                for _ in 0..20 {
                    tx.send(panic_event("test", "fixture".into(), "fixture".into()))
                        .await
                        .unwrap();
                }
            }),
        );
        let count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = count.clone();
        sup.track(
            "sink",
            tokio::spawn(async move {
                while rx.recv().await.is_some() {
                    observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
            }),
        );
        cancel.cancel();
        assert_eq!(
            sup.drain(
                "test".into(),
                weak,
                Duration::from_secs(1),
                std::future::pending()
            )
            .await
            .unwrap(),
            0
        );
        assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 20);
    }

    #[tokio::test]
    async fn deadline_reports_failure_and_aborts_stuck_task() {
        let mut sup = Supervisor::new();
        let (tx, _rx) = mpsc::channel(1);
        let weak = tx.downgrade();
        let (dropped_tx, dropped_rx) = tokio::sync::oneshot::channel::<()>();
        sup.track(
            "stuck",
            tokio::spawn(async move {
                let _owned = dropped_tx;
                std::future::pending::<()>().await;
            }),
        );
        sup.shutdown.cancel();
        let error = sup
            .drain(
                "test".into(),
                weak,
                Duration::from_millis(20),
                std::future::pending(),
            )
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(tokio::time::timeout(Duration::from_secs(1), dropped_rx)
            .await
            .unwrap()
            .is_err());
    }
}
