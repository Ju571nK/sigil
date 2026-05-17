//! Phase 3b.4-pre — host_meta_snapshot_task. Emits a HostMetaSnapshot
//! event on boot, every 24h (re-attestation), and whenever a 5-minute
//! change-check sees the snapshot's canonical hash change. Mirrors
//! ai_guard_task's trigger model.

use crate::host_meta_snapshot::{collect, snapshot_hash};
use crate::state_task::CommittableEvent;
use parking_lot::RwLock;
use sigil_core::event::{
    Event, Evidence, HostMetaSnapshot, Severity, SourceKind, Subject,
    AGENT_VERSION, SCHEMA_VERSION,
};
use std::sync::Arc;
use std::time::Duration;
use time::OffsetDateTime;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// Trait surface the task uses to collect snapshots. Real prod uses
/// `crate::platform::ActivePlatform`; tests substitute a scripted impl.
pub trait SnapshotSource: Send + Sync + 'static {
    fn snapshot(&self) -> HostMetaSnapshot;
}

/// Blanket impl so ActivePlatform (the real OS-detection struct) plugs in
/// without an extra wrapper.
impl SnapshotSource for crate::platform::ActivePlatform {
    fn snapshot(&self) -> HostMetaSnapshot {
        collect(self)
    }
}

#[derive(Clone, Debug, Default)]
pub struct LatestSnapshot {
    pub snapshot: Option<HostMetaSnapshot>,
    pub snapshot_hash: Option<[u8; 32]>,
    pub last_emitted_ts: Option<OffsetDateTime>,
}

pub struct TaskCtx<S: SnapshotSource> {
    pub source: Arc<S>,
    pub event_tx: mpsc::Sender<CommittableEvent>,
    pub host_id: String,
    pub latest: Arc<RwLock<LatestSnapshot>>,
    pub heartbeat_interval: Duration,
    pub change_check_interval: Duration,
    pub shutdown: CancellationToken,
}

pub async fn run<S: SnapshotSource>(ctx: TaskCtx<S>) {
    // 1. Boot scan — always emit, is_reattestation=false (no prior state).
    eval_and_emit(&ctx, /* force */ true).await;

    let mut heartbeat = tokio::time::interval(ctx.heartbeat_interval);
    heartbeat.tick().await; // skip immediate first tick
    let mut change_check = tokio::time::interval(ctx.change_check_interval);
    change_check.tick().await;

    loop {
        tokio::select! {
            biased;
            _ = ctx.shutdown.cancelled() => return,
            _ = heartbeat.tick() => {
                eval_and_emit(&ctx, /* force */ true).await;
            }
            _ = change_check.tick() => {
                eval_and_emit(&ctx, /* force */ false).await;
            }
        }
    }
}

async fn eval_and_emit<S: SnapshotSource>(ctx: &TaskCtx<S>, force: bool) {
    let snapshot = ctx.source.snapshot();
    let hash = snapshot_hash(&snapshot);
    let prev_hash = ctx.latest.read().snapshot_hash;
    let changed = prev_hash.map(|h| h != hash).unwrap_or(true);

    if !changed && !force {
        return;
    }

    let now = OffsetDateTime::now_utc();
    // Reattestation iff force-emitted AND a prior state existed AND nothing
    // changed. Boot (no prior state) is NOT a re-attestation even though
    // force=true.
    let is_reattestation = force && prev_hash.is_some() && !changed;

    {
        let mut w = ctx.latest.write();
        w.snapshot = Some(snapshot.clone());
        w.snapshot_hash = Some(hash);
        w.last_emitted_ts = Some(now);
    }

    let event = Event {
        schema_version: SCHEMA_VERSION,
        event_id: Uuid::now_v7(),
        ts: now,
        host_id: ctx.host_id.clone(),
        agent_version: AGENT_VERSION.to_string(),
        severity: Severity::Info,
        source: SourceKind::Agent,
        subject: Subject::Self_,
        evidence: Evidence::HostMetaSnapshot { snapshot, is_reattestation },
        target_id: None,
    };
    if ctx
        .event_tx
        .send(CommittableEvent {
            event,
            new_hash: None,
            path_for_db: std::path::PathBuf::new(),
            target_id: String::new(),
        })
        .await
        .is_err()
    {
        tracing::debug!("host_meta_snapshot event_tx send failed (sink closed during shutdown?)");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigil_core::event::HostMetaSnapshot;
    use std::sync::Mutex as StdMutex;

    /// Returns scripted snapshots in order; once exhausted, repeats the last one.
    struct ScriptedSource {
        scripts: StdMutex<Vec<HostMetaSnapshot>>,
        last: StdMutex<Option<HostMetaSnapshot>>,
    }

    impl ScriptedSource {
        fn new(scripts: Vec<HostMetaSnapshot>) -> Arc<Self> {
            Arc::new(Self {
                scripts: StdMutex::new(scripts),
                last: StdMutex::new(None),
            })
        }
    }

    impl SnapshotSource for ScriptedSource {
        fn snapshot(&self) -> HostMetaSnapshot {
            let mut s = self.scripts.lock().unwrap();
            if let Some(next) = s.first().cloned() {
                s.remove(0);
                *self.last.lock().unwrap() = Some(next.clone());
                next
            } else {
                self.last.lock().unwrap().clone().expect("scripts must have at least one entry")
            }
        }
    }

    fn snap(hostname: &str) -> HostMetaSnapshot {
        HostMetaSnapshot {
            hostname: Some(hostname.into()),
            os_name: Some("macOS".into()),
            os_version: Some("14.5".into()),
            kernel_version: Some("23.5.0".into()),
            architecture: Some("arm64".into()),
            interfaces: vec![],
            default_gateway_v4: None,
            default_gateway_v6: None,
            dns_servers: vec![],
        }
    }

    fn ctx_with(
        source: Arc<ScriptedSource>,
        heartbeat: Duration,
        change_check: Duration,
    ) -> (TaskCtx<ScriptedSource>, mpsc::Receiver<CommittableEvent>) {
        let (tx, rx) = mpsc::channel(16);
        (
            TaskCtx {
                source,
                event_tx: tx,
                host_id: "test-host".into(),
                latest: Arc::new(RwLock::new(LatestSnapshot::default())),
                heartbeat_interval: heartbeat,
                change_check_interval: change_check,
                shutdown: CancellationToken::new(),
            },
            rx,
        )
    }

    #[tokio::test(start_paused = true)]
    async fn boot_emits_initial_event_with_is_reattestation_false() {
        let src = ScriptedSource::new(vec![snap("alice-mbp")]);
        let (ctx, mut events) =
            ctx_with(src, Duration::from_secs(24 * 3600), Duration::from_secs(300));
        let h = tokio::spawn(run(ctx));
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(10)).await;
        let ev = events.recv().await.expect("boot event");
        match ev.event.evidence {
            Evidence::HostMetaSnapshot { snapshot, is_reattestation } => {
                assert_eq!(snapshot.hostname.as_deref(), Some("alice-mbp"));
                assert!(!is_reattestation, "boot scan must NOT be re-attestation");
            }
            other => panic!("expected HostMetaSnapshot, got {other:?}"),
        }
        h.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn heartbeat_with_unchanged_snapshot_emits_is_reattestation_true() {
        let src = ScriptedSource::new(vec![snap("alice-mbp"), snap("alice-mbp")]);
        let (ctx, mut events) =
            ctx_with(src, Duration::from_millis(100), Duration::from_secs(3600));
        let h = tokio::spawn(run(ctx));
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(10)).await;
        let _boot = events.recv().await.expect("boot event");
        tokio::time::advance(Duration::from_millis(150)).await;
        let ev = events.recv().await.expect("heartbeat event");
        match ev.event.evidence {
            Evidence::HostMetaSnapshot { is_reattestation, .. } => {
                assert!(is_reattestation, "unchanged heartbeat must be re-attestation");
            }
            other => panic!("got {other:?}"),
        }
        h.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn heartbeat_with_changed_snapshot_emits_is_reattestation_false() {
        let src = ScriptedSource::new(vec![snap("alice-mbp"), snap("alice-mbp-renamed")]);
        let (ctx, mut events) =
            ctx_with(src, Duration::from_millis(100), Duration::from_secs(3600));
        let h = tokio::spawn(run(ctx));
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(10)).await;
        let _boot = events.recv().await.expect("boot");
        tokio::time::advance(Duration::from_millis(150)).await;
        let ev = events.recv().await.expect("changed heartbeat");
        match ev.event.evidence {
            Evidence::HostMetaSnapshot { snapshot, is_reattestation } => {
                assert_eq!(snapshot.hostname.as_deref(), Some("alice-mbp-renamed"));
                assert!(!is_reattestation, "changed heartbeat must NOT be re-attestation");
            }
            other => panic!("got {other:?}"),
        }
        h.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn change_check_with_unchanged_does_not_emit() {
        let src = ScriptedSource::new(vec![snap("alice-mbp"), snap("alice-mbp")]);
        let (ctx, mut events) =
            ctx_with(src, Duration::from_secs(3600), Duration::from_millis(100));
        let h = tokio::spawn(run(ctx));
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(10)).await;
        let _boot = events.recv().await.expect("boot");
        tokio::time::advance(Duration::from_millis(150)).await;
        let attempt = tokio::time::timeout(Duration::from_millis(100), events.recv()).await;
        assert!(attempt.is_err(), "expected no second emit, got {attempt:?}");
        h.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn change_check_with_changed_emits_is_reattestation_false() {
        let src = ScriptedSource::new(vec![snap("alice-mbp"), snap("alice-mbp-renamed")]);
        let (ctx, mut events) =
            ctx_with(src, Duration::from_secs(3600), Duration::from_millis(100));
        let h = tokio::spawn(run(ctx));
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(10)).await;
        let _boot = events.recv().await.expect("boot");
        tokio::time::advance(Duration::from_millis(150)).await;
        let ev = events.recv().await.expect("change-check event");
        match ev.event.evidence {
            Evidence::HostMetaSnapshot { snapshot, is_reattestation } => {
                assert_eq!(snapshot.hostname.as_deref(), Some("alice-mbp-renamed"));
                assert!(!is_reattestation, "change-check changed must NOT be re-attestation");
            }
            other => panic!("got {other:?}"),
        }
        h.abort();
    }
}
