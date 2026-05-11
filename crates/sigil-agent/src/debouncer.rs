//! Debouncer task. Drives `andeda_core::debounce::Debouncer` with tokio time.

use crate::normalizer::NormalizedEvent;
use andeda_core::debounce::{Debouncer, PendingEvent};
use andeda_core::policy::Tier;
use std::time::Duration;
use tokio::sync::mpsc;

pub async fn run(mut rx: mpsc::Receiver<NormalizedEvent>, tx: mpsc::Sender<PendingEvent>) {
    let mut debouncer = Debouncer::new();
    let mut tick = tokio::time::interval(Duration::from_millis(25));
    tick.tick().await;
    loop {
        tokio::select! {
            biased;
            maybe = rx.recv() => {
                let Some(ev) = maybe else { break; };
                let now_ms = monotonic_ms();
                let critical = matches!(ev.tier, Tier::Critical);
                if let Some(pending) = debouncer.push(ev.path.clone(), ev.kind, critical, now_ms) {
                    if tx.send(pending).await.is_err() {
                        return;
                    }
                }
            }
            _ = tick.tick() => {
                let now_ms = monotonic_ms();
                for pending in debouncer.drain_due(now_ms) {
                    if tx.send(pending).await.is_err() {
                        return;
                    }
                }
            }
        }
    }
    // Drain on shutdown.
    for pending in debouncer.drain_all() {
        let _ = tx.send(pending).await;
    }
}

fn monotonic_ms() -> u64 {
    use std::time::SystemTime;
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
