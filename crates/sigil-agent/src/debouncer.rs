//! Debouncer task. Drives `sigil_core::debounce::Debouncer` with tokio time.
//!
//! `sigil_core::debounce` is path/kind only, so this task carries the rename
//! pairing (`NormalizedEvent::rename_from`) across the debounce window in a
//! side-map and re-attaches it to the `PendingEvent` on the way out.

use crate::normalizer::NormalizedEvent;
use sigil_core::debounce::{Debouncer, PendingEvent};
use sigil_core::event::FileChangeKind;
use sigil_core::policy::Tier;
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;
use tokio::sync::mpsc;

pub async fn run(mut rx: mpsc::Receiver<NormalizedEvent>, tx: mpsc::Sender<PendingEvent>) {
    let mut debouncer = Debouncer::new();
    // target path -> prior path, for `Renamed` events held across the window.
    let mut rename_from: HashMap<PathBuf, PathBuf> = HashMap::new();
    let mut tick = tokio::time::interval(Duration::from_millis(25));
    tick.tick().await;
    loop {
        tokio::select! {
            biased;
            maybe = rx.recv() => {
                let Some(ev) = maybe else { break; };
                let now_ms = monotonic_ms();
                let critical = matches!(ev.tier, Tier::Critical);
                if ev.kind == FileChangeKind::Renamed {
                    if let Some(from) = ev.rename_from.clone() {
                        rename_from.insert(ev.path.clone(), from);
                    }
                }
                if let Some(mut pending) = debouncer.push(ev.path.clone(), ev.kind, critical, now_ms)
                {
                    attach_rename(&mut rename_from, &mut pending);
                    if tx.send(pending).await.is_err() {
                        return;
                    }
                }
            }
            _ = tick.tick() => {
                let now_ms = monotonic_ms();
                for mut pending in debouncer.drain_due(now_ms) {
                    attach_rename(&mut rename_from, &mut pending);
                    if tx.send(pending).await.is_err() {
                        return;
                    }
                }
            }
        }
    }
    // Drain on shutdown.
    for mut pending in debouncer.drain_all() {
        attach_rename(&mut rename_from, &mut pending);
        let _ = tx.send(pending).await;
    }
}

fn attach_rename(map: &mut HashMap<PathBuf, PathBuf>, pending: &mut PendingEvent) {
    if pending.kind == FileChangeKind::Renamed {
        pending.rename_from = map.remove(&pending.path);
    }
}

fn monotonic_ms() -> u64 {
    use std::time::SystemTime;
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pending(path: &str, kind: FileChangeKind) -> PendingEvent {
        PendingEvent {
            path: PathBuf::from(path),
            kind,
            first_seen_ms: 0,
            last_seen_ms: 0,
            coalesced_count: 1,
            critical: false,
            rename_from: None,
        }
    }

    #[test]
    fn attach_rename_consumes_pairing_for_renamed() {
        let mut map = HashMap::new();
        map.insert(PathBuf::from("/new"), PathBuf::from("/old"));
        let mut ev = pending("/new", FileChangeKind::Renamed);
        attach_rename(&mut map, &mut ev);
        assert_eq!(ev.rename_from, Some(PathBuf::from("/old")));
        assert!(map.is_empty(), "the pairing should be consumed");
    }

    #[test]
    fn attach_rename_ignores_non_renamed_kinds() {
        let mut map = HashMap::new();
        map.insert(PathBuf::from("/new"), PathBuf::from("/old"));
        let mut ev = pending("/new", FileChangeKind::Modified);
        attach_rename(&mut map, &mut ev);
        assert_eq!(ev.rename_from, None);
        assert_eq!(
            map.len(),
            1,
            "a Modified event must not consume the pairing"
        );
    }

    #[test]
    fn attach_rename_tolerates_missing_pairing() {
        let mut map: HashMap<PathBuf, PathBuf> = HashMap::new();
        let mut ev = pending("/new", FileChangeKind::Renamed);
        attach_rename(&mut map, &mut ev);
        assert_eq!(ev.rename_from, None);
    }
}
