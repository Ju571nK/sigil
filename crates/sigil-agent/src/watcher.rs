//! `notify` integration. Bridges OS-thread callbacks to a tokio mpsc.

use notify::{
    event::{EventKind as NEvent, ModifyKind, RenameMode},
    Config, Event, RecommendedWatcher, RecursiveMode, Watcher,
};
use sigil_core::event::FileChangeKind;
use std::path::PathBuf;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::mpsc;

#[derive(Debug, Error)]
pub enum WatcherError {
    #[error("notify: {0}")]
    Notify(#[from] notify::Error),
    #[error("send to bridge channel failed (receiver dropped)")]
    BridgeClosed,
}

#[derive(Debug, Clone)]
pub struct RawFsEvent {
    pub path: PathBuf,
    pub kind: FileChangeKind,
    pub rename_id: Option<u64>, // notify reports a tracker id we surface for pairing
}

/// Spawns the OS-thread watcher and returns a tokio receiver for raw events.
/// `roots` is the list of (path, recursive) pairs to watch.
pub struct WatcherHandle {
    pub rx: mpsc::Receiver<RawFsEvent>,
    pub backend_name: &'static str,
    _watcher: RecommendedWatcher,
}

pub fn spawn_watcher(
    roots: Vec<(PathBuf, bool)>,
    runtime_handle: tokio::runtime::Handle,
    capacity: usize,
) -> Result<WatcherHandle, WatcherError> {
    let (tx, rx) = mpsc::channel::<RawFsEvent>(capacity);
    let tx = Arc::new(tx);
    let handle_for_cb = runtime_handle.clone();

    let mut watcher: RecommendedWatcher = RecommendedWatcher::new(
        move |res: notify::Result<Event>| {
            let Ok(event) = res else {
                return;
            };
            let mapped = map_notify_event(&event);
            for raw in mapped {
                let tx = tx.clone();
                handle_for_cb.spawn(async move {
                    let _ = tx.send(raw).await;
                });
            }
        },
        Config::default(),
    )?;

    for (root, recursive) in roots {
        let mode = if recursive {
            RecursiveMode::Recursive
        } else {
            RecursiveMode::NonRecursive
        };
        watcher.watch(&root, mode)?;
    }

    let backend_name = if cfg!(target_os = "macos") {
        "fsevents"
    } else if cfg!(target_os = "windows") {
        "read_directory_changes_w"
    } else {
        "polling"
    };

    Ok(WatcherHandle {
        rx,
        backend_name,
        _watcher: watcher,
    })
}

fn map_notify_event(event: &Event) -> Vec<RawFsEvent> {
    let mut out = Vec::new();
    let tracker_id = event.attrs.tracker().map(|t| t as u64);
    for path in event.paths.iter() {
        let kind = match event.kind {
            NEvent::Create(_) => Some(FileChangeKind::Created),
            NEvent::Modify(ModifyKind::Name(RenameMode::From))
            | NEvent::Modify(ModifyKind::Name(RenameMode::To))
            | NEvent::Modify(ModifyKind::Name(RenameMode::Both)) => Some(FileChangeKind::Renamed),
            NEvent::Modify(_) => Some(FileChangeKind::Modified),
            NEvent::Remove(_) => Some(FileChangeKind::Removed),
            _ => None,
        };
        if let Some(k) = kind {
            out.push(RawFsEvent {
                path: path.clone(),
                kind: k,
                rename_id: tracker_id,
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File};
    use std::io::Write;
    use std::time::Duration;
    use tempfile::TempDir;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn detects_create_in_watched_dir() {
        let td = TempDir::new().unwrap();
        let handle = tokio::runtime::Handle::current();
        let mut watcher =
            spawn_watcher(vec![(td.path().to_path_buf(), false)], handle, 16).unwrap();

        // Give the watcher a moment to register on macOS FSEvents.
        tokio::time::sleep(Duration::from_millis(200)).await;

        let p = td.path().join("new.json");
        let mut f = File::create(&p).unwrap();
        f.write_all(b"{}").unwrap();
        f.sync_all().unwrap();
        drop(f);

        let event = tokio::time::timeout(Duration::from_secs(3), watcher.rx.recv())
            .await
            .expect("timed out")
            .expect("channel closed");
        assert!(matches!(
            event.kind,
            FileChangeKind::Created | FileChangeKind::Modified
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn detects_remove() {
        let td = TempDir::new().unwrap();
        let p = td.path().join("victim.json");
        File::create(&p).unwrap().write_all(b"x").unwrap();
        let handle = tokio::runtime::Handle::current();
        let mut watcher =
            spawn_watcher(vec![(td.path().to_path_buf(), false)], handle, 16).unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        fs::remove_file(&p).unwrap();
        let mut saw_remove = false;
        for _ in 0..10 {
            if let Ok(Some(ev)) =
                tokio::time::timeout(Duration::from_secs(1), watcher.rx.recv()).await
            {
                if ev.kind == FileChangeKind::Removed {
                    saw_remove = true;
                    break;
                }
            }
        }
        assert!(saw_remove);
    }
}
