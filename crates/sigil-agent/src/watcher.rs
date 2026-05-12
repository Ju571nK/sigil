//! `notify` integration. Bridges OS-thread callbacks to a tokio mpsc.

use notify::{
    event::{EventKind as NEvent, ModifyKind, RenameMode},
    Config, Event, PollWatcher, RecommendedWatcher, RecursiveMode, Watcher,
};
use sigil_core::event::FileChangeKind;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
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
    // Held only to keep the watcher (and its OS thread) alive for the
    // lifetime of the handle.
    _watcher: BackendWatcher,
}

// Variants carry the live watcher only so its OS thread stays alive until the
// `WatcherHandle` is dropped; the value itself is never read.
#[allow(dead_code)]
enum BackendWatcher {
    Native(RecommendedWatcher),
    Poll(PollWatcher),
}

/// Spawn the filesystem watcher.
///
/// `poll_interval = Some(d)` forces a polling watcher with interval `d` — use
/// this where OS-native FS events are unreliable (NFS, `virtiofs`/`9p`,
/// bind-mounts in VM-backed container engines). `None` uses the OS-native
/// backend (inotify / FSEvents / ReadDirectoryChangesW).
pub fn spawn_watcher(
    roots: Vec<(PathBuf, bool)>,
    runtime_handle: tokio::runtime::Handle,
    capacity: usize,
    poll_interval: Option<Duration>,
) -> Result<WatcherHandle, WatcherError> {
    let (tx, rx) = mpsc::channel::<RawFsEvent>(capacity);
    let tx = Arc::new(tx);
    let handle_for_cb = runtime_handle.clone();

    let on_event = move |res: notify::Result<Event>| {
        let event = match res {
            Ok(ev) => ev,
            Err(e) => {
                tracing::warn!(error = %e, "notify backend reported an error");
                return;
            }
        };
        tracing::trace!(kind = ?event.kind, paths = ?event.paths, "raw notify event");
        let mapped = map_notify_event(&event);
        for raw in mapped {
            tracing::debug!(path = %raw.path.display(), kind = ?raw.kind, "fs event");
            let tx = tx.clone();
            handle_for_cb.spawn(async move {
                let _ = tx.send(raw).await;
            });
        }
    };

    let recursive_mode = |recursive: bool| {
        if recursive {
            RecursiveMode::Recursive
        } else {
            RecursiveMode::NonRecursive
        }
    };

    // A failure on one root (gone missing, permission, `max_user_watches`) must
    // not bring the whole agent down — log it and keep the rest. (Construction
    // of the watcher itself is still fatal.)
    let watch_all = |w: &mut dyn Watcher, roots: &[(PathBuf, bool)]| {
        let mut ok = 0usize;
        for (root, recursive) in roots {
            match w.watch(root, recursive_mode(*recursive)) {
                Ok(()) => {
                    ok += 1;
                    tracing::debug!(root = %root.display(), recursive, "watching root");
                }
                Err(e) => tracing::warn!(
                    root = %root.display(),
                    recursive,
                    error = %e,
                    "failed to watch root; continuing without it"
                ),
            }
        }
        if ok == 0 && !roots.is_empty() {
            tracing::warn!("no watch roots could be registered; file-change events disabled");
        }
    };

    let (backend, backend_name): (BackendWatcher, &'static str) = match poll_interval {
        Some(interval) => {
            let mut w = PollWatcher::new(on_event, Config::default().with_poll_interval(interval))?;
            watch_all(&mut w, &roots);
            (BackendWatcher::Poll(w), "polling")
        }
        None => {
            let mut w = RecommendedWatcher::new(on_event, Config::default())?;
            watch_all(&mut w, &roots);
            (BackendWatcher::Native(w), os_backend_name())
        }
    };

    Ok(WatcherHandle {
        rx,
        backend_name,
        _watcher: backend,
    })
}

fn os_backend_name() -> &'static str {
    if cfg!(target_os = "macos") {
        "fsevents"
    } else if cfg!(target_os = "windows") {
        "read_directory_changes_w"
    } else if cfg!(target_os = "linux") {
        "inotify"
    } else {
        "polling"
    }
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
            spawn_watcher(vec![(td.path().to_path_buf(), false)], handle, 16, None).unwrap();

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
            spawn_watcher(vec![(td.path().to_path_buf(), false)], handle, 16, None).unwrap();
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn poll_watcher_detects_modify() {
        let td = TempDir::new().unwrap();
        let p = td.path().join("watched.json");
        fs::write(&p, b"a").unwrap();
        let handle = tokio::runtime::Handle::current();
        let mut watcher = spawn_watcher(
            vec![(td.path().to_path_buf(), false)],
            handle,
            64,
            Some(Duration::from_millis(120)),
        )
        .unwrap();
        assert_eq!(watcher.backend_name, "polling");
        // There's no signal for "initial snapshot taken", so keep rewriting the
        // file (size + mtime change, which the default poll comparison detects)
        // until an event lands or we give up. Robust under loaded CI.
        let mut saw_change = false;
        for i in 0..40 {
            fs::write(&p, vec![b'x'; i + 2]).unwrap();
            if let Ok(Some(ev)) =
                tokio::time::timeout(Duration::from_millis(300), watcher.rx.recv()).await
            {
                if matches!(ev.kind, FileChangeKind::Modified | FileChangeKind::Created) {
                    saw_change = true;
                    break;
                }
            }
        }
        assert!(saw_change, "poll watcher did not report the change");
    }
}
