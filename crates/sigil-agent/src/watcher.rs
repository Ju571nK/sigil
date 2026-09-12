//! `notify` integration. Bridges OS-thread callbacks to a tokio mpsc.

use notify::{
    event::{EventKind as NEvent, ModifyKind, RenameMode},
    Config, Event, PollWatcher, RecommendedWatcher, RecursiveMode, Watcher,
};
use sigil_core::event::FileChangeKind;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
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

/// Holds the live OS watcher (keeping its thread alive) and lets callers
/// add/remove watch roots after construction.
pub struct WatcherHandle {
    pub backend_name: &'static str,
    watcher: BackendWatcher,
    desired: BTreeMap<PathBuf, bool>,
    active: BTreeMap<PathBuf, (bool, RootIdentity)>,
    catchups: BTreeMap<PathBuf, tokio::task::JoinHandle<()>>,
    tx: Arc<mpsc::Sender<RawFsEvent>>,
    runtime: tokio::runtime::Handle,
}

pub(crate) const ROOT_RECHECK_INTERVAL: Duration = Duration::from_secs(5);

#[derive(PartialEq, Eq)]
struct RootIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(windows)]
    file: same_file::Handle,
    #[cfg(not(any(unix, windows)))]
    created: Option<std::time::SystemTime>,
}

impl RootIdentity {
    fn read(path: &Path) -> std::io::Result<Self> {
        #[cfg(not(windows))]
        let metadata = std::fs::metadata(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            Ok(Self {
                device: metadata.dev(),
                inode: metadata.ino(),
            })
        }
        #[cfg(windows)]
        {
            // Creation times can survive replacement (NTFS tunneling). Keep a
            // handle open and compare volume/file IDs, not timestamps.
            Ok(Self {
                file: same_file::Handle::from_path(path)?,
            })
        }
        #[cfg(not(any(unix, windows)))]
        Ok(Self {
            created: metadata.created().ok(),
        })
    }
}

enum BackendWatcher {
    Native(RecommendedWatcher),
    Poll(PollWatcher),
}

impl BackendWatcher {
    fn as_watcher_mut(&mut self) -> &mut dyn Watcher {
        match self {
            BackendWatcher::Native(w) => w,
            BackendWatcher::Poll(w) => w,
        }
    }
}

impl WatcherHandle {
    /// Record desired coverage, including failed registrations, for retry.
    pub fn watch(&mut self, root: &Path, recursive: bool) -> notify::Result<()> {
        self.desired.insert(root.to_path_buf(), recursive);
        self.refresh_root(root, true)
    }

    fn refresh_root(&mut self, root: &Path, catch_up: bool) -> notify::Result<()> {
        let recursive = self.desired[root];
        let identity = RootIdentity::read(root);
        if let (Some((mode, previous)), Ok(current)) = (self.active.get(root), &identity) {
            if *mode == recursive && previous == current {
                return Ok(());
            }
        }
        // A deleted/replaced directory may retain a stale backend subscription.
        if self.active.remove(root).is_some() {
            let _ = self.watcher.as_watcher_mut().unwatch(root);
        }
        if let Some(task) = self.catchups.remove(root) {
            task.abort();
        }
        let identity = identity.map_err(notify::Error::io)?;
        let mode = if recursive {
            RecursiveMode::Recursive
        } else {
            RecursiveMode::NonRecursive
        };
        self.watcher.as_watcher_mut().watch(root, mode)?;
        self.active
            .insert(root.to_path_buf(), (recursive, identity));
        if catch_up {
            // Register first, then replay current files to cover the subscription gap.
            let task = self.runtime.spawn(catch_up_files(
                root.to_path_buf(),
                recursive,
                self.tx.clone(),
            ));
            self.catchups.insert(root.to_path_buf(), task);
            tracing::info!(root = %root.display(), recursive, "watch root recovered; scanning current files");
        }
        Ok(())
    }

    /// Check only configured roots, never recursively subscribe to an ancestor.
    pub(crate) fn reconcile(&mut self) {
        self.catchups.retain(|_, task| !task.is_finished());
        for root in self.desired.keys().cloned().collect::<Vec<_>>() {
            if let Err(e) = self.refresh_root(&root, true) {
                tracing::debug!(root = %root.display(), error = %e, "watch root still unavailable; will retry");
            }
        }
    }

    /// Stop watching a root.
    pub fn unwatch(&mut self, root: &Path) -> notify::Result<()> {
        self.desired.remove(root);
        if let Some(task) = self.catchups.remove(root) {
            task.abort();
        }
        if self.active.remove(root).is_some() {
            self.watcher.as_watcher_mut().unwatch(root)
        } else {
            Ok(())
        }
    }
}

impl Drop for WatcherHandle {
    fn drop(&mut self) {
        for task in self.catchups.values() {
            task.abort();
        }
    }
}

async fn catch_up_files(root: PathBuf, recursive: bool, tx: Arc<mpsc::Sender<RawFsEvent>>) {
    let Ok(meta) = tokio::fs::symlink_metadata(&root).await else {
        return;
    };
    if meta.is_file() {
        let _ = replay_file(root, &tx).await;
        return;
    }
    if !meta.is_dir() {
        return;
    }
    let mut stack = Vec::new();
    match tokio::fs::read_dir(&root).await {
        Ok(entries) => stack.push(entries),
        Err(e) => {
            tracing::warn!(path = %root.display(), error = %e, "watch recovery scan could not read directory");
            return;
        }
    }
    // Stream depth-first with channel backpressure, without collecting the whole tree.
    while let Some(entries) = stack.last_mut() {
        match entries.next_entry().await {
            Ok(Some(entry)) => {
                let Ok(kind) = entry.file_type().await else {
                    continue;
                };
                if kind.is_file() {
                    if !replay_file(entry.path(), &tx).await {
                        return;
                    }
                } else if recursive && kind.is_dir() {
                    // Symlinked children are not followed outside the configured tree.
                    match tokio::fs::read_dir(entry.path()).await {
                        Ok(children) => stack.push(children),
                        Err(e) => {
                            tracing::warn!(path = %entry.path().display(), error = %e, "watch recovery scan could not read directory")
                        }
                    }
                }
            }
            Ok(None) => {
                stack.pop();
            }
            Err(e) => {
                tracing::warn!(root = %root.display(), error = %e, "watch recovery scan interrupted");
                stack.pop();
            }
        }
    }
}

async fn replay_file(path: PathBuf, tx: &mpsc::Sender<RawFsEvent>) -> bool {
    // A current-state observation, not a reconstructed creation time.
    tx.send(RawFsEvent {
        path,
        kind: FileChangeKind::Modified,
        rename_id: None,
    })
    .await
    .is_ok()
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
) -> Result<(mpsc::Receiver<RawFsEvent>, WatcherHandle), WatcherError> {
    let (tx, rx) = mpsc::channel::<RawFsEvent>(capacity);
    let tx = Arc::new(tx);
    let tx_for_cb = tx.clone();
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
            let tx = tx_for_cb.clone();
            handle_for_cb.spawn(async move {
                let _ = tx.send(raw).await;
            });
        }
    };

    let (backend, backend_name): (BackendWatcher, &'static str) = match poll_interval {
        Some(interval) => {
            let w = PollWatcher::new(on_event, Config::default().with_poll_interval(interval))?;
            (BackendWatcher::Poll(w), "polling")
        }
        None => {
            let w = RecommendedWatcher::new(on_event, Config::default())?;
            (BackendWatcher::Native(w), os_backend_name())
        }
    };

    let mut handle = WatcherHandle {
        backend_name,
        watcher: backend,
        desired: BTreeMap::new(),
        active: BTreeMap::new(),
        catchups: BTreeMap::new(),
        tx,
        runtime: runtime_handle,
    };
    for (root, recursive) in roots {
        *handle.desired.entry(root).or_default() |= recursive;
    }
    for root in handle.desired.keys().cloned().collect::<Vec<_>>() {
        if let Err(e) = handle.refresh_root(&root, false) {
            tracing::warn!(root = %root.display(), error = %e, "watch root unavailable; will retry");
        }
    }
    Ok((rx, handle))
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

    async fn receive_path(rx: &mut mpsc::Receiver<RawFsEvent>, path: &Path) {
        let expected = dunce::canonicalize(path).unwrap();
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let event = rx.recv().await.expect("watcher channel closed");
                if dunce::canonicalize(event.path).ok().as_ref() == Some(&expected) {
                    break;
                }
            }
        })
        .await
        .unwrap_or_else(|_| panic!("missing recovered file event for {}", path.display()));
    }

    async fn recovers_missing_root(poll: Option<Duration>) {
        let td = TempDir::new().unwrap();
        let root = td.path().join("missing/cache/tools");
        let (mut rx, mut watcher) = spawn_watcher(
            vec![(root.clone(), true)],
            tokio::runtime::Handle::current(),
            16,
            poll,
        )
        .unwrap();
        assert!(watcher.active.is_empty());
        assert_eq!(watcher.desired.len(), 1);
        assert!(!watcher.desired.contains_key(td.path()));
        let file = root.join("nested/snapshot.json");
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(&file, b"written once before subscription").unwrap();
        watcher.reconcile();
        receive_path(&mut rx, &file).await;
        assert_eq!(watcher.active.len(), 1);
        // Wait for the catch-up task before testing the live backend separately.
        if let Some(task) = watcher.catchups.remove(&root) {
            task.await.unwrap();
        }
        let later = root.join("later.json");
        fs::write(&later, b"created after recovery").unwrap();
        receive_path(&mut rx, &later).await;

        // Replacement at the same path, without observing an intermediate absence.
        fs::rename(&root, td.path().join("old-tools")).unwrap();
        fs::create_dir_all(&root).unwrap();
        let replacement = root.join("replacement.json");
        fs::write(&replacement, b"new directory identity").unwrap();
        watcher.reconcile();
        receive_path(&mut rx, &replacement).await;
        watcher.unwatch(&root).unwrap();
        watcher.reconcile();
        assert!(watcher.desired.is_empty());
        assert!(watcher.active.is_empty());
        assert!(watcher.catchups.is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn native_recovers_missing_and_replaced_roots() {
        recovers_missing_root(None).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn polling_recovers_missing_and_replaced_roots() {
        recovers_missing_root(Some(Duration::from_millis(100))).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn removed_pending_root_is_not_retried() {
        let td = TempDir::new().unwrap();
        let root = td.path().join("missing");
        let (_rx, mut watcher) = spawn_watcher(
            vec![],
            tokio::runtime::Handle::current(),
            16,
            Some(Duration::from_millis(100)),
        )
        .unwrap();
        assert!(watcher.watch(&root, false).is_err());
        assert!(watcher.desired.contains_key(&root));
        watcher.unwatch(&root).unwrap();
        fs::create_dir(&root).unwrap();
        watcher.reconcile();
        assert!(watcher.active.is_empty());
        assert!(watcher.catchups.is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unchanged_roots_do_not_rescan_but_mode_changes_do() {
        let td = TempDir::new().unwrap();
        let root = td.path().to_path_buf();
        let file = root.join("nested/file.json");
        fs::create_dir(file.parent().unwrap()).unwrap();
        fs::write(&file, b"existing").unwrap();
        let (mut rx, mut watcher) = spawn_watcher(
            vec![(root.clone(), false)],
            tokio::runtime::Handle::current(),
            16,
            Some(Duration::from_secs(60)),
        )
        .unwrap();
        watcher.reconcile();
        assert!(watcher.catchups.is_empty());
        watcher.watch(&root, true).unwrap();
        receive_path(&mut rx, &file).await;
        watcher.catchups.remove(&root).unwrap().await.unwrap();
        watcher.reconcile();
        assert!(watcher.catchups.is_empty());
        assert!(watcher.active[&root].0);
    }

    #[tokio::test]
    async fn catchup_respects_depth_and_does_not_follow_child_symlinks() {
        let td = TempDir::new().unwrap();
        let root = td.path().join("watched");
        fs::create_dir_all(root.join("nested")).unwrap();
        fs::write(root.join("direct.json"), b"a").unwrap();
        fs::write(root.join("nested/child.json"), b"b").unwrap();
        #[cfg(unix)]
        {
            let outside = td.path().join("outside");
            fs::create_dir(&outside).unwrap();
            fs::write(outside.join("secret.json"), b"excluded").unwrap();
            std::os::unix::fs::symlink(outside, root.join("link")).unwrap();
        }
        for (recursive, expected) in [(false, 1), (true, 2)] {
            let (tx, mut rx) = mpsc::channel(8);
            catch_up_files(root.clone(), recursive, Arc::new(tx)).await;
            let mut count = 0;
            while let Some(event) = rx.recv().await {
                assert_ne!(event.path.file_name().unwrap(), "secret.json");
                count += 1;
            }
            assert_eq!(count, expected);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unwatch_cancels_backpressured_catchup() {
        let td = TempDir::new().unwrap();
        let root = td.path().join("missing");
        let (mut rx, mut watcher) = spawn_watcher(
            vec![(root.clone(), true)],
            tokio::runtime::Handle::current(),
            1,
            Some(Duration::from_secs(60)),
        )
        .unwrap();
        fs::create_dir(&root).unwrap();
        for i in 0..20 {
            fs::write(root.join(format!("{i}.json")), b"x").unwrap();
        }
        watcher.reconcile();
        tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .unwrap()
            .unwrap();
        let task = watcher.catchups.remove(&root).unwrap();
        // Put it back so unwatch owns and cancels it, retaining its abort handle for inspection.
        let abort = task.abort_handle();
        watcher.catchups.insert(root.clone(), task);
        watcher.unwatch(&root).unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            while !abort.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn detects_create_in_watched_dir() {
        let td = TempDir::new().unwrap();
        let handle = tokio::runtime::Handle::current();
        let (mut rx, _watcher) =
            spawn_watcher(vec![(td.path().to_path_buf(), false)], handle, 16, None).unwrap();

        // Give the watcher a moment to register on macOS FSEvents.
        tokio::time::sleep(Duration::from_millis(200)).await;

        let p = td.path().join("new.json");
        let mut f = File::create(&p).unwrap();
        f.write_all(b"{}").unwrap();
        f.sync_all().unwrap();
        drop(f);

        let event = tokio::time::timeout(Duration::from_secs(3), rx.recv())
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
        let (mut rx, _watcher) =
            spawn_watcher(vec![(td.path().to_path_buf(), false)], handle, 16, None).unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        fs::remove_file(&p).unwrap();
        let mut saw_remove = false;
        for _ in 0..10 {
            if let Ok(Some(ev)) = tokio::time::timeout(Duration::from_secs(1), rx.recv()).await {
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
        let (mut rx, watcher) = spawn_watcher(
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
            if let Ok(Some(ev)) = tokio::time::timeout(Duration::from_millis(300), rx.recv()).await
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
