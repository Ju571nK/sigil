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
    resolved: BTreeMap<PathBuf, bool>,
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
        let requested = resolve_directory_pattern(root);
        self.desired.insert(root.to_path_buf(), recursive);
        let mut errors = self.rebuild_roots(true);
        for path in requested {
            if let Some(error) = errors.remove(&path) {
                return Err(error);
            }
        }
        Ok(())
    }

    fn refresh_root(&mut self, root: &Path, catch_up: bool) -> notify::Result<()> {
        let recursive = self.resolved[root];
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

    /// Expand only the directory components of configured patterns. Discovery
    /// never creates a recursive subscription on a broad ancestor (#223).
    fn rebuild_roots(&mut self, catch_up: bool) -> BTreeMap<PathBuf, notify::Error> {
        let mut resolved = BTreeMap::new();
        for (pattern, recursive) in &self.desired {
            for root in resolve_directory_pattern(pattern) {
                *resolved.entry(root).or_default() |= recursive;
            }
        }
        let obsolete: Vec<_> = self
            .resolved
            .keys()
            .filter(|root| !resolved.contains_key(*root))
            .cloned()
            .collect();
        for root in obsolete {
            // Backends may already have forgotten a deleted directory.
            let _ = self.remove_active(&root);
        }
        self.resolved = resolved;
        let mut errors = BTreeMap::new();
        for root in self.resolved.keys().cloned().collect::<Vec<_>>() {
            if let Err(error) = self.refresh_root(&root, catch_up) {
                tracing::debug!(root = %root.display(), %error, "watch root unavailable; will retry");
                errors.insert(root, error);
            }
        }
        errors
    }

    /// Check only configured roots, never recursively subscribe to an ancestor.
    pub(crate) fn reconcile(&mut self) {
        self.catchups.retain(|_, task| !task.is_finished());
        let _ = self.rebuild_roots(true);
    }

    /// Stop watching a root.
    pub fn unwatch(&mut self, root: &Path) -> notify::Result<()> {
        self.desired.remove(root);
        // Other desired patterns may still own some of the same concrete roots.
        self.reconcile();
        Ok(())
    }

    fn remove_active(&mut self, root: &Path) -> notify::Result<()> {
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

fn has_glob(path: &Path) -> bool {
    path.to_string_lossy()
        .contains(['*', '?', '[', ']', '{', '}'])
}

/// Walk one directory level per pattern component, not an entire subtree.
/// Literal missing roots retain #219's retry behavior; wildcard roots are
/// discovered afresh so installation/removal/replacement needs no restart.
fn resolve_directory_pattern(pattern: &Path) -> Vec<PathBuf> {
    if !has_glob(pattern) {
        return vec![pattern.to_path_buf()];
    }
    let mut candidates = vec![PathBuf::new()];
    let mut in_pattern = false;
    for component in pattern.components() {
        let part = Path::new(component.as_os_str());
        if has_glob(part) {
            in_pattern = true;
            let Ok(glob) = sigil_core::policy::glob::CompiledGlob::new(&part.to_string_lossy())
            else {
                return Vec::new();
            };
            let mut matches = Vec::new();
            for parent in candidates {
                let Ok(entries) = std::fs::read_dir(&parent) else {
                    continue;
                };
                for entry in entries.flatten() {
                    if entry.file_type().is_ok_and(|kind| kind.is_dir())
                        && glob.is_match(Path::new(&entry.file_name()))
                    {
                        matches.push(entry.path());
                    }
                }
            }
            candidates = matches;
        } else {
            candidates = candidates
                .into_iter()
                .filter_map(|mut parent| {
                    parent.push(part);
                    // Do not follow a wildcard match's symlink descendants outside
                    // the policy's canonical prefix (normalizer paths must agree).
                    if !in_pattern || std::fs::symlink_metadata(&parent).is_ok_and(|m| m.is_dir()) {
                        Some(parent)
                    } else {
                        None
                    }
                })
                .collect();
        }
    }
    candidates
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
        resolved: BTreeMap::new(),
        active: BTreeMap::new(),
        catchups: BTreeMap::new(),
        tx,
        runtime: runtime_handle,
    };
    for (root, recursive) in roots {
        *handle.desired.entry(root).or_default() |= recursive;
    }
    let _ = handle.rebuild_roots(false);
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

    async fn wildcard_directory_lifecycle(poll: Option<Duration>) {
        let td = TempDir::new().unwrap();
        let apps = td.path().join("Applications");
        let existing = apps.join("Existing.app/Contents");
        fs::create_dir_all(&existing).unwrap();
        fs::create_dir_all(apps.join("Unrelated/Contents/deep")).unwrap();
        let pattern = apps.join("*.app/Contents");
        let (mut rx, mut watcher) = spawn_watcher(
            vec![(pattern.clone(), false)],
            tokio::runtime::Handle::current(),
            32,
            poll,
        )
        .unwrap();
        assert_eq!(watcher.active.len(), 1);
        assert!(watcher.active.contains_key(&existing));
        assert!(!watcher.active[&existing].0);
        assert!(!watcher.active.contains_key(&apps));
        assert!(!watcher.active.contains_key(&pattern));
        tokio::time::sleep(Duration::from_millis(250)).await;
        let first = existing.join("Info.plist");
        fs::write(&first, b"live existing app").unwrap();
        receive_path(&mut rx, &first).await;

        let late = apps.join("New.app/Contents");
        fs::create_dir_all(&late).unwrap();
        let late_file = late.join("Info.plist");
        fs::write(&late_file, b"written once before discovery").unwrap();
        watcher.reconcile();
        receive_path(&mut rx, &late_file).await;
        assert_eq!(watcher.active.len(), 2);
        if let Some(task) = watcher.catchups.remove(&late) {
            task.await.unwrap();
        }
        watcher.reconcile();
        assert!(watcher.catchups.is_empty(), "stable roots must not rescan");

        fs::rename(&late, td.path().join("old-contents")).unwrap();
        fs::create_dir(&late).unwrap();
        let replaced = late.join("replacement.json");
        fs::write(&replaced, b"replacement").unwrap();
        watcher.reconcile();
        receive_path(&mut rx, &replaced).await;
        fs::remove_dir_all(apps.join("New.app")).unwrap();
        watcher.reconcile();
        assert!(!watcher.active.contains_key(&late));

        // Removing a glob on policy reload must retain a shared literal root.
        watcher.watch(&existing, true).unwrap();
        watcher.unwatch(&pattern).unwrap();
        assert_eq!(watcher.active.len(), 1);
        assert!(watcher.active[&existing].0);
        watcher.unwatch(&existing).unwrap();
        assert!(watcher.active.is_empty());
        assert!(watcher.resolved.is_empty());
        assert!(watcher.catchups.is_empty());
        fs::create_dir_all(&late).unwrap();
        watcher.reconcile();
        assert!(watcher.active.is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn native_wildcard_directory_lifecycle() {
        wildcard_directory_lifecycle(None).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn polling_wildcard_directory_lifecycle() {
        wildcard_directory_lifecycle(Some(Duration::from_millis(100))).await;
    }

    #[test]
    fn nested_directory_patterns_use_policy_glob_syntax() {
        let td = TempDir::new().unwrap();
        let expected = td.path().join("GroupA/App1.app/Contents");
        fs::create_dir_all(&expected).unwrap();
        fs::create_dir_all(td.path().join("GroupB/App2.app/Contents")).unwrap();
        fs::create_dir_all(td.path().join("GroupA/App22.app/Contents")).unwrap();
        assert_eq!(
            resolve_directory_pattern(&td.path().join("Group[A]/{App,Tool}?.app/Contents")),
            vec![expected]
        );
        assert!(resolve_directory_pattern(&td.path().join("Missing*/*.app/Contents")).is_empty());
    }

    #[cfg(windows)]
    #[test]
    fn mixed_windows_separators_resolve_the_same_directories() {
        let td = TempDir::new().unwrap();
        let expected = td.path().join("Example.app/Contents");
        fs::create_dir_all(&expected).unwrap();
        let pattern = PathBuf::from(format!("{}/*.app/Contents", td.path().display()));
        assert_eq!(resolve_directory_pattern(&pattern), vec![expected]);
    }

    #[cfg(unix)]
    #[test]
    fn wildcard_discovery_does_not_follow_symlink_directories() {
        let td = TempDir::new().unwrap();
        let outside = td.path().join("outside");
        fs::create_dir_all(outside.join("Contents")).unwrap();
        std::os::unix::fs::symlink(&outside, td.path().join("Link.app")).unwrap();
        fs::create_dir(td.path().join("Real.app")).unwrap();
        std::os::unix::fs::symlink(
            outside.join("Contents"),
            td.path().join("Real.app/Contents"),
        )
        .unwrap();
        assert!(resolve_directory_pattern(&td.path().join("*.app/Contents")).is_empty());
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

    #[tokio::test]
    async fn watch_result_does_not_report_an_unrelated_missing_root() {
        let td = TempDir::new().unwrap();
        let (_rx, mut watcher) = spawn_watcher(
            vec![(td.path().join("missing"), false)],
            tokio::runtime::Handle::current(),
            16,
            Some(Duration::from_secs(60)),
        )
        .unwrap();
        let existing = td.path().join("existing");
        fs::create_dir(&existing).unwrap();
        watcher.watch(&existing, false).unwrap();
        assert!(watcher.active.contains_key(&existing));
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
    async fn dropping_watcher_during_catchup_closes_raw_channel() {
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
        rx.recv().await.unwrap();
        drop(watcher);
        tokio::time::timeout(Duration::from_secs(2), async {
            while rx.recv().await.is_some() {}
        })
        .await
        .expect("shutdown retained a raw-event sender");
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
