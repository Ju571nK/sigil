//! rule-packs.yaml 전용 fsnotify watcher (#134).
//! 메인 watcher는 normalizer가 policy target에 안 맞는 경로를 drop하므로
//! 재사용 불가. 이 모듈은 rule-packs.yaml의 부모 디렉터리를 감시하고,
//! 대상 파일 변경 시 rule_packs_version_tx에 트리거 카운터를 보내
//! policy_reload_task의 rule_packs_version_rx.changed()를 깨운다.
//!
//! ## 구현 노트 — spawn_blocking
//!
//! notify의 RecommendedWatcher는 내부적으로 std::sync::mpsc 채널을 사용하며,
//! recv_timeout은 blocking 호출이다. tokio 워커 스레드를 blocking으로 점유하면
//! async 런타임이 stall할 수 있으므로, 이벤트 드레인 루프를 spawn_blocking으로
//! 분리하고 tokio::sync::mpsc를 통해 async 컨텍스트와 통신한다.
//!
//! ## 구현 노트 — 경로 정규화
//!
//! macOS에서 /var → /private/var, /tmp → /private/tmp 심볼릭 링크로 인해
//! TempDir::new()가 반환하는 경로(비정규)와 notify가 보고하는 이벤트 경로(정규)가
//! 달라진다. `dunce::canonicalize`로 target과 watch 디렉터리를 정규화해 비교가
//! 올바르게 이루어지도록 한다.
use notify::{Config, Event, PollWatcher, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::{Path, PathBuf};
use std::sync::mpsc as std_mpsc;
use std::time::Duration;
use tokio::sync::{mpsc as tokio_mpsc, watch};
use tokio_util::sync::CancellationToken;

/// 이벤트 경로가 주어진 경로(rule-packs.yaml 또는 부모 디렉터리)와 일치하는지 판정.
fn is_rule_packs_event(target: &Path, evented: &Path) -> bool {
    evented == target
}

/// 전용 watcher 태스크. 조부모 디렉터리(항상 존재: `~/.config`, `/etc`, `$HOME`)를
/// 감시해 부모 디렉터리의 생성/삭제를 관측하고, 부모 디렉터리가 (재)등장하면
/// 부모 watch를 (재)무장해 대상 파일 변경 시 `version_tx`에 단조 증가 카운터를
/// 보낸다. 부모가 시작 시점에 없어도 영구 비활성화되지 않는다 (#135).
/// 조부모 디렉터리마저 없으면 경고만 남기고 종료.
///
/// `poll_interval = Some(d)`이면 메인 watcher와 동일하게 `PollWatcher`를 쓴다
/// (NFS/virtiofs/9p 등 OS-네이티브 FS 이벤트가 신뢰 불가한 호스트, `--poll`).
/// `None`이면 OS-네이티브 `RecommendedWatcher`. runtime은 메인 watcher와
/// 동일한 값을 넘겨, 운영자가 깨졌다고 선언한 FS 이벤트에 hot-reload가
/// 의존하지 않도록 한다.
///
/// notify 이벤트 드레인은 spawn_blocking으로 분리해 tokio 워커를 점유하지 않는다.
pub async fn run(
    target: PathBuf,
    version_tx: watch::Sender<i64>,
    poll_interval: Option<Duration>,
    shutdown: CancellationToken,
) {
    // #135 — watch the GRANDPARENT dir (always present: ~/.config, /etc, $HOME),
    // not just the parent. That lets us (re)arm the parent-dir watch when the
    // config dir is created — or deleted and re-created — at runtime, instead of
    // giving up permanently when the parent is absent at start.
    let parent = match target.parent() {
        Some(p) => p.to_path_buf(),
        None => {
            tracing::warn!(path = %target.display(),
                "rule-packs.yaml has no parent dir; dedicated watcher not started");
            return;
        }
    };
    let grandparent = match parent.parent() {
        Some(g) => g.to_path_buf(),
        None => {
            tracing::warn!(path = %target.display(),
                "rule-packs.yaml has no grandparent dir; dedicated watcher not started");
            return;
        }
    };
    if !grandparent.exists() {
        tracing::warn!(path = %grandparent.display(),
            "rule-packs.yaml grandparent dir absent; dedicated watcher not started");
        return;
    }
    // Two parent representations are needed because the grandparent and parent
    // watches report the dir differently:
    //   * `parent_entry` = the parent as it appears *inside* the (canonical)
    //     grandparent — `canon_grandparent/<name>`. The grandparent watch reports
    //     parent-dir create/delete events under this lexical path (a symlinked
    //     config dir is still listed by its own name in the grandparent), so this
    //     is the re-arm trigger to compare against.
    //   * `canon_parent` = the *resolved* parent (`canonicalize(parent)` when it
    //     exists). The parent watch's target-file events arrive under the resolved
    //     path on FSEvents and under the registered (canonical) path on inotify, so
    //     we watch and compare against the canonical form — restoring #134's
    //     symlinked-parent handling that a lexical grandparent-join would regress.
    // For a real (non-symlink) dir the two are identical.
    let canon_grandparent =
        dunce::canonicalize(&grandparent).unwrap_or_else(|_| grandparent.clone());
    let parent_entry = parent
        .file_name()
        .map(|name| canon_grandparent.join(name))
        .unwrap_or_else(|| parent.clone());
    let canon_parent = if parent.exists() {
        dunce::canonicalize(&parent).unwrap_or_else(|_| parent_entry.clone())
    } else {
        parent_entry.clone()
    };
    let canonical_target = target
        .file_name()
        .map(|name| canon_parent.join(name))
        .unwrap_or_else(|| target.clone());

    // std::sync::mpsc for notify callback → blocking drain loop.
    let (std_tx, std_rx) = std_mpsc::channel::<()>();
    // tokio::sync::mpsc to ferry "something changed" signals to async context.
    let (tok_tx, mut tok_rx) = tokio_mpsc::channel::<()>(8);

    let target_for_cb = canonical_target.clone();
    let parent_entry_for_cb = parent_entry.clone();
    let canon_parent_for_cb = canon_parent.clone();
    // Mirror the main watcher's callback: log backend errors instead of
    // silently dropping them. If inotify watch-limit / kqueue fd exhaustion
    // hits, hot-reload would otherwise die with no trace.
    //
    // Forward a single "something changed" signal when an event touches the
    // target file (via the parent watch → drives reload) OR the parent dir
    // itself (via the grandparent watch → drives re-arm + reload). The parent dir
    // can be reported as either the grandparent-relative `parent_entry` or the
    // resolved `canon_parent` depending on backend; match both. #135.
    let on_event = move |res: notify::Result<Event>| match res {
        Ok(ev) => {
            if ev.paths.iter().any(|p| {
                is_rule_packs_event(&target_for_cb, p)
                    || is_rule_packs_event(&parent_entry_for_cb, p)
                    || is_rule_packs_event(&canon_parent_for_cb, p)
            }) {
                let _ = std_tx.send(());
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "rule-packs watcher backend error");
        }
    };
    // `--poll` (poll_interval = Some) → PollWatcher, matching the main watcher.
    // Otherwise the OS-native RecommendedWatcher. `Box<dyn Watcher>` lets both
    // backends share the rest of the function (only watch()/drop() are needed).
    let mut watcher: Box<dyn Watcher + Send> = match poll_interval {
        Some(interval) => {
            match PollWatcher::new(on_event, Config::default().with_poll_interval(interval)) {
                Ok(w) => Box::new(w),
                Err(e) => {
                    tracing::error!(error = ?e, "rule-packs poll watcher init failed");
                    return;
                }
            }
        }
        None => match RecommendedWatcher::new(on_event, Config::default()) {
            Ok(w) => Box::new(w),
            Err(e) => {
                tracing::error!(error = ?e, "rule-packs watcher init failed");
                return;
            }
        },
    };
    // Watch the grandparent so parent-dir create/delete is observable (the
    // re-arm source). Fatal if this fails — without it there is no recovery
    // path. Canonical path so macOS FSEvents receives the real dir, not a
    // /var → /private/var symlink.
    if let Err(e) = watcher.watch(&canon_grandparent, RecursiveMode::NonRecursive) {
        tracing::error!(error = ?e, dir = %canon_grandparent.display(),
            "rule-packs grandparent watch failed");
        return;
    }
    // Watch the parent too when it exists now (the target-file event source).
    // Non-fatal: if the parent is absent at start, a later parent-create event
    // re-arms it in the async loop below. `parent_armed` tracks whether the watch
    // is currently registered so the loop only (re)arms on absent→present edges —
    // re-watching on every event would grow notify's FSEvents watch list unbounded
    // (its backend appends rather than dedups). #135.
    let mut parent_armed = false;
    if parent_entry.exists() {
        match watcher.watch(&canon_parent, RecursiveMode::NonRecursive) {
            Ok(()) => parent_armed = true,
            Err(e) => tracing::warn!(error = ?e, dir = %canon_parent.display(),
                "rule-packs parent watch failed; will retry on next event"),
        }
    }
    tracing::info!(
        grandparent = %canon_grandparent.display(),
        parent = %canon_parent.display(),
        target = %canonical_target.display(),
        "rule-packs.yaml dedicated watcher started"
    );

    // Blocking drain loop — runs on a dedicated thread pool thread so the tokio
    // workers stay free. Debounces bursts by draining the channel after each hit.
    // Sends a single () on tok_tx per debounced event group.
    let tok_tx_clone = tok_tx.clone();
    let _drain_handle = tokio::task::spawn_blocking(move || {
        loop {
            match std_rx.recv_timeout(Duration::from_millis(300)) {
                Ok(()) => {
                    // Drain any additional events queued during the bounce window.
                    while std_rx.recv_timeout(Duration::from_millis(50)).is_ok() {}
                    // Best-effort: if receiver is gone, stop the drain loop.
                    if tok_tx_clone.blocking_send(()).is_err() {
                        break;
                    }
                }
                Err(std_mpsc::RecvTimeoutError::Timeout) => continue,
                Err(std_mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
    });

    // Drop our retained sender so the `None` arm below becomes genuinely
    // reachable: once `tok_tx_clone` in the drain thread also drops (on its own
    // exit), `tok_rx.recv()` returns None and the loop ends. Normal shutdown
    // still flows through the CancellationToken arm.
    drop(tok_tx);

    // Async event loop — receives debounced signals from the drain thread.
    let mut counter = *version_tx.borrow();
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            msg = tok_rx.recv() => {
                match msg {
                    Some(()) => {
                        // #135 — re-arm the parent watch ONLY on absent→present /
                        // present→absent transitions, never on every event: notify's
                        // FSEvents backend appends (does not dedup) on watch(), so
                        // re-watching per file edit would grow the watch list
                        // unbounded on macOS. The version bump below runs regardless,
                        // so reload() always re-reads the file from disk.
                        let present = parent_entry.exists();
                        if present && !parent_armed {
                            // (Re)appeared — unwatch any stale registration first so
                            // FSEvents keeps a single entry, then arm.
                            let _ = watcher.unwatch(&canon_parent);
                            match watcher.watch(&canon_parent, RecursiveMode::NonRecursive) {
                                Ok(()) => parent_armed = true,
                                Err(e) => tracing::debug!(error = ?e,
                                    "rule-packs parent re-arm watch failed"),
                            }
                        } else if !present && parent_armed {
                            // Disappeared — drop the watch so the next appearance
                            // re-arms cleanly (the reload below reads NotFound).
                            let _ = watcher.unwatch(&canon_parent);
                            parent_armed = false;
                        }
                        counter += 1;
                        let _ = version_tx.send(counter);
                        tracing::debug!(counter, "rule-packs.yaml changed; reload triggered");
                    }
                    // Drain thread exited (its sender dropped); nothing more to do.
                    None => break,
                }
            }
        }
    }
    // Keep `watcher` alive until the loop exits so notify keeps firing.
    drop(watcher);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_target_file_only() {
        let target = PathBuf::from("/some/dir/rule-packs.yaml");

        // Exact match → true.
        assert!(
            is_rule_packs_event(&target, Path::new("/some/dir/rule-packs.yaml")),
            "exact match should return true"
        );

        // Sibling file (policy.yaml in the same dir) → false.
        assert!(
            !is_rule_packs_event(&target, Path::new("/some/dir/policy.yaml")),
            "sibling policy.yaml should return false"
        );

        // Same filename but different directory → false.
        assert!(
            !is_rule_packs_event(&target, Path::new("/other/dir/rule-packs.yaml")),
            "same filename in different dir should return false"
        );
    }

    /// Poll-path coverage (#134 review item 2): with `poll_interval = Some(..)`
    /// the watcher builds a `PollWatcher` (not the native backend) and still
    /// bumps `version_tx` when rule-packs.yaml is written. Polling is backend-
    /// independent, so this is fast and deterministic on every OS/CI.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn poll_watcher_triggers_version_bump() {
        let dir = tempfile::tempdir().unwrap();
        let root = dunce::canonicalize(dir.path()).unwrap();
        let target = root.join("rule-packs.yaml");
        std::fs::write(&target, "version: 1\n").unwrap();

        let (tx, mut rx) = watch::channel(0i64);
        let shutdown = CancellationToken::new();

        // Short poll interval so the test completes quickly.
        let handle = tokio::spawn(run(
            target.clone(),
            tx,
            Some(Duration::from_millis(100)),
            shutdown.clone(),
        ));

        // Repeatedly mutate the file (growing content so mtime + size change)
        // while waiting for the counter to advance past its initial 0. The loop
        // tolerates the registration window and any poll-tick alignment so the
        // test stays deterministic regardless of timer phase.
        let bumped = tokio::time::timeout(Duration::from_secs(10), async {
            let mut n = 2u32;
            loop {
                std::fs::write(&target, format!("version: {n}\n")).unwrap();
                n += 1;
                tokio::select! {
                    r = rx.changed() => {
                        if r.is_err() {
                            break false;
                        }
                        if *rx.borrow() > 0 {
                            break true;
                        }
                    }
                    _ = tokio::time::sleep(Duration::from_millis(200)) => {}
                }
            }
        })
        .await
        .expect("poll watcher should bump version within 10s");
        assert!(bumped, "version_tx counter should advance on file change");

        shutdown.cancel();
        let _ = handle.await;
    }

    /// #135 re-arm (absent-at-start): the config dir does NOT exist when the
    /// watcher starts. It must arm on the grandparent and report changes once
    /// the dir appears — proving it no longer permanently disables itself.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rearm_when_parent_created_after_start() {
        let gp = tempfile::tempdir().unwrap();
        let grandparent = dunce::canonicalize(gp.path()).unwrap();
        let parent = grandparent.join("sigil");
        let target = parent.join("rule-packs.yaml");

        let (tx, mut rx) = watch::channel(0i64);
        let shutdown = CancellationToken::new();
        let handle = tokio::spawn(run(
            target.clone(),
            tx,
            Some(Duration::from_millis(100)),
            shutdown.clone(),
        ));

        let bumped = tokio::time::timeout(Duration::from_secs(10), async {
            let mut n = 1u32;
            loop {
                // Create the config dir (idempotent) and write the file.
                std::fs::create_dir_all(&parent).unwrap();
                std::fs::write(&target, format!("version: {n}\n")).unwrap();
                n += 1;
                tokio::select! {
                    r = rx.changed() => {
                        if r.is_err() {
                            break false;
                        }
                        if *rx.borrow() > 0 {
                            break true;
                        }
                    }
                    _ = tokio::time::sleep(Duration::from_millis(200)) => {}
                }
            }
        })
        .await
        .expect("watcher should arm + report after the config dir appears within 10s");
        assert!(
            bumped,
            "version_tx should advance once the config dir is created"
        );

        shutdown.cancel();
        let _ = handle.await;
    }

    /// #135 re-arm (delete + recreate): the parent exists at start, then is
    /// deleted and re-created at runtime. A by-inode watch would go silent; the
    /// grandparent watch must re-arm the parent so changes are reported again.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rearm_when_parent_deleted_and_recreated() {
        let gp = tempfile::tempdir().unwrap();
        let grandparent = dunce::canonicalize(gp.path()).unwrap();
        let parent = grandparent.join("sigil");
        std::fs::create_dir(&parent).unwrap();
        let target = parent.join("rule-packs.yaml");
        std::fs::write(&target, "version: 1\n").unwrap();

        let (tx, mut rx) = watch::channel(0i64);
        let shutdown = CancellationToken::new();
        let handle = tokio::spawn(run(
            target.clone(),
            tx,
            Some(Duration::from_millis(100)),
            shutdown.clone(),
        ));

        // Phase A — confirm the parent watch is armed. A pre-existing file emits
        // no event, so mutate until the counter first advances.
        let armed = tokio::time::timeout(Duration::from_secs(10), async {
            let mut n = 2u32;
            loop {
                std::fs::write(&target, format!("version: {n}\n")).unwrap();
                n += 1;
                tokio::select! {
                    r = rx.changed() => {
                        if r.is_err() {
                            break false;
                        }
                        if *rx.borrow() > 0 {
                            break true;
                        }
                    }
                    _ = tokio::time::sleep(Duration::from_millis(200)) => {}
                }
            }
        })
        .await
        .expect("parent watch should arm within 10s");
        assert!(armed, "baseline arm");
        let baseline = *rx.borrow();

        // Phase B — delete the config dir, let the grandparent poll observe the
        // absence, then re-create it. The watcher must re-arm and report changes
        // past the baseline.
        std::fs::remove_dir_all(&parent).unwrap();
        tokio::time::sleep(Duration::from_millis(250)).await;
        std::fs::create_dir(&parent).unwrap();

        let rearmed = tokio::time::timeout(Duration::from_secs(10), async {
            let mut n = 100u32;
            loop {
                std::fs::write(&target, format!("version: {n}\n")).unwrap();
                n += 1;
                tokio::select! {
                    r = rx.changed() => {
                        if r.is_err() {
                            break false;
                        }
                        if *rx.borrow() > baseline {
                            break true;
                        }
                    }
                    _ = tokio::time::sleep(Duration::from_millis(200)) => {}
                }
            }
        })
        .await
        .expect("watcher should re-arm + report after dir re-creation within 10s");
        assert!(
            rearmed,
            "version_tx should advance past baseline after the config dir is re-created"
        );

        shutdown.cancel();
        let _ = handle.await;
    }
}
