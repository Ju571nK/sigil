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
use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::{Path, PathBuf};
use std::sync::mpsc as std_mpsc;
use std::time::Duration;
use tokio::sync::{mpsc as tokio_mpsc, watch};
use tokio_util::sync::CancellationToken;

/// 이벤트 경로가 감시 대상(rule-packs.yaml)인지 판정.
pub(crate) fn is_rule_packs_event(target: &Path, evented: &Path) -> bool {
    evented == target
}

/// 부모 디렉터리가 존재하면 그 경로, 없으면 None.
fn existing_parent(target: &Path) -> Option<PathBuf> {
    target
        .parent()
        .filter(|p| p.exists())
        .map(|p| p.to_path_buf())
}

/// 전용 watcher 태스크. 부모 디렉터리를 감시하고 대상 파일 변경 시
/// `version_tx`에 단조 증가 카운터를 보낸다. 부모 디렉터리가 없으면
/// 경고만 남기고 종료.
///
/// notify 이벤트 드레인은 spawn_blocking으로 분리해 tokio 워커를 점유하지 않는다.
pub async fn run(target: PathBuf, version_tx: watch::Sender<i64>, shutdown: CancellationToken) {
    let parent = match existing_parent(&target) {
        Some(p) => p,
        None => {
            tracing::warn!(path = %target.display(),
                "rule-packs.yaml parent dir absent; dedicated watcher not started");
            return;
        }
    };
    // Canonicalize target so notify event paths (always canonical on macOS/Linux
    // where /tmp → /private/tmp, /var → /private/var) compare correctly.
    // If the file doesn't exist yet (first boot before any rule-packs.yaml is
    // written), fall back to canonicalizing the parent and re-joining the filename.
    let canon_parent = dunce::canonicalize(&parent).unwrap_or_else(|_| parent.clone());
    let canonical_target = if target.exists() {
        dunce::canonicalize(&target).unwrap_or_else(|_| target.clone())
    } else {
        target
            .file_name()
            .map(|name| canon_parent.join(name))
            .unwrap_or(target.clone())
    };

    // std::sync::mpsc for notify callback → blocking drain loop.
    let (std_tx, std_rx) = std_mpsc::channel::<()>();
    // tokio::sync::mpsc to ferry "something changed" signals to async context.
    let (tok_tx, mut tok_rx) = tokio_mpsc::channel::<()>(8);

    let target_for_cb = canonical_target.clone();
    let mut watcher = match RecommendedWatcher::new(
        move |res: notify::Result<Event>| {
            if let Ok(ev) = res {
                if ev
                    .paths
                    .iter()
                    .any(|p| is_rule_packs_event(&target_for_cb, p))
                {
                    let _ = std_tx.send(());
                }
            }
        },
        notify::Config::default(),
    ) {
        Ok(w) => w,
        Err(e) => {
            tracing::error!(error = ?e, "rule-packs watcher init failed");
            return;
        }
    };
    // Canonicalize the watch directory so FSEvents on macOS receives the real
    // path (not the /var → /private/var symlink). Without this, FSEvents may
    // not deliver events when the watch path is a symlink target.
    if let Err(e) = watcher.watch(&canon_parent, RecursiveMode::NonRecursive) {
        tracing::error!(error = ?e, dir = %canon_parent.display(), "rule-packs watch failed");
        return;
    }
    tracing::info!(
        dir = %canon_parent.display(),
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

    // Async event loop — receives debounced signals from the drain thread.
    let mut counter = *version_tx.borrow();
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            msg = tok_rx.recv() => {
                match msg {
                    Some(()) => {
                        counter += 1;
                        let _ = version_tx.send(counter);
                        tracing::debug!(counter, "rule-packs.yaml changed; reload triggered");
                    }
                    None => break, // drain loop exited
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
}
