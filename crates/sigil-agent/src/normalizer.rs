//! Normalizer task. Owns:
//! - canonicalization (`dunce::canonicalize`)
//! - glob filtering against active WatchTargets
//! - rename pairing within a 200 ms window
//! - per-target token-bucket rate limiting
//!
//! Event paths are canonicalized (symlinks resolved); policy paths are
//! canonicalized up to the first glob metacharacter when they're compiled into
//! globs (see [`canonicalize_glob_prefix`]), so a watch path under a symlinked
//! directory — on macOS `/var`, `/tmp`, `/etc` are symlinks to `/private/...` —
//! still matches.

use crate::watcher::RawFsEvent;
use sigil_core::event::FileChangeKind;
use sigil_core::policy::{glob::CompiledGlob, EffectivePolicy, Tier};
use sigil_core::ratelimit::{DropReport, RateLimiter};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::Instant;

const SEPS: [char; 2] = ['/', '\\'];

fn ends_with_sep(s: &OsStr) -> bool {
    s.to_string_lossy().ends_with(SEPS)
}

/// Canonicalize the literal directory prefix of a watch path — everything up to
/// the first glob metacharacter — leaving the glob portion verbatim. This makes
/// globs compiled from policy paths match the canonical event paths the
/// normalizer produces: on macOS `/var/...`, `/tmp/...`, `/etc/...` are
/// symlinks to `/private/...`, and `dunce::canonicalize` resolves event paths
/// to that form. The longest *existing* directory ancestor is canonicalized, so
/// it works even before the watched leaf exists; if no ancestor exists yet (or
/// the path isn't absolute) the pattern is returned unchanged.
pub fn canonicalize_glob_prefix(pattern: &Path) -> PathBuf {
    let s = pattern.to_string_lossy();
    let glob_at = s.find(['*', '?', '[', ']', '{', '}']);
    let (head, glob_tail): (&str, &str) = match glob_at {
        Some(i) => (&s[..i], &s[i..]),
        None => (&s, ""),
    };
    // Split `head` into a directory path (which we can canonicalize) and a
    // verbatim trailing fragment that may be only part of a filename
    // (`events-` in `events-*.jsonl`, or `policy.yaml` when there's no glob).
    let Some(last_sep) = head.rfind(SEPS) else {
        return pattern.to_path_buf();
    };
    let (dir, leaf) = (&head[..=last_sep], &head[last_sep + 1..]);
    let dir_path = Path::new(dir);
    if !dir_path.is_absolute() {
        return pattern.to_path_buf();
    }
    for ancestor in dir_path.ancestors() {
        if ancestor.as_os_str().is_empty() {
            break;
        }
        let Ok(canon) = dunce::canonicalize(ancestor) else {
            continue;
        };
        // `dir`, with its `ancestor` prefix replaced by the canonical form,
        // then the verbatim leaf and glob tail re-attached. `dir` ends with a
        // separator; `dir_rest` is "" (ancestor == dir) or starts with one.
        let dir_rest = dir.strip_prefix(&*ancestor.to_string_lossy()).unwrap_or("");
        let mut out = canon.into_os_string();
        if !dir_rest.is_empty() && !ends_with_sep(&out) && !dir_rest.starts_with(SEPS) {
            out.push(std::path::MAIN_SEPARATOR_STR);
        }
        out.push(dir_rest);
        if !ends_with_sep(&out) {
            out.push(std::path::MAIN_SEPARATOR_STR);
        }
        out.push(leaf);
        out.push(glob_tail);
        return PathBuf::from(out);
    }
    pattern.to_path_buf()
}

pub const RENAME_PAIR_WINDOW: Duration = Duration::from_millis(200);

#[derive(Debug, Clone)]
pub struct NormalizedEvent {
    pub path: PathBuf,
    pub kind: FileChangeKind,
    pub rename_from: Option<PathBuf>,
    pub target_id: String,
    pub tier: Tier,
}

pub struct CompiledTarget {
    pub id: String,
    pub tier: Tier,
    pub globs: Vec<CompiledGlob>,
}

/// Compile the effective policy's expanded paths into matchers. Callers pass
/// paths that have already been run through [`canonicalize_glob_prefix`] so the
/// globs match the canonical event paths the normalizer produces.
pub fn compile_targets(
    policy: &EffectivePolicy,
    expanded_paths: &HashMap<String, Vec<PathBuf>>,
) -> Vec<CompiledTarget> {
    let mut out = Vec::new();
    for t in &policy.targets {
        let mut globs = Vec::new();
        if let Some(paths) = expanded_paths.get(&t.id) {
            for p in paths {
                if let Ok(g) = CompiledGlob::new(&p.to_string_lossy()) {
                    globs.push(g);
                }
            }
        }
        out.push(CompiledTarget {
            id: t.id.clone(),
            tier: t.tier,
            globs,
        });
    }
    out
}

fn match_target<'a>(path: &Path, targets: &'a [CompiledTarget]) -> Option<&'a CompiledTarget> {
    targets
        .iter()
        .find(|t| t.globs.iter().any(|g| g.is_match(path)))
}

/// Re-derive the `NormalizedEvent` for an already-canonical `path` by matching
/// it against `targets`. Used downstream (the hasher) to recover target/tier
/// metadata for a `PendingEvent`. Rename pairing isn't reconstructed here — that
/// happens once, in `run`, before the event reaches the debouncer.
pub fn lookup(
    targets: &[CompiledTarget],
    path: &Path,
    kind: FileChangeKind,
) -> Option<NormalizedEvent> {
    let t = match_target(path, targets)?;
    Some(NormalizedEvent {
        path: path.to_path_buf(),
        kind,
        rename_from: None,
        target_id: t.id.clone(),
        tier: t.tier,
    })
}

#[derive(Debug, Default)]
struct PendingFrom {
    path: PathBuf,
    inserted_at: Option<Instant>,
}

pub async fn run(
    targets: Arc<Vec<CompiledTarget>>,
    mut rx_raw: mpsc::Receiver<RawFsEvent>,
    tx_norm: mpsc::Sender<NormalizedEvent>,
    tx_dropped: mpsc::Sender<DropReport>,
) {
    let mut limiter = RateLimiter::new();
    let mut pending_from: HashMap<u64, PendingFrom> = HashMap::new();
    let mut report_tick = tokio::time::interval(Duration::from_secs(10));
    report_tick.tick().await; // skip immediate

    loop {
        tokio::select! {
            biased;
            maybe_event = rx_raw.recv() => {
                let Some(raw) = maybe_event else { break; };
                let canonical = dunce::canonicalize(&raw.path).unwrap_or(raw.path.clone());
                tracing::debug!(
                    raw_path = %raw.path.display(),
                    canonical = %canonical.display(),
                    kind = ?raw.kind,
                    matched = match_target(&canonical, &targets).map(|t| t.id.as_str()),
                    "normalizer received raw event"
                );
                let now_ms = monotonic_ms();
                let mut to_emit: Vec<NormalizedEvent> = Vec::new();

                if raw.kind == FileChangeKind::Renamed {
                    if let Some(id) = raw.rename_id {
                        match pending_from.entry(id) {
                            std::collections::hash_map::Entry::Occupied(o) => {
                                let pf = o.remove();
                                let to = canonical.clone();
                                if let Some(t) = match_target(&to, &targets) {
                                    to_emit.push(NormalizedEvent {
                                        path: to,
                                        kind: FileChangeKind::Renamed,
                                        rename_from: Some(pf.path),
                                        target_id: t.id.clone(),
                                        tier: t.tier,
                                    });
                                } else if let Some(t) = match_target(&pf.path, &targets) {
                                    // Moved out of watchlist
                                    to_emit.push(NormalizedEvent {
                                        path: pf.path.clone(),
                                        kind: FileChangeKind::Removed,
                                        rename_from: Some(pf.path),
                                        target_id: t.id.clone(),
                                        tier: t.tier,
                                    });
                                }
                            }
                            std::collections::hash_map::Entry::Vacant(v) => {
                                v.insert(PendingFrom {
                                    path: canonical.clone(),
                                    inserted_at: Some(Instant::now()),
                                });
                            }
                        }
                    } else if let Some(t) = match_target(&canonical, &targets) {
                        // No tracker id — treat as a Modified.
                        to_emit.push(NormalizedEvent {
                            path: canonical,
                            kind: FileChangeKind::Modified,
                            rename_from: None,
                            target_id: t.id.clone(),
                            tier: t.tier,
                        });
                    }
                } else if let Some(t) = match_target(&canonical, &targets) {
                    to_emit.push(NormalizedEvent {
                        path: canonical,
                        kind: raw.kind,
                        rename_from: None,
                        target_id: t.id.clone(),
                        tier: t.tier,
                    });
                }

                // Apply rate limit
                for ev in to_emit {
                    if limiter.allow(&ev.target_id, now_ms) {
                        if tx_norm.send(ev).await.is_err() {
                            return;
                        }
                    } else {
                        limiter.record_drop(&ev.target_id, ev.path.clone(), now_ms);
                    }
                }
            }
            _ = report_tick.tick() => {
                let now_ms = monotonic_ms();
                expire_pending(&mut pending_from);
                for r in limiter.drain_reports(now_ms) {
                    let _ = tx_dropped.send(r).await;
                }
            }
        }
    }
}

fn expire_pending(pending: &mut HashMap<u64, PendingFrom>) {
    let now = Instant::now();
    pending.retain(|_, v| match v.inserted_at {
        Some(t) => now.duration_since(t) < RENAME_PAIR_WINDOW,
        None => false,
    });
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
    use super::canonicalize_glob_prefix;
    use std::path::{Path, PathBuf};

    #[test]
    fn passthrough_for_relative_paths() {
        let p = Path::new("relative/dir/file-*.json");
        assert_eq!(canonicalize_glob_prefix(p), PathBuf::from(p));
    }

    #[test]
    fn passthrough_when_nothing_exists_keeps_value() {
        // On unix every ancestor up to "/" canonicalizes to itself, so the
        // value is unchanged; on Windows the path isn't absolute (no drive
        // letter) so it's returned as-is. Either way: no change.
        let p = Path::new("/definitely/not/here/x-*.json");
        assert_eq!(canonicalize_glob_prefix(p), PathBuf::from(p));
    }

    #[cfg(unix)]
    #[test]
    fn resolves_symlinked_directory_prefix_keeping_glob() {
        let tmp = tempfile::tempdir().unwrap();
        let real = tmp.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let canon_real = dunce::canonicalize(&real).unwrap();

        // `*` glob: the `link` component resolves, `*/x.json` stays verbatim.
        let got = canonicalize_glob_prefix(&link.join("*").join("x.json"));
        assert_eq!(got, canon_real.join("*").join("x.json"));

        // Partial-filename leaf: `events-` is part of the final component, so it
        // must re-attach after the resolved dir and before the glob.
        let pattern = format!("{}/events-*.jsonl", link.display());
        let got = canonicalize_glob_prefix(Path::new(&pattern));
        assert_eq!(
            got,
            PathBuf::from(format!("{}/events-*.jsonl", canon_real.display()))
        );

        // No glob at all: the directory prefix is still resolved.
        let got = canonicalize_glob_prefix(&link.join("config.json"));
        assert_eq!(got, canon_real.join("config.json"));
    }

    #[cfg(unix)]
    #[test]
    fn resolves_through_a_partially_missing_dir() {
        // `link -> real`, but `real/nested` doesn't exist yet. The longest
        // existing ancestor (`real`, via `link`) is what gets canonicalized;
        // the missing `nested/` is kept verbatim.
        let tmp = tempfile::tempdir().unwrap();
        let real = tmp.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let canon_real = dunce::canonicalize(&real).unwrap();

        let got = canonicalize_glob_prefix(&link.join("nested").join("y-*.txt"));
        assert_eq!(got, canon_real.join("nested").join("y-*.txt"));
    }
}
