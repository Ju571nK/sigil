//! Normalizer task. Owns:
//! - canonicalization (`dunce::canonicalize`)
//! - glob filtering against active WatchTargets
//! - rename pairing within a 200 ms window
//! - per-target token-bucket rate limiting
//!
//! Known limitation: event paths are canonicalized (symlinks resolved) but
//! policy paths/globs are not, so a policy path under a symlinked prefix won't
//! match. On macOS that means `/var/...`, `/tmp/...`, `/etc/...` (all symlinks
//! to `/private/...`) silently fail — write the `/private/...` form instead.
//! Linux and Windows are unaffected. Proper fix (canonicalize the literal
//! prefix of each glob) is a tracked `TODO(community)`.

use crate::watcher::RawFsEvent;
use sigil_core::event::FileChangeKind;
use sigil_core::policy::{glob::CompiledGlob, EffectivePolicy, Tier};
use sigil_core::ratelimit::{DropReport, RateLimiter};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::Instant;

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

/// Compile the effective policy's expanded paths into matchers.
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
