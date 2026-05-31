//! Shared test fixtures.

#![allow(dead_code)]

pub use sigil_agent::test_support::*;

pub fn policy_for_paths(paths: &[&str], tier: &str) -> String {
    let id = format!("test-target-{}", uuid::Uuid::new_v4().simple());
    let mut yaml = String::new();
    yaml.push_str("version: 1\n");
    yaml.push_str("targets:\n");
    yaml.push_str(&format!("  - id: {id}\n"));
    yaml.push_str("    description: integration-test target\n");
    yaml.push_str(&format!("    tier: {tier}\n"));
    yaml.push_str("    platform: any\n");
    yaml.push_str("    paths:\n");
    for p in paths {
        // Single-quoted so backslashes (Windows paths) aren't treated as YAML
        // escapes. (Temp paths never contain `'`.)
        yaml.push_str(&format!("      - '{p}'\n"));
    }
    yaml.push_str("    recursive: false\n");
    yaml.push_str("    follow_symlinks: false\n");
    yaml
}

/// Wait budget for OS-watcher-driven (`wait_for_event` and equivalent poll
/// loops) assertions. `wait_for_event` returns as soon as the event arrives, so
/// a generous budget is free on success and only bounds the *failure* deadline.
/// OS watcher delivery (FSEvents, inotify) lags badly under the heavy
/// cross-process parallelism of `cargo test --workspace` (issues #25, #66), so
/// keep ample headroom — and let a loaded host raise it further without a
/// rebuild via `SIGIL_TEST_FS_TIMEOUT_SECS`.
pub fn fs_event_timeout() -> std::time::Duration {
    let base = if cfg!(target_os = "macos") { 30 } else { 15 };
    let secs = std::env::var("SIGIL_TEST_FS_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(base);
    std::time::Duration::from_secs(secs)
}
