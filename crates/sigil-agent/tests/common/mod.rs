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

/// Wait budget for OS-watcher-driven (`wait_for_event`) assertions. macOS
/// FSEvents delivery can lag well past a few seconds under parallel test load
/// (issue #25), so give it more headroom there; other platforms keep the tight
/// 5s and fail fast.
pub fn fs_event_timeout() -> std::time::Duration {
    std::time::Duration::from_secs(if cfg!(target_os = "macos") { 15 } else { 5 })
}
