//! Shared test fixtures.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

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

/// The path to put in a test policy for `p`. On macOS, `/var`/`/tmp`/`/etc` are
/// symlinks to `/private/...` and the agent canonicalizes event paths, so the
/// policy path has to match. On Linux/Windows the path is fine as-is — and on
/// Windows `std::fs::canonicalize` would add a `\\?\` verbatim prefix that
/// `globset` mis-parses (the `?` becomes a wildcard).
pub fn policy_path(p: &Path) -> PathBuf {
    if cfg!(target_os = "macos") {
        std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())
    } else {
        p.to_path_buf()
    }
}
