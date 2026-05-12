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
