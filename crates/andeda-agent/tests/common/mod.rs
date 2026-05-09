//! Shared test fixtures.

#![allow(dead_code)]

pub use andeda_agent::test_support::*;

pub fn policy_for_paths(paths: &[&str], tier: &str) -> String {
    let id = format!("test-target-{}", uuid::Uuid::new_v4().simple());
    let mut yaml = String::new();
    yaml.push_str("version: 1\n");
    yaml.push_str("targets:\n");
    yaml.push_str(&format!("  - id: {}\n", id));
    yaml.push_str("    description: integration-test target\n");
    yaml.push_str(&format!("    tier: {}\n", tier));
    yaml.push_str("    platform: any\n");
    yaml.push_str("    paths:\n");
    for p in paths {
        yaml.push_str(&format!("      - \"{}\"\n", p));
    }
    yaml.push_str("    recursive: false\n");
    yaml.push_str("    follow_symlinks: false\n");
    yaml
}
