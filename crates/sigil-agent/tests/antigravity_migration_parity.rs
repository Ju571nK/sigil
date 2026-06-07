//! Measurement pilot (#102): does the declarative rule-pack DSL reproduce the
//! hardcoded `AntigravityParser`? Builds an Antigravity pack as a fixture, runs
//! both over a corpus, and pins the measured divergence. NOT wired into the
//! runtime / DEFAULT_RULE_PACKS — measurement only. See the spec + findings doc.

use sigil_core::policy::RulePack;

/// The Antigravity pilot pack — exact serde shape (`{ kind: ... }` snake_case).
/// Settings rules FIRST (mirrors the hardcoded read order: settings -> mcp).
/// `on_file` uses `~` so the test can rewire it to a tempdir (see `rewire`).
const PILOT_PACK: &str = r#"
id: rp-antigravity-pilot
pack_version: 2
tool: antigravity
scope: { kind: user_global }
watched_paths:
  - "~/.gemini/antigravity-cli/settings.json"
  - "~/.gemini/config/mcp_config.json"
rules:
  - id: s1-sandbox
    on_file: "~/.gemini/antigravity-cli/settings.json"
    format: json
    selector: "$.enableTerminalSandbox"
    matcher: { kind: equals, value: "false" }
    emit: { kind: sandbox_disabled }
  - id: s2-toolperm-auto
    on_file: "~/.gemini/antigravity-cli/settings.json"
    format: json
    selector: "$.toolPermission"
    matcher: { kind: equals, value: "auto-approve" }
    emit: { kind: auto_approval_enabled, mode: "auto-approve" }
  - id: s3-allowall
    on_file: "~/.gemini/antigravity-cli/settings.json"
    format: json
    selector: "$.permissions.allowAll"
    matcher: { kind: equals, value: "true" }
    emit: { kind: auto_approval_enabled, mode: "allow_all" }
    when:
      - selector: "$.toolPermission"
        matcher: { kind: equals, value: "auto-approve" }
        negate: true
  - id: m1-remote-url
    on_file: "~/.gemini/config/mcp_config.json"
    format: json
    selector: "$.mcpServers.*.url"
    matcher: { kind: regex, pattern: '(?i)^\s*https?://' }
    emit: { kind: mcp_server_remote, server_name: "<selector-key>", url: "<selector-value>" }
  - id: m2-remote-httpurl
    on_file: "~/.gemini/config/mcp_config.json"
    format: json
    selector: "$.mcpServers.*.httpUrl"
    matcher: { kind: regex, pattern: '(?i)^\s*https?://' }
    emit: { kind: mcp_server_remote, server_name: "<selector-key>", url: "<selector-value>" }
  - id: m3-trust
    on_file: "~/.gemini/config/mcp_config.json"
    format: json
    selector: "$.mcpServers.*.trust"
    matcher: { kind: equals, value: "true" }
    emit: { kind: trusted_mcp_server, server_name: "<selector-key>" }
  - id: m4-local-command
    on_file: "~/.gemini/config/mcp_config.json"
    format: json
    selector: "$.mcpServers.*.command"
    matcher: { kind: exists }
    emit: { kind: mcp_server_local_command, server_name: "<selector-key>", command: "<selector-value>" }
  - id: m5-nosandbox
    on_file: "~/.gemini/config/mcp_config.json"
    format: json
    selector: "$.mcpServers.*.command"
    matcher: { kind: exists }
    emit: { kind: no_sandbox, executor: "mcp_command" }
"#;

#[test]
fn pilot_pack_deserializes_with_real_serde_shape() {
    let pack: RulePack = serde_yaml::from_str(PILOT_PACK).expect("pilot pack must deserialize");
    assert_eq!(pack.id, "rp-antigravity-pilot");
    assert_eq!(pack.pack_version, 2);
    assert_eq!(pack.tool, sigil_core::event::AiTool::Antigravity);
    assert_eq!(pack.rules.len(), 8);
    // v2 + a `when` gate must pass the loadability gate (v1 + when is rejected).
    assert!(sigil_agent::ai_guard::rule_pack::pack_is_loadable(&pack));
}

// ---------------------------------------------------------------------------
// Task 2 — parity harness (rewire / diff / multiset)
// ---------------------------------------------------------------------------

use sigil_agent::ai_guard::parser::AiGuardParser;
use sigil_agent::ai_guard::{AntigravityParser, RulePackParser};
use sigil_core::event::AiGuardReason;
use std::path::Path;

/// Rewire the pack's `~` on_file paths to `home`, so the pack reads the same
/// tempdir the AntigravityParser does. (UserGlobal RulePackParser env-expands
/// on_file; an absolute path passes through unchanged.)
fn rewired_pack(home: &Path) -> RulePack {
    let mut pack: RulePack = serde_yaml::from_str(PILOT_PACK).unwrap();
    let home_str = home.to_string_lossy();
    for r in &mut pack.rules {
        r.on_file = r.on_file.replacen('~', &home_str, 1);
    }
    pack
}

// used by later parity-fixture tasks (#102)
#[allow(dead_code)]
fn write_file(home: &Path, rel: &str, body: &str) {
    let p = home.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, body).unwrap();
}

/// Canonical multiset key for an AiGuardReason (serialized JSON).
fn key(r: &AiGuardReason) -> String {
    serde_json::to_string(r).unwrap()
}

/// Multiset difference a - b (keeps duplicates), sorted.
fn multiset_minus(a: &[AiGuardReason], b: &[AiGuardReason]) -> Vec<String> {
    let mut remaining: Vec<String> = b.iter().map(key).collect();
    let mut only = Vec::new();
    for r in a {
        let k = key(r);
        if let Some(pos) = remaining.iter().position(|x| *x == k) {
            remaining.remove(pos); // matched -> consume one
        } else {
            only.push(k);
        }
    }
    only.sort();
    only
}

struct Divergence {
    parser_only: Vec<String>,
    pack_only: Vec<String>,
}

/// Run BOTH parsers over `home` and classify. Both must succeed (Ok).
fn diff(home: &Path) -> Divergence {
    let parser_reasons = AntigravityParser.assess(home).expect("parser assess Ok");
    let pack_reasons = RulePackParser::new(rewired_pack(home))
        .expect("pack loads")
        .assess(home)
        .expect("pack assess Ok");
    Divergence {
        parser_only: multiset_minus(&parser_reasons, &pack_reasons),
        pack_only: multiset_minus(&pack_reasons, &parser_reasons),
    }
}

#[test]
fn empty_home_is_full_parity() {
    let home = tempfile::tempdir().unwrap();
    let d = diff(home.path());
    assert!(d.parser_only.is_empty(), "parser_only: {:?}", d.parser_only);
    assert!(d.pack_only.is_empty(), "pack_only: {:?}", d.pack_only);
}
