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
