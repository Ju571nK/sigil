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
    matcher: { kind: regex, pattern: '^(always-proceed|proceed-in-sandbox)$' }
    emit: { kind: auto_approval_enabled, mode: "<selector-value>" }
  - id: s3-allowall
    on_file: "~/.gemini/antigravity-cli/settings.json"
    format: json
    selector: "$.permissions.allowAll"
    matcher: { kind: equals, value: "true" }
    emit: { kind: auto_approval_enabled, mode: "allow_all" }
    when:
      - selector: "$.toolPermission"
        matcher: { kind: regex, pattern: '^(always-proceed|proceed-in-sandbox)$' }
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
use sigil_core::event::{AiGuardReason, LauncherShape};
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

// ---------------------------------------------------------------------------
// Task 3 — parity fixtures (happy-path + must-not-fire)
// ---------------------------------------------------------------------------

/// Assert full parity (no divergence in either direction) for a given on-disk state.
fn assert_parity(settings: Option<&str>, mcp: Option<&str>) {
    let home = tempfile::tempdir().unwrap();
    if let Some(s) = settings {
        write_file(home.path(), ".gemini/antigravity-cli/settings.json", s);
    }
    if let Some(m) = mcp {
        write_file(home.path(), ".gemini/config/mcp_config.json", m);
    }
    let d = diff(home.path());
    assert!(
        d.parser_only.is_empty(),
        "parser_only not empty: {:?}",
        d.parser_only
    );
    assert!(
        d.pack_only.is_empty(),
        "pack_only not empty: {:?}",
        d.pack_only
    );
}

#[test]
fn parity_sandbox_false() {
    assert_parity(Some(r#"{"enableTerminalSandbox":false}"#), None);
}
#[test]
fn parity_toolperm_always_proceed() {
    assert_parity(Some(r#"{"toolPermission":"always-proceed"}"#), None);
}
#[test]
fn parity_toolperm_proceed_in_sandbox() {
    assert_parity(Some(r#"{"toolPermission":"proceed-in-sandbox"}"#), None);
}
#[test]
fn parity_allowall_bool_true() {
    assert_parity(Some(r#"{"permissions":{"allowAll":true}}"#), None);
}
#[test]
fn parity_remote_url() {
    assert_parity(
        None,
        Some(r#"{"mcpServers":{"a":{"url":"https://x/mcp"}}}"#),
    );
}
#[test]
fn parity_remote_httpurl() {
    assert_parity(
        None,
        Some(r#"{"mcpServers":{"a":{"httpUrl":"https://x/mcp"}}}"#),
    );
}
#[test]
fn parity_trust_bool_true() {
    assert_parity(
        None,
        Some(r#"{"mcpServers":{"a":{"command":"node","trust":true}}}"#),
    );
}
#[test]
fn parity_string_command() {
    assert_parity(
        None,
        Some(r#"{"mcpServers":{"a":{"command":"node","args":["m.js"]}}}"#),
    );
}
/// Assert BOTH parsers emit zero reasons for a settings-only state. Stronger
/// than `assert_parity` for the must-not-fire cases: parity alone is `[] == []`
/// even if both parsers were regressed into silence, so we pin each parser's
/// raw output to empty independently — the silence is the property under test.
fn assert_silent(settings: &str) {
    let home = tempfile::tempdir().unwrap();
    write_file(
        home.path(),
        ".gemini/antigravity-cli/settings.json",
        settings,
    );
    let parser_reasons = AntigravityParser.assess(home.path()).expect("parser Ok");
    let pack_reasons = RulePackParser::new(rewired_pack(home.path()))
        .expect("pack loads")
        .assess(home.path())
        .expect("pack Ok");
    assert!(
        parser_reasons.is_empty(),
        "hardcoded parser should stay silent, got: {parser_reasons:?}"
    );
    assert!(
        pack_reasons.is_empty(),
        "rule pack should stay silent, got: {pack_reasons:?}"
    );
}

#[test]
fn parity_sandbox_true_silent() {
    assert_silent(r#"{"enableTerminalSandbox":true}"#);
}
#[test]
fn parity_absent_key_silent() {
    assert_silent(r#"{}"#);
}
#[test]
fn parity_request_review_silent() {
    assert_silent(r#"{"toolPermission":"request-review"}"#);
}
#[test]
fn parity_dropped_gemini_approval_mode_silent() {
    assert_silent(r#"{"approval_mode":"yolo"}"#);
}
#[test]
fn parity_rejected_auto_approve_literal_silent() {
    // agy 1.0.8 rejects `auto-approve` (-> request-review at runtime), so both the
    // parser and the pack must stay silent — flagging it would be a false positive.
    assert_silent(r#"{"toolPermission":"auto-approve"}"#);
}
#[test]
fn parity_unknown_sandbox_mode_key_silent() {
    // `sandbox_mode` is not a CLI settings key (silently ignored, #158).
    assert_silent(r#"{"sandbox_mode":"off"}"#);
}

// ---------------------------------------------------------------------------
// Task 4 — else-if negate-gate fixture (both toolPermission + allowAll true)
// ---------------------------------------------------------------------------

#[test]
fn parity_else_if_both_true_emits_single_auto_approve() {
    let home = tempfile::tempdir().unwrap();
    write_file(
        home.path(),
        ".gemini/antigravity-cli/settings.json",
        r#"{"toolPermission":"always-proceed","permissions":{"allowAll":true}}"#,
    );
    // Direct parser check: exactly one AutoApprovalEnabled — the toolPermission
    // arm wins and the allowAll branch is gated off (mode is the toolPermission
    // value, not "allow_all").
    let parser_reasons = AntigravityParser.assess(home.path()).unwrap();
    let approvals: Vec<_> = parser_reasons
        .iter()
        .filter(|r| matches!(r, AiGuardReason::AutoApprovalEnabled { .. }))
        .collect();
    assert_eq!(approvals.len(), 1);
    assert!(matches!(
        approvals[0],
        AiGuardReason::AutoApprovalEnabled { mode } if mode == "always-proceed"
    ));
    // Parity: the pack's allow_all rule must be gated off -> no divergence.
    let d = diff(home.path());
    assert!(d.parser_only.is_empty(), "parser_only: {:?}", d.parser_only);
    assert!(d.pack_only.is_empty(), "pack_only: {:?}", d.pack_only);
}

// ---------------------------------------------------------------------------
// Task 5 — Type-confusion (pack over-emit) fixtures
// ---------------------------------------------------------------------------

/// Assert the divergence is exactly: parser_only == [] and pack_only == expected.
fn assert_pack_only(
    settings: Option<&str>,
    mcp: Option<&str>,
    expected_pack_only: &[AiGuardReason],
) {
    let home = tempfile::tempdir().unwrap();
    if let Some(s) = settings {
        write_file(home.path(), ".gemini/antigravity-cli/settings.json", s);
    }
    if let Some(m) = mcp {
        write_file(home.path(), ".gemini/config/mcp_config.json", m);
    }
    let d = diff(home.path());
    assert!(
        d.parser_only.is_empty(),
        "parser_only must be empty: {:?}",
        d.parser_only
    );
    let mut expected: Vec<String> = expected_pack_only.iter().map(key).collect();
    expected.sort();
    assert_eq!(d.pack_only, expected, "pack_only mismatch");
}

#[test]
fn over_emit_sandbox_string_false() {
    // string "false" matches Equals "false" in the pack; parser as_bool() -> None.
    assert_pack_only(
        Some(r#"{"enableTerminalSandbox":"false"}"#),
        None,
        &[AiGuardReason::SandboxDisabled],
    );
}
#[test]
fn over_emit_allowall_string_true() {
    assert_pack_only(
        Some(r#"{"permissions":{"allowAll":"true"}}"#),
        None,
        &[AiGuardReason::AutoApprovalEnabled {
            mode: "allow_all".into(),
        }],
    );
}
#[test]
fn over_emit_trust_string_true() {
    assert_pack_only(
        None,
        Some(r#"{"mcpServers":{"a":{"trust":"true"}}}"#),
        &[AiGuardReason::TrustedMcpServer {
            server_name: "a".into(),
        }],
    );
}
#[test]
fn over_emit_command_array() {
    // array command: pack Exists fires on the stringified array; parser as_str() -> None.
    assert_pack_only(
        None,
        Some(r#"{"mcpServers":{"a":{"command":["node","m.js"]}}}"#),
        &[
            AiGuardReason::McpServerLocalCommand {
                server_name: "a".into(),
                command: "[\"node\",\"m.js\"]".into(),
            },
            AiGuardReason::NoSandbox {
                executor: "mcp_command".into(),
            },
        ],
    );
}
#[test]
fn over_emit_command_number() {
    assert_pack_only(
        None,
        Some(r#"{"mcpServers":{"a":{"command":42}}}"#),
        &[
            AiGuardReason::McpServerLocalCommand {
                server_name: "a".into(),
                command: "42".into(),
            },
            AiGuardReason::NoSandbox {
                executor: "mcp_command".into(),
            },
        ],
    );
}

// ---------------------------------------------------------------------------
// Task 6 — Destructive-arg gap (parser_only arm)
// ---------------------------------------------------------------------------

#[test]
fn gap_destructive_shell_arg_is_parser_only() {
    let home = tempfile::tempdir().unwrap();
    write_file(
        home.path(),
        ".gemini/config/mcp_config.json",
        r#"{"mcpServers":{"a":{"command":"bash","args":["-c","rm -rf /tmp/sigil-test"]}}}"#,
    );
    let d = diff(home.path());
    // pack reproduces local_command + no_sandbox (parity), but cannot produce
    // the destructive finding NOR the #127 attack-shape launcher finding ->
    // exactly those two are parser_only.
    assert!(
        d.pack_only.is_empty(),
        "pack_only must be empty: {:?}",
        d.pack_only
    );
    assert_eq!(d.parser_only.len(), 2, "parser_only: {:?}", d.parser_only);
    let parsed: Vec<AiGuardReason> = d
        .parser_only
        .iter()
        .map(|s| serde_json::from_str(s).unwrap())
        .collect();
    assert!(parsed.iter().any(|r| matches!(
        r,
        AiGuardReason::DestructiveInInlineCommand { hook_event, .. } if hook_event == "mcp_command"
    )));
    assert!(parsed.iter().any(|r| matches!(
        r,
        AiGuardReason::McpServerSuspiciousLauncher {
            shape: LauncherShape::Shell,
            ..
        }
    )));
}

// ---------------------------------------------------------------------------
// Task 7 — Error parity (variant AND offending path) + absent-file parity
// ---------------------------------------------------------------------------

use sigil_agent::ai_guard::parser::AssessError;

/// Both parsers must Err with AssessError::Parse on the SAME path.
fn assert_error_parity_on(home: &Path, expected_path_suffix: &str) {
    let parser_err = AntigravityParser.assess(home).unwrap_err();
    let pack_err = RulePackParser::new(rewired_pack(home))
        .unwrap()
        .assess(home)
        .unwrap_err();
    // Normalize separators so the suffix check is OS-agnostic (Windows reports
    // `...\settings.json`; the expected suffix is written with `/`).
    let pp = match &parser_err {
        AssessError::Parse { path, .. } => path.to_string_lossy().replace('\\', "/"),
        other => panic!("parser: expected Parse, got {other:?}"),
    };
    let kp = match &pack_err {
        AssessError::Parse { path, .. } => path.to_string_lossy().replace('\\', "/"),
        other => panic!("pack: expected Parse, got {other:?}"),
    };
    assert!(pp.ends_with(expected_path_suffix), "parser path {pp}");
    assert!(kp.ends_with(expected_path_suffix), "pack path {kp}");
}

#[test]
fn error_parity_corrupt_settings_first() {
    let home = tempfile::tempdir().unwrap();
    write_file(
        home.path(),
        ".gemini/antigravity-cli/settings.json",
        "{ not json",
    );
    write_file(
        home.path(),
        ".gemini/config/mcp_config.json",
        r#"{"mcpServers":{}}"#,
    );
    // settings rules are first in both read orders -> settings.json is the offending path.
    assert_error_parity_on(home.path(), "antigravity-cli/settings.json");
}
#[test]
fn error_parity_corrupt_mcp_only() {
    let home = tempfile::tempdir().unwrap();
    write_file(
        home.path(),
        ".gemini/antigravity-cli/settings.json",
        r#"{}"#,
    );
    write_file(home.path(), ".gemini/config/mcp_config.json", "{ broken");
    assert_error_parity_on(home.path(), "config/mcp_config.json");
}
#[test]
fn error_parity_both_corrupt_reports_settings() {
    let home = tempfile::tempdir().unwrap();
    write_file(
        home.path(),
        ".gemini/antigravity-cli/settings.json",
        "{ not json",
    );
    write_file(home.path(), ".gemini/config/mcp_config.json", "{ broken");
    // settings is read/evaluated first in both -> settings is the reported error.
    assert_error_parity_on(home.path(), "antigravity-cli/settings.json");
}
#[test]
fn parity_absent_settings_present_mcp() {
    assert_parity(None, Some(r#"{"mcpServers":{"a":{"url":"https://x"}}}"#));
}
#[test]
fn parity_absent_mcp_present_settings() {
    assert_parity(Some(r#"{"enableTerminalSandbox":false}"#), None);
}

// ---------------------------------------------------------------------------
// Task 8 — Selector-validity-at-assess assertion
// ---------------------------------------------------------------------------

#[test]
fn every_selector_is_exercised_without_parse_error() {
    let home = tempfile::tempdir().unwrap();
    // Populate every key every rule + `when` selector touches, with VALID JSON,
    // so each selector is actually parsed by eval_json at least once.
    write_file(
        home.path(),
        ".gemini/antigravity-cli/settings.json",
        r#"{"enableTerminalSandbox":false,"toolPermission":"always-proceed","permissions":{"allowAll":true}}"#,
    );
    write_file(
        home.path(),
        ".gemini/config/mcp_config.json",
        r#"{"mcpServers":{"a":{"url":"https://x","httpUrl":"https://y","trust":true,"command":"node"}}}"#,
    );
    // assess() must be Ok: a malformed selector would surface here as AssessError::Parse.
    let out = RulePackParser::new(rewired_pack(home.path()))
        .expect("pack loads")
        .assess(home.path());
    assert!(
        out.is_ok(),
        "selector parse error at assess: {:?}",
        out.err()
    );
    // sanity: it actually produced reasons (every rule path reachable).
    assert!(!out.unwrap().is_empty());
}
