//! Watchlist policy: parsing, merging, expansion.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::PathBuf;
use thiserror::Error;

pub mod atomic_writer;
pub mod canonical;
pub mod expand;
pub mod glob;
pub mod pubkeys;
pub mod signed_envelope;
pub mod verify;

pub use atomic_writer::{atomic_write, AtomicWriteError};
pub use canonical::{to_canonical_bytes, CanonicalError};
pub use pubkeys::{Keystore, KeystoreEntry, KeystoreError};
pub use signed_envelope::{SignedEnvelope, SignedPolicyResponse};
pub use verify::{verify_envelope, VerifiedPolicy, VerifyError};

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    Critical,
    Standard,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    Macos,
    Windows,
    Linux,
    Any,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct WatchTarget {
    pub id: String,
    pub description: String,
    pub tier: Tier,
    pub platform: Platform,
    pub paths: Vec<String>,
    #[serde(default)]
    pub recursive: bool,
    #[serde(default)]
    pub follow_symlinks: bool,
    #[serde(default)]
    pub disabled: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HostIdStrategy {
    MachineId,
    Hostname,
    Uuid,
    Static(String),
}

/// Phase 3b.7 — declarative rule pack. See
/// docs/superpowers/specs/2026-05-19-phase-3b7-declarative-rule-pack-architecture-design.html
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct RulePack {
    pub id: String,
    pub pack_version: u32,
    pub tool: crate::event::AiTool,
    pub scope: crate::event::AiGuardScope,
    pub watched_paths: Vec<String>,
    #[serde(default)]
    pub platforms: Option<Vec<Platform>>,
    pub rules: Vec<RuleEntry>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct RuleEntry {
    pub id: String,
    pub on_file: String,
    pub format: RuleFormat,
    pub selector: String,
    pub matcher: Matcher,
    pub emit: crate::event::AiGuardReason,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuleFormat {
    Json,
    Toml,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Matcher {
    Exists,
    Equals { value: String },
    NotEquals { value: String },
    Regex { pattern: String },
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Override {
    pub id: String,
    #[serde(default)]
    pub disabled: Option<bool>,
    #[serde(default)]
    pub tier: Option<Tier>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PolicyDocument {
    pub version: u32,
    #[serde(default = "default_host_id_strategy")]
    pub host_id_strategy: HostIdStrategy,
    #[serde(default)]
    pub overrides: Vec<Override>,
    #[serde(default)]
    pub targets: Vec<WatchTarget>,
    /// Phase 3b.6.1 — workspace root paths under which the agent looks
    /// 1-level deep for `.continue/config.json` and spawns per-repo
    /// ContinueDevProjectParser instances. Empty / absent = feature off.
    /// Tilde + env-var expansion happens at discovery time.
    #[serde(default)]
    pub continue_workspaces: Vec<String>,
    /// Phase 3b.6.2 — Claude Code workspace roots. 1-level scan for
    /// `<subdir>/.claude/settings.json` marker.
    #[serde(default)]
    pub claude_code_workspaces: Vec<String>,
    /// Phase 3b.6.2 — Codex workspace roots. 1-level scan for
    /// `<subdir>/.codex/config.toml` marker.
    #[serde(default)]
    pub codex_workspaces: Vec<String>,
    /// Phase 3b.7 — operator-supplied rule packs (declarative scan rules).
    /// Wire-additive; merged by id with sigil-rules-basic defaults.
    #[serde(default)]
    pub rule_packs: Vec<RulePack>,
}

fn default_host_id_strategy() -> HostIdStrategy {
    HostIdStrategy::MachineId
}

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("YAML parse error: {0}")]
    Parse(#[from] serde_yaml::Error),
    #[error("unsupported policy version {found}; supported: 1")]
    UnsupportedVersion { found: u32 },
    #[error("duplicate target id: {0}")]
    DuplicateId(String),
    #[error("override references unknown id: {0}")]
    UnknownOverrideId(String),
    #[error("follow_symlinks: true is not supported in Phase 1 (target {0})")]
    FollowSymlinksNotSupported(String),
    #[error("path glob uses unsupported `**` (target {0}, path {1})")]
    DoubleStarUnsupported(String, String),
    #[error("targets list is empty after merge")]
    EmptyTargets,
}

/// Parse a YAML document into a `PolicyDocument`. Validates schema version.
pub fn parse(yaml: &str) -> Result<PolicyDocument, PolicyError> {
    let doc: PolicyDocument = serde_yaml::from_str(yaml)?;
    if doc.version != 1 {
        return Err(PolicyError::UnsupportedVersion { found: doc.version });
    }
    for t in &doc.targets {
        if t.follow_symlinks {
            return Err(PolicyError::FollowSymlinksNotSupported(t.id.clone()));
        }
        for p in &t.paths {
            if p.contains("**") {
                return Err(PolicyError::DoubleStarUnsupported(t.id.clone(), p.clone()));
            }
        }
    }
    Ok(doc)
}

/// Current host's platform (set at compile time).
pub fn current_platform() -> Platform {
    if cfg!(target_os = "macos") {
        Platform::Macos
    } else if cfg!(target_os = "windows") {
        Platform::Windows
    } else if cfg!(target_os = "linux") {
        Platform::Linux
    } else {
        Platform::Any
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectivePolicy {
    pub host_id_strategy: HostIdStrategy,
    pub targets: Vec<WatchTarget>,
    /// Phase 3b.6.1 — forwarded from user PolicyDocument (defaults never set).
    pub continue_workspaces: Vec<String>,
    pub claude_code_workspaces: Vec<String>,
    pub codex_workspaces: Vec<String>,
    pub rule_packs: Vec<RulePack>,
}

/// Merge a defaults document and a user-override document into an effective policy.
/// Steps follow spec section 2.3.
pub fn merge(
    defaults: PolicyDocument,
    user: Option<PolicyDocument>,
    current: Platform,
) -> Result<EffectivePolicy, PolicyError> {
    let strategy = user
        .as_ref()
        .map(|u| u.host_id_strategy.clone())
        .unwrap_or(defaults.host_id_strategy.clone());

    // 1. Start with defaults' targets.
    let mut by_id: Vec<WatchTarget> = defaults.targets.clone();

    if let Some(ref user) = user {
        // 2. Apply overrides.
        for ov in &user.overrides {
            let t = by_id
                .iter_mut()
                .find(|t| t.id == ov.id)
                .ok_or_else(|| PolicyError::UnknownOverrideId(ov.id.clone()))?;
            if let Some(d) = ov.disabled {
                t.disabled = d;
            }
            if let Some(tier) = ov.tier {
                t.tier = tier;
            }
        }
        // 3. Append user's custom targets, checking for id collisions.
        let mut seen: HashSet<String> = by_id.iter().map(|t| t.id.clone()).collect();
        for t in &user.targets {
            if !seen.insert(t.id.clone()) {
                return Err(PolicyError::DuplicateId(t.id.clone()));
            }
            by_id.push(t.clone());
        }
    }

    // 4. Drop disabled.
    by_id.retain(|t| !t.disabled);
    // 5. Filter by current platform (Any always passes).
    by_id.retain(|t| matches!(t.platform, Platform::Any) || t.platform == current);
    // 6. Empty after merge is an error.
    if by_id.is_empty() {
        return Err(PolicyError::EmptyTargets);
    }

    let continue_workspaces = user
        .as_ref()
        .map(|u| u.continue_workspaces.clone())
        .unwrap_or_default();
    let claude_code_workspaces = user
        .as_ref()
        .map(|u| u.claude_code_workspaces.clone())
        .unwrap_or_default();
    let codex_workspaces = user
        .as_ref()
        .map(|u| u.codex_workspaces.clone())
        .unwrap_or_default();

    // Phase 3b.7 — id-keyed reconciliation: start with defaults' packs;
    // user packs replace by id or append.
    let rule_packs: Vec<RulePack> = {
        let mut packs = defaults.rule_packs.clone();
        if let Some(ref u) = user {
            for upack in &u.rule_packs {
                if let Some(idx) = packs.iter().position(|p| p.id == upack.id) {
                    packs[idx] = upack.clone();
                } else {
                    packs.push(upack.clone());
                }
            }
        }
        packs
    };

    Ok(EffectivePolicy {
        host_id_strategy: strategy,
        targets: by_id,
        continue_workspaces,
        claude_code_workspaces,
        codex_workspaces,
        rule_packs,
    })
}

/// Built-in defaults for the current OS, parsed from a compile-time-embedded YAML.
///
/// Source data lives in the `sigil-rules-basic` crate so the OSS baseline
/// ruleset can evolve independently. Extended/commercial rule packs ship
/// as **signed policy bundles** (Plan B) delivered over the Phase 2
/// transport — they are NOT linked into the OSS binary at build time.
/// See `LICENSING.md` for the rationale.
pub fn defaults() -> Result<PolicyDocument, PolicyError> {
    let rule_packs = parse_default_rule_packs()?;
    match sigil_rules_basic::defaults_for_current_os() {
        Some(yaml) => {
            let mut doc = parse(yaml)?;
            doc.rule_packs = rule_packs;
            Ok(doc)
        }
        None => Ok(PolicyDocument {
            // Platforms with no built-in baseline (anything other than
            // macOS / Windows / Linux): empty until an operator policy loads.
            version: 1,
            host_id_strategy: HostIdStrategy::MachineId,
            overrides: vec![],
            targets: vec![],
            continue_workspaces: vec![],
            claude_code_workspaces: vec![],
            codex_workspaces: vec![],
            rule_packs,
        }),
    }
}

/// Phase 3b.7 — parse the compile-time-embedded default rule pack YAMLs
/// from sigil-rules-basic into RulePack instances. Failure here is a
/// build-time bug in the OSS defaults (malformed YAML or schema drift)
/// and surfaces as PolicyError::Parse at startup.
fn parse_default_rule_packs() -> Result<Vec<RulePack>, PolicyError> {
    sigil_rules_basic::DEFAULT_RULE_PACKS
        .iter()
        .map(|yaml| serde_yaml::from_str::<RulePack>(yaml).map_err(PolicyError::from))
        .collect()
}

// Silence unused-import warning when `PathBuf` is only used via submodules.
#[allow(dead_code)]
fn _path_buf_marker(_p: PathBuf) {}

#[cfg(test)]
mod tests {
    use super::*;

    fn yaml_minimal() -> &'static str {
        r#"
version: 1
targets:
  - id: t1
    description: Test target
    tier: critical
    platform: macos
    paths: ["/tmp/foo"]
"#
    }

    #[test]
    fn parses_minimal_policy() {
        let doc = parse(yaml_minimal()).unwrap();
        assert_eq!(doc.version, 1);
        assert_eq!(doc.targets.len(), 1);
        assert_eq!(doc.targets[0].id, "t1");
        assert_eq!(doc.targets[0].tier, Tier::Critical);
        assert_eq!(doc.host_id_strategy, HostIdStrategy::MachineId);
    }

    #[test]
    fn rejects_version_other_than_one() {
        let yaml = r#"
version: 2
targets: []
"#;
        let err = parse(yaml).unwrap_err();
        assert!(matches!(err, PolicyError::UnsupportedVersion { found: 2 }));
    }

    #[test]
    fn rejects_double_star_glob() {
        let yaml = r#"
version: 1
targets:
  - id: bad
    description: x
    tier: standard
    platform: any
    paths: ["~/**.json"]
"#;
        let err = parse(yaml).unwrap_err();
        assert!(matches!(err, PolicyError::DoubleStarUnsupported(_, _)));
    }

    #[test]
    fn rejects_follow_symlinks_true() {
        let yaml = r#"
version: 1
targets:
  - id: bad
    description: x
    tier: standard
    platform: any
    paths: ["/tmp/x"]
    follow_symlinks: true
"#;
        let err = parse(yaml).unwrap_err();
        assert!(matches!(err, PolicyError::FollowSymlinksNotSupported(_)));
    }

    #[test]
    fn host_id_static_round_trips() {
        let yaml = r#"
version: 1
host_id_strategy: !static "fixed-id-123"
targets:
  - id: t1
    description: x
    tier: standard
    platform: any
    paths: ["/tmp/x"]
"#;
        let doc = parse(yaml).unwrap();
        assert_eq!(
            doc.host_id_strategy,
            HostIdStrategy::Static("fixed-id-123".into())
        );
    }

    fn def_target(id: &str, tier: Tier, platform: Platform) -> WatchTarget {
        WatchTarget {
            id: id.into(),
            description: "test".into(),
            tier,
            platform,
            paths: vec!["/tmp/x".into()],
            recursive: false,
            follow_symlinks: false,
            disabled: false,
        }
    }

    fn defaults_doc() -> PolicyDocument {
        PolicyDocument {
            version: 1,
            host_id_strategy: HostIdStrategy::MachineId,
            overrides: vec![],
            targets: vec![
                def_target("d1", Tier::Critical, Platform::Macos),
                def_target("d2", Tier::Standard, Platform::Windows),
            ],
            continue_workspaces: vec![],
            claude_code_workspaces: vec![],
            codex_workspaces: vec![],
            rule_packs: vec![],
        }
    }

    #[test]
    fn merge_defaults_alone_filters_by_platform() {
        let eff = merge(defaults_doc(), None, Platform::Macos).unwrap();
        assert_eq!(eff.targets.len(), 1);
        assert_eq!(eff.targets[0].id, "d1");
    }

    #[test]
    fn override_disables_default() {
        let user = PolicyDocument {
            version: 1,
            host_id_strategy: HostIdStrategy::MachineId,
            overrides: vec![Override {
                id: "d1".into(),
                disabled: Some(true),
                tier: None,
            }],
            targets: vec![def_target("u1", Tier::Critical, Platform::Macos)],
            continue_workspaces: vec![],
            claude_code_workspaces: vec![],
            codex_workspaces: vec![],
            rule_packs: vec![],
        };
        let eff = merge(defaults_doc(), Some(user), Platform::Macos).unwrap();
        let ids: Vec<&str> = eff.targets.iter().map(|t| t.id.as_str()).collect();
        assert_eq!(ids, vec!["u1"]);
    }

    #[test]
    fn override_changes_tier() {
        let user = PolicyDocument {
            version: 1,
            host_id_strategy: HostIdStrategy::MachineId,
            overrides: vec![Override {
                id: "d1".into(),
                disabled: None,
                tier: Some(Tier::Standard),
            }],
            targets: vec![],
            continue_workspaces: vec![],
            claude_code_workspaces: vec![],
            codex_workspaces: vec![],
            rule_packs: vec![],
        };
        let eff = merge(defaults_doc(), Some(user), Platform::Macos).unwrap();
        assert_eq!(eff.targets[0].tier, Tier::Standard);
    }

    #[test]
    fn override_unknown_id_errors() {
        let user = PolicyDocument {
            version: 1,
            host_id_strategy: HostIdStrategy::MachineId,
            overrides: vec![Override {
                id: "ghost".into(),
                disabled: Some(true),
                tier: None,
            }],
            targets: vec![],
            continue_workspaces: vec![],
            claude_code_workspaces: vec![],
            codex_workspaces: vec![],
            rule_packs: vec![],
        };
        let err = merge(defaults_doc(), Some(user), Platform::Macos).unwrap_err();
        assert!(matches!(err, PolicyError::UnknownOverrideId(_)));
    }

    #[test]
    fn id_collision_in_user_targets_errors() {
        let user = PolicyDocument {
            version: 1,
            host_id_strategy: HostIdStrategy::MachineId,
            overrides: vec![],
            targets: vec![def_target("d1", Tier::Critical, Platform::Macos)],
            continue_workspaces: vec![],
            claude_code_workspaces: vec![],
            codex_workspaces: vec![],
            rule_packs: vec![],
        };
        let err = merge(defaults_doc(), Some(user), Platform::Macos).unwrap_err();
        assert!(matches!(err, PolicyError::DuplicateId(_)));
    }

    #[test]
    fn empty_after_filter_errors() {
        let defaults = PolicyDocument {
            version: 1,
            host_id_strategy: HostIdStrategy::MachineId,
            overrides: vec![],
            targets: vec![def_target(
                "only-windows",
                Tier::Critical,
                Platform::Windows,
            )],
            continue_workspaces: vec![],
            claude_code_workspaces: vec![],
            codex_workspaces: vec![],
            rule_packs: vec![],
        };
        let err = merge(defaults, None, Platform::Macos).unwrap_err();
        assert!(matches!(err, PolicyError::EmptyTargets));
    }

    #[test]
    fn defaults_parses_for_current_platform() {
        let doc = defaults().unwrap();
        assert_eq!(doc.version, 1);
        if cfg!(any(
            target_os = "macos",
            target_os = "windows",
            target_os = "linux"
        )) {
            assert!(!doc.targets.is_empty());
            for t in &doc.targets {
                assert!(!t.id.is_empty());
                assert!(!t.paths.is_empty());
            }
        }
    }

    #[test]
    fn builtin_defaults_merge_nonempty_for_current_platform() {
        // The OSS baseline + current platform filter must leave at least one
        // target — otherwise a fresh agent on this OS watches nothing and
        // `doctor` fails. (Only meaningful on the three runtime platforms.)
        if cfg!(any(
            target_os = "macos",
            target_os = "windows",
            target_os = "linux"
        )) {
            let eff = merge(defaults().unwrap(), None, current_platform()).unwrap();
            assert!(!eff.targets.is_empty());
        }
    }

    #[test]
    fn builtin_linux_baseline_is_valid() {
        // Compiled in on every platform but only consumed at runtime on Linux —
        // parse it here so a YAML mistake fails CI everywhere, not just Linux.
        let doc = parse(sigil_rules_basic::DEFAULTS_LINUX).unwrap();
        assert_eq!(doc.version, 1);
        assert!(!doc.targets.is_empty());
        for t in &doc.targets {
            assert_eq!(t.platform, Platform::Linux);
            assert!(!t.id.is_empty());
            assert!(!t.paths.is_empty());
        }
    }

    #[test]
    fn policy_document_continue_workspaces_round_trip() {
        let yaml = r#"version: 1
host_id_strategy: machine_id
continue_workspaces:
  - "~/code"
  - "/abs/work"
targets: []
"#;
        let doc: PolicyDocument = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(
            doc.continue_workspaces,
            vec!["~/code".to_string(), "/abs/work".to_string()]
        );
    }

    #[test]
    fn policy_document_without_continue_workspaces_defaults_to_empty() {
        // Backward compat: pre-3b.6.1 policy.yaml has no continue_workspaces field;
        // deserialization must still succeed and produce an empty Vec.
        let yaml = r#"version: 1
host_id_strategy: machine_id
targets: []
"#;
        let doc: PolicyDocument = serde_yaml::from_str(yaml).unwrap();
        assert!(doc.continue_workspaces.is_empty());
    }

    #[test]
    fn policy_doc_round_trip_with_claude_codex_workspaces() {
        let yaml = r#"version: 1
host_id_strategy: machine_id
claude_code_workspaces:
  - "~/work"
  - "/abs/path"
codex_workspaces:
  - "~/projects"
targets: []
"#;
        let doc: PolicyDocument = parse(yaml).expect("parse");
        assert_eq!(doc.claude_code_workspaces, vec!["~/work", "/abs/path"]);
        assert_eq!(doc.codex_workspaces, vec!["~/projects"]);
        let back = serde_yaml::to_string(&doc).unwrap();
        let again: PolicyDocument = parse(&back).expect("re-parse");
        assert_eq!(again.claude_code_workspaces, doc.claude_code_workspaces);
        assert_eq!(again.codex_workspaces, doc.codex_workspaces);
    }

    #[test]
    fn policy_doc_backward_compat_no_workspace_fields_means_empty() {
        let yaml = "version: 1\nhost_id_strategy: machine_id\ntargets: []\n";
        let doc: PolicyDocument = parse(yaml).expect("parse");
        assert!(doc.claude_code_workspaces.is_empty());
        assert!(doc.codex_workspaces.is_empty());
    }

    #[test]
    fn merge_forwards_user_claude_codex_workspaces() {
        let user = parse(
            "version: 1\nhost_id_strategy: machine_id\nclaude_code_workspaces:\n  - '~/forks'\ncodex_workspaces:\n  - '~/work'\ntargets: []\n",
        )
        .unwrap();
        let eff = merge(defaults().unwrap(), Some(user), current_platform()).unwrap();
        assert_eq!(eff.claude_code_workspaces, vec!["~/forks"]);
        assert_eq!(eff.codex_workspaces, vec!["~/work"]);
    }

    #[test]
    fn rule_pack_round_trip_serde() {
        let yaml = r#"
id: test-pack
pack_version: 1
tool: gemini
scope:
  kind: user_global
watched_paths:
  - "~/.gemini/settings.json"
rules:
  - id: r1
    on_file: "~/.gemini/settings.json"
    format: json
    selector: "$.sandbox"
    matcher:
      kind: equals
      value: "false"
    emit:
      kind: sandbox_disabled
"#;
        let pack: RulePack = serde_yaml::from_str(yaml).expect("parse");
        assert_eq!(pack.id, "test-pack");
        assert_eq!(pack.pack_version, 1);
        assert_eq!(pack.tool, crate::event::AiTool::Gemini);
        assert!(matches!(pack.scope, crate::event::AiGuardScope::UserGlobal));
        assert_eq!(pack.rules.len(), 1);
        assert_eq!(pack.rules[0].format, RuleFormat::Json);
        let back = serde_yaml::to_string(&pack).unwrap();
        let again: RulePack = serde_yaml::from_str(&back).expect("re-parse");
        assert_eq!(again.id, pack.id);
    }

    #[test]
    fn policy_doc_with_rule_packs_round_trip() {
        let yaml = r#"version: 1
host_id_strategy: machine_id
targets: []
rule_packs:
  - id: mycorp-cursor
    pack_version: 1
    tool: cursor
    scope:
      kind: user_global
    watched_paths:
      - "~/.cursor/mcp.json"
    rules:
      - id: r1
        on_file: "~/.cursor/mcp.json"
        format: json
        selector: "$.mcpServers.*.url"
        matcher:
          kind: exists
        emit:
          kind: mcp_server_remote
          server_name: "<selector-key>"
          url: ""
"#;
        let doc: PolicyDocument = parse(yaml).expect("parse");
        assert_eq!(doc.rule_packs.len(), 1);
        assert_eq!(doc.rule_packs[0].id, "mycorp-cursor");
    }

    #[test]
    fn policy_doc_backward_compat_no_rule_packs_field() {
        let yaml = "version: 1\nhost_id_strategy: machine_id\ntargets:\n  - id: t1\n    description: minimal\n    tier: standard\n    platform: any\n    paths: [\"/tmp/x\"]\n";
        let doc: PolicyDocument = parse(yaml).expect("parse");
        assert!(doc.rule_packs.is_empty());
    }

    #[test]
    fn merge_rule_packs_user_overrides_default_by_id() {
        let defaults_doc = parse(
            "version: 1\nhost_id_strategy: machine_id\ntargets:\n  - id: t1\n    description: x\n    tier: standard\n    platform: any\n    paths: [\"/tmp/x\"]\nrule_packs:\n  - id: gemini-default\n    pack_version: 1\n    tool: gemini\n    scope:\n      kind: user_global\n    watched_paths: [\"/orig\"]\n    rules: []\n",
        )
        .unwrap();
        let user = parse(
            "version: 1\nhost_id_strategy: machine_id\ntargets: []\nrule_packs:\n  - id: gemini-default\n    pack_version: 1\n    tool: gemini\n    scope:\n      kind: user_global\n    watched_paths: [\"~/override/path\"]\n    rules: []\n",
        )
        .unwrap();
        let eff = merge(defaults_doc, Some(user), current_platform()).unwrap();
        assert_eq!(eff.rule_packs.len(), 1);
        assert_eq!(eff.rule_packs[0].watched_paths, vec!["~/override/path"]);
    }

    #[test]
    fn defaults_includes_two_rule_packs() {
        let doc = defaults().expect("defaults parse");
        assert_eq!(doc.rule_packs.len(), 2);
        let ids: Vec<&str> = doc.rule_packs.iter().map(|p| p.id.as_str()).collect();
        assert!(ids.contains(&"gemini-default"));
        assert!(ids.contains(&"cursor-default"));
    }

    #[test]
    fn default_rule_pack_gemini_has_expected_shape() {
        let doc = defaults().expect("defaults");
        let gemini = doc
            .rule_packs
            .iter()
            .find(|p| p.id == "gemini-default")
            .unwrap();
        assert_eq!(gemini.pack_version, 1);
        assert_eq!(gemini.tool, crate::event::AiTool::Gemini);
        assert!(matches!(gemini.scope, crate::event::AiGuardScope::UserGlobal));
        assert_eq!(gemini.watched_paths, vec!["~/.gemini/settings.json"]);
        assert!(gemini.rules.iter().any(|r| r.id == "sandbox-disabled"));
    }

    #[test]
    fn default_rule_pack_cursor_has_expected_shape() {
        let doc = defaults().expect("defaults");
        let cursor = doc
            .rule_packs
            .iter()
            .find(|p| p.id == "cursor-default")
            .unwrap();
        assert_eq!(cursor.pack_version, 1);
        assert_eq!(cursor.tool, crate::event::AiTool::Cursor);
        assert!(matches!(cursor.scope, crate::event::AiGuardScope::UserGlobal));
        assert_eq!(cursor.watched_paths, vec!["~/.cursor/mcp.json"]);
    }

    #[test]
    fn merge_rule_packs_user_new_id_appends() {
        let defaults_doc = parse(
            "version: 1\nhost_id_strategy: machine_id\ntargets:\n  - id: t1\n    description: x\n    tier: standard\n    platform: any\n    paths: [\"/tmp/x\"]\nrule_packs:\n  - id: gemini-default\n    pack_version: 1\n    tool: gemini\n    scope:\n      kind: user_global\n    watched_paths: []\n    rules: []\n",
        )
        .unwrap();
        let user = parse(
            "version: 1\nhost_id_strategy: machine_id\ntargets: []\nrule_packs:\n  - id: mycorp-tool\n    pack_version: 1\n    tool: gemini\n    scope:\n      kind: user_global\n    watched_paths: []\n    rules: []\n",
        )
        .unwrap();
        let eff = merge(defaults_doc, Some(user), current_platform()).unwrap();
        assert_eq!(eff.rule_packs.len(), 2);
        assert!(eff.rule_packs.iter().any(|p| p.id == "mycorp-tool"));
        assert!(eff.rule_packs.iter().any(|p| p.id == "gemini-default"));
    }
}
