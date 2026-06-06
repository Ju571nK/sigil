//! Watchlist policy: parsing, merging, expansion.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use thiserror::Error;

pub mod atomic_writer;
pub mod canonical;
pub mod expand;
pub mod glob;
pub mod pubkeys;
pub mod signed_envelope;
pub mod verify;

pub use atomic_writer::{atomic_write, atomic_write_rule_packs, AtomicWriteError};
pub use canonical::{to_canonical_bytes, CanonicalError};
pub use pubkeys::{Keystore, KeystoreEntry, KeystoreError};
pub use signed_envelope::{SignedEnvelope, SignedPolicyResponse};
pub use verify::{verify_envelope, VerifiedPolicy, VerifyError};

pub mod deny_rule;
pub use deny_rule::{DenyRule, FailMode, HookActionMatch};

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

/// Phase 3b.7.2 — authoring scope for a rule pack. Decoupled from the runtime
/// `event::AiGuardScope`: the operator writes a tag with NO path; the engine
/// stamps the concrete `AiGuardScope::Project { path: repo_root }` per repo.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RulePackScope {
    UserGlobal,
    Project,
}

/// Phase 3b.7 — declarative rule pack. See
/// docs/superpowers/specs/2026-05-19-phase-3b7-declarative-rule-pack-architecture-design.html
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct RulePack {
    pub id: String,
    pub pack_version: u32,
    pub tool: crate::event::AiTool,
    pub scope: RulePackScope,
    pub watched_paths: Vec<String>,
    #[serde(default)]
    pub platforms: Option<Vec<Platform>>,
    /// Phase 3b.7.5 — human name for a generic `tool: other` pack. Required when
    /// `tool == AiTool::Other`; ignored otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_label: Option<String>,
    pub rules: Vec<RuleEntry>,
}

/// Phase 3b.7.1 (Tier 2) — a gate condition on a rule. The rule emits only when
/// every condition holds; a condition holds iff its selector finds at least one
/// value matching its matcher, XOR `negate`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Condition {
    pub selector: String,
    pub matcher: Matcher,
    #[serde(default)]
    pub negate: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct RuleEntry {
    pub id: String,
    pub on_file: String,
    pub format: RuleFormat,
    pub selector: String,
    pub matcher: Matcher,
    pub emit: crate::event::AiGuardReason,
    /// Phase 3b.7.1 (Tier 2) — gate conditions (AND). Empty (default) = the flat
    /// Tier-1 rule (no gating). Requires pack_version 2.
    #[serde(default)]
    pub when: Vec<Condition>,
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

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
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
    /// Phase 3b.8 — Gemini workspace roots. 1-level scan for
    /// `<subdir>/.gemini/settings.json` marker.
    #[serde(default)]
    pub gemini_workspaces: Vec<String>,
    /// Phase 3b.8 — Cursor workspace roots. 1-level scan for
    /// `<subdir>/.cursor/mcp.json` marker.
    #[serde(default)]
    pub cursor_workspaces: Vec<String>,
    /// Antigravity workspace roots. 1-level scan for
    /// `<subdir>/.antigravity/settings.json` marker.
    #[serde(default)]
    pub antigravity_workspaces: Vec<String>,
    /// Phase 3b.7 — operator-supplied rule packs (declarative scan rules).
    /// Wire-additive; merged by id with sigil-rules-basic defaults.
    #[serde(default)]
    pub rule_packs: Vec<RulePack>,
    /// Phase 3b.5 — operator-tunable rubric weights.
    /// Keys are snake_case `rubric::kind_key()` output (e.g.,
    /// `"destructive_in_hook_script"`). Unknown keys are logged + ignored at
    /// runtime. Absent field = no overrides.
    #[serde(default)]
    pub rubric_overrides: HashMap<String, f32>,
    /// Stage 2 (#100) — operator deny rules evaluated by the hook-decide path.
    /// Empty/absent = no enforcement (observe-only). Wire-additive, back-compat.
    #[serde(default)]
    pub hook_deny_rules: Vec<deny_rule::DenyRule>,
    /// Stage 2 (#100) — behavior when a verdict cannot be obtained. Default open.
    // Consumed by the hook locally via its --on-failure registration flag (not by
    // the agent); intentionally not threaded into EffectivePolicy.
    #[serde(default)]
    pub on_failure: deny_rule::FailMode,
    /// #107 — opt-in hook-silence detection config. Empty `enabled_agents` = feature OFF.
    #[serde(default)]
    pub hook_silence: HookSilenceCfg,
}

fn default_host_id_strategy() -> HostIdStrategy {
    HostIdStrategy::MachineId
}

fn dflt_window() -> u64 {
    43_200
}
fn dflt_horizon() -> u64 {
    604_800
}
fn dflt_tick() -> u64 {
    1_800
}
fn dflt_max_entries() -> usize {
    256
}
fn dflt_max_depth() -> usize {
    3
}
fn dflt_budget_ms() -> u64 {
    50
}

/// Caps bounding the cost (and privacy exposure) of one session-dir probe scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeCap {
    /// Max directory entries visited per probe scan.
    #[serde(default = "dflt_max_entries")]
    pub max_entries: usize,
    /// Max directory-traversal depth per probe scan.
    #[serde(default = "dflt_max_depth")]
    pub max_depth: usize,
    /// Wall-time budget per probe scan, in milliseconds.
    #[serde(default = "dflt_budget_ms")]
    pub budget_ms: u64,
}
impl Default for ProbeCap {
    fn default() -> Self {
        Self {
            max_entries: dflt_max_entries(),
            max_depth: dflt_max_depth(),
            budget_ms: dflt_budget_ms(),
        }
    }
}

/// #107 — opt-in hook-silence detection. Empty `enabled_agents` = feature OFF.
/// When enabled for an agent, the daemon flags it when it has recent session
/// activity but its hook has gone silent (a low-confidence tamper hint).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HookSilenceCfg {
    /// Per-agent opt-in allowlist. Empty = the whole feature is off.
    #[serde(default)]
    pub enabled_agents: Vec<crate::event::AiTool>,
    /// Silence window W (seconds): an opted-in agent with session activity but
    /// zero hook events for longer than this is flagged (default 43200 = 12h).
    #[serde(default = "dflt_window")]
    pub window_secs: u64,
    /// Expectation horizon H (seconds): an agent is only eligible to be flagged
    /// if its last hook event was within this long; older = treated as
    /// abandoned and never flagged (default 604800 = 7d).
    #[serde(default = "dflt_horizon")]
    pub horizon_secs: u64,
    /// How often the detector sweeps, in seconds (default 1800 = 30min).
    #[serde(default = "dflt_tick")]
    pub tick_secs: u64,
    /// Caps on the per-agent session-directory scan.
    #[serde(default)]
    pub probe_cap: ProbeCap,
}
impl Default for HookSilenceCfg {
    fn default() -> Self {
        Self {
            enabled_agents: vec![],
            window_secs: dflt_window(),
            horizon_secs: dflt_horizon(),
            tick_secs: dflt_tick(),
            probe_cap: ProbeCap::default(),
        }
    }
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

#[derive(Debug, Clone, PartialEq)]
pub struct EffectivePolicy {
    pub host_id_strategy: HostIdStrategy,
    pub targets: Vec<WatchTarget>,
    /// Phase 3b.6.1 — forwarded from user PolicyDocument (defaults never set).
    pub continue_workspaces: Vec<String>,
    pub claude_code_workspaces: Vec<String>,
    pub codex_workspaces: Vec<String>,
    pub gemini_workspaces: Vec<String>,
    pub cursor_workspaces: Vec<String>,
    pub antigravity_workspaces: Vec<String>,
    pub rule_packs: Vec<RulePack>,
    /// Phase 3b.5 — operator-tunable rubric weights (merged from user
    /// PolicyDocument; defaults map is empty).
    pub rubric_overrides: HashMap<String, f32>,
    /// Stage 2 (#100) — operator deny rules forwarded from user PolicyDocument.
    /// Empty = no enforcement (observe-only).
    pub hook_deny_rules: Vec<deny_rule::DenyRule>,
    /// #107 — opt-in hook-silence detection config forwarded from user PolicyDocument.
    pub hook_silence: HookSilenceCfg,
}

/// Merge a defaults document and a user-override document into an effective policy.
/// Steps follow spec section 2.3.
pub fn merge(
    defaults: PolicyDocument,
    user: Option<PolicyDocument>,
    bundle: Option<PolicyDocument>,
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
    let gemini_workspaces = user
        .as_ref()
        .map(|u| u.gemini_workspaces.clone())
        .unwrap_or_default();
    let cursor_workspaces = user
        .as_ref()
        .map(|u| u.cursor_workspaces.clone())
        .unwrap_or_default();
    let antigravity_workspaces = user
        .as_ref()
        .map(|u| u.antigravity_workspaces.clone())
        .unwrap_or_default();

    // Phase 3b.7 — id-keyed reconciliation across three layers: start with
    // defaults' packs; user packs replace by id or append; then bundle packs
    // replace/append LAST (so a signed pack-set bundle wins on id collision).
    // Only `bundle.rule_packs` is consulted — the bundle's other fields are
    // ignored.
    let rule_packs: Vec<RulePack> = {
        let mut packs = defaults.rule_packs.clone();
        fn fold_packs(packs: &mut Vec<RulePack>, layer: &[RulePack]) {
            for up in layer {
                if let Some(i) = packs.iter().position(|p| p.id == up.id) {
                    packs[i] = up.clone();
                } else {
                    packs.push(up.clone());
                }
            }
        }
        if let Some(ref u) = user {
            fold_packs(&mut packs, &u.rule_packs);
        }
        if let Some(ref b) = bundle {
            fold_packs(&mut packs, &b.rule_packs);
        }
        packs
    };

    let rubric_overrides = user
        .as_ref()
        .map(|u| u.rubric_overrides.clone())
        .unwrap_or_default();

    let hook_deny_rules = user
        .as_ref()
        .map(|u| u.hook_deny_rules.clone())
        .unwrap_or_default();

    let hook_silence = user
        .as_ref()
        .map(|u| u.hook_silence.clone())
        .unwrap_or_default();

    Ok(EffectivePolicy {
        host_id_strategy: strategy,
        targets: by_id,
        continue_workspaces,
        claude_code_workspaces,
        codex_workspaces,
        gemini_workspaces,
        cursor_workspaces,
        antigravity_workspaces,
        rule_packs,
        rubric_overrides,
        hook_deny_rules,
        hook_silence,
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
            gemini_workspaces: vec![],
            cursor_workspaces: vec![],
            antigravity_workspaces: vec![],
            rule_packs,
            rubric_overrides: HashMap::new(),
            hook_deny_rules: vec![],
            on_failure: deny_rule::FailMode::Open,
            hook_silence: HookSilenceCfg::default(),
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
            gemini_workspaces: vec![],
            cursor_workspaces: vec![],
            antigravity_workspaces: vec![],
            rule_packs: vec![],
            rubric_overrides: HashMap::new(),
            hook_deny_rules: vec![],
            on_failure: deny_rule::FailMode::Open,
            hook_silence: HookSilenceCfg::default(),
        }
    }

    #[test]
    fn merge_defaults_alone_filters_by_platform() {
        let eff = merge(defaults_doc(), None, None, Platform::Macos).unwrap();
        assert_eq!(eff.targets.len(), 1);
        assert_eq!(eff.targets[0].id, "d1");
    }

    #[test]
    fn merge_bundle_packs_win_over_policy_and_defaults() {
        fn pack(id: &str, ver: u32) -> RulePack {
            RulePack {
                id: id.into(),
                pack_version: ver,
                tool: crate::event::AiTool::Other,
                tool_label: Some("x".into()),
                scope: RulePackScope::UserGlobal,
                watched_paths: vec![],
                platforms: None,
                rules: vec![],
            }
        }
        let mut defaults = defaults_doc();
        defaults.rule_packs = vec![pack("a", 1)];
        // The user-policy and bundle layers carry only rule_packs here; clear
        // their targets so the id-collision check on the target merge doesn't
        // fire against the defaults' targets (we are exercising rule_packs).
        let mut policy = defaults_doc();
        policy.targets = vec![];
        policy.rule_packs = vec![pack("a", 2), pack("b", 1)];
        let mut bundle = defaults_doc();
        bundle.targets = vec![];
        bundle.rule_packs = vec![pack("b", 9)];
        let eff = merge(defaults, Some(policy), Some(bundle), Platform::Macos).unwrap();
        let by_id = |id: &str| {
            eff.rule_packs
                .iter()
                .find(|p| p.id == id)
                .unwrap()
                .pack_version
        };
        assert_eq!(by_id("a"), 2); // policy beat defaults
        assert_eq!(by_id("b"), 9); // bundle beat policy
        assert_eq!(eff.rule_packs.len(), 2);
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
            gemini_workspaces: vec![],
            cursor_workspaces: vec![],
            antigravity_workspaces: vec![],
            rule_packs: vec![],
            rubric_overrides: HashMap::new(),
            hook_deny_rules: vec![],
            on_failure: deny_rule::FailMode::Open,
            hook_silence: HookSilenceCfg::default(),
        };
        let eff = merge(defaults_doc(), Some(user), None, Platform::Macos).unwrap();
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
            gemini_workspaces: vec![],
            cursor_workspaces: vec![],
            antigravity_workspaces: vec![],
            rule_packs: vec![],
            rubric_overrides: HashMap::new(),
            hook_deny_rules: vec![],
            on_failure: deny_rule::FailMode::Open,
            hook_silence: HookSilenceCfg::default(),
        };
        let eff = merge(defaults_doc(), Some(user), None, Platform::Macos).unwrap();
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
            gemini_workspaces: vec![],
            cursor_workspaces: vec![],
            antigravity_workspaces: vec![],
            rule_packs: vec![],
            rubric_overrides: HashMap::new(),
            hook_deny_rules: vec![],
            on_failure: deny_rule::FailMode::Open,
            hook_silence: HookSilenceCfg::default(),
        };
        let err = merge(defaults_doc(), Some(user), None, Platform::Macos).unwrap_err();
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
            gemini_workspaces: vec![],
            cursor_workspaces: vec![],
            antigravity_workspaces: vec![],
            rule_packs: vec![],
            rubric_overrides: HashMap::new(),
            hook_deny_rules: vec![],
            on_failure: deny_rule::FailMode::Open,
            hook_silence: HookSilenceCfg::default(),
        };
        let err = merge(defaults_doc(), Some(user), None, Platform::Macos).unwrap_err();
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
            gemini_workspaces: vec![],
            cursor_workspaces: vec![],
            antigravity_workspaces: vec![],
            rule_packs: vec![],
            rubric_overrides: HashMap::new(),
            hook_deny_rules: vec![],
            on_failure: deny_rule::FailMode::Open,
            hook_silence: HookSilenceCfg::default(),
        };
        let err = merge(defaults, None, None, Platform::Macos).unwrap_err();
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
            let eff = merge(defaults().unwrap(), None, None, current_platform()).unwrap();
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
        let eff = merge(defaults().unwrap(), Some(user), None, current_platform()).unwrap();
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
        assert!(matches!(pack.scope, RulePackScope::UserGlobal));
        assert_eq!(pack.rules.len(), 1);
        assert_eq!(pack.rules[0].format, RuleFormat::Json);
        let back = serde_yaml::to_string(&pack).unwrap();
        let again: RulePack = serde_yaml::from_str(&back).expect("re-parse");
        assert_eq!(again.id, pack.id);
    }

    #[test]
    fn rule_pack_project_scope_yaml_deserializes() {
        let yaml = r#"
id: project-pack
pack_version: 1
tool: gemini
scope:
  kind: project
watched_paths: []
rules: []
"#;
        let pack: RulePack = serde_yaml::from_str(yaml).expect("parse");
        assert_eq!(pack.scope, RulePackScope::Project);
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
        let eff = merge(defaults_doc, Some(user), None, current_platform()).unwrap();
        assert_eq!(eff.rule_packs.len(), 1);
        assert_eq!(eff.rule_packs[0].watched_paths, vec!["~/override/path"]);
    }

    #[test]
    fn defaults_includes_no_rule_packs() {
        // Phase 3b.8: gemini-default and cursor-default are retired from the
        // built-in defaults (superseded by the hardcoded parsers in 3b.8).
        // Operators can still supply their own rule packs via signed policy
        // overlay — the engine remains intact.
        let doc = defaults().expect("defaults parse");
        assert!(doc.rule_packs.is_empty());
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
        let eff = merge(defaults_doc, Some(user), None, current_platform()).unwrap();
        assert_eq!(eff.rule_packs.len(), 2);
        assert!(eff.rule_packs.iter().any(|p| p.id == "mycorp-tool"));
        assert!(eff.rule_packs.iter().any(|p| p.id == "gemini-default"));
    }

    #[test]
    fn policy_document_round_trips_rubric_overrides() {
        let yaml = r#"
version: 1
host_id_strategy: hostname
rubric_overrides:
  destructive_in_hook_script: 5.0
  broad_matcher_other: 0.0
"#;
        let doc: PolicyDocument = parse(yaml).unwrap();
        assert_eq!(doc.rubric_overrides.len(), 2);
        assert_eq!(
            doc.rubric_overrides.get("destructive_in_hook_script"),
            Some(&5.0_f32)
        );
        assert_eq!(
            doc.rubric_overrides.get("broad_matcher_other"),
            Some(&0.0_f32)
        );
    }

    #[test]
    fn policy_document_absent_rubric_overrides_is_empty_map() {
        let yaml = r#"
version: 1
host_id_strategy: hostname
"#;
        let doc: PolicyDocument = parse(yaml).unwrap();
        assert!(doc.rubric_overrides.is_empty());
    }

    #[test]
    fn shipped_policy_example_yaml_parses_with_rubric_overrides() {
        // The packaged example (ships to /etc/sigil/policy.yaml.example) must stay
        // schema-valid and keep demonstrating rubric_overrides (epic #9 wrap-up).
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../config/policy.example.yaml"
        );
        let contents = std::fs::read_to_string(path).expect("read policy.example.yaml");
        let doc: PolicyDocument =
            serde_yaml::from_str(&contents).expect("policy.example.yaml must parse");
        assert_eq!(doc.version, 1);
        assert!(
            doc.rubric_overrides
                .contains_key("external_script_unscanned"),
            "example should demonstrate rubric_overrides"
        );
    }

    #[test]
    fn merge_forwards_user_rubric_overrides() {
        let defaults = defaults().unwrap();
        // PolicyDocument doesn't derive Default (HostIdStrategy has no Default
        // variant), so construct explicitly.
        let mut user = PolicyDocument {
            version: 1,
            host_id_strategy: HostIdStrategy::MachineId,
            overrides: vec![],
            targets: vec![],
            continue_workspaces: vec![],
            claude_code_workspaces: vec![],
            codex_workspaces: vec![],
            gemini_workspaces: vec![],
            cursor_workspaces: vec![],
            antigravity_workspaces: vec![],
            rule_packs: vec![],
            rubric_overrides: HashMap::new(),
            hook_deny_rules: vec![],
            on_failure: deny_rule::FailMode::Open,
            hook_silence: HookSilenceCfg::default(),
        };
        user.rubric_overrides
            .insert("destructive_in_hook_script".into(), 5.5);
        let eff = merge(defaults, Some(user), None, current_platform()).unwrap();
        assert_eq!(
            eff.rubric_overrides.get("destructive_in_hook_script"),
            Some(&5.5_f32)
        );
    }

    #[test]
    fn policy_document_gemini_cursor_workspaces_round_trip() {
        let yaml = "version: 1\ngemini_workspaces:\n  - \"~/src/a\"\ncursor_workspaces:\n  - \"~/src/b\"\n";
        let doc = parse(yaml).unwrap();
        assert_eq!(doc.gemini_workspaces, vec!["~/src/a".to_string()]);
        assert_eq!(doc.cursor_workspaces, vec!["~/src/b".to_string()]);
    }

    #[test]
    fn policy_document_without_gemini_cursor_workspaces_defaults_empty() {
        let doc = parse("version: 1\n").unwrap();
        assert!(doc.gemini_workspaces.is_empty());
        assert!(doc.cursor_workspaces.is_empty());
    }

    #[test]
    fn rule_entry_when_defaults_empty_and_round_trips() {
        // a rule WITHOUT `when` parses to an empty when (back-compat)
        let r: RuleEntry = serde_yaml::from_str(
            "id: r1\non_file: /x\nformat: json\nselector: \"$.a\"\nmatcher: { kind: exists }\nemit: { kind: sandbox_disabled }\n",
        ).unwrap();
        assert!(r.when.is_empty());

        // a rule WITH when conditions (incl. negate default) round-trips
        let y = "id: r2\non_file: /x\nformat: json\nselector: \"$.a\"\nmatcher: { kind: exists }\nemit: { kind: sandbox_disabled }\nwhen:\n  - selector: \"$.b\"\n    matcher: { kind: equals, value: \"true\" }\n  - selector: \"$.c\"\n    matcher: { kind: exists }\n    negate: true\n";
        let r2: RuleEntry = serde_yaml::from_str(y).unwrap();
        assert_eq!(r2.when.len(), 2);
        assert!(!r2.when[0].negate);
        assert!(r2.when[1].negate);
    }

    #[test]
    fn rule_pack_scope_serde_round_trips() {
        use super::RulePackScope;
        let ug: RulePackScope = serde_json::from_str(r#"{"kind":"user_global"}"#).unwrap();
        assert_eq!(ug, RulePackScope::UserGlobal);
        let pj: RulePackScope = serde_json::from_str(r#"{"kind":"project"}"#).unwrap();
        assert_eq!(pj, RulePackScope::Project);
        assert_eq!(
            serde_json::to_string(&RulePackScope::Project).unwrap(),
            r#"{"kind":"project"}"#
        );
    }

    #[test]
    fn merge_forwards_gemini_cursor_workspaces() {
        // PolicyDocument doesn't derive Default (HostIdStrategy has no Default
        // variant), so construct explicitly — mirror merge_forwards_user_rubric_overrides.
        let user = PolicyDocument {
            version: 1,
            host_id_strategy: HostIdStrategy::MachineId,
            overrides: vec![],
            targets: vec![],
            continue_workspaces: vec![],
            claude_code_workspaces: vec![],
            codex_workspaces: vec![],
            gemini_workspaces: vec!["~/src/a".to_string()],
            cursor_workspaces: vec!["~/src/b".to_string()],
            antigravity_workspaces: vec!["~/src/c".to_string()],
            rule_packs: vec![],
            rubric_overrides: HashMap::new(),
            hook_deny_rules: vec![],
            on_failure: deny_rule::FailMode::Open,
            hook_silence: HookSilenceCfg::default(),
        };
        let eff = merge(defaults().unwrap(), Some(user), None, current_platform()).unwrap();
        assert_eq!(eff.gemini_workspaces, vec!["~/src/a".to_string()]);
        assert_eq!(eff.cursor_workspaces, vec!["~/src/b".to_string()]);
        assert_eq!(eff.antigravity_workspaces, vec!["~/src/c".to_string()]);
    }

    #[test]
    fn policy_without_hook_deny_rules_defaults_empty_open() {
        // use the same minimal valid policy shape the other tests in this module use
        let doc = parse(yaml_minimal()).unwrap();
        assert!(doc.hook_deny_rules.is_empty());
        assert_eq!(doc.on_failure, FailMode::Open);
    }

    #[test]
    fn hook_silence_defaults_disabled() {
        let doc: PolicyDocument = parse(
            "version: 1\ntargets:\n  - id: t\n    description: x\n    tier: standard\n    platform: any\n    paths: [\"~/x\"]\n",
        ).unwrap();
        assert!(doc.hook_silence.enabled_agents.is_empty());
        assert_eq!(doc.hook_silence.window_secs, 43_200);
        assert_eq!(doc.hook_silence.horizon_secs, 604_800);
        assert_eq!(doc.hook_silence.tick_secs, 1_800);
        assert_eq!(doc.hook_silence.probe_cap.max_entries, 256);
        assert_eq!(doc.hook_silence.probe_cap.max_depth, 3);
        assert_eq!(doc.hook_silence.probe_cap.budget_ms, 50);
    }

    #[test]
    fn merge_forwards_hook_silence_from_user() {
        let user: PolicyDocument = parse(
            "version: 1\ntargets: []\nhook_silence:\n  enabled_agents: [codex]\n  window_secs: 60\n",
        ).unwrap();
        let eff = merge(defaults_doc(), Some(user), None, Platform::Macos).unwrap();
        assert_eq!(
            eff.hook_silence.enabled_agents,
            vec![crate::event::AiTool::Codex]
        );
        assert_eq!(eff.hook_silence.window_secs, 60);
        // a field absent from the user's partial block still takes the documented default
        assert_eq!(eff.hook_silence.horizon_secs, 604_800);
    }
}
