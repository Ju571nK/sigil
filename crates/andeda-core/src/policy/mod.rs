//! Watchlist policy: parsing, merging, expansion.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::PathBuf;
use thiserror::Error;

pub mod canonical;
pub mod expand;
pub mod glob;
pub mod pubkeys;
pub mod signed_envelope;
pub mod verify;

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
    } else {
        Platform::Any
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectivePolicy {
    pub host_id_strategy: HostIdStrategy,
    pub targets: Vec<WatchTarget>,
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
    Ok(EffectivePolicy {
        host_id_strategy: strategy,
        targets: by_id,
    })
}

const DEFAULTS_MACOS: &str = include_str!("defaults_macos.yaml");
const DEFAULTS_WINDOWS: &str = include_str!("defaults_windows.yaml");

/// Built-in defaults for the current OS, parsed from a compile-time-embedded YAML.
pub fn defaults() -> Result<PolicyDocument, PolicyError> {
    let yaml = if cfg!(target_os = "macos") {
        DEFAULTS_MACOS
    } else if cfg!(target_os = "windows") {
        DEFAULTS_WINDOWS
    } else {
        // Linux build-only: defaults are empty so callers can supply user policy.
        return Ok(PolicyDocument {
            version: 1,
            host_id_strategy: HostIdStrategy::MachineId,
            overrides: vec![],
            targets: vec![],
        });
    };
    parse(yaml)
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
        };
        let err = merge(defaults, None, Platform::Macos).unwrap_err();
        assert!(matches!(err, PolicyError::EmptyTargets));
    }

    #[test]
    fn defaults_parses_for_current_platform() {
        let doc = defaults().unwrap();
        assert_eq!(doc.version, 1);
        if cfg!(target_os = "macos") || cfg!(target_os = "windows") {
            assert!(!doc.targets.is_empty());
            for t in &doc.targets {
                assert!(!t.id.is_empty());
                assert!(!t.paths.is_empty());
            }
        }
    }
}
