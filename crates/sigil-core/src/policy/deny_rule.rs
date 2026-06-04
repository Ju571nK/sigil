//! Stage 2 (#100): operator deny rules over runtime hook actions. The subject
//! is a `HookAction` (a tool call), distinct from rule packs (config files).
use crate::policy::Matcher;
use serde::{Deserialize, Serialize};

/// What to do when no verdict is obtainable (daemon down, timeout, malformed).
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum FailMode {
    #[default]
    Open,
    Closed,
}

/// One deny rule. Fires when its `match_` holds for the action.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct DenyRule {
    pub id: String,
    #[serde(rename = "match")]
    pub match_: HookActionMatch,
}

/// Matches one HookAction shape. Every present field-matcher must hold (AND).
/// The `kind` tag mirrors `hook_proto::HookAction`'s wire kinds.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HookActionMatch {
    Bash {
        command: Matcher,
    },
    FileEdit {
        path: Matcher,
    },
    McpCall {
        server: Matcher,
        tool: Matcher,
    },
    /// `detail` matches against the normalized detail PREVIEW form, not the
    /// opaque `detail_hash`.
    Other {
        label: Matcher,
        detail: Matcher,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_rule_yaml_round_trips_with_match_rename() {
        let yaml = r#"
id: no-rm-rf-root
match:
  kind: bash
  command: { kind: regex, pattern: "rm -rf /" }
"#;
        let r: DenyRule = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(r.id, "no-rm-rf-root");
        match &r.match_ {
            HookActionMatch::Bash {
                command: Matcher::Regex { pattern },
            } => assert_eq!(pattern, "rm -rf /"),
            _ => panic!("expected bash/regex"),
        }
        // serialize direction: the `match_` field must re-emit as `match:`.
        let out = serde_yaml::to_string(&r).unwrap();
        assert!(out.contains("match:"));
    }

    #[test]
    fn fail_mode_defaults_to_open() {
        assert_eq!(FailMode::default(), FailMode::Open);
        let m: FailMode = serde_yaml::from_str("closed").unwrap();
        assert_eq!(m, FailMode::Closed);
    }

    #[test]
    fn mcp_match_round_trips_both_fields() {
        let yaml = r#"
id: no-prod-deploy
match:
  kind: mcp_call
  server: { kind: equals, value: "deploy" }
  tool:   { kind: equals, value: "promote_production" }
"#;
        let r: DenyRule = serde_yaml::from_str(yaml).unwrap();
        match r.match_ {
            HookActionMatch::McpCall {
                server: Matcher::Equals { value: s },
                tool: Matcher::Equals { value: t },
            } => {
                assert_eq!(s, "deploy");
                assert_eq!(t, "promote_production");
            }
            _ => panic!("expected mcp_call/equals"),
        }
    }

    #[test]
    fn file_edit_match_deserializes() {
        let yaml = r#"
id: no-edit-etc
match:
  kind: file_edit
  path: { kind: regex, pattern: "/etc/" }
"#;
        let r: DenyRule = serde_yaml::from_str(yaml).unwrap();
        match r.match_ {
            HookActionMatch::FileEdit {
                path: Matcher::Regex { pattern },
            } => assert_eq!(pattern, "/etc/"),
            _ => panic!("expected file_edit/regex"),
        }
    }

    #[test]
    fn other_match_deserializes_both_fields() {
        let yaml = r#"
id: no-weird-tool
match:
  kind: other
  label:  { kind: equals, value: "browser" }
  detail: { kind: equals, value: "navigate" }
"#;
        let r: DenyRule = serde_yaml::from_str(yaml).unwrap();
        match r.match_ {
            HookActionMatch::Other {
                label: Matcher::Equals { value: l },
                detail: Matcher::Equals { value: d },
            } => {
                assert_eq!(l, "browser");
                assert_eq!(d, "navigate");
            }
            _ => panic!("expected other/equals"),
        }
    }
}
