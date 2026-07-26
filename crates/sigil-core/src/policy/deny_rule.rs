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
    /// #198 — tested against the raw command preview AND each shell-normalized
    /// segment, so a rule written as `rm -rf /` also catches `r''m -rf /` and
    /// `rm${IFS}-rf${IFS}/`.
    Bash {
        command: Matcher,
    },
    /// #198 — matches on the *shape* of a command whose effect cannot be known
    /// statically (`$(...)`, `eval`, `... | sh`), rather than on its text. The
    /// field is named `indirection` and not `kind` because `kind` is the serde
    /// tag for this enum.
    ///
    /// Values are `shell_norm::Indirection::as_str()`:
    /// `command_substitution`, `eval`, `pipe_to_shell`,
    /// `unresolved_command_variable`, `unparsable`.
    BashIndirection {
        indirection: Matcher,
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

    /// #198 — the indirection rule's field is `indirection`, not `kind`, which
    /// is the serde tag for this enum. Pin the wire shape so a rename can't
    /// silently collide with the tag.
    #[test]
    fn bash_indirection_rule_round_trips() {
        let yaml = r#"
id: no-opaque-commands
match:
  kind: bash_indirection
  indirection: { kind: equals, value: pipe_to_shell }
"#;
        let r: DenyRule = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(r.id, "no-opaque-commands");
        match &r.match_ {
            HookActionMatch::BashIndirection {
                indirection: Matcher::Equals { value },
            } => assert_eq!(value, "pipe_to_shell"),
            other => panic!("expected bash_indirection/equals, got {other:?}"),
        }
        let out = serde_yaml::to_string(&r).unwrap();
        assert!(out.contains("kind: bash_indirection"), "{out}");
        assert!(out.contains("indirection:"), "{out}");
    }

    /// Packs written before #198 must keep parsing untouched.
    #[test]
    fn pre_198_bash_rule_still_parses() {
        let yaml = r#"
id: legacy
match:
  kind: bash
  command: { kind: equals, value: "rm -rf /" }
"#;
        let r: DenyRule = serde_yaml::from_str(yaml).unwrap();
        assert!(matches!(r.match_, HookActionMatch::Bash { .. }));
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
