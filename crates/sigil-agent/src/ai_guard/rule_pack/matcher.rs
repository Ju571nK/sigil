//! Phase 3b.7 — Matcher evaluation for rule pack DSL.

use crate::ai_guard::rule_pack::selector::MatchedValue;
use sigil_core::policy::Matcher;

/// Evaluate a Matcher against a single MatchedValue. Returns true when
/// the matcher condition is satisfied. For Regex matchers, the caller
/// must pass a pre-compiled `regex::Regex` (see `compile_pack_regexes`);
/// `None` for non-Regex matchers.
pub fn matches_value(
    m: &Matcher,
    value: &MatchedValue,
    compiled_regex: Option<&regex::Regex>,
) -> bool {
    match m {
        Matcher::Exists => true,
        Matcher::Equals { value: target } => &value.value == target,
        Matcher::NotEquals { value: target } => &value.value != target,
        Matcher::Regex { pattern: _ } => compiled_regex
            .map(|r| r.is_match(&value.value))
            .unwrap_or(false),
    }
}

/// Compile all Regex-typed matchers in a pack's rules into a parallel Vec.
/// Returns `Vec<Option<Regex>>` with the same length as `rules` — element
/// is `Some` iff the rule's matcher is `Matcher::Regex`. Returns `Err` at
/// the first malformed pattern so the caller can reject the entire pack
/// with a useful error carrying the offending rule id.
pub fn compile_pack_regexes(
    rules: &[sigil_core::policy::RuleEntry],
) -> Result<Vec<Option<regex::Regex>>, CompileError> {
    rules
        .iter()
        .map(|r| match &r.matcher {
            Matcher::Regex { pattern } => {
                regex::Regex::new(pattern)
                    .map(Some)
                    .map_err(|source| CompileError {
                        rule_id: r.id.clone(),
                        pattern: pattern.clone(),
                        source,
                    })
            }
            _ => Ok(None),
        })
        .collect()
}

/// Compile the Regex matchers of every rule's `when` conditions. Returns a Vec
/// parallel to `rules`; each element is a Vec parallel to that rule's `when`
/// (Some iff the condition matcher is Regex). Errors at the first malformed
/// pattern, carrying the offending rule id.
pub fn compile_condition_regexes(
    rules: &[sigil_core::policy::RuleEntry],
) -> Result<Vec<Vec<Option<regex::Regex>>>, CompileError> {
    rules
        .iter()
        .map(|r| {
            r.when
                .iter()
                .map(|c| match &c.matcher {
                    sigil_core::policy::Matcher::Regex { pattern } => regex::Regex::new(pattern)
                        .map(Some)
                        .map_err(|source| CompileError {
                            rule_id: r.id.clone(),
                            pattern: pattern.clone(),
                            source,
                        }),
                    _ => Ok(None),
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .collect()
}

#[derive(Debug, thiserror::Error)]
#[error("rule '{rule_id}': regex pattern '{pattern}' failed to compile: {source}")]
pub struct CompileError {
    pub rule_id: String,
    pub pattern: String,
    pub source: regex::Error,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mv(v: &str) -> MatchedValue {
        MatchedValue {
            key: "k".into(),
            value: v.into(),
        }
    }

    #[test]
    fn exists_always_true_on_match() {
        assert!(matches_value(&Matcher::Exists, &mv("anything"), None));
    }

    #[test]
    fn equals_true_on_exact_match() {
        assert!(matches_value(
            &Matcher::Equals {
                value: "danger".into()
            },
            &mv("danger"),
            None,
        ));
    }

    #[test]
    fn equals_false_on_mismatch() {
        assert!(!matches_value(
            &Matcher::Equals {
                value: "danger".into()
            },
            &mv("safe"),
            None,
        ));
    }

    #[test]
    fn not_equals_true_on_mismatch() {
        assert!(matches_value(
            &Matcher::NotEquals {
                value: "safe".into()
            },
            &mv("danger"),
            None,
        ));
    }

    #[test]
    fn regex_true_on_pattern_match() {
        let r = regex::Regex::new("^https://").unwrap();
        assert!(matches_value(
            &Matcher::Regex {
                pattern: "^https://".into()
            },
            &mv("https://example.com"),
            Some(&r),
        ));
    }

    #[test]
    fn regex_false_on_pattern_mismatch() {
        let r = regex::Regex::new("^https://").unwrap();
        assert!(!matches_value(
            &Matcher::Regex {
                pattern: "^https://".into()
            },
            &mv("http://insecure"),
            Some(&r),
        ));
    }

    #[test]
    fn compile_pack_regexes_collects_only_regex_rules() {
        let rules = vec![
            sigil_core::policy::RuleEntry {
                id: "r1".into(),
                on_file: "x".into(),
                format: sigil_core::policy::RuleFormat::Json,
                selector: "$.x".into(),
                matcher: Matcher::Exists,
                emit: sigil_core::event::AiGuardReason::SandboxDisabled,
                when: vec![],
            },
            sigil_core::policy::RuleEntry {
                id: "r2".into(),
                on_file: "x".into(),
                format: sigil_core::policy::RuleFormat::Json,
                selector: "$.x".into(),
                matcher: Matcher::Regex {
                    pattern: "^http".into(),
                },
                emit: sigil_core::event::AiGuardReason::SandboxDisabled,
                when: vec![],
            },
        ];
        let out = compile_pack_regexes(&rules).unwrap();
        assert_eq!(out.len(), 2);
        assert!(out[0].is_none());
        assert!(out[1].is_some());
    }

    #[test]
    fn compile_pack_regexes_fails_on_malformed_pattern() {
        let rules = vec![sigil_core::policy::RuleEntry {
            id: "bad".into(),
            on_file: "x".into(),
            format: sigil_core::policy::RuleFormat::Json,
            selector: "$.x".into(),
            matcher: Matcher::Regex {
                pattern: "[unclosed".into(),
            },
            emit: sigil_core::event::AiGuardReason::SandboxDisabled,
            when: vec![],
        }];
        let err = compile_pack_regexes(&rules).unwrap_err();
        assert_eq!(err.rule_id, "bad");
    }

    #[test]
    fn compile_condition_regexes_collects_only_regex_conditions() {
        let rules = vec![sigil_core::policy::RuleEntry {
            id: "r1".into(),
            on_file: "x".into(),
            format: sigil_core::policy::RuleFormat::Json,
            selector: "$.x".into(),
            matcher: Matcher::Exists,
            emit: sigil_core::event::AiGuardReason::SandboxDisabled,
            when: vec![
                sigil_core::policy::Condition {
                    selector: "$.a".into(),
                    matcher: Matcher::Regex {
                        pattern: "^http".into(),
                    },
                    negate: false,
                },
                sigil_core::policy::Condition {
                    selector: "$.b".into(),
                    matcher: Matcher::Exists,
                    negate: false,
                },
            ],
        }];
        let out = compile_condition_regexes(&rules).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].len(), 2);
        assert!(out[0][0].is_some());
        assert!(out[0][1].is_none());
    }

    #[test]
    fn compile_condition_regexes_fails_on_malformed_pattern() {
        let rules = vec![sigil_core::policy::RuleEntry {
            id: "bad".into(),
            on_file: "x".into(),
            format: sigil_core::policy::RuleFormat::Json,
            selector: "$.x".into(),
            matcher: Matcher::Exists,
            emit: sigil_core::event::AiGuardReason::SandboxDisabled,
            when: vec![sigil_core::policy::Condition {
                selector: "$.a".into(),
                matcher: Matcher::Regex {
                    pattern: "[unclosed".into(),
                },
                negate: false,
            }],
        }];
        let err = compile_condition_regexes(&rules).unwrap_err();
        assert_eq!(err.rule_id, "bad");
    }
}
