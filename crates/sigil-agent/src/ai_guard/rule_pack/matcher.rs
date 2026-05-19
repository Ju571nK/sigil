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
        }];
        let err = compile_pack_regexes(&rules).unwrap_err();
        assert_eq!(err.rule_id, "bad");
    }
}
