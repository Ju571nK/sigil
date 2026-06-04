//! Stage 2 (#100): pure deny-rule evaluation over a runtime HookAction.
//! Regexes are compiled once at construction. First matching rule wins.
use sigil_core::hook_proto::HookAction;
use sigil_core::policy::{DenyRule, HookActionMatch, Matcher};

pub struct DenyEvaluator {
    rules: Vec<CompiledRule>,
}

struct CompiledRule {
    id: String,
    matcher: CompiledMatch,
}

enum CompiledMatch {
    Bash(FieldMatch),
    FileEdit(FieldMatch),
    McpCall {
        server: FieldMatch,
        tool: FieldMatch,
    },
    Other {
        label: FieldMatch,
        detail: FieldMatch,
    },
}

/// A field test with any Regex pre-compiled.
struct FieldMatch {
    matcher: Matcher,
    regex: Option<regex::Regex>,
}

impl FieldMatch {
    fn compile(m: &Matcher) -> Result<Self, regex::Error> {
        let regex = match m {
            Matcher::Regex { pattern } => Some(regex::Regex::new(pattern)?),
            _ => None,
        };
        Ok(FieldMatch {
            matcher: m.clone(),
            regex,
        })
    }

    /// Test against an optional string. `None` (no preview / absent field) never
    /// matches — capture-aware fail-open.
    fn holds(&self, value: Option<&str>) -> bool {
        let Some(v) = value else { return false };
        match &self.matcher {
            Matcher::Exists => true,
            Matcher::Equals { value } => v == value,
            Matcher::NotEquals { value } => v != value,
            Matcher::Regex { .. } => self.regex.as_ref().map(|r| r.is_match(v)).unwrap_or(false),
        }
    }
}

impl DenyEvaluator {
    /// Compile all rules; first malformed regex fails construction (caller logs
    /// and treats deny rules as empty — fail-open).
    pub fn new(rules: &[DenyRule]) -> Result<Self, regex::Error> {
        let mut out = Vec::with_capacity(rules.len());
        for r in rules {
            let matcher = match &r.match_ {
                HookActionMatch::Bash { command } => {
                    CompiledMatch::Bash(FieldMatch::compile(command)?)
                }
                HookActionMatch::FileEdit { path } => {
                    CompiledMatch::FileEdit(FieldMatch::compile(path)?)
                }
                HookActionMatch::McpCall { server, tool } => CompiledMatch::McpCall {
                    server: FieldMatch::compile(server)?,
                    tool: FieldMatch::compile(tool)?,
                },
                HookActionMatch::Other { label, detail } => CompiledMatch::Other {
                    label: FieldMatch::compile(label)?,
                    detail: FieldMatch::compile(detail)?,
                },
            };
            out.push(CompiledRule {
                id: r.id.clone(),
                matcher,
            });
        }
        Ok(DenyEvaluator { rules: out })
    }

    // used by runtime wiring (Task 7)
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// First matching rule → (rule_id, reason). Slice 1 reason = the rule id.
    pub fn evaluate(&self, action: &HookAction) -> Option<(String, String)> {
        for r in &self.rules {
            if rule_matches(&r.matcher, action) {
                return Some((r.id.clone(), format!("matched deny rule {}", r.id)));
            }
        }
        None
    }
}

fn rule_matches(m: &CompiledMatch, action: &HookAction) -> bool {
    match (m, action) {
        (
            CompiledMatch::Bash(f),
            HookAction::Bash {
                command_preview, ..
            },
        ) => f.holds(command_preview.as_deref()),
        (CompiledMatch::FileEdit(f), HookAction::FileEdit { path_preview, .. }) => {
            f.holds(path_preview.as_deref())
        }
        // server/tool/label are non-optional in HookAction; wrap in Some to satisfy holds().
        (
            CompiledMatch::McpCall { server, tool },
            HookAction::McpCall {
                server: s, tool: t, ..
            },
        ) => server.holds(Some(s.as_str())) && tool.holds(Some(t.as_str())),
        // server/tool/label are non-optional in HookAction; wrap in Some to satisfy holds().
        (
            CompiledMatch::Other { label, detail },
            HookAction::Other {
                label: l,
                detail_preview,
                ..
            },
        ) => label.holds(Some(l.as_str())) && detail.holds(detail_preview.as_deref()),
        // shape mismatch: a bash rule never matches an mcp action, etc.
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigil_core::policy::{DenyRule, HookActionMatch, Matcher};

    fn bash(preview: Option<&str>) -> HookAction {
        HookAction::Bash {
            command_hash: "ab".repeat(32),
            command_preview: preview.map(String::from),
        }
    }

    #[test]
    fn regex_bash_rule_matches_preview() {
        let ev = DenyEvaluator::new(&[DenyRule {
            id: "no-rm".into(),
            match_: HookActionMatch::Bash {
                command: Matcher::Regex {
                    pattern: r"rm\s+-rf\s+/".into(),
                },
            },
        }])
        .unwrap();
        assert_eq!(ev.evaluate(&bash(Some("rm -rf /"))).unwrap().0, "no-rm");
        assert!(ev.evaluate(&bash(Some("ls -la"))).is_none());
    }

    #[test]
    fn hash_only_no_preview_never_matches() {
        let ev = DenyEvaluator::new(&[DenyRule {
            id: "no-rm".into(),
            match_: HookActionMatch::Bash {
                command: Matcher::Regex {
                    pattern: "rm".into(),
                },
            },
        }])
        .unwrap();
        assert!(
            ev.evaluate(&bash(None)).is_none(),
            "no preview → fail-open (allow)"
        );
    }

    #[test]
    fn mcp_equals_matches_server_and_tool() {
        let ev = DenyEvaluator::new(&[DenyRule {
            id: "no-deploy".into(),
            match_: HookActionMatch::McpCall {
                server: Matcher::Equals {
                    value: "deploy".into(),
                },
                tool: Matcher::Equals {
                    value: "promote".into(),
                },
            },
        }])
        .unwrap();
        let act = HookAction::McpCall {
            server: "deploy".into(),
            tool: "promote".into(),
            args_hash: "ab".repeat(32),
            args_preview: None,
        };
        assert_eq!(ev.evaluate(&act).unwrap().0, "no-deploy");
    }

    #[test]
    fn first_match_wins() {
        let ev = DenyEvaluator::new(&[
            DenyRule {
                id: "a".into(),
                match_: HookActionMatch::Bash {
                    command: Matcher::Regex {
                        pattern: "rm".into(),
                    },
                },
            },
            DenyRule {
                id: "b".into(),
                match_: HookActionMatch::Bash {
                    command: Matcher::Regex {
                        pattern: "rm".into(),
                    },
                },
            },
        ])
        .unwrap();
        assert_eq!(ev.evaluate(&bash(Some("rm x"))).unwrap().0, "a");
    }

    #[test]
    fn not_equals_matches_when_different() {
        let ev = DenyEvaluator::new(&[DenyRule {
            id: "not-safe".into(),
            match_: HookActionMatch::Bash {
                command: Matcher::NotEquals {
                    value: "safe".into(),
                },
            },
        }])
        .unwrap();
        // Different from "safe" → matches.
        assert_eq!(ev.evaluate(&bash(Some("rm -rf /"))).unwrap().0, "not-safe");
        // Equal to "safe" → does not match.
        assert!(ev.evaluate(&bash(Some("safe"))).is_none());
        // No preview → fail-open (allow).
        assert!(ev.evaluate(&bash(None)).is_none());
    }
}
