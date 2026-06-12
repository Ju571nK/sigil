//! Stage 2 (#100): pure deny-rule evaluation over a runtime HookAction.
//! Regexes are compiled once at construction. First matching rule wins.
use sigil_core::hook_proto::HookAction;
use sigil_core::policy::{DenyRule, HookActionMatch, Matcher};

/// Shared, hot-swappable evaluator: snapshotted per decide request, rebuilt+swapped on policy reload (#115).
pub type SharedEvaluator = std::sync::Arc<parking_lot::RwLock<std::sync::Arc<DenyEvaluator>>>;

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

    /// Evaluate a proposed bash command preview against the loaded deny rules,
    /// using the same path the hook enforcement uses. Returns (rule_id, reason)
    /// on a deny match. Shared by sigil-hook enforcement and the assess primitive (#149).
    ///
    /// The `command_hash` is computed as `blake3(preview.as_bytes()).to_hex()` —
    /// the same formula that `sigil-hook`'s `redact::capture` uses when building
    /// `HookAction::Bash` from a live tool call. This ensures the assess path and
    /// the enforcement path produce an identical action shape.
    pub fn evaluate_bash_preview(&self, preview: &str) -> Option<(String, String)> {
        // NOTE: sigil-hook adapters (e.g. claude_code.rs) construct an equivalent
        // HookAction::Bash via redact::capture, which hashes over the raw command
        // with blake3. We mirror that here so both call the same evaluate() path.
        let command_hash = blake3::hash(preview.as_bytes()).to_hex().to_string();
        let action = HookAction::Bash {
            command_hash,
            command_preview: Some(preview.to_string()),
        };
        self.evaluate(&action)
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

    #[test]
    fn evaluate_bash_preview_matches_deny_rule() {
        let ev = DenyEvaluator::new(&[DenyRule {
            id: "no-rm".into(),
            match_: HookActionMatch::Bash {
                command: Matcher::Regex {
                    pattern: r"rm\s+-rf\s+/".into(),
                },
            },
        }])
        .unwrap();
        let result = ev.evaluate_bash_preview("rm -rf /");
        assert!(result.is_some(), "should deny rm -rf /");
        assert_eq!(result.unwrap().0, "no-rm");
    }

    #[test]
    fn evaluate_bash_preview_no_match() {
        let ev = DenyEvaluator::new(&[DenyRule {
            id: "no-rm".into(),
            match_: HookActionMatch::Bash {
                command: Matcher::Regex {
                    pattern: r"rm\s+-rf\s+/".into(),
                },
            },
        }])
        .unwrap();
        assert!(ev.evaluate_bash_preview("ls -la").is_none());
    }

    #[test]
    fn evaluate_bash_preview_equals_direct_evaluate() {
        let ev = DenyEvaluator::new(&[DenyRule {
            id: "no-rm".into(),
            match_: HookActionMatch::Bash {
                command: Matcher::Regex {
                    pattern: r"rm\s+-rf\s+/".into(),
                },
            },
        }])
        .unwrap();
        let preview = "rm -rf /";
        let via_helper = ev.evaluate_bash_preview(preview);
        let command_hash = blake3::hash(preview.as_bytes()).to_hex().to_string();
        let direct_action = HookAction::Bash {
            command_hash,
            command_preview: Some(preview.to_string()),
        };
        let via_direct = ev.evaluate(&direct_action);
        assert_eq!(via_helper, via_direct, "helper must be a faithful wrapper");
    }

    #[test]
    fn shared_evaluator_swaps_and_bad_regex_keeps_previous() {
        use parking_lot::RwLock;
        use std::sync::Arc;

        // A rule set that DENIES bash commands matching "rm".
        let deny_rule = DenyRule {
            id: "no-rm".into(),
            match_: HookActionMatch::Bash {
                command: Matcher::Regex {
                    pattern: "rm".into(),
                },
            },
        };
        let action_a = bash(Some("rm -rf /"));

        let denies = DenyEvaluator::new(&[deny_rule]).unwrap();
        let shared: SharedEvaluator = Arc::new(RwLock::new(Arc::new(denies)));

        // Snapshot → denies action_a.
        let ev = { Arc::clone(&*shared.read()) };
        assert!(
            ev.evaluate(&action_a).is_some(),
            "initial evaluator should deny rm"
        );

        // Swap to empty (allow-all) → now allowed.
        *shared.write() = Arc::new(DenyEvaluator::new(&[]).unwrap());
        let ev = { Arc::clone(&*shared.read()) };
        assert!(
            ev.evaluate(&action_a).is_none(),
            "empty evaluator should allow rm"
        );

        // Emulate reload keep-previous: a bad-regex rebuild fails → do NOT swap.
        let bad_rule = DenyRule {
            id: "bad".into(),
            match_: HookActionMatch::Bash {
                command: Matcher::Regex {
                    pattern: "(".into(), // invalid regex
                },
            },
        };
        match DenyEvaluator::new(&[bad_rule]) {
            Ok(e) => *shared.write() = Arc::new(e),
            Err(_) => { /* keep previous */ }
        }
        let ev = { Arc::clone(&*shared.read()) };
        assert!(
            ev.evaluate(&action_a).is_none(),
            "previous (empty) evaluator should still allow rm after failed rebuild"
        );
    }
}
