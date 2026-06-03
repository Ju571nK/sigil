//! Phase 3b.7.2 — expand one authored RulePack into runtime parser instances.
use crate::ai_guard::rule_pack::parser::RulePackParser;
use sigil_core::policy::{RulePack, RulePackScope};
use std::path::PathBuf;

/// UserGlobal -> exactly one parser. Project -> one per repo in `repos`
/// (empty repos -> zero instances). Regex-compile failures are warn-logged and
/// skipped (consistent with boot/reload behavior).
pub fn expand_pack_parsers(pack: &RulePack, repos: &[PathBuf]) -> Vec<RulePackParser> {
    let mut out = Vec::new();
    match pack.scope {
        RulePackScope::UserGlobal => match RulePackParser::new(pack.clone()) {
            Ok(p) => out.push(p),
            Err(e) => tracing::warn!(id = %pack.id, error = ?e, "rule_pack: load failed; skipping"),
        },
        RulePackScope::Project => {
            for repo in repos {
                match RulePackParser::new_project(pack.clone(), repo.clone()) {
                    Ok(p) => out.push(p),
                    Err(e) => tracing::warn!(id = %pack.id, repo = %repo.display(), error = ?e,
                        "rule_pack: per-repo load failed; skipping"),
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ai_guard::parser::AiGuardParser;
    use sigil_core::event::{AiGuardReason, AiGuardScope, AiTool};
    use sigil_core::policy::{Matcher, RuleEntry, RuleFormat};

    fn base(scope: RulePackScope) -> RulePack {
        RulePack {
            id: "p".into(),
            pack_version: 1,
            tool: AiTool::Gemini,
            scope,
            watched_paths: vec![".gemini/s.json".into()],
            platforms: None,
            tool_label: None,
            rules: vec![RuleEntry {
                id: "r".into(),
                on_file: ".gemini/s.json".into(),
                format: RuleFormat::Json,
                selector: "$.x".into(),
                matcher: Matcher::Exists,
                emit: AiGuardReason::SandboxDisabled,
            }],
        }
    }
    #[test]
    fn user_global_expands_to_one() {
        assert_eq!(
            expand_pack_parsers(&base(RulePackScope::UserGlobal), &[]).len(),
            1
        );
    }
    #[test]
    fn project_expands_per_repo() {
        let repos = vec![PathBuf::from("/a"), PathBuf::from("/b")];
        let ps = expand_pack_parsers(&base(RulePackScope::Project), &repos);
        assert_eq!(ps.len(), 2);
        assert_eq!(ps[0].scope(), AiGuardScope::Project { path: "/a".into() });
        assert_eq!(ps[1].scope(), AiGuardScope::Project { path: "/b".into() });
    }
    #[test]
    fn project_with_no_repos_expands_to_zero() {
        assert!(expand_pack_parsers(&base(RulePackScope::Project), &[]).is_empty());
    }
}
