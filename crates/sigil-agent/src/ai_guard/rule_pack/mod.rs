//! Phase 3b.7 — declarative rule pack engine. Loads RulePack from
//! sigil-rules-basic defaults + operator policy.yaml overlay and runs
//! Tier 1 DSL (path glob + JSON/TOML selector + matcher → AiGuardReason emit).

pub mod expand;
pub mod matcher;
pub mod parser;
pub mod selector;

/// Pack format version range this interpreter supports.
pub const MIN_PACK_VERSION: u32 = 1;
pub const MAX_PACK_VERSION: u32 = 1;

/// Cheap pre-flight check applied at boot + reload time. Heavier checks
/// (regex compile, selector syntax) happen inside RulePackParser::new.
pub fn pack_is_loadable(pack: &sigil_core::policy::RulePack) -> bool {
    if pack.pack_version < MIN_PACK_VERSION || pack.pack_version > MAX_PACK_VERSION {
        tracing::warn!(
            id = %pack.id, pack_version = pack.pack_version,
            "rule_pack: incompatible pack_version; skipping"
        );
        return false;
    }
    match pack.scope {
        sigil_core::policy::RulePackScope::UserGlobal => {}
        sigil_core::policy::RulePackScope::Project => {
            // Project on_file paths are resolved relative to each repo_root, so an
            // absolute path is an authoring error — reject the whole pack loudly.
            if let Some(bad) = pack
                .rules
                .iter()
                .find(|r| std::path::Path::new(&r.on_file).is_absolute())
            {
                tracing::warn!(
                    id = %pack.id, rule = %bad.id, on_file = %bad.on_file,
                    "rule_pack: Project scope requires relative on_file; skipping pack"
                );
                return false;
            }
        }
    }
    if let Some(plats) = &pack.platforms {
        if !plats.is_empty() && !plats.contains(&sigil_core::policy::current_platform()) {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigil_core::event::{AiGuardReason, AiTool};
    use sigil_core::policy::{Matcher, RuleEntry, RuleFormat, RulePack, RulePackScope};

    fn pack(scope: RulePackScope, on_file: &str) -> RulePack {
        RulePack {
            id: "p".into(),
            pack_version: 1,
            tool: AiTool::Gemini,
            scope,
            watched_paths: vec![],
            platforms: None,
            rules: vec![RuleEntry {
                id: "r".into(),
                on_file: on_file.into(),
                format: RuleFormat::Json,
                selector: "$.x".into(),
                matcher: Matcher::Exists,
                emit: AiGuardReason::SandboxDisabled,
            }],
        }
    }

    #[test]
    fn project_scope_is_loadable() {
        assert!(pack_is_loadable(&pack(
            RulePackScope::Project,
            ".gemini/x.json"
        )));
    }

    #[test]
    fn project_with_absolute_on_file_rejected() {
        assert!(!pack_is_loadable(&pack(
            RulePackScope::Project,
            "/abs/x.json"
        )));
    }

    #[test]
    fn user_global_with_absolute_on_file_still_ok() {
        assert!(pack_is_loadable(&pack(
            RulePackScope::UserGlobal,
            "/abs/x.json"
        )));
    }
}
