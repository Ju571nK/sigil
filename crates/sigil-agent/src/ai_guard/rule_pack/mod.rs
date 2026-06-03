//! Phase 3b.7 — declarative rule pack engine. Loads RulePack from
//! sigil-rules-basic defaults + operator policy.yaml overlay and runs
//! Tier 1 DSL (path glob + JSON/TOML selector + matcher → AiGuardReason emit).

pub mod expand;
pub mod matcher;
pub mod parser;
pub mod selector;

/// Pack format version range this interpreter supports.
pub const MIN_PACK_VERSION: u32 = 1;
pub const MAX_PACK_VERSION: u32 = 2;

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
    // `when` conditions are a Tier-2 (pack_version 2) capability. A v1 pack that
    // carries them is an authoring error — older engines would silently ignore the
    // gate and over-emit. Reject so the version is an honest capability gate.
    if pack.pack_version < 2 {
        if let Some(bad) = pack.rules.iter().find(|r| !r.when.is_empty()) {
            tracing::warn!(
                id = %pack.id, rule = %bad.id,
                "rule_pack: 'when' conditions require pack_version 2; skipping pack"
            );
            return false;
        }
    }
    match pack.scope {
        sigil_core::policy::RulePackScope::UserGlobal => {}
        sigil_core::policy::RulePackScope::Project => {
            // Project on_file paths are resolved relative to each repo_root, so a
            // rooted path is an authoring error — reject the whole pack loudly.
            // Check the first component rather than `is_absolute()`: on Windows a
            // leading-slash path (`/abs/x`) is NOT `is_absolute` (it lacks a drive
            // prefix) yet is still rooted, not repo-relative. RootDir covers
            // `/x` and `\x`; Prefix covers `C:\x` / UNC.
            if let Some(bad) = pack.rules.iter().find(|r| {
                matches!(
                    std::path::Path::new(&r.on_file).components().next(),
                    Some(std::path::Component::RootDir | std::path::Component::Prefix(_))
                )
            }) {
                tracing::warn!(
                    id = %pack.id, rule = %bad.id, on_file = %bad.on_file,
                    "rule_pack: Project scope requires relative on_file; skipping pack"
                );
                return false;
            }
        }
    }
    if matches!(pack.tool, sigil_core::event::AiTool::Other) {
        // Generic tools must name themselves, and are UserGlobal-only: there is no
        // built-in per-repo discovery for an unknown tool, and per-repo generic
        // packs need pack-declared discovery (out of scope — 3b.7.5 non-goal).
        let labelled = pack
            .tool_label
            .as_deref()
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false);
        if !labelled {
            tracing::warn!(id = %pack.id, "rule_pack: tool=other requires a non-empty tool_label; skipping");
            return false;
        }
        if matches!(pack.scope, sigil_core::policy::RulePackScope::Project) {
            tracing::warn!(id = %pack.id, "rule_pack: tool=other supports UserGlobal scope only; skipping");
            return false;
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
            tool_label: None,
            rules: vec![RuleEntry {
                id: "r".into(),
                on_file: on_file.into(),
                format: RuleFormat::Json,
                selector: "$.x".into(),
                matcher: Matcher::Exists,
                emit: AiGuardReason::SandboxDisabled,
                when: vec![],
            }],
        }
    }

    fn pack_tool(tool: AiTool, label: Option<&str>, scope: RulePackScope) -> RulePack {
        RulePack {
            id: "p".into(),
            pack_version: 1,
            tool,
            tool_label: label.map(|s| s.to_string()),
            scope,
            watched_paths: vec![],
            platforms: None,
            rules: vec![RuleEntry {
                id: "r".into(),
                on_file: ".x/c.json".into(),
                format: RuleFormat::Json,
                selector: "$.x".into(),
                matcher: Matcher::Exists,
                emit: AiGuardReason::SandboxDisabled,
                when: vec![],
            }],
        }
    }

    #[test]
    fn other_tool_with_label_is_loadable() {
        assert!(pack_is_loadable(&pack_tool(
            AiTool::Other,
            Some("acme-ai"),
            RulePackScope::UserGlobal
        )));
    }

    #[test]
    fn other_tool_without_label_rejected() {
        assert!(!pack_is_loadable(&pack_tool(
            AiTool::Other,
            None,
            RulePackScope::UserGlobal
        )));
        assert!(!pack_is_loadable(&pack_tool(
            AiTool::Other,
            Some("   "),
            RulePackScope::UserGlobal
        )));
    }

    #[test]
    fn other_tool_with_project_scope_rejected() {
        assert!(!pack_is_loadable(&pack_tool(
            AiTool::Other,
            Some("acme-ai"),
            RulePackScope::Project
        )));
    }

    #[test]
    fn builtin_tool_with_stray_label_still_loadable() {
        assert!(pack_is_loadable(&pack_tool(
            AiTool::Gemini,
            Some("ignored"),
            RulePackScope::UserGlobal
        )));
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

    fn pack_with_when(pack_version: u32) -> RulePack {
        use sigil_core::policy::Condition;
        RulePack {
            id: "p".into(),
            pack_version,
            tool: AiTool::Gemini,
            tool_label: None,
            scope: RulePackScope::UserGlobal,
            watched_paths: vec![],
            platforms: None,
            rules: vec![RuleEntry {
                id: "r".into(),
                on_file: ".x/c.json".into(),
                format: RuleFormat::Json,
                selector: "$.a".into(),
                matcher: Matcher::Exists,
                emit: AiGuardReason::SandboxDisabled,
                when: vec![Condition {
                    selector: "$.b".into(),
                    matcher: Matcher::Exists,
                    negate: false,
                }],
            }],
        }
    }

    #[test]
    fn pack_version_2_with_when_is_loadable() {
        assert!(pack_is_loadable(&pack_with_when(2)));
    }

    #[test]
    fn pack_version_1_with_when_is_rejected() {
        assert!(!pack_is_loadable(&pack_with_when(1)));
    }

    #[test]
    fn pack_version_1_without_when_still_loadable() {
        let mut p = pack_with_when(1);
        p.rules[0].when.clear();
        assert!(pack_is_loadable(&p));
    }
}
