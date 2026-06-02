//! Phase 3b.7 — declarative rule pack engine. Loads RulePack from
//! sigil-rules-basic defaults + operator policy.yaml overlay and runs
//! Tier 1 DSL (path glob + JSON/TOML selector + matcher → AiGuardReason emit).

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
    if !matches!(pack.scope, sigil_core::policy::RulePackScope::UserGlobal) {
        tracing::warn!(
            id = %pack.id, scope = ?pack.scope,
            "rule_pack: Project scope not yet enabled; skipping"
        );
        return false;
    }
    if let Some(plats) = &pack.platforms {
        if !plats.is_empty() && !plats.contains(&sigil_core::policy::current_platform()) {
            return false;
        }
    }
    true
}
