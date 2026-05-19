//! Phase 3b.1 — AI Guard Risk Index.
//!
//! Reads AI coding-agent guard surfaces (Claude Code `~/.claude/`,
//! Codex `~/.codex/`), scores them against a rubric, and emits
//! `Evidence::AiGuardRiskAssessed` events on file change + on a 24h heartbeat.
//! Sigil measures, does not block.

pub mod ext_script;
pub mod parser;
pub mod rubric;
pub mod rule_pack;
pub mod task;
pub mod workspace_discovery;

pub use parser::claude_code::{ClaudeCodeParser, ClaudeCodeProjectParser};
pub use parser::claude_desktop::ClaudeDesktopParser;
pub use parser::codex::{CodexParser, CodexProjectParser};
pub use parser::continue_dev::{ContinueDevParser, ContinueDevProjectParser};
pub use rule_pack::parser::RulePackParser;
pub use task::{run, CachedAssessment, StateMap, TaskCtx};

/// Phase 3b.3 — shared registry mapping each parser's (tool, scope) to the
/// external hook-script paths it currently references. Populated by runtime
/// boot + policy_reload_task; read by `ai_guard::task::run` dispatcher to
/// route fsnotify events on script paths to the right parser.
pub type ExtScriptRegistry = std::sync::Arc<
    parking_lot::RwLock<
        std::collections::HashMap<
            (sigil_core::event::AiTool, sigil_core::event::AiGuardScope),
            Vec<std::path::PathBuf>,
        >,
    >,
>;

/// Construct an empty `ExtScriptRegistry`. Used by tests + runtime bootstrap.
pub fn empty_ext_script_registry() -> ExtScriptRegistry {
    std::sync::Arc::new(parking_lot::RwLock::new(std::collections::HashMap::new()))
}
