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
