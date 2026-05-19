//! Phase 3b.1 — per-tool parser trait. Each implementation reads a single
//! tool's user-global config and returns the assessed reasons.

pub mod claude_code;
pub mod claude_desktop;
pub mod codex;
pub mod continue_dev;

use sigil_core::event::{AiGuardReason, AiGuardScope, AiTool};
use std::io;
use std::path::{Path, PathBuf};

/// Per-tool guard-surface reader.
pub trait AiGuardParser: Send + Sync {
    /// Returns the tool identity this parser covers. Used by `ai_guard_task`
    /// to dispatch file_change events to the right parser and to tag the
    /// emitted `AiGuardRiskAssessed` events.
    fn tool(&self) -> AiTool;

    /// Returns the scope to tag emitted events with. CLI parsers (claude_code,
    /// codex) return `UserGlobal`; application-form parsers return
    /// `Application{app:"..."}`. Phase 3b.6.
    fn scope(&self) -> AiGuardScope;

    /// Path globs (canonical/expanded) the parser cares about. Used by
    /// `ai_guard_task` to decide whether an incoming file_change belongs to
    /// this parser.
    fn watched_paths(&self, home_dir: &Path) -> Vec<PathBuf>;

    /// Read current state from disk and return reasons. Empty Vec = clean.
    /// Missing primary config file = empty Vec (operator hasn't enabled the
    /// tool — not a finding). I/O / parse errors bubble up.
    fn assess(&self, home_dir: &Path) -> Result<Vec<AiGuardReason>, AssessError>;

    /// Phase 3b.7 — downcast hook for hot-reload reconciliation. Default
    /// returns a static unit reference; only RulePackParser overrides to
    /// return `self` so policy_reload_task can identify rule pack parsers
    /// and reconcile them by id. Existing hardcoded parsers don't need
    /// downcasting (they're identified structurally by tool+scope).
    fn as_any(&self) -> &dyn std::any::Any {
        &()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AssessError {
    #[error("read {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("parse {path}: {message}")]
    Parse { path: PathBuf, message: String },
}
