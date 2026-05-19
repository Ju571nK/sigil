//! Basic open-source detection rule defaults for Sigil.
//!
//! This crate ships the OSS baseline ruleset (file-watch targets) that the
//! agent uses when no operator policy is supplied. It is intentionally
//! minimal — extended/proprietary rule packs ship as separate crates or as
//! signed policy bundles delivered over the Phase 2 transport.
//!
//! See `LICENSING.md` at the repository root for the public-vs-commercial
//! split policy.

/// Compile-time-embedded YAML for the macOS basic ruleset.
pub const DEFAULTS_MACOS: &str = include_str!("defaults_macos.yaml");

/// Compile-time-embedded YAML for the Windows basic ruleset.
pub const DEFAULTS_WINDOWS: &str = include_str!("defaults_windows.yaml");

/// Compile-time-embedded YAML for the Linux basic ruleset.
pub const DEFAULTS_LINUX: &str = include_str!("defaults_linux.yaml");

/// Compile-time-embedded YAML for the Gemini CLI default rule pack
/// (Phase 3b.7). sigil-core's `defaults()` parses this into a `RulePack`
/// and includes it in the returned `PolicyDocument.rule_packs`.
pub const DEFAULT_RULE_PACK_GEMINI: &str =
    include_str!("default_rule_packs/gemini.yaml");

/// Compile-time-embedded YAML for the Cursor IDE default rule pack
/// (Phase 3b.7). Same handling as `DEFAULT_RULE_PACK_GEMINI`.
pub const DEFAULT_RULE_PACK_CURSOR: &str =
    include_str!("default_rule_packs/cursor.yaml");

/// All default rule packs for Phase 3b.7. Order matters only for stable
/// ordering in the merged PolicyDocument — the engine evaluates each
/// pack independently.
pub const DEFAULT_RULE_PACKS: &[&str] =
    &[DEFAULT_RULE_PACK_GEMINI, DEFAULT_RULE_PACK_CURSOR];

/// Returns the basic ruleset YAML for the current build target, or `None`
/// for platforms other than macOS / Windows / Linux (which have no built-in
/// baseline — an operator policy must be supplied there).
pub const fn defaults_for_current_os() -> Option<&'static str> {
    #[cfg(target_os = "macos")]
    {
        Some(DEFAULTS_MACOS)
    }
    #[cfg(target_os = "windows")]
    {
        Some(DEFAULTS_WINDOWS)
    }
    #[cfg(target_os = "linux")]
    {
        Some(DEFAULTS_LINUX)
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        None
    }
}
