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

/// Default rule packs embedded at compile time.
///
/// Phase 3b.8: the Gemini and Cursor built-in packs have been retired here
/// because the hardcoded parsers added in 3b.8 cover the same
/// `(tool, UserGlobal)` identity and would double-emit. The declarative
/// rule-pack ENGINE remains intact — operators can still ship their own packs
/// via signed policy overlay.
pub const DEFAULT_RULE_PACKS: &[&str] = &[];

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
