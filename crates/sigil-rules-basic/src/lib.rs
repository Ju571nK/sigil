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

/// Returns the basic ruleset YAML for the current build target, or `None`
/// for platforms (e.g. Linux) that have no built-in baseline.
pub const fn defaults_for_current_os() -> Option<&'static str> {
    #[cfg(target_os = "macos")]
    {
        Some(DEFAULTS_MACOS)
    }
    #[cfg(target_os = "windows")]
    {
        Some(DEFAULTS_WINDOWS)
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        None
    }
}
