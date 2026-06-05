//! tamper-evidence (#100): compare the recorded install baseline against the
//! live agent settings file. Pure (filesystem read only) — no IPC here.
use crate::install;
use serde::Deserialize;
use sigil_core::hook_proto::DriftKind;
use std::path::{Path, PathBuf};

/// Subset of hook-registration.json we compare against (serde ignores the rest).
#[derive(Deserialize, Debug, Clone)]
pub struct Baseline {
    #[allow(dead_code)] // used by the verify subcommand (Task 5)
    pub agent: String,
    pub settings_path: String,
    pub command: String,
    pub matcher: String,
    pub block_hash: String,
}

/// A detected drift. `None` from `check()`/`check_one()` means clean.
#[derive(Debug, Clone, PartialEq)]
pub struct DriftReport {
    pub kind: DriftKind,
    pub settings_path: String,
    pub expected_command_hash: String,
    pub observed_command_hash: Option<String>,
    pub expected_matcher: Option<String>,
    pub observed_matcher: Option<String>,
}

fn baseline_path() -> PathBuf {
    install::state_dir().join("hook-registration.json")
}

/// Load the baseline, or None if absent/unreadable/malformed.
// used by the verify subcommand (Task 5)
#[allow(dead_code)]
pub fn load_baseline(path: &Path) -> Option<Baseline> {
    let raw = std::fs::read(path).ok()?;
    serde_json::from_slice(&raw).ok()
}

/// Full check: None when clean, Some(report) on any drift (incl. baseline_absent).
pub fn check() -> Option<DriftReport> {
    let bp = baseline_path();
    let Some(b) = load_baseline(&bp) else {
        return Some(DriftReport {
            kind: DriftKind::BaselineAbsent,
            settings_path: bp.to_string_lossy().into_owned(),
            expected_command_hash: String::new(),
            observed_command_hash: None,
            expected_matcher: None,
            observed_matcher: None,
        });
    };
    check_one(&b)
}

/// Compare one baseline against its live settings file. None = clean.
/// Order: entry_missing -> command_drift -> matcher_drift.
pub fn check_one(b: &Baseline) -> Option<DriftReport> {
    let exe = install::first_token(&b.command).to_string();
    let root: serde_json::Value = std::fs::read(&b.settings_path)
        .ok()
        .and_then(|raw| serde_json::from_slice(&raw).ok())
        // treat both an absent and a corrupt settings file as "entry not present" —
        // the sigil entry simply can't be found, yielding EntryMissing.
        .unwrap_or(serde_json::Value::Null);
    let entry = root
        .get("hooks")
        .and_then(|h| h.get("PreToolUse"))
        .and_then(|p| p.as_array())
        .and_then(|arr| arr.iter().find(|e| install::claude_entry_is_ours(e, &exe)));

    let Some(entry) = entry else {
        return Some(DriftReport {
            kind: DriftKind::EntryMissing,
            settings_path: b.settings_path.clone(),
            expected_command_hash: b.block_hash.clone(),
            observed_command_hash: None,
            expected_matcher: Some(b.matcher.clone()),
            observed_matcher: None,
        });
    };

    // block_hash was written as blake3(full command string); claude_entry_cmd
    // returns that same inner command, so the hashes line up.
    let live_cmd = install::claude_entry_cmd(entry).unwrap_or("");
    let observed_hash = blake3::hash(live_cmd.as_bytes()).to_hex().to_string();
    let observed_matcher = entry
        .get("matcher")
        .and_then(|m| m.as_str())
        .map(String::from);

    // note: a change to the binary PATH makes claude_entry_is_ours not match →
    // EntryMissing, not CommandDrift; CommandDrift covers arg/flag-level changes
    // to the same exe.
    if observed_hash != b.block_hash {
        return Some(DriftReport {
            kind: DriftKind::CommandDrift,
            settings_path: b.settings_path.clone(),
            expected_command_hash: b.block_hash.clone(),
            observed_command_hash: Some(observed_hash),
            expected_matcher: Some(b.matcher.clone()),
            observed_matcher,
        });
    }
    if observed_matcher.as_deref() != Some(b.matcher.as_str()) {
        return Some(DriftReport {
            kind: DriftKind::MatcherDrift,
            settings_path: b.settings_path.clone(),
            expected_command_hash: b.block_hash.clone(),
            observed_command_hash: Some(observed_hash),
            expected_matcher: Some(b.matcher.clone()),
            observed_matcher,
        });
    }
    None // clean
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn baseline(dir: &Path, exe: &str, matcher: &str) -> Baseline {
        let cmd = format!("{exe} claude-code --capture redacted");
        Baseline {
            agent: "claude-code".into(),
            settings_path: dir.join("settings.json").to_string_lossy().into_owned(),
            command: cmd.clone(),
            matcher: matcher.into(),
            block_hash: blake3::hash(cmd.as_bytes()).to_hex().to_string(),
        }
    }
    fn write_settings(b: &Baseline, json: &str) {
        let mut f = std::fs::File::create(&b.settings_path).unwrap();
        f.write_all(json.as_bytes()).unwrap();
    }

    #[test]
    fn clean_when_settings_match_baseline() {
        let dir = tempfile::tempdir().unwrap();
        let b = baseline(dir.path(), "/usr/bin/sigil-hook", "*");
        write_settings(
            &b,
            r#"{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"/usr/bin/sigil-hook claude-code --capture redacted"}]}]}}"#,
        );
        assert_eq!(check_one(&b), None);
    }

    #[test]
    fn entry_missing_when_no_sigil_entry() {
        let dir = tempfile::tempdir().unwrap();
        let b = baseline(dir.path(), "/usr/bin/sigil-hook", "*");
        write_settings(
            &b,
            r#"{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"/other/tool run"}]}]}}"#,
        );
        assert_eq!(check_one(&b).unwrap().kind, DriftKind::EntryMissing);
    }

    #[test]
    fn command_drift_when_command_changed() {
        let dir = tempfile::tempdir().unwrap();
        let b = baseline(dir.path(), "/usr/bin/sigil-hook", "*");
        write_settings(
            &b,
            r#"{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"/usr/bin/sigil-hook claude-code --capture raw"}]}]}}"#,
        );
        assert_eq!(check_one(&b).unwrap().kind, DriftKind::CommandDrift);
    }

    #[test]
    fn matcher_drift_when_matcher_narrowed() {
        let dir = tempfile::tempdir().unwrap();
        let b = baseline(dir.path(), "/usr/bin/sigil-hook", "*");
        write_settings(
            &b,
            r#"{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"/usr/bin/sigil-hook claude-code --capture redacted"}]}]}}"#,
        );
        let r = check_one(&b).unwrap();
        assert_eq!(r.kind, DriftKind::MatcherDrift);
        assert_eq!(r.observed_matcher.as_deref(), Some("Bash"));
    }

    #[test]
    fn entry_missing_when_settings_file_absent() {
        let dir = tempfile::tempdir().unwrap();
        let b = baseline(dir.path(), "/usr/bin/sigil-hook", "*"); // settings.json never written
        assert_eq!(check_one(&b).unwrap().kind, DriftKind::EntryMissing);
    }

    #[test]
    fn baseline_absent_when_no_baseline() {
        assert!(load_baseline(Path::new("/nonexistent/hook-registration.json")).is_none());
    }

    // --- enforce-install baseline tests (#100 regression) ---

    /// An enforce-mode baseline is clean when the settings file contains the
    /// exact enforce command string that was written at install time.
    #[test]
    fn clean_for_enforce_install_baseline() {
        let dir = tempfile::tempdir().unwrap();
        let exe = "/usr/bin/sigil-hook";
        let enforce_cmd =
            format!("{exe} claude-code --enforce --on-failure open --capture redacted");
        let b = Baseline {
            agent: "claude-code".into(),
            settings_path: dir
                .path()
                .join("settings.json")
                .to_string_lossy()
                .into_owned(),
            command: enforce_cmd.clone(),
            matcher: "*".into(),
            block_hash: blake3::hash(enforce_cmd.as_bytes()).to_hex().to_string(),
        };
        // Settings registered WITH the enforce command => clean (no drift).
        let mut f = std::fs::File::create(&b.settings_path).unwrap();
        write!(
            f,
            r#"{{"hooks":{{"PreToolUse":[{{"matcher":"*","hooks":[{{"type":"command","command":"{enforce_cmd}"}}]}}]}}}}"#
        )
        .unwrap();
        assert_eq!(
            check_one(&b),
            None,
            "enforce baseline must be clean against matching settings"
        );
    }

    /// An enforce-mode baseline detects drift when the settings file contains
    /// only the observe command (the bug this fix addresses: verify spuriously
    /// reported command_drift right after 'install --enforce --write').
    #[test]
    fn command_drift_when_observe_command_in_enforce_baseline() {
        let dir = tempfile::tempdir().unwrap();
        let exe = "/usr/bin/sigil-hook";
        let enforce_cmd =
            format!("{exe} claude-code --enforce --on-failure open --capture redacted");
        let observe_cmd = format!("{exe} claude-code --capture redacted");
        let b = Baseline {
            agent: "claude-code".into(),
            settings_path: dir
                .path()
                .join("settings.json")
                .to_string_lossy()
                .into_owned(),
            command: enforce_cmd.clone(),
            matcher: "*".into(),
            block_hash: blake3::hash(enforce_cmd.as_bytes()).to_hex().to_string(),
        };
        // Settings registered with the OBSERVE command while baseline expects ENFORCE
        // => command_drift (this is the genuine tamper signal, not a false positive).
        let mut f = std::fs::File::create(&b.settings_path).unwrap();
        write!(
            f,
            r#"{{"hooks":{{"PreToolUse":[{{"matcher":"*","hooks":[{{"type":"command","command":"{observe_cmd}"}}]}}]}}}}"#
        )
        .unwrap();
        let report = check_one(&b).expect("should detect drift");
        assert_eq!(
            report.kind,
            DriftKind::CommandDrift,
            "downgrade from enforce to observe command must be reported as command_drift"
        );
    }
}
