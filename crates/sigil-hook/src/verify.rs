//! tamper-evidence (#100): compare the recorded install baseline against the
//! live agent settings file. Pure (filesystem read only) — no IPC here.
use crate::install;
use serde::Deserialize;
use sigil_core::hook_proto::DriftKind;
use std::path::Path;

/// Subset of hook-registration-<agent>.json we compare against (serde ignores the rest).
#[derive(Deserialize, Debug, Clone)]
pub struct Baseline {
    #[allow(dead_code)] // used by the verify subcommand (agent dispatch)
    pub agent: String,
    pub settings_path: String,
    pub command: String,
    pub matcher: String,
    pub block_hash: String,
    #[serde(default)]
    pub fail_closed: Option<bool>,
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
    pub expected_fail_closed: Option<bool>,
    pub observed_fail_closed: Option<bool>,
}

/// Load the baseline, or None if absent/unreadable/malformed.
pub fn load_baseline(path: &Path) -> Option<Baseline> {
    let raw = std::fs::read(path).ok()?;
    serde_json::from_slice(&raw).ok()
}

fn absent(path: &str) -> DriftReport {
    DriftReport {
        kind: DriftKind::BaselineAbsent,
        settings_path: path.into(),
        expected_command_hash: String::new(),
        observed_command_hash: None,
        expected_matcher: None,
        observed_matcher: None,
        expected_fail_closed: None,
        observed_fail_closed: None,
    }
}

/// Full check: None when clean, Some(report) on any drift (incl. baseline_absent).
pub fn check(agent: &str) -> Option<DriftReport> {
    let Some(bp) = install::baseline_path(agent) else {
        return Some(absent(&format!("<unknown agent {agent}>")));
    };
    let Some(b) = load_baseline(&bp) else {
        return Some(absent(&bp.to_string_lossy()));
    };
    check_one(&b)
}

/// Compare one baseline against its live settings file. None = clean.
/// Dispatches by agent format: Cursor gets a 3-pass algorithm (missing > command > fail-mode);
/// Claude/codex use the NestedPreToolUse path (entry_missing -> command_drift -> matcher_drift).
pub fn check_one(b: &Baseline) -> Option<DriftReport> {
    match install::agent_format(&b.agent) {
        Some(install::HookFormat::Cursor) => check_one_cursor(b),
        _ => check_one_claude(b), // NestedPreToolUse (claude-code/codex) + unknown fall back
    }
}

/// Claude/codex path (verbatim original check_one logic).
/// Order: entry_missing -> command_drift -> matcher_drift.
fn check_one_claude(b: &Baseline) -> Option<DriftReport> {
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
            expected_fail_closed: None,
            observed_fail_closed: None,
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
            expected_fail_closed: None,
            observed_fail_closed: None,
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
            expected_fail_closed: None,
            observed_fail_closed: None,
        });
    }
    None // clean
}

/// Cursor path: 3-pass drift check.
/// Cursor writes our entry into BOTH `beforeShellExecution` and
/// `beforeMCPExecution`; both must be present and consistent, or an attacker
/// could strip coverage from one event. `failClosed` is a Cursor-native field
/// (gates whether a crashing hook blocks vs passes through) — absent from the
/// Claude/Codex format, which is why only this path checks it.
/// PASS 1 — entry missing in any event (highest priority)
/// PASS 2 — command hash differs in any event
/// PASS 3 — failClosed differs from baseline in any event
fn check_one_cursor(b: &Baseline) -> Option<DriftReport> {
    use install::{
        cursor_entry_command, cursor_entry_fail_closed, cursor_entry_is_ours, first_token,
        CURSOR_EVENTS,
    };
    let exe = first_token(&b.command).to_string();
    let root: serde_json::Value = std::fs::read(&b.settings_path)
        .ok()
        .and_then(|raw| serde_json::from_slice(&raw).ok())
        .unwrap_or(serde_json::Value::Null);
    let our = |ev: &str| -> Option<serde_json::Value> {
        root.get("hooks")
            .and_then(|h| h.get(ev))
            .and_then(|a| a.as_array())
            .and_then(|arr| arr.iter().find(|e| cursor_entry_is_ours(e, &exe)).cloned())
    };
    let entries: Vec<(&str, Option<serde_json::Value>)> =
        CURSOR_EVENTS.iter().map(|ev| (*ev, our(ev))).collect();

    // PASS 1 — any event missing our entry
    if entries.iter().any(|(_, e)| e.is_none()) {
        return Some(DriftReport {
            kind: DriftKind::EntryMissing,
            settings_path: b.settings_path.clone(),
            expected_command_hash: b.block_hash.clone(),
            observed_command_hash: None,
            expected_matcher: None,
            observed_matcher: None,
            expected_fail_closed: None,
            observed_fail_closed: None,
        });
    }
    // PASS 2 — any event's command hash differs
    for (_, e) in &entries {
        let v = e.as_ref().unwrap(); // guaranteed Some past PASS 1
                                     // cursor_entry_is_ours already matched on first_token(command), so command is present past PASS 1
        let cmd = cursor_entry_command(v).unwrap_or("");
        let observed = blake3::hash(cmd.as_bytes()).to_hex().to_string();
        if observed != b.block_hash {
            return Some(DriftReport {
                kind: DriftKind::CommandDrift,
                settings_path: b.settings_path.clone(),
                expected_command_hash: b.block_hash.clone(),
                observed_command_hash: Some(observed),
                expected_matcher: None,
                observed_matcher: None,
                expected_fail_closed: None,
                observed_fail_closed: None,
            });
        }
    }
    // PASS 3 — any event's failClosed differs from baseline
    let expected_fc = b.fail_closed.unwrap_or(false);
    for (_, e) in &entries {
        let v = e.as_ref().unwrap(); // guaranteed Some past PASS 1
        let observed_fc = cursor_entry_fail_closed(v);
        if observed_fc != expected_fc {
            return Some(DriftReport {
                kind: DriftKind::FailModeDrift,
                settings_path: b.settings_path.clone(),
                expected_command_hash: b.block_hash.clone(),
                observed_command_hash: None,
                expected_matcher: None,
                observed_matcher: None,
                expected_fail_closed: Some(expected_fc),
                observed_fail_closed: Some(observed_fc),
            });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::Path;

    fn baseline(dir: &Path, exe: &str, matcher: &str) -> Baseline {
        let cmd = format!("{exe} claude-code --capture redacted");
        Baseline {
            agent: "claude-code".into(),
            settings_path: dir.join("settings.json").to_string_lossy().into_owned(),
            command: cmd.clone(),
            matcher: matcher.into(),
            block_hash: blake3::hash(cmd.as_bytes()).to_hex().to_string(),
            fail_closed: None,
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
            fail_closed: None,
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
            fail_closed: None,
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

    // --- Cursor verify tests ---

    fn cursor_baseline(dir: &Path, fail_closed: bool) -> Baseline {
        let exe = "/usr/bin/sigil-hook";
        let cmd = format!(
            "{exe} cursor --enforce --on-failure {} --capture redacted",
            if fail_closed { "closed" } else { "open" }
        );
        Baseline {
            agent: "cursor".into(),
            settings_path: dir.join("hooks.json").to_string_lossy().into_owned(),
            command: cmd.clone(),
            matcher: "*".into(),
            fail_closed: Some(fail_closed),
            block_hash: blake3::hash(cmd.as_bytes()).to_hex().to_string(),
        }
    }

    fn write_cursor_settings(b: &Baseline, sh: &str, mcp: &str) {
        let json = format!(
            r#"{{"version":1,"hooks":{{"beforeShellExecution":[{sh}],"beforeMCPExecution":[{mcp}]}}}}"#
        );
        std::fs::write(&b.settings_path, json).unwrap();
    }

    #[test]
    fn cursor_clean() {
        let dir = tempfile::tempdir().unwrap();
        let b = cursor_baseline(dir.path(), true);
        let entry = format!(r#"{{"command":"{}","failClosed":true}}"#, b.command);
        write_cursor_settings(&b, &entry, &entry);
        assert_eq!(check_one(&b), None);
    }

    #[test]
    fn cursor_entry_missing_in_one_event() {
        let dir = tempfile::tempdir().unwrap();
        let b = cursor_baseline(dir.path(), true);
        let entry = format!(r#"{{"command":"{}","failClosed":true}}"#, b.command);
        write_cursor_settings(&b, &entry, ""); // mcp event empty → missing
        assert_eq!(check_one(&b).unwrap().kind, DriftKind::EntryMissing);
    }

    #[test]
    fn cursor_command_drift() {
        let dir = tempfile::tempdir().unwrap();
        let b = cursor_baseline(dir.path(), true);
        let tampered = format!(
            r#"{{"command":"{} --capture raw","failClosed":true}}"#,
            b.command
        );
        write_cursor_settings(&b, &tampered, &tampered);
        assert_eq!(check_one(&b).unwrap().kind, DriftKind::CommandDrift);
    }

    #[test]
    fn cursor_fail_mode_drift_when_failclosed_flipped() {
        let dir = tempfile::tempdir().unwrap();
        let b = cursor_baseline(dir.path(), true); // baseline expects failClosed=true
        let downgraded = format!(r#"{{"command":"{}","failClosed":false}}"#, b.command);
        write_cursor_settings(&b, &downgraded, &downgraded); // command intact, only failClosed flipped
        let r = check_one(&b).unwrap();
        assert_eq!(r.kind, DriftKind::FailModeDrift);
        assert_eq!(r.expected_fail_closed, Some(true));
        assert_eq!(r.observed_fail_closed, Some(false));
    }

    #[test]
    fn missing_precedence_beats_command() {
        let dir = tempfile::tempdir().unwrap();
        let b = cursor_baseline(dir.path(), true);
        let drifted = format!(
            r#"{{"command":"{} --capture raw","failClosed":true}}"#,
            b.command
        );
        write_cursor_settings(&b, &drifted, ""); // shell drifted, mcp missing → report EntryMissing
        assert_eq!(check_one(&b).unwrap().kind, DriftKind::EntryMissing);
    }
}
