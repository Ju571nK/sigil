//! Phase 3b.1 — pure scoring + canonicalization. No I/O. No side effects.
//! Phase 3b.5 — `Rubric` struct introduced for operator-tunable weights.
//! The free `pub fn score()` is preserved as a back-compat shim that
//! delegates to `Rubric::defaults().score()` so existing callers (tests,
//! doctor static-fallback path) keep working unchanged.

use sigil_core::event::{AiGuardBucket, AiGuardReason};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::OnceLock;

/// CVSS-style cap.
const SCORE_MAX: f32 = 10.0;
/// Each additional occurrence of the same reason kind adds this fraction of
/// the base weight (the second is `+25%`, third `+50%`, etc.). Surcharge,
/// not discount — repeats make the score worse, not better.
const REPEAT_WEIGHT_STEP: f32 = 0.25;

/// `discriminant`-style key used for "same kind" grouping in the discount math.
fn kind_key(reason: &AiGuardReason) -> &'static str {
    match reason {
        AiGuardReason::DestructiveInInlineCommand { .. } => "destructive_in_inline_command",
        AiGuardReason::DestructiveInHookScript { .. } => "destructive_in_hook_script",
        AiGuardReason::SandboxDisabled => "sandbox_disabled",
        AiGuardReason::NoSandbox { .. } => "no_sandbox",
        AiGuardReason::PermissionsAllowBroad { .. } => "permissions_allow_broad",
        AiGuardReason::ExternalScriptUnscanned { .. } => "external_script_unscanned",
        AiGuardReason::BroadMatcher { hook_event, .. } if hook_event == "PreToolUse" => {
            "broad_matcher_pre_tool_use"
        }
        AiGuardReason::BroadMatcher { .. } => "broad_matcher_other",
        AiGuardReason::PermissionsDenyEmpty => "permissions_deny_empty",
        AiGuardReason::McpServerRemote { .. } => "mcp_server_remote",
        AiGuardReason::McpServerLocalCommand { .. } => "mcp_server_local_command",
    }
}

/// Phase 3b.5 — operator-tunable rubric. Holds the active weights and
/// metadata about which entries came from operator overrides. Built once
/// at boot and on each policy reload; consulted by the score() pipeline.
#[derive(Debug, Clone)]
pub struct Rubric {
    /// kind_key → weight. Keys are static strings owned by the rubric
    /// module (returned by `kind_key()`). Defaults populate all 11 known
    /// kinds; with_overrides() may replace values but never adds keys.
    pub weights: HashMap<&'static str, f32>,
    /// Subset of `weights` whose value came from an operator override
    /// (vs hardcoded default). Used by doctor to display `*` marker.
    pub overridden: HashSet<&'static str>,
    /// Snake_case keys the operator override referenced but didn't match
    /// any known kind. Surfaced by doctor as `[WARN] rubric override
    /// ignored — unknown reason kind: '...'`.
    pub unknown_override_keys: Vec<String>,
}

impl Rubric {
    /// Build the canonical hardcoded weights — single source of truth for
    /// defaults. Must match the historical `weight_for()` match arms for
    /// all 11 kinds.
    pub fn defaults() -> Self {
        let mut w: HashMap<&'static str, f32> = HashMap::new();
        w.insert("destructive_in_inline_command", 4.0);
        w.insert("destructive_in_hook_script", 4.0);
        w.insert("sandbox_disabled", 3.0);
        w.insert("no_sandbox", 2.0);
        w.insert("permissions_allow_broad", 2.0);
        w.insert("external_script_unscanned", 1.5);
        w.insert("broad_matcher_pre_tool_use", 1.5);
        w.insert("broad_matcher_other", 0.5);
        w.insert("permissions_deny_empty", 1.0);
        w.insert("mcp_server_remote", 1.0);
        w.insert("mcp_server_local_command", 0.5);
        Rubric {
            weights: w,
            overridden: HashSet::new(),
            unknown_override_keys: Vec::new(),
        }
    }

    /// Apply operator overrides. Known keys (preloaded by `defaults()`) get
    /// their weight replaced; the key is added to `overridden`. Unknown
    /// keys are logged via `tracing::warn!` and accumulated into
    /// `unknown_override_keys` (surfaced by doctor).
    pub fn with_overrides(mut self, overrides: &HashMap<String, f32>) -> Self {
        for (key, weight) in overrides {
            let matched: Option<&'static str> =
                self.weights.keys().copied().find(|k| *k == key.as_str());
            match matched {
                Some(static_key) => {
                    self.weights.insert(static_key, *weight);
                    self.overridden.insert(static_key);
                }
                None => {
                    tracing::warn!(
                        key = %key,
                        weight = %weight,
                        "rubric override: unknown reason kind, ignoring"
                    );
                    self.unknown_override_keys.push(key.clone());
                }
            }
        }
        self
    }

    /// Weight for one occurrence of `reason`. Delegates to the existing
    /// free `kind_key()` to determine the lookup key. Returns 0.0 (with a
    /// `debug_assert!` for visibility in debug builds) if the kind is
    /// unknown — defensive fallback so a future AiGuardReason variant
    /// added without updating `Rubric::defaults()` doesn't panic in
    /// release.
    pub fn weight_for(&self, reason: &AiGuardReason) -> f32 {
        let key = kind_key(reason);
        match self.weights.get(key).copied() {
            Some(w) => w,
            None => {
                debug_assert!(false, "Rubric::weight_for: unknown kind_key '{key}'");
                0.0
            }
        }
    }

    /// Total score for a reason set. Mirrors the existing free `score()`
    /// math exactly: per-kind grouping, first occurrence at full weight,
    /// each repeat at +REPEAT_WEIGHT_STEP*i surcharge, sum across kinds,
    /// clamp to [0.0, SCORE_MAX].
    pub fn score(&self, reasons: &[AiGuardReason]) -> f32 {
        let mut by_kind: BTreeMap<&'static str, Vec<&AiGuardReason>> = BTreeMap::new();
        for r in reasons {
            by_kind.entry(kind_key(r)).or_default().push(r);
        }
        let mut total = 0.0_f32;
        for (_kind, group) in by_kind {
            let base = self.weight_for(group[0]);
            for (i, _r) in group.iter().enumerate() {
                total += base * (1.0 + REPEAT_WEIGHT_STEP * (i as f32));
            }
        }
        total.min(SCORE_MAX)
    }
}

/// Back-compat shim — Phase 3b.5 introduced `Rubric` for tunable weights.
/// Callers without access to a `RubricHandle` (e.g., tests, doctor's static
/// fallback) keep this entry point. Live agent code uses
/// `ctx.rubric.read().score(reasons)` via the handle.
pub fn score(reasons: &[AiGuardReason]) -> f32 {
    Rubric::defaults().score(reasons)
}

/// Map a score to its bucket per spec thresholds.
pub fn bucket(score: f32) -> AiGuardBucket {
    if score < 1.0 {
        AiGuardBucket::Low
    } else if score < 4.0 {
        AiGuardBucket::Medium
    } else if score < 7.0 {
        AiGuardBucket::High
    } else {
        AiGuardBucket::Critical
    }
}

/// Hardcoded destructive patterns. False positive cost is low (we don't block).
const DESTRUCTIVE_PATTERNS: &[&str] = &[
    r"rm\s+-[rR][fF]\s+/(?:[^*]|$)",
    r"rm\s+-[rR][fF]\s+~",
    r"rm\s+-[rR][fF]\s+\$HOME",
    r"dd\s+if=",
    r"mkfs\.\w+",
    r":\(\)\s*\{\s*:\|:&\s*\}",
    r"\bcurl\b[^|]*\|\s*(?:ba)?sh\b",
    r"\bwget\b[^|]*\|\s*(?:ba)?sh\b",
    r"chmod\s+-?R?\s*[0-7]*7[0-7]{0,2}\s+/",
    r"shutdown\s+(-h|-r)",
    r"\breboot\b",
];

fn compiled() -> &'static Vec<regex::Regex> {
    static CELL: OnceLock<Vec<regex::Regex>> = OnceLock::new();
    CELL.get_or_init(|| {
        DESTRUCTIVE_PATTERNS
            .iter()
            .map(|p| regex::Regex::new(p).expect("baseline destructive pattern compiles"))
            .collect()
    })
}

/// True iff `cmd` matches any baseline destructive pattern.
pub fn is_destructive(cmd: &str) -> bool {
    compiled().iter().any(|re| re.is_match(cmd))
}

/// Returns the first destructive pattern (regex source) that matches `cmd`,
/// for inclusion in the emitted `AiGuardReason`.
pub fn first_destructive_pattern(cmd: &str) -> Option<&'static str> {
    for (i, re) in compiled().iter().enumerate() {
        if re.is_match(cmd) {
            return Some(DESTRUCTIVE_PATTERNS[i]);
        }
    }
    None
}

/// Deterministic hash of a reason set for change detection. Two permutations
/// of the same reasons produce the same hash; any field difference (or kind
/// difference) produces a different hash.
///
/// Definition (spec §canonical_hash):
/// 1. For each reason, build a `(kind_str, payload_json)` tuple where
///    `kind_str` is the snake_case discriminant and `payload_json` is the
///    full serde_json serialization (which includes the kind tag plus all
///    fields, in field-declaration order — stable per build).
/// 2. Sort the tuples lexicographically by `(kind_str, payload_json)`.
/// 3. Serialize the sorted Vec to a JSON string.
/// 4. Hash the string with blake3 → 32-byte digest.
pub fn canonical_hash(reasons: &[AiGuardReason]) -> [u8; 32] {
    let mut tuples: Vec<(String, String)> = reasons
        .iter()
        .map(|r| {
            let kind = kind_key(r).to_string();
            let payload = serde_json::to_string(r).expect("AiGuardReason is Serialize");
            (kind, payload)
        })
        .collect();
    tuples.sort();
    let canonical = serde_json::to_string(&tuples).expect("Vec<(String,String)> is Serialize");
    *blake3::hash(canonical.as_bytes()).as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigil_core::event::AiGuardReason;
    use std::path::PathBuf;

    #[test]
    fn destructive_inline_command_weighs_4_0() {
        let reasons = vec![AiGuardReason::DestructiveInInlineCommand {
            pattern: "rm -rf".into(),
            hook_event: "PreToolUse".into(),
            snippet: "rm -rf /".into(),
        }];
        assert_eq!(score(&reasons), 4.0);
    }

    #[test]
    fn no_sandbox_weighs_2_0() {
        let reasons = vec![AiGuardReason::NoSandbox {
            executor: "host_shell".into(),
        }];
        assert_eq!(score(&reasons), 2.0);
    }

    #[test]
    fn sandbox_disabled_weighs_3_0() {
        let reasons = vec![AiGuardReason::SandboxDisabled];
        assert_eq!(score(&reasons), 3.0);
    }

    #[test]
    fn pre_tool_use_broad_matcher_weighs_1_5_other_events_0_5() {
        let pre = vec![AiGuardReason::BroadMatcher {
            hook_event: "PreToolUse".into(),
            matcher: ".*".into(),
        }];
        let stop = vec![AiGuardReason::BroadMatcher {
            hook_event: "Stop".into(),
            matcher: ".*".into(),
        }];
        assert_eq!(score(&pre), 1.5);
        assert_eq!(score(&stop), 0.5);
    }

    #[test]
    fn two_destructive_inline_second_occurrence_scores_higher() {
        let reasons = vec![
            AiGuardReason::DestructiveInInlineCommand {
                pattern: "rm -rf".into(),
                hook_event: "PreToolUse".into(),
                snippet: "rm -rf /a".into(),
            },
            AiGuardReason::DestructiveInInlineCommand {
                pattern: "rm -rf".into(),
                hook_event: "PreToolUse".into(),
                snippet: "rm -rf /b".into(),
            },
        ];
        // 4.0 + 4.0 * 1.25 = 9.0
        assert_eq!(score(&reasons), 9.0);
    }

    #[test]
    fn worked_example_from_spec_clamps_to_10() {
        let reasons = vec![
            AiGuardReason::DestructiveInInlineCommand {
                pattern: "rm -rf".into(),
                hook_event: "PreToolUse".into(),
                snippet: "rm -rf /tmp/sigil-test/* && exit 0".into(),
            },
            AiGuardReason::NoSandbox {
                executor: "host_shell".into(),
            },
            AiGuardReason::BroadMatcher {
                hook_event: "PreToolUse".into(),
                matcher: ".*".into(),
            },
            AiGuardReason::PermissionsAllowBroad {
                rule: "Bash:.*".into(),
            },
            AiGuardReason::PermissionsDenyEmpty,
        ];
        // 4.0 + 2.0 + 1.5 + 2.0 + 1.0 = 10.5 → clamp 10.0
        assert_eq!(score(&reasons), 10.0);
    }

    #[test]
    fn empty_reasons_score_zero_bucket_low() {
        assert_eq!(score(&[]), 0.0);
        assert_eq!(bucket(0.0), sigil_core::event::AiGuardBucket::Low);
    }

    #[test]
    fn bucket_thresholds_match_spec() {
        use sigil_core::event::AiGuardBucket::*;
        assert_eq!(bucket(0.0), Low);
        assert_eq!(bucket(0.99), Low);
        assert_eq!(bucket(1.0), Medium);
        assert_eq!(bucket(3.99), Medium);
        assert_eq!(bucket(4.0), High);
        assert_eq!(bucket(6.99), High);
        assert_eq!(bucket(7.0), Critical);
        assert_eq!(bucket(10.0), Critical);
    }

    #[test]
    fn destructive_pattern_matches_rm_rf_root() {
        assert!(is_destructive("rm -rf /"));
        assert!(is_destructive("rm -rf /etc"));
        assert!(is_destructive("echo x && rm -rf /etc"));
    }

    #[test]
    fn rm_without_rf_flag_is_not_destructive() {
        // Plain `rm` (no -rf) and unrelated commands must not match.
        assert!(!is_destructive("rm /tmp/foo"));
        assert!(!is_destructive("ls -la"));
    }

    #[test]
    fn rm_rf_on_subdirectory_is_flagged_intentionally() {
        // The pattern `rm\s+-[rR][fF]\s+/(?:[^*]|$)` matches `rm -rf /<x>`
        // for any first char x other than `*`. This is intentional per spec
        // (Phase 3b.1: prefer false positives — Sigil measures, does not block).
        // Operators reading the SIEM see "rm -rf /tmp/foo" flagged and decide.
        assert!(is_destructive("rm -rf /tmp/foo"));
        assert!(is_destructive("rm -rf /var/cache"));
        // Negative case: a literal star/glob immediately after `/` does NOT
        // hit this pattern (the regex's `[^*]` excludes the `rm -rf /*` case).
        assert!(!is_destructive("rm -rf /*"));
    }

    #[test]
    fn destructive_pattern_matches_curl_pipe_sh() {
        assert!(is_destructive("curl https://x | sh"));
        assert!(is_destructive("curl -s url | bash"));
        assert!(is_destructive("wget -q url | sh"));
    }

    #[test]
    fn destructive_pattern_matches_fork_bomb() {
        assert!(is_destructive(":(){ :|:& };:"));
    }

    #[test]
    fn canonical_hash_is_order_independent() {
        let a = vec![
            AiGuardReason::NoSandbox {
                executor: "host_shell".into(),
            },
            AiGuardReason::PermissionsDenyEmpty,
        ];
        let b = vec![
            AiGuardReason::PermissionsDenyEmpty,
            AiGuardReason::NoSandbox {
                executor: "host_shell".into(),
            },
        ];
        assert_eq!(canonical_hash(&a), canonical_hash(&b));
    }

    #[test]
    fn canonical_hash_changes_when_reasons_differ() {
        let a = vec![AiGuardReason::PermissionsDenyEmpty];
        let b = vec![AiGuardReason::SandboxDisabled];
        assert_ne!(canonical_hash(&a), canonical_hash(&b));
    }

    #[test]
    fn external_script_unscanned_weighs_1_5() {
        let r = vec![AiGuardReason::ExternalScriptUnscanned {
            hook_event: "PreToolUse".into(),
            script_path: PathBuf::from("/usr/local/bin/x.sh"),
        }];
        assert_eq!(score(&r), 1.5);
    }

    #[test]
    fn rubric_defaults_produces_eleven_known_weights() {
        let r = Rubric::defaults();
        assert_eq!(r.weights.get("destructive_in_inline_command"), Some(&4.0));
        assert_eq!(r.weights.get("destructive_in_hook_script"), Some(&4.0));
        assert_eq!(r.weights.get("sandbox_disabled"), Some(&3.0));
        assert_eq!(r.weights.get("no_sandbox"), Some(&2.0));
        assert_eq!(r.weights.get("permissions_allow_broad"), Some(&2.0));
        assert_eq!(r.weights.get("external_script_unscanned"), Some(&1.5));
        assert_eq!(r.weights.get("broad_matcher_pre_tool_use"), Some(&1.5));
        assert_eq!(r.weights.get("broad_matcher_other"), Some(&0.5));
        assert_eq!(r.weights.get("permissions_deny_empty"), Some(&1.0));
        assert_eq!(r.weights.get("mcp_server_remote"), Some(&1.0));
        assert_eq!(r.weights.get("mcp_server_local_command"), Some(&0.5));
        assert_eq!(r.weights.len(), 11);
    }

    #[test]
    fn rubric_with_overrides_replaces_known_keys() {
        let mut overrides = std::collections::HashMap::new();
        overrides.insert("destructive_in_hook_script".to_string(), 5.5);
        overrides.insert("broad_matcher_other".to_string(), 0.0);
        let r = Rubric::defaults().with_overrides(&overrides);
        assert_eq!(r.weights.get("destructive_in_hook_script"), Some(&5.5));
        assert_eq!(r.weights.get("broad_matcher_other"), Some(&0.0));
        assert!(r.overridden.contains("destructive_in_hook_script"));
        assert!(r.overridden.contains("broad_matcher_other"));
        assert!(r.unknown_override_keys.is_empty());
    }

    #[test]
    fn rubric_with_overrides_records_unknown_keys() {
        let mut overrides = std::collections::HashMap::new();
        overrides.insert("unknown_key_test".to_string(), 3.0);
        overrides.insert("destructive_in_hook_script".to_string(), 5.0);
        let r = Rubric::defaults().with_overrides(&overrides);
        assert_eq!(r.weights.get("destructive_in_hook_script"), Some(&5.0));
        assert_eq!(
            r.unknown_override_keys,
            vec!["unknown_key_test".to_string()]
        );
    }

    #[test]
    fn rubric_with_overrides_empty_map_no_change() {
        let r = Rubric::defaults().with_overrides(&std::collections::HashMap::new());
        assert_eq!(r.weights, Rubric::defaults().weights);
        assert!(r.overridden.is_empty());
        assert!(r.unknown_override_keys.is_empty());
    }

    #[test]
    fn rubric_score_matches_free_score_for_defaults() {
        let reasons = vec![
            AiGuardReason::DestructiveInInlineCommand {
                pattern: "rm -rf".into(),
                hook_event: "PreToolUse".into(),
                snippet: "rm -rf /tmp".into(),
            },
            AiGuardReason::SandboxDisabled,
        ];
        assert_eq!(Rubric::defaults().score(&reasons), score(&reasons));
    }

    #[test]
    fn rubric_score_with_override_changes_result() {
        let mut overrides = std::collections::HashMap::new();
        overrides.insert("destructive_in_hook_script".to_string(), 0.0);
        let r = Rubric::defaults().with_overrides(&overrides);
        let reasons = vec![AiGuardReason::DestructiveInHookScript {
            pattern: "rm -rf".into(),
            hook_event: "PreToolUse".into(),
            script_path: std::path::PathBuf::from("/tmp/h.sh"),
            snippet: "rm -rf /tmp".into(),
            source_chain: Vec::new(),
        }];
        assert_eq!(r.score(&reasons), 0.0);
    }

    #[test]
    fn rubric_weight_for_unknown_kind_returns_zero() {
        // Defensive: build a Rubric with an empty weights map and assert
        // weight_for returns 0.0 (with debug_assert! firing in debug mode,
        // but this test runs in release config too — the assertion is
        // skipped in release, the 0.0 fallback still applies).
        //
        // We can't easily test debug_assert separately, so we just check
        // the fallback value here.
        let r = Rubric {
            weights: std::collections::HashMap::new(),
            overridden: std::collections::HashSet::new(),
            unknown_override_keys: vec![],
        };
        // Use a real variant so we don't have to construct anything weird —
        // an empty weights map means kind_key() will return a string that
        // isn't in r.weights, so weight_for returns 0.0.
        // In a debug build the debug_assert will fire BEFORE returning 0.0,
        // which fails the test. Wrap in std::panic::catch_unwind so the
        // test passes in both debug and release builds.
        let reason = AiGuardReason::SandboxDisabled;
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| r.weight_for(&reason)));
        match result {
            Ok(w) => assert_eq!(
                w, 0.0,
                "release build: weight_for returns 0.0 for unknown kind"
            ),
            Err(_) => {
                // Debug build: debug_assert! panicked. That's expected behavior.
            }
        }
    }
}
