//! Boot-equivalent cold policy loader (#149).
//!
//! `load_effective_policy` builds the same `(Rubric, DenyEvaluator,
//! enforce_bucket)` triple the running agent has at boot — **including** the
//! rule-pack bundle layer (`rule-packs.yaml`).  Callers (e.g. the `assess`
//! CLI subcommand) can use this without starting a daemon.
//!
//! ## Merge order
//! `defaults < policy.yaml < rule-packs.yaml(bundle)`
//!
//! ## Error semantics
//! Unlike the live `reload()` path, which is fail-open (keep previous state
//! on any error), this function is **fail-loud**: any parse/merge/regex error
//! returns `Err`.  A cold caller has no "previous state" to fall back to.

use crate::ai_guard::rubric::Rubric;
use crate::hook_deny::DenyEvaluator;
use sigil_core::event::AiGuardBucket;
use sigil_core::policy::{current_platform, defaults, merge, validate_deny_rule_ids};
use std::path::Path;

/// Build `(Rubric, DenyEvaluator, enforce_bucket)` from disk — cold, no daemon.
///
/// # Bundle layer
/// `rule_packs_path` is read with the same [`read_bundle_state`] helper used
/// by the live reload task:
/// - `Absent` → no bundle (same as agent boot when file is missing).
/// - `Present` → merged as 3rd layer.
/// - `Empty` → no bundle (matches the daemon: empty rule-packs.yaml is tolerated).
/// - `Corrupt` → returns `Err` (parse failed; a cold load has no last-good state).
///
/// # enforce_bucket
/// `EffectivePolicy` has no dedicated enforce-threshold field today.  The
/// constant `AiGuardBucket::High` is used, matching the hardcoded default
/// in `AssessCtx` documentation.  When a policy field is added later, update
/// this function to read it.
///
/// # Errors
/// Returns `Err` on:
/// - malformed `policy.yaml` or `rule-packs.yaml`
/// - `defaults()` failure
/// - `merge()` failure
/// - `validate_deny_rule_ids` failure
/// - any regex compile error in `hook_deny_rules`
pub fn load_effective_policy(
    policy_path: &Path,
    rule_packs_path: &Path,
) -> anyhow::Result<(Rubric, DenyEvaluator, AiGuardBucket)> {
    // ── 1. Parse policy.yaml (optional — absent file → None) ─────────────────
    let user_doc = if policy_path.exists() {
        let yaml = std::fs::read_to_string(policy_path)
            .map_err(|e| anyhow::anyhow!("policy.yaml read failed: {e}"))?;
        Some(
            sigil_core::policy::parse(&yaml)
                .map_err(|e| anyhow::anyhow!("policy.yaml parse failed: {e}"))?,
        )
    } else {
        None
    };

    // ── 2. Read the rule-pack bundle ─────────────────────────────────────────
    // Match the daemon's tolerance so a cold `sigil assess` agrees with a running
    // agent: boot/reload treat an empty (zero-byte / whitespace) rule-packs.yaml
    // as "no bundle" (Absent at boot, retain-last-good on live reload — #135), not
    // a hard error. A benign empty file (a `touch`, or a `cp` truncation window)
    // must NOT make assess exit 1. Only a genuinely Corrupt (parse-failed) file is
    // fail-loud, since a cold load has no last-good to fall back to.
    use crate::policy_reload_task::{read_bundle_state, BundleState};
    let bundle_doc = match read_bundle_state(rule_packs_path) {
        BundleState::Present(d) => Some(*d),
        BundleState::Absent | BundleState::Empty => None,
        BundleState::Corrupt => {
            return Err(anyhow::anyhow!(
                "rule-packs.yaml is corrupt (read/parse failed); cold load cannot continue"
            ))
        }
    };

    // ── 3. Merge: defaults < policy.yaml < bundle ─────────────────────────────
    let effective = merge(defaults()?, user_doc, bundle_doc, current_platform())
        .map_err(|e| anyhow::anyhow!("policy merge failed: {e}"))?;

    // ── 4. Build Rubric from rubric_overrides ─────────────────────────────────
    let rubric = Rubric::defaults().with_overrides(&effective.rubric_overrides);

    // ── 5. Build DenyEvaluator — fail-loud on id validation or regex error ────
    validate_deny_rule_ids(&effective.hook_deny_rules)
        .map_err(|e| anyhow::anyhow!("hook_deny_rules id validation failed: {e}"))?;
    let deny_evaluator = DenyEvaluator::new(&effective.hook_deny_rules)
        .map_err(|e| anyhow::anyhow!("hook_deny_rules regex compile failed: {e}"))?;

    // ── 6. enforce_bucket — no dedicated policy field today; default High ─────
    // When EffectivePolicy gains an enforce_threshold field, replace this line
    // with: effective.enforce_threshold.unwrap_or(AiGuardBucket::High)
    let enforce_bucket = AiGuardBucket::High;

    Ok((rubric, deny_evaluator, enforce_bucket))
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    /// Minimal policy.yaml content with one custom target so merge() doesn't
    /// emit EmptyTargets (defaults' targets are filtered to the current platform
    /// in tests, which is fine, but we add one to be explicit).
    fn minimal_policy() -> &'static str {
        "version: 1\ntargets:\n  - id: test-target\n    description: test\n    tier: standard\n    platform: any\n    paths:\n      - '/tmp/test'\n    recursive: false\n    follow_symlinks: false\n"
    }

    /// A rule-packs.yaml carrying a `hook_deny_rules` entry.  The rule denies
    /// any Bash command equal to `__sigil_test_deny__`.
    fn bundle_with_deny_rule() -> &'static str {
        "version: 1\ntargets:\n  - id: bundle-target\n    description: bundle\n    tier: standard\n    platform: any\n    paths:\n      - '/tmp/bundle'\n    recursive: false\n    follow_symlinks: false\nhook_deny_rules:\n  - id: deny-test-marker\n    match:\n      kind: bash\n      command:\n        kind: equals\n        value: __sigil_test_deny__\n"
    }

    // ── TDD test 1 ────────────────────────────────────────────────────────────
    /// The bundle layer IS applied: a deny rule carried only in rule-packs.yaml
    /// must cause the returned `DenyEvaluator` to deny a matching action.
    /// The doctor path (which passes bundle=None) would miss this.
    #[test]
    fn load_effective_policy_includes_rule_pack_bundle() {
        let dir = tempdir().unwrap();
        let policy_path = dir.path().join("policy.yaml");
        let rule_packs_path = dir.path().join("rule-packs.yaml");

        std::fs::write(&policy_path, minimal_policy()).unwrap();
        std::fs::write(&rule_packs_path, bundle_with_deny_rule()).unwrap();

        let (_rubric, deny, _bucket) =
            load_effective_policy(&policy_path, &rule_packs_path).unwrap();

        // The deny rule from the bundle must match the marker command via
        // evaluate_bash_preview (same path as live enforcement).
        let result = deny.evaluate_bash_preview("__sigil_test_deny__");
        assert!(
            result.is_some(),
            "expected deny-test-marker to fire but got None; bundle layer was not applied"
        );
        assert_eq!(result.unwrap().0, "deny-test-marker");
    }

    // ── TDD test 2 ────────────────────────────────────────────────────────────
    /// rule-packs.yaml absent → Ok, rubric built, deny evaluator empty (no error).
    #[test]
    fn load_effective_policy_missing_rule_packs_ok() {
        let dir = tempdir().unwrap();
        let policy_path = dir.path().join("policy.yaml");
        let rule_packs_path = dir.path().join("rule-packs.yaml"); // intentionally absent

        std::fs::write(&policy_path, minimal_policy()).unwrap();

        let (rubric, deny, bucket) = load_effective_policy(&policy_path, &rule_packs_path).unwrap();

        // Rubric should be built (has at least the default weights).
        assert!(
            !rubric.weights.is_empty(),
            "expected non-empty rubric weights"
        );
        // DenyEvaluator should be empty (no rules from an absent bundle).
        assert!(deny.is_empty(), "expected empty deny evaluator");
        // enforce_bucket should default to High.
        assert_eq!(bucket, AiGuardBucket::High);
    }

    /// A benign empty (zero-byte / whitespace) rule-packs.yaml is tolerated like
    /// an absent one — Ok with no bundle — so a cold `sigil assess` agrees with a
    /// running daemon (which treats empty as "no bundle" / retain-last-good, #135),
    /// instead of hard-failing. Only a Corrupt (parse-failed) bundle errors.
    #[test]
    fn load_effective_policy_empty_rule_packs_ok() {
        let dir = tempdir().unwrap();
        let policy_path = dir.path().join("policy.yaml");
        let rule_packs_path = dir.path().join("rule-packs.yaml");
        std::fs::write(&policy_path, minimal_policy()).unwrap();
        std::fs::write(&rule_packs_path, "   \n\t\n").unwrap(); // whitespace-only

        let (_rubric, deny, bucket) =
            load_effective_policy(&policy_path, &rule_packs_path).unwrap();
        assert!(deny.is_empty(), "empty bundle => no deny rules");
        assert_eq!(bucket, AiGuardBucket::High);
    }

    // ── TDD test 3 ────────────────────────────────────────────────────────────
    /// Malformed policy.yaml → Err (cold load fails loudly).
    #[test]
    fn load_effective_policy_bad_policy_errs() {
        let dir = tempdir().unwrap();
        let policy_path = dir.path().join("policy.yaml");
        let rule_packs_path = dir.path().join("rule-packs.yaml"); // absent

        std::fs::write(&policy_path, b": not : valid : yaml :::\n").unwrap();

        let result = load_effective_policy(&policy_path, &rule_packs_path);
        assert!(
            result.is_err(),
            "expected Err for malformed policy.yaml, got Ok"
        );
    }
}
