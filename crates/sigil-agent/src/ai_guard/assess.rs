//! Pure assess engine (#149) — turns a proposed command or MCP server
//! definition into an `AssessVerdict` using policy snapshots injected by the
//! caller.
//!
//! # Purity guarantee
//! No disk, network, or clock access. All policy state is passed in via
//! `AssessCtx`. Transient-path and destructive-pattern detection are string
//! operations on the input, not filesystem probes.

use sigil_core::assess::{AssessInput, AssessVerdict, Decision, DenyMatch};
use sigil_core::event::AiGuardBucket;

use crate::ai_guard::command_scan::{render_bash_preview, scan_command};
use crate::ai_guard::parser::mcp_scan::emit_one_server;
use crate::ai_guard::rubric;
use crate::ai_guard::rubric::Rubric;
use crate::hook_deny::DenyEvaluator;

/// Immutable policy snapshot injected into every `assess` call.
///
/// The caller (e.g. a task dispatcher or a hook handler) snapshot-clones both
/// the rubric and deny evaluator under a short read guard before any `.await`,
/// then passes borrows here. `assess` itself is synchronous and pure.
pub struct AssessCtx<'a> {
    /// Operator-tunable scoring rubric.
    pub rubric: &'a Rubric,
    /// Compiled deny-rule evaluator.
    pub deny: &'a DenyEvaluator,
    /// Bucket threshold: `bucket >= enforce_bucket` → `Deny`.
    /// Callers typically set this to `AiGuardBucket::High`.
    pub enforce_bucket: AiGuardBucket,
}

/// Score a proposed action and return a full verdict.
///
/// # Flow
/// 1. Build reasons from the input (Command → `scan_command`; McpServer → `emit_one_server`).
/// 2. Compute `score` + `bucket` via the rubric.
/// 3. For `Command`, run `deny.evaluate_bash_preview`; for `McpServer`, `deny_match = None` (v1 scope).
/// 4. Decide: `deny_match.is_some() || bucket >= enforce_bucket` → Deny;
///    `bucket >= Medium` → Warn; else Allow.
pub fn assess(input: &AssessInput, ctx: &AssessCtx) -> AssessVerdict {
    // ── 1. Build reasons ─────────────────────────────────────────────────────
    let mut reasons = Vec::new();
    let deny_match: Option<DenyMatch>;

    match input {
        AssessInput::Command { command, args } => {
            reasons = scan_command(command, args);

            let preview = render_bash_preview(command, args);
            deny_match = ctx
                .deny
                .evaluate_bash_preview(&preview)
                .map(|(rule_id, reason)| DenyMatch { rule_id, reason });
        }
        AssessInput::McpServer {
            server_name,
            definition,
        } => {
            emit_one_server(server_name, definition, &mut reasons);
            // v1 scope: deny rules are not applied to MCP server definitions.
            deny_match = None;
        }
    }

    // ── 2. Score + bucket ────────────────────────────────────────────────────
    let score = ctx.rubric.score(&reasons);
    let bucket = rubric::bucket(score);

    // ── 3. Decision ──────────────────────────────────────────────────────────
    let decision = if deny_match.is_some() || bucket >= ctx.enforce_bucket {
        Decision::Deny
    } else if bucket >= AiGuardBucket::Medium {
        Decision::Warn
    } else {
        Decision::Allow
    };

    AssessVerdict {
        bucket,
        score,
        reasons,
        deny_match,
        decision,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use sigil_core::assess::AssessInput;
    use sigil_core::event::AiGuardBucket;
    use sigil_core::event::AiGuardReason;
    use sigil_core::policy::{DenyRule, HookActionMatch, Matcher};

    fn default_ctx<'a>(rubric: &'a Rubric, deny: &'a DenyEvaluator) -> AssessCtx<'a> {
        AssessCtx {
            rubric,
            deny,
            enforce_bucket: AiGuardBucket::High,
        }
    }

    fn empty_deny() -> DenyEvaluator {
        DenyEvaluator::new(&[]).unwrap()
    }

    fn deny_with_bash_regex(id: &str, pattern: &str) -> DenyEvaluator {
        DenyEvaluator::new(&[DenyRule {
            id: id.to_string(),
            match_: HookActionMatch::Bash {
                command: Matcher::Regex {
                    pattern: pattern.to_string(),
                },
            },
        }])
        .unwrap()
    }

    // ── Test 1: destructive command → bucket High+ → Deny via bucket threshold ──

    /// `rm -rf /tmp/x` → bucket High (score=4.0) → decision Deny.
    /// Also asserts that DestructiveInInlineCommand is in reasons.
    #[test]
    fn assess_raw_command_destructive_denies() {
        let rubric = Rubric::defaults();
        let deny = empty_deny();
        let ctx = default_ctx(&rubric, &deny);

        let input = AssessInput::Command {
            command: "rm".to_string(),
            args: vec!["-rf".to_string(), "/tmp/x".to_string()],
        };
        let verdict = assess(&input, &ctx);

        assert!(
            verdict
                .reasons
                .iter()
                .any(|r| matches!(r, AiGuardReason::DestructiveInInlineCommand { .. })),
            "expected DestructiveInInlineCommand in reasons, got: {:?}",
            verdict.reasons
        );
        assert!(
            verdict.bucket >= AiGuardBucket::High,
            "expected bucket >= High, got {:?}",
            verdict.bucket
        );
        assert_eq!(
            verdict.decision,
            Decision::Deny,
            "expected Deny, got {:?}",
            verdict.decision
        );
        assert!(
            verdict.deny_match.is_none(),
            "no deny rules loaded, deny_match should be None"
        );
    }

    // ── Test 2: safe command → Low, Allow, no deny_match ──────────────────────

    #[test]
    fn assess_command_safe_allows() {
        let rubric = Rubric::defaults();
        let deny = empty_deny();
        let ctx = default_ctx(&rubric, &deny);

        let input = AssessInput::Command {
            command: "ls".to_string(),
            args: vec!["-la".to_string()],
        };
        let verdict = assess(&input, &ctx);

        assert_eq!(
            verdict.bucket,
            AiGuardBucket::Low,
            "ls -la should be Low, got {:?}",
            verdict.bucket
        );
        assert_eq!(
            verdict.decision,
            Decision::Allow,
            "ls -la should Allow, got {:?}",
            verdict.decision
        );
        assert!(
            verdict.deny_match.is_none(),
            "no deny rules → deny_match None"
        );
    }

    // ── Test 3: MCP server with shell launcher → launcher reason + weighted bucket ──

    /// A stdio MCP server using `bash -c` → McpServerSuspiciousLauncher(Shell) emitted.
    #[test]
    fn assess_mcp_server_shell_launcher() {
        let rubric = Rubric::defaults();
        let deny = empty_deny();
        let ctx = default_ctx(&rubric, &deny);

        // bash -c is a shell launcher shape (mcp_scan recognizes this)
        let input = AssessInput::McpServer {
            server_name: "evil-mcp".to_string(),
            definition: serde_json::json!({
                "command": "bash",
                "args": ["-c", "npx @some/mcp-server"]
            }),
        };
        let verdict = assess(&input, &ctx);

        assert!(
            verdict.reasons.iter().any(|r| matches!(
                r,
                AiGuardReason::McpServerSuspiciousLauncher {
                    shape: sigil_core::event::LauncherShape::Shell,
                    ..
                }
            )),
            "expected Shell launcher reason, got: {:?}",
            verdict.reasons
        );
        // bash -c emits: McpServerLocalCommand(0.5) + NoSandbox(2.0) + Shell(3.0) = 5.5 → High
        assert!(
            verdict.bucket >= AiGuardBucket::Medium,
            "shell launcher should score at least Medium, got {:?}",
            verdict.bucket
        );
        // deny_match is None for MCP path (v1 scope)
        assert!(verdict.deny_match.is_none());
    }

    // ── Test 4: deny rule match forces Deny even when bucket is Low ────────────

    #[test]
    fn assess_deny_rule_match_forces_deny() {
        let rubric = Rubric::defaults();
        // A deny rule that matches "echo hello" — a completely benign command
        let deny = deny_with_bash_regex("no-echo", r"^echo hello$");
        let ctx = default_ctx(&rubric, &deny);

        let input = AssessInput::Command {
            command: "echo".to_string(),
            args: vec!["hello".to_string()],
        };
        let verdict = assess(&input, &ctx);

        // The command itself should score Low (no structural risk)
        assert_eq!(
            verdict.bucket,
            AiGuardBucket::Low,
            "echo hello should be Low bucket, got {:?}",
            verdict.bucket
        );
        // But deny_match must be Some
        assert!(
            verdict.deny_match.is_some(),
            "expected deny_match Some for matched deny rule, got None"
        );
        assert_eq!(verdict.deny_match.as_ref().unwrap().rule_id, "no-echo");
        // And decision must be Deny
        assert_eq!(
            verdict.decision,
            Decision::Deny,
            "deny rule match must produce Deny even when bucket=Low"
        );
    }

    // ── Test 5: MCP def with both url and command → both reason types emitted ──

    #[test]
    fn assess_mcp_def_url_and_command_both_emit() {
        let rubric = Rubric::defaults();
        let deny = empty_deny();
        let ctx = default_ctx(&rubric, &deny);

        let input = AssessInput::McpServer {
            server_name: "hybrid-server".to_string(),
            definition: serde_json::json!({
                "url": "https://example.com/mcp",
                "command": "node",
                "args": ["/usr/local/lib/mcp/server.js"]
            }),
        };
        let verdict = assess(&input, &ctx);

        assert!(
            verdict
                .reasons
                .iter()
                .any(|r| matches!(r, AiGuardReason::McpServerRemote { .. })),
            "expected McpServerRemote reason for url field"
        );
        assert!(
            verdict
                .reasons
                .iter()
                .any(|r| matches!(r, AiGuardReason::McpServerLocalCommand { .. })),
            "expected McpServerLocalCommand reason for command field"
        );
        // Both evaluated independently — parity with emit_one_server
        assert!(
            verdict.reasons.len() >= 2,
            "should have at least 2 reasons (url + command paths)"
        );
    }

    // ── Test 6: same input + ctx → identical verdict ───────────────────────────

    #[test]
    fn assess_deterministic() {
        let rubric = Rubric::defaults();
        let deny = empty_deny();
        let ctx = default_ctx(&rubric, &deny);

        let input = AssessInput::Command {
            command: "rm".to_string(),
            args: vec!["-rf".to_string(), "/tmp/test".to_string()],
        };

        let v1 = assess(&input, &ctx);
        let v2 = assess(&input, &ctx);

        assert_eq!(
            v1, v2,
            "assess must be deterministic for identical input+ctx"
        );
    }
}
