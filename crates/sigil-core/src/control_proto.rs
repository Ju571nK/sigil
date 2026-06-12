//! Wire protocol for the agent control socket (IPC). Shared by `sigil-agent`
//! (server/handlers) and `sigil-mcp` (local-mode client) so the two can never
//! drift. Types only — no handler/dispatch logic lives here.
use crate::assess::AssessInput;
pub use crate::assess::AssessVerdict;
use crate::event::{AiGuardBucket, AiGuardScope, AiTool, PolicySignatureInvalidReason};
use crate::policy::signed_envelope::SignedPolicyResponse;
use crate::policy::Tier;
use crate::stats::StatsSnapshot;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Pure resolver for the agent's default control-socket path — split out so the
/// root/non-root/XDG/TMPDIR branches can be unit-tested without touching the
/// process euid or environment. The agent's `default_control_socket()` wrapper
/// reads euid/root/XDG/TMPDIR then delegates here.
///
/// As root, the system path `/var/run/sigil` (matches the systemd unit's
/// `RuntimeDirectory=`). A non-root agent (macOS, non-root Linux) can't write
/// there, so fall back to `$XDG_RUNTIME_DIR/sigil` (else `$TMPDIR`/`/tmp`
/// namespaced by uid), keeping the control plane usable without elevation.
pub fn resolve_control_socket(
    is_root: bool,
    xdg_runtime: Option<String>,
    tmpdir: Option<String>,
    uid: u32,
) -> PathBuf {
    if is_root {
        return PathBuf::from("/var/run/sigil/control.sock");
    }
    if let Some(dir) = xdg_runtime {
        return PathBuf::from(dir).join("sigil").join("control.sock");
    }
    let base = tmpdir.unwrap_or_else(|| "/tmp".to_string());
    PathBuf::from(base)
        .join(format!("sigil-{uid}"))
        .join("control.sock")
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    /// Existing Phase 1 command — unchanged on the wire.
    #[serde(rename = "stats")]
    Stats,
    /// Plan B `sigil-sender` hands a verified envelope here for application.
    ApplyPolicy {
        /// The full server response — agent re-verifies independently.
        response: SignedPolicyResponse,
    },
    /// `sigil-sender` hands a verified rule-pack bundle here for application.
    /// Mirrors `ApplyPolicy` but advances the SEPARATE rule-packs watermark and
    /// writes `rule-packs.yaml` — it never touches policy.yaml or the policy
    /// version.
    ApplyRulePacks {
        /// The full server bundle response — agent re-verifies independently.
        response: SignedPolicyResponse,
    },
    /// Operator + sender introspection: returns the agent's current
    /// `last_applied_policy_version`, the active `valid_until`, and whether
    /// the active policy is currently expired.
    PolicyStatus,
    /// Operator introspection: returns the agent's currently-active watch
    /// targets and their compiled glob patterns.
    Targets,
    /// Operator action: re-read the policy file (after a hand-edit) without
    /// verifying a signed envelope. Re-uses the existing live-reload pipeline
    /// by nudging the policy-version watch channel.
    ReloadPolicy,
    /// Operator introspection: returns the latest AI Guard risk assessment
    /// for each tool (or a single tool if `tool` is set).
    Risk { tool: Option<AiTool> },
    /// Operator introspection: returns a snapshot of the AI Guard
    /// subsystem state for `sigil doctor`. Phase 3b.5.
    DoctorAiGuardReport,
    /// Ask the running daemon to evaluate a proposed command or MCP server
    /// definition against its LIVE loaded policy and return a verdict.
    /// Phase 3b.9 (#149).
    Assess {
        /// The proposed action to evaluate.
        input: AssessInput,
    },
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Response {
    pub ok: bool,
    pub stats: Option<StatsSnapshot>,
    /// Present iff the request was `ApplyPolicy`.
    pub apply_policy: Option<ApplyPolicyResult>,
    /// Present iff the request was `PolicyStatus`.
    pub policy_status: Option<PolicyStatusPayload>,
    /// Present iff the request was `Targets` (Phase 2 operator introspection).
    pub targets: Option<TargetsPayload>,
    /// Present iff the request was `Risk`.
    pub risk: Option<RiskPayload>,
    /// Present iff the request was `DoctorAiGuardReport`. Phase 3b.5.
    pub doctor_ai_guard: Option<DoctorAiGuardReport>,
    /// Present iff the request was `Assess`. Phase 3b.9 (#149).
    pub assess_verdict: Option<AssessVerdict>,
    pub error: Option<String>,
}

/// Outcome of an `apply_policy` request.
#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ApplyPolicyResult {
    /// Verifier accepted; policy.yaml written; version advanced.
    Accepted {
        /// The new `last_applied_policy_version`.
        applied_policy_version: i64,
    },
    /// Verifier rejected. The wire-stable `reason` matches the
    /// `PolicySignatureInvalid` event variant emitted in parallel.
    Rejected {
        /// Which check failed.
        reason: PolicySignatureInvalidReason,
    },
}

/// Snapshot of the agent's current policy state.
#[derive(Serialize, Deserialize, Debug)]
pub struct PolicyStatusPayload {
    pub last_applied_policy_version: i64,
    /// RFC 3339; `None` if no envelope has ever been applied.
    pub active_envelope_valid_until: Option<String>,
    /// `true` iff `now >= active_envelope_valid_until`.
    pub policy_expired_active: bool,
}

/// Summary of one active watch target — what the agent is currently watching
/// post-policy-merge + post-canonicalization.
#[derive(Serialize, Deserialize, Debug)]
pub struct TargetSummary {
    pub id: String,
    pub tier: Tier,
    pub globs: Vec<String>,
}

/// Payload for the `targets` control-IPC response: the agent's currently-active
/// compiled targets.
#[derive(Serialize, Deserialize, Debug)]
pub struct TargetsPayload {
    pub targets: Vec<TargetSummary>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RiskPayload {
    pub assessments: Vec<RiskSummary>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RiskSummary {
    pub tool: AiTool,
    pub scope: AiGuardScope,
    pub score: f32,
    pub bucket: AiGuardBucket,
    pub reasons_count: usize,
    /// RFC 3339.
    pub last_assessed_ts: String,
}

/// Phase 3b.5 — serializable snapshot of the agent's AI Guard subsystem
/// state, returned by `Request::DoctorAiGuardReport` for `sigil doctor`.
#[derive(Serialize, Deserialize, Debug)]
pub struct DoctorAiGuardReport {
    /// Active parser instances. One entry per (tool, scope) pair.
    pub parsers: Vec<ParserInfo>,
    /// Discovered per-repo workspaces, count per tool.
    pub per_repo: PerRepoSummary,
    /// Loaded rule packs (3b.7). Skipped packs are not currently retained;
    /// only loaded ones are reported. Future enhancement may surface skip
    /// reasons from the loader.
    pub rule_packs: Vec<RulePackInfo>,
    /// External hook scripts (3b.3) currently being watched.
    pub ext_scripts: ExtScriptSummary,
    /// Latest risk assessment per (tool, scope) from ai_guard_state cache.
    pub latest_risk: Vec<RiskSummary>,
    /// Effective rubric — every kind_key with current weight + whether it
    /// came from an operator override.
    pub effective_rubric: Vec<RubricEntry>,
    /// Snake_case override keys the envelope referenced but didn't match
    /// any known kind. Surfaced by doctor as `[WARN]`.
    pub unknown_override_keys: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ParserInfo {
    pub tool: AiTool,
    pub scope: AiGuardScope,
    pub watched_path_count: usize,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct PerRepoSummary {
    pub continue_dev: usize,
    pub claude_code: usize,
    pub codex: usize,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RulePackInfo {
    pub id: String,
    pub loaded: bool,
    /// `None` when loaded. Reserved for future surfacing of skip reasons.
    pub skip_reason: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct ExtScriptSummary {
    /// Total unique canonical script paths across all parsers.
    pub unique_paths: usize,
    /// Number of (tool, scope) entries that have at least one ext-script.
    pub parser_entries: usize,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RubricEntry {
    pub kind_key: String,
    pub weight: f32,
    pub overridden: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::signed_envelope::{SignedEnvelope, SignedPolicyResponse};
    use time::macros::datetime;

    fn sample_response() -> SignedPolicyResponse {
        SignedPolicyResponse {
            etag: "abc".into(),
            signed_envelope: SignedEnvelope {
                policy_version: 7,
                policy_bytes_b64: "AAA=".into(),
                valid_until: datetime!(2026-06-15 0:00 UTC),
                issued_at: datetime!(2026-05-15 8:00 UTC),
            },
            signature: "sig".into(),
            signing_pubkey_id: "k1".into(),
            applied_at: datetime!(2026-05-15 8:01 UTC),
        }
    }

    #[test]
    fn apply_policy_request_round_trips() {
        let req = Request::ApplyPolicy {
            response: sample_response(),
        };
        let s = serde_json::to_string(&req).unwrap();
        // The cmd discriminator MUST be exactly "apply_policy" (snake_case is
        // wrong here — the existing Phase 1 control protocol uses lowercase).
        assert!(s.contains("\"cmd\":\"apply_policy\""));
        let back: Request = serde_json::from_str(&s).unwrap();
        match back {
            Request::ApplyPolicy { response } => {
                assert_eq!(response.signed_envelope.policy_version, 7);
            }
            _ => panic!("expected ApplyPolicy, got {back:?}"),
        }
    }

    #[test]
    fn policy_status_request_round_trips() {
        let req = Request::PolicyStatus;
        let s = serde_json::to_string(&req).unwrap();
        assert!(s.contains("\"cmd\":\"policy_status\""));
        let _: Request = serde_json::from_str(&s).unwrap();
    }

    #[test]
    fn response_includes_optional_apply_policy_payload() {
        let r = Response {
            ok: true,
            stats: None,
            apply_policy: Some(ApplyPolicyResult::Accepted {
                applied_policy_version: 9,
            }),
            policy_status: None,
            targets: None,
            risk: None,
            doctor_ai_guard: None,
            assess_verdict: None,
            error: None,
        };
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains("\"apply_policy\""));
        assert!(s.contains("\"applied_policy_version\":9"));
    }

    #[test]
    fn response_apply_policy_rejected_carries_reason() {
        let r = Response {
            ok: false,
            stats: None,
            apply_policy: Some(ApplyPolicyResult::Rejected {
                reason: PolicySignatureInvalidReason::Expired,
            }),
            policy_status: None,
            targets: None,
            risk: None,
            doctor_ai_guard: None,
            assess_verdict: None,
            error: None,
        };
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains("\"reason\":\"expired\""));
    }

    #[test]
    fn response_with_targets_round_trips() {
        let resp = Response {
            ok: true,
            stats: None,
            apply_policy: None,
            policy_status: None,
            targets: Some(TargetsPayload {
                targets: vec![TargetSummary {
                    id: "tgt-1".into(),
                    tier: Tier::Critical,
                    globs: vec!["/etc/foo.yaml".into(), "/var/log/bar/*.log".into()],
                }],
            }),
            risk: None,
            doctor_ai_guard: None,
            assess_verdict: None,
            error: None,
        };
        let s = serde_json::to_string(&resp).unwrap();
        assert!(s.contains("\"targets\""));
        assert!(s.contains("\"tgt-1\""));
        assert!(
            s.contains("\"critical\""),
            "Tier::Critical serializes lowercase, got: {s}"
        );
        let back: Response = serde_json::from_str(&s).unwrap();
        assert!(back.targets.is_some());
        assert_eq!(back.targets.as_ref().unwrap().targets[0].id, "tgt-1");
    }

    #[test]
    fn request_targets_round_trips() {
        let req = Request::Targets;
        let s = serde_json::to_string(&req).unwrap();
        assert_eq!(s, r#"{"cmd":"targets"}"#);
        let back: Request = serde_json::from_str(&s).unwrap();
        assert!(matches!(back, Request::Targets));
    }

    #[test]
    fn request_reload_policy_round_trips() {
        let req = Request::ReloadPolicy;
        let s = serde_json::to_string(&req).unwrap();
        assert_eq!(s, r#"{"cmd":"reload_policy"}"#);
        let back: Request = serde_json::from_str(&s).unwrap();
        assert!(matches!(back, Request::ReloadPolicy));
    }

    #[test]
    fn request_risk_round_trips_no_filter() {
        let req = Request::Risk { tool: None };
        let s = serde_json::to_string(&req).unwrap();
        assert!(s.contains("\"cmd\":\"risk\""), "got: {s}");
        let back: Request = serde_json::from_str(&s).unwrap();
        assert!(matches!(back, Request::Risk { tool: None }));
    }

    #[test]
    fn request_risk_round_trips_with_tool_filter() {
        let req = Request::Risk {
            tool: Some(AiTool::ClaudeCode),
        };
        let s = serde_json::to_string(&req).unwrap();
        assert!(s.contains("\"tool\":\"claude_code\""), "got: {s}");
        let back: Request = serde_json::from_str(&s).unwrap();
        assert!(matches!(
            back,
            Request::Risk {
                tool: Some(AiTool::ClaudeCode)
            }
        ));
    }

    #[test]
    fn response_with_risk_payload_round_trips() {
        let resp = Response {
            ok: true,
            stats: None,
            apply_policy: None,
            policy_status: None,
            targets: None,
            risk: Some(RiskPayload {
                assessments: vec![RiskSummary {
                    tool: AiTool::Codex,
                    scope: AiGuardScope::UserGlobal,
                    score: 2.0,
                    bucket: AiGuardBucket::Medium,
                    reasons_count: 1,
                    last_assessed_ts: "2026-05-16T06:00:00Z".into(),
                }],
            }),
            doctor_ai_guard: None,
            assess_verdict: None,
            error: None,
        };
        let s = serde_json::to_string(&resp).unwrap();
        assert!(s.contains("\"risk\""));
        assert!(s.contains("\"tool\":\"codex\""));
        assert!(s.contains("\"bucket\":\"medium\""));
        let back: Response = serde_json::from_str(&s).unwrap();
        assert!(back.risk.is_some());
        assert_eq!(back.risk.as_ref().unwrap().assessments.len(), 1);
    }

    #[test]
    fn root_uses_system_run_path() {
        assert_eq!(
            resolve_control_socket(
                true,
                Some("/run/user/1000".into()),
                Some("/tmp".into()),
                1000
            ),
            PathBuf::from("/var/run/sigil/control.sock")
        );
    }

    #[test]
    fn nonroot_prefers_xdg_runtime_dir() {
        assert_eq!(
            resolve_control_socket(
                false,
                Some("/run/user/501".into()),
                Some("/tmp".into()),
                501
            ),
            PathBuf::from("/run/user/501/sigil/control.sock")
        );
    }

    #[test]
    fn nonroot_without_xdg_uses_tmpdir_namespaced_by_uid() {
        assert_eq!(
            resolve_control_socket(false, None, Some("/custom/tmp".into()), 501),
            PathBuf::from("/custom/tmp/sigil-501/control.sock")
        );
    }

    #[test]
    fn nonroot_without_xdg_or_tmpdir_falls_back_to_slash_tmp() {
        assert_eq!(
            resolve_control_socket(false, None, None, 42),
            PathBuf::from("/tmp/sigil-42/control.sock")
        );
    }

    #[test]
    fn doctor_report_round_trips() {
        let r = Response {
            ok: true,
            stats: None,
            apply_policy: None,
            policy_status: None,
            targets: None,
            risk: None,
            error: None,
            assess_verdict: None,
            doctor_ai_guard: Some(DoctorAiGuardReport {
                parsers: vec![],
                rule_packs: vec![],
                ext_scripts: Default::default(),
                per_repo: PerRepoSummary {
                    continue_dev: 0,
                    claude_code: 2,
                    codex: 1,
                },
                latest_risk: vec![RiskSummary {
                    tool: AiTool::ClaudeCode,
                    scope: AiGuardScope::UserGlobal,
                    score: 8.0,
                    bucket: AiGuardBucket::High,
                    reasons_count: 3,
                    last_assessed_ts: "2026-05-29T00:00:00Z".into(),
                }],
                effective_rubric: vec![RubricEntry {
                    kind_key: "no_sandbox".into(),
                    weight: 2.0,
                    overridden: false,
                }],
                unknown_override_keys: vec![],
            }),
        };
        let s = serde_json::to_string(&r).unwrap();
        let back: Response = serde_json::from_str(&s).unwrap();
        assert_eq!(back.doctor_ai_guard.unwrap().per_repo.claude_code, 2);
    }

    #[test]
    fn request_assess_round_trips() {
        use crate::assess::AssessInput;
        let req = Request::Assess {
            input: AssessInput::Command {
                command: "rm".into(),
                args: vec!["-rf".into(), "/tmp/x".into()],
            },
        };
        let s = serde_json::to_string(&req).unwrap();
        assert!(s.contains("\"cmd\":\"assess\""), "got: {s}");
        assert!(s.contains("\"kind\":\"command\""), "got: {s}");
        let back: Request = serde_json::from_str(&s).unwrap();
        assert!(matches!(back, Request::Assess { .. }));
    }

    #[test]
    fn response_with_assess_verdict_round_trips() {
        use crate::assess::{AssessVerdict, Decision};
        use crate::event::{AiGuardBucket, AiGuardReason};
        let resp = Response {
            ok: true,
            stats: None,
            apply_policy: None,
            policy_status: None,
            targets: None,
            risk: None,
            doctor_ai_guard: None,
            assess_verdict: Some(AssessVerdict {
                bucket: AiGuardBucket::High,
                score: 4.0,
                reasons: vec![AiGuardReason::NoSandbox {
                    executor: "host_shell".into(),
                }],
                deny_match: None,
                decision: Decision::Deny,
            }),
            error: None,
        };
        let s = serde_json::to_string(&resp).unwrap();
        assert!(s.contains("\"assess_verdict\""), "got: {s}");
        assert!(s.contains("\"decision\":\"deny\""), "got: {s}");
        let back: Response = serde_json::from_str(&s).unwrap();
        let v = back.assess_verdict.unwrap();
        assert_eq!(v.decision, Decision::Deny);
        assert_eq!(v.bucket, AiGuardBucket::High);
    }
}
