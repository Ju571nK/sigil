//! Posture event types.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;
use time::OffsetDateTime;
use uuid::Uuid;

/// Coarse severity. Phase 1 emits only `Info` and `Warn`.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Warn,
}

/// Origin of an event.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SourceKind {
    FileSystem,
    Agent,
    /// sigil-hook runtime observation (#64).
    AgentHook,
    /// Forward-compat fallback (see Evidence::Unknown).
    #[serde(other)]
    Unknown,
}

/// Technical identifier of the observed thing.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Subject {
    Path {
        value: PathBuf,
    },
    #[serde(rename = "self")]
    Self_,
}

/// A filesystem change kind.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum FileChangeKind {
    Created,
    Modified,
    Removed,
    Renamed,
}

/// Quality marker on a `FileChange` event.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceQuality {
    /// Single event, clean debounce window.
    Definitive,
    /// Multiple events coalesced inside the debounce window.
    BestEffort,
    /// Event spent > 1 s in any queue before reaching the sink.
    Delayed,
    /// Observation could not be fully captured (e.g., file removed before hash).
    Incomplete,
}

/// Why the agent is shutting down abnormally.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AgentDyingReason {
    Panic,
    UnrecoverableSinkError,
    Signal,
}

/// Spec §3.8.2 rejection reasons. Stable wire strings — operators filter by
/// these in the SIEM, so renames are breaking changes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicySignatureInvalidReason {
    /// `signing_pubkey_id` not present in the keystore at all.
    PubkeyUnknown,
    /// Keystore entry exists but `now` is outside its validity window.
    PubkeyInactive,
    /// Pubkey resolved but ed25519 verification failed against the canonical bytes.
    SignatureInvalid,
    /// `now >= signed_envelope.valid_until`.
    Expired,
    /// `policy_version <= host_meta.last_applied_policy_version` (replay or rollback).
    VersionRegression,
    /// Base64 decode succeeded but the YAML did not parse to a `Policy`.
    ParseFailed,
}

/// Phase 3b.1 — which AI coding agent is being assessed.
/// Stable wire strings — operators filter by these in the SIEM, so renames are
/// breaking changes.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum AiTool {
    ClaudeCode,
    Codex,
    /// Phase 3b.6 — Claude Desktop (Anthropic.app), application-form companion to ClaudeCode CLI.
    ClaudeDesktop,
    /// Phase 3b.6 — Continue.dev VSCode/JetBrains extension.
    ContinueDev,
    /// Phase 3b.7 — Gemini CLI (google-gemini/gemini-cli). Wire string: "gemini".
    Gemini,
    /// Phase 3b.7 — Cursor IDE. Wire string: "cursor".
    Cursor,
    /// Antigravity (Google) — successor to Gemini CLI (Gemini CLI sunset
    /// 2026-06-18). Config reuses the `~/.gemini/` tree. Wire string: "antigravity".
    Antigravity,
    /// Phase 3b.7.5 — an operator-defined tool with no built-in parser. Wire
    /// string: "other". The human name rides `tool_label` (rule pack + event),
    /// never inside the enum, so AiTool stays Copy + a bare-string wire value.
    Other,
}

/// Phase 3b.1 — where the assessment applies on the host.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AiGuardScope {
    /// `~/.claude/`, `~/.codex/` — user's global config.
    UserGlobal,
    /// Operator-added paths in policy.yaml not under user-global.
    Project { path: PathBuf },
    /// Phase 3b.6 — application/IDE-installed AI agent (Claude Desktop, Continue.dev, ...).
    /// `app` is a stable snake_case identifier matching the parser
    /// (e.g., "claude_desktop", "continue").
    Application { app: String },
}

/// Phase 3b.1 — auto-derived from `score`. low <1 / medium <4 / high <7 / critical 7+.
/// Stable wire strings — operators filter by these in the SIEM, so renames are
/// breaking changes.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AiGuardBucket {
    Low,
    Medium,
    High,
    Critical,
}

/// Phase 3b.1 — one finding inside an `AiGuardRiskAssessed` event.
/// Stable wire strings — operators filter by these in the SIEM, so renames are
/// breaking changes.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AiGuardReason {
    /// Inline shell command in a hook contains a destructive pattern.
    DestructiveInInlineCommand {
        pattern: String,
        hook_event: String,
        snippet: String,
    },
    /// Same, but the destructive pattern was in a script file we read
    /// (convention dir like `~/.claude/hooks/`).
    DestructiveInHookScript {
        pattern: String,
        hook_event: String,
        script_path: PathBuf,
        snippet: String,
        /// 3b.3.1 — chain of script paths from the entry hook down to the
        /// file where the pattern matched. Empty = match was in the entry
        /// (back-compat with 3b.3 emissions). Populated form is
        /// `[entry, ..., matched_file]`.
        #[serde(default)]
        source_chain: Vec<PathBuf>,
    },
    /// Hook command points to an external script we did NOT scan
    /// (path outside known convention dir). 3b.3 marker.
    ExternalScriptUnscanned {
        hook_event: String,
        script_path: PathBuf,
    },
    /// Hook executes in host shell with no sandbox boundary.
    NoSandbox { executor: String },
    /// Hook matcher catches all/most tool invocations.
    BroadMatcher { hook_event: String, matcher: String },
    /// Permission deny array empty / missing.
    PermissionsDenyEmpty,
    /// Permission allow includes a wildcard rule.
    PermissionsAllowBroad { rule: String },
    /// Codex sandbox is fully disabled: top-level `sandbox_mode = "danger-full-access"`.
    /// Codex-only reason — Claude Code uses `NoSandbox{executor:"host_shell"}`
    /// instead, since Claude Code has no built-in sandbox concept.
    SandboxDisabled,
    /// MCP server pointing at a remote URL was added.
    McpServerRemote { server_name: String, url: String },
    /// MCP server using a local command (stdio transport) was added.
    /// Phase 3b.7 — rule pack engine emits this when a `command:` key is
    /// found under `mcpServers.*` in Gemini/Cursor settings files.
    McpServerLocalCommand {
        server_name: String,
        command: String,
    },
    /// Phase 3b.8 — an MCP server is marked `trust: true`, bypassing
    /// per-tool confirmation for every tool it exposes (Gemini).
    TrustedMcpServer { server_name: String },
    /// Phase 3b.8 — the agent's default approval mode auto-approves a class
    /// of tool calls without prompting (e.g. Gemini `defaultApprovalMode: "auto_edit"`).
    AutoApprovalEnabled { mode: String },
}

/// Persisted form of a hook observation (#64). Distinct from the IPC
/// `hook_proto::HookInvocation` so the SIEM schema and the IPC schema evolve
/// independently. `peer_uid` is stamped by the agent from the kernel
/// (`SO_PEERCRED`), never self-reported by the hook.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct HookInvocationEvidence {
    pub agent: AiTool,
    pub peer_uid: u32,
    pub agent_session_id: Option<String>,
    pub tool_use_id: Option<String>,
    /// Normalized action kind: "bash" | "file_edit" | "mcp_call" | "other".
    pub action_kind: String,
    /// Tool name when `action_kind == "other"`, else `None`. Carries the
    /// original tool name (e.g. "WebFetch") for non-Bash/Edit/MCP tools.
    pub other_label: Option<String>,
    /// blake3 over the raw pre-mask normalized action (lowercase hex).
    pub action_hash: String,
    /// Redacted/capped preview, or `None` under hash_only.
    pub action_preview: Option<String>,
    pub capture_level: String,
    pub capture_status: String,
}

/// sigil-hook Stage 2 (#100). A consequential decision outcome — a deny, or a
/// degradation where enforcement could not be evaluated. NOT emitted on allow
/// (observe already records every invocation via HookInvocation).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct HookDecisionEvidence {
    pub agent: AiTool,
    pub peer_uid: u32,
    pub agent_session_id: Option<String>,
    pub tool_use_id: Option<String>,
    /// Normalized action kind: "bash" | "file_edit" | "mcp_call" | "other".
    pub action_kind: String,
    pub action_hash: String,
    pub action_preview: Option<String>,
    /// "deny" | "fail_open_error" | "fail_closed_error".
    /// `fail_*_error` values are reserved for the daemon-reachable-but-failed
    /// degradation path (follow-on); slice 1's pre-compiled evaluator emits only "deny".
    pub decision: String,
    pub rule_id: Option<String>,
    pub deny_reason: Option<String>,
    /// "observe" | "enforce".
    pub enforcement_mode: String,
    pub capture_level: String,
}

/// Phase 3b.4-pre — full host identity / OS / network snapshot, emitted by
/// host_meta_snapshot_task. Surfaces hostname (so server-side fleet views
/// can label hosts with something human-readable instead of UUIDs) plus
/// OS and network metadata for additional fleet attribution.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct HostMetaSnapshot {
    /// Local hostname per the OS (e.g., "alice-macbook-pro").
    pub hostname: Option<String>,

    /// OS name (e.g., "macOS", "Rocky Linux", "Windows").
    pub os_name: Option<String>,
    /// OS version string (e.g., "14.5", "9.3", "11").
    pub os_version: Option<String>,
    /// Kernel version (e.g., "23.5.0", "5.14.0-427.20.1.el9_4.x86_64").
    pub kernel_version: Option<String>,
    /// CPU architecture (e.g., "x86_64", "aarch64").
    pub architecture: Option<String>,

    /// All non-loopback network interfaces with assigned addresses.
    pub interfaces: Vec<NetworkInterface>,
    /// IPv4 default gateway, if discoverable.
    pub default_gateway_v4: Option<String>,
    /// IPv6 default gateway, if discoverable.
    pub default_gateway_v6: Option<String>,
    /// Configured DNS resolver IPs (system resolver only — not per-interface).
    pub dns_servers: Vec<String>,
}

/// Phase 3b.4-pre — one network interface inside a `HostMetaSnapshot`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct NetworkInterface {
    /// Interface name (e.g., "en0", "eth0", "Ethernet 1").
    pub name: String,
    /// MAC address as colon-separated lowercase hex
    /// (e.g., "00:1b:44:11:3a:b7"). None for interfaces without an L2
    /// address (loopback excluded upstream).
    pub mac: Option<String>,
    /// IPv4 addresses assigned, each as "addr/prefix" (e.g., "10.0.1.42/24").
    pub ipv4: Vec<String>,
    /// IPv6 addresses assigned, each as "addr/prefix" (e.g., "fe80::1/64").
    pub ipv6: Vec<String>,
}

/// The observation payload of an event.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Evidence {
    FileChange {
        change_kind: FileChangeKind,
        before_hash: Option<String>,
        after_hash: Option<String>,
        recheck_hash: Option<String>,
        rename_from: Option<PathBuf>,
        size_after: Option<u64>,
        evidence_quality: EvidenceQuality,
    },
    Heartbeat {
        uptime_s: u64,
        is_final: bool,
        channel_stall_events_total: u64,
        events_emitted_total: u64,
        events_by_kind: BTreeMap<String, u64>,
        hash_p50_ms: u32,
        hash_p99_ms: u32,
        watcher_backend: String,
        state_db_size_bytes: u64,
        #[serde(with = "time::serde::rfc3339::option")]
        last_log_rotation_ts: Option<OffsetDateTime>,
        /// Phase 2: agent's currently-applied policy version (0 if none yet).
        last_applied_policy_version: i64,
        /// Phase 2: `true` iff the active envelope's valid_until is in the past.
        policy_expired_active: bool,
        /// Phase 2: `true` iff `events/` is currently above the GC soft floor.
        jsonl_above_soft_floor: bool,
    },
    PermissionMissing {
        resource: String,
        platform_hint: String,
    },
    ChannelStall {
        channel: String,
        blocked_seconds_in_window: f32,
        block_events_in_window: u64,
        #[serde(with = "time::serde::rfc3339")]
        first_block_ts: OffsetDateTime,
    },
    WatcherDegraded {
        from: String,
        to: String,
        reason: String,
    },
    AgentDying {
        reason: AgentDyingReason,
        detail: String,
        task: Option<String>,
    },
    RateLimitExceeded {
        target_id: String,
        count_dropped_in_window: u64,
        common_path_prefix: PathBuf,
    },
    /// Spec §3.10: hw_fingerprint changed while host_id stayed the same.
    /// Emitted by the agent when the freshly-computed fingerprint differs
    /// from the persisted one in `state.db`.
    HostIdFingerprintDrift {
        /// Previously-persisted fingerprint hex (blake3 → 64 chars).
        prev_fingerprint: String,
        /// Freshly-computed fingerprint hex.
        new_fingerprint: String,
    },
    /// Spec §3.9: emitted exactly once per GC cycle that crossed the
    /// hard ceiling (size or age). Operators dashboard on this — non-zero
    /// rate means the host is permanently behind on shipping.
    AgentJsonlForceGc {
        /// Total bytes in `events/` at the time of the cycle.
        total_bytes: u64,
        /// Age in seconds of the oldest segment at the time of the cycle.
        oldest_segment_age_s: u64,
        /// How many segments were deleted in the cycle.
        segments_deleted: u32,
        /// Of those, how many were past the sender offset.
        segments_skipped_past_sender: u32,
    },
    /// Spec §3.9: emitted whenever the GC deleted at least one segment
    /// that the sender had NOT yet shipped. One event per cycle (NOT per file).
    SenderSkippedSegment {
        /// Number of segments dropped past the sender in this cycle.
        count: u32,
        /// Filename of the OLDEST segment dropped past the sender (operators
        /// can grep their SIEM around this segment's expected event-id range).
        oldest_dropped_filename: String,
    },
    /// Spec §3.8.2: a `SignedPolicyResponse` was rejected by the verification
    /// chain. Emitted by the agent when an inbound envelope fails any check;
    /// the policy is NOT applied and `last_applied_policy_version` is NOT
    /// advanced.
    PolicySignatureInvalid {
        /// Which check failed.
        reason: PolicySignatureInvalidReason,
        /// `signing_pubkey_id` from the rejected response (operator triage).
        signing_pubkey_id: String,
        /// `policy_version` claimed by the rejected envelope.
        policy_version_in_envelope: i64,
        /// The agent's current `last_applied_policy_version` at rejection time.
        last_applied_policy_version: i64,
    },
    /// Spec §3.10: emitted exactly once when a freshly-verified policy is
    /// committed to disk + state.db. Operators use this to confirm rollouts.
    PolicyReloaded {
        /// The new `last_applied_policy_version`.
        policy_version: i64,
    },
    /// Emitted exactly once when a freshly-verified rule-pack bundle is
    /// committed to disk + state.db. Sibling of `PolicyReloaded` for the
    /// SEPARATE rule-packs watermark, so operators can distinguish a rule-pack
    /// rollout from a policy rollout in the SIEM.
    RulePackBundleApplied {
        /// The new `last_applied_rule_packs_version`.
        version: i64,
    },
    /// Spec §3.10: emitted exactly once per "transition into expired".
    /// The agent continues to enforce the expired policy until a replacement
    /// arrives — `valid_until` is informational, not blocking. (Spec §1.4
    /// "Active policy passing valid_until" — agent keeps applying the last
    /// good policy on the local file system; SIEM operators triage.)
    PolicyExpiredActive {
        /// The version of the policy whose `valid_until` was crossed.
        policy_version: i64,
        /// RFC 3339 — when `valid_until` was crossed.
        #[serde(with = "time::serde::rfc3339")]
        valid_until: time::OffsetDateTime,
    },
    /// Sender saw HTTP 409 from /v1/events: host_id bound to a different cert.
    HostIdConflict { observed_status: u16 },
    /// Sender saw HTTP 426 from /v1/events: agent is two minor versions or older.
    AgentTooOld {
        observed_status: u16,
        agent_version: String,
    },
    /// Sender's client cert past `valid_until` or close to it.
    CertExpired {
        #[serde(with = "time::serde::rfc3339")]
        cert_expires_at: time::OffsetDateTime,
    },
    /// TLS handshake failure (CA mismatch, expired cert, etc.).
    TlsFailure { reason: String },
    /// Per-event hard rejection logged locally for operator audit.
    EventUnprocessableLocal {
        original_event_id: uuid::Uuid,
        server_reason: String,
    },
    /// Server returned 200 without `high_water_event_id` (or other shape break).
    ServerProtocolViolation { detail: String },
    /// `oldest_unsent_age` exceeded the agent's JSONL retention window.
    SenderLagCritical {
        lag_events: u64,
        lag_bytes: u64,
        oldest_unsent_age_s: u64,
    },
    /// Phase 3b.1 — periodic + change-triggered assessment of an AI coding
    /// agent's local guard surface (hooks, permissions, sandbox).
    /// Emitted by ai_guard_task. Sigil measures, does not block.
    AiGuardRiskAssessed {
        tool: AiTool,
        scope: AiGuardScope,
        /// 0.0..=10.0 (CVSS-style continuous; higher = more risk).
        score: f32,
        /// Auto-derived from `score` (low <1 / medium <4 / high <7 / critical 7+).
        bucket: AiGuardBucket,
        /// Per-finding breakdown. Empty array = clean assessment.
        reasons: Vec<AiGuardReason>,
        /// `true` iff this is the periodic re-attestation heartbeat (no
        /// reason set change since last emission). `false` = something changed.
        is_reattestation: bool,
        /// Phase 3b.7.2 — Some(pack id) when emitted by an operator rule-pack
        /// parser; None (omitted) for built-in structural parsers. Forward-compat.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        rule_pack_id: Option<String>,
        /// Phase 3b.7.5 — human-readable name of an `AiTool::Other` tool, from the
        /// rule pack's `tool_label`. None (omitted) for built-in tools. Forward-compat.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tool_label: Option<String>,
    },
    /// Phase 3b.4-pre — periodic snapshot of host identity + network + OS
    /// metadata. Emitted by host_meta_snapshot_task on boot, every 24h, and
    /// whenever the snapshot's canonical hash differs from the last
    /// emission. Sigil measures, does not block.
    HostMetaSnapshot {
        snapshot: HostMetaSnapshot,
        /// `true` iff this is the periodic 24h re-attestation (snapshot
        /// unchanged since last emit). `false` = boot scan or change detected.
        is_reattestation: bool,
    },
    /// sigil-hook Stage 1 (#64). One observed agent tool call.
    HookInvocation(HookInvocationEvidence),
    /// sigil-hook Stage 2 (#100). A deny / degradation decision outcome.
    HookDecision(HookDecisionEvidence),
    /// Forward-compat: an evidence kind this build doesn't recognize. A newer
    /// producer's variant deserializes here instead of failing the whole event.
    #[serde(other)]
    Unknown,
}

/// Schema version. Bumps follow the policy in spec section 3.3.
pub const SCHEMA_VERSION: u32 = 1;

/// `env!("CARGO_PKG_VERSION")` of the agent crate at build time.
pub const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// A single posture event.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Event {
    pub schema_version: u32,
    pub event_id: Uuid,
    #[serde(with = "time::serde::rfc3339")]
    pub ts: OffsetDateTime,
    pub host_id: String,
    pub agent_version: String,
    pub severity: Severity,
    pub source: SourceKind,
    pub subject: Subject,
    pub evidence: Evidence,
    pub target_id: Option<String>,
}

impl Event {
    /// Convenience builder used in tests and by callers that have all fields ready.
    pub fn new_file_change(
        ts: OffsetDateTime,
        host_id: impl Into<String>,
        path: PathBuf,
        evidence: Evidence,
        target_id: Option<String>,
    ) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            event_id: Uuid::now_v7(),
            ts,
            host_id: host_id.into(),
            agent_version: AGENT_VERSION.to_string(),
            severity: Severity::Warn,
            source: SourceKind::FileSystem,
            subject: Subject::Path { value: path },
            evidence,
            target_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use time::macros::datetime;

    #[test]
    fn severity_round_trips_as_lower_snake() {
        let s = Severity::Warn;
        let j = serde_json::to_string(&s).unwrap();
        assert_eq!(j, r#""warn""#);
        let back: Severity = serde_json::from_str(&j).unwrap();
        assert_eq!(back, Severity::Warn);
    }

    #[test]
    fn source_kind_round_trips_with_kind_tag() {
        let s = SourceKind::FileSystem;
        let j = serde_json::to_string(&s).unwrap();
        assert_eq!(j, r#"{"kind":"file_system"}"#);
    }

    #[test]
    fn subject_path_round_trips() {
        let s = Subject::Path {
            value: PathBuf::from("/tmp/x.json"),
        };
        let j = serde_json::to_string(&s).unwrap();
        assert_eq!(j, r#"{"kind":"path","value":"/tmp/x.json"}"#);
        let back: Subject = serde_json::from_str(&j).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn subject_self_serializes_with_self_tag() {
        let s = Subject::Self_;
        let j = serde_json::to_string(&s).unwrap();
        assert_eq!(j, r#"{"kind":"self"}"#);
    }

    #[test]
    fn file_change_kind_serializes_snake() {
        assert_eq!(
            serde_json::to_string(&FileChangeKind::Renamed).unwrap(),
            r#""renamed""#
        );
    }

    #[test]
    fn evidence_quality_has_four_variants() {
        for q in [
            EvidenceQuality::Definitive,
            EvidenceQuality::BestEffort,
            EvidenceQuality::Delayed,
            EvidenceQuality::Incomplete,
        ] {
            let j = serde_json::to_string(&q).unwrap();
            let back: EvidenceQuality = serde_json::from_str(&j).unwrap();
            assert_eq!(back, q);
        }
    }

    #[test]
    fn agent_dying_reason_round_trips() {
        let r = AgentDyingReason::Panic;
        let j = serde_json::to_string(&r).unwrap();
        assert_eq!(j, r#""panic""#);
    }

    #[test]
    fn file_change_round_trips() {
        let ev = Evidence::FileChange {
            change_kind: FileChangeKind::Modified,
            before_hash: Some("aa".into()),
            after_hash: Some("bb".into()),
            recheck_hash: None,
            rename_from: None,
            size_after: Some(42),
            evidence_quality: EvidenceQuality::Definitive,
        };
        let j = serde_json::to_string(&ev).unwrap();
        let back: Evidence = serde_json::from_str(&j).unwrap();
        assert_eq!(back, ev);
    }

    #[test]
    fn heartbeat_serializes_with_kind_tag() {
        let ev = Evidence::Heartbeat {
            uptime_s: 60,
            is_final: false,
            channel_stall_events_total: 0,
            events_emitted_total: 5,
            events_by_kind: BTreeMap::new(),
            hash_p50_ms: 1,
            hash_p99_ms: 4,
            watcher_backend: "fsevents".into(),
            state_db_size_bytes: 0,
            last_log_rotation_ts: None,
            last_applied_policy_version: 0,
            policy_expired_active: false,
            jsonl_above_soft_floor: false,
        };
        let j = serde_json::to_string(&ev).unwrap();
        assert!(j.starts_with(r#"{"kind":"heartbeat""#));
    }

    #[test]
    fn rate_limit_exceeded_round_trips() {
        let ev = Evidence::RateLimitExceeded {
            target_id: "t1".into(),
            count_dropped_in_window: 17,
            common_path_prefix: PathBuf::from("/tmp/spam"),
        };
        let j = serde_json::to_string(&ev).unwrap();
        let back: Evidence = serde_json::from_str(&j).unwrap();
        assert_eq!(back, ev);
    }

    #[test]
    fn channel_stall_uses_rfc3339_timestamp() {
        let ev = Evidence::ChannelStall {
            channel: "norm_to_hasher".into(),
            blocked_seconds_in_window: 5.5,
            block_events_in_window: 3,
            first_block_ts: datetime!(2026-05-08 14:23:45 UTC),
        };
        let j = serde_json::to_string(&ev).unwrap();
        assert!(j.contains("2026-05-08T14:23:45Z"));
    }

    #[test]
    fn policy_signature_invalid_serializes_with_reason_field() {
        let ev = Evidence::PolicySignatureInvalid {
            reason: PolicySignatureInvalidReason::PubkeyUnknown,
            signing_pubkey_id: "sigil-policy-2026-05".into(),
            policy_version_in_envelope: 42,
            last_applied_policy_version: 41,
        };
        let s = serde_json::to_string(&ev).unwrap();
        assert!(
            s.contains("\"kind\":\"policy_signature_invalid\""),
            "got: {s}"
        );
        assert!(s.contains("\"reason\":\"pubkey_unknown\""));
        assert!(s.contains("\"signing_pubkey_id\":\"sigil-policy-2026-05\""));
        assert!(s.contains("\"policy_version_in_envelope\":42"));
        assert!(s.contains("\"last_applied_policy_version\":41"));
    }

    #[test]
    fn each_reason_renders_as_snake_case() {
        for (variant, expected) in [
            (
                PolicySignatureInvalidReason::PubkeyUnknown,
                "pubkey_unknown",
            ),
            (
                PolicySignatureInvalidReason::PubkeyInactive,
                "pubkey_inactive",
            ),
            (
                PolicySignatureInvalidReason::SignatureInvalid,
                "signature_invalid",
            ),
            (PolicySignatureInvalidReason::Expired, "expired"),
            (
                PolicySignatureInvalidReason::VersionRegression,
                "version_regression",
            ),
            (PolicySignatureInvalidReason::ParseFailed, "parse_failed"),
        ] {
            let s = serde_json::to_string(&variant).unwrap();
            assert_eq!(s, format!("\"{expected}\""));
        }
    }

    #[test]
    fn host_id_fingerprint_drift_serializes_with_snake_case_kind() {
        let ev = Evidence::HostIdFingerprintDrift {
            prev_fingerprint: "deadbeef".into(),
            new_fingerprint: "cafef00d".into(),
        };
        let s = serde_json::to_string(&ev).unwrap();
        assert!(
            s.contains("\"kind\":\"host_id_fingerprint_drift\""),
            "got: {s}"
        );
        assert!(s.contains("\"prev_fingerprint\":\"deadbeef\""));
        assert!(s.contains("\"new_fingerprint\":\"cafef00d\""));
    }

    #[test]
    fn sender_variants_serialize_with_kind_tag() {
        let cases = [
            (
                Evidence::HostIdConflict {
                    observed_status: 409,
                },
                "host_id_conflict",
            ),
            (
                Evidence::AgentTooOld {
                    observed_status: 426,
                    agent_version: "0.1.0".into(),
                },
                "agent_too_old",
            ),
            (
                Evidence::CertExpired {
                    cert_expires_at: time::macros::datetime!(2026-01-01 0:00 UTC),
                },
                "cert_expired",
            ),
            (Evidence::TlsFailure { reason: "x".into() }, "tls_failure"),
            (
                Evidence::EventUnprocessableLocal {
                    original_event_id: uuid::Uuid::nil(),
                    server_reason: "x".into(),
                },
                "event_unprocessable_local",
            ),
            (
                Evidence::ServerProtocolViolation { detail: "x".into() },
                "server_protocol_violation",
            ),
            (
                Evidence::SenderLagCritical {
                    lag_events: 1,
                    lag_bytes: 2,
                    oldest_unsent_age_s: 3,
                },
                "sender_lag_critical",
            ),
        ];
        for (ev, expected_kind) in cases {
            let s = serde_json::to_string(&ev).unwrap();
            assert!(
                s.contains(&format!("\"kind\":\"{expected_kind}\"")),
                "for {expected_kind}: {s}"
            );
        }
    }

    #[test]
    fn ai_guard_risk_assessed_serializes_with_kind_and_round_trips() {
        let ev = Evidence::AiGuardRiskAssessed {
            tool: AiTool::ClaudeCode,
            scope: AiGuardScope::UserGlobal,
            score: 7.5,
            bucket: AiGuardBucket::Critical,
            reasons: vec![
                AiGuardReason::DestructiveInInlineCommand {
                    pattern: "rm -rf".into(),
                    hook_event: "PreToolUse".into(),
                    snippet: "rm -rf /tmp/sigil-test/*".into(),
                },
                AiGuardReason::NoSandbox {
                    executor: "host_shell".into(),
                },
                AiGuardReason::BroadMatcher {
                    hook_event: "PreToolUse".into(),
                    matcher: ".*".into(),
                },
            ],
            is_reattestation: false,
            rule_pack_id: None,
            tool_label: None,
        };
        let s = serde_json::to_string(&ev).unwrap();
        assert!(
            s.contains("\"kind\":\"ai_guard_risk_assessed\""),
            "got: {s}"
        );
        assert!(s.contains("\"tool\":\"claude_code\""));
        assert!(s.contains("\"bucket\":\"critical\""));
        assert!(s.contains("\"is_reattestation\":false"));
        assert!(s.contains("\"kind\":\"destructive_in_inline_command\""));
        assert!(s.contains("\"kind\":\"no_sandbox\""));
        assert!(s.contains("\"executor\":\"host_shell\""));
        let back: Evidence = serde_json::from_str(&s).unwrap();
        assert_eq!(back, ev);
    }

    #[test]
    fn ai_tool_other_serde_round_trips_to_other_string() {
        assert_eq!(serde_json::to_string(&AiTool::Other).unwrap(), r#""other""#);
        assert_eq!(
            serde_json::from_str::<AiTool>(r#""other""#).unwrap(),
            AiTool::Other
        );
    }

    #[test]
    fn ai_guard_risk_assessed_omits_tool_label_when_none() {
        let ev = Evidence::AiGuardRiskAssessed {
            tool: AiTool::ClaudeCode,
            scope: AiGuardScope::UserGlobal,
            score: 0.0,
            bucket: AiGuardBucket::Low,
            reasons: vec![],
            is_reattestation: false,
            rule_pack_id: None,
            tool_label: None,
        };
        let s = serde_json::to_string(&ev).unwrap();
        assert!(!s.contains("tool_label"));
        assert_eq!(ev, serde_json::from_str::<Evidence>(&s).unwrap());
    }

    #[test]
    fn ai_guard_risk_assessed_round_trips_tool_label() {
        let ev = Evidence::AiGuardRiskAssessed {
            tool: AiTool::Other,
            scope: AiGuardScope::UserGlobal,
            score: 1.0,
            bucket: AiGuardBucket::Medium,
            reasons: vec![],
            is_reattestation: false,
            rule_pack_id: Some("p".into()),
            tool_label: Some("acme-ai".into()),
        };
        let s = serde_json::to_string(&ev).unwrap();
        assert!(s.contains(r#""tool":"other""#) && s.contains(r#""tool_label":"acme-ai""#));
        assert_eq!(ev, serde_json::from_str::<Evidence>(&s).unwrap());
    }

    #[test]
    fn ai_guard_scope_project_serializes_with_path() {
        let s = AiGuardScope::Project {
            path: std::path::PathBuf::from("/Users/alice/code/repo-a/.claude"),
        };
        let j = serde_json::to_string(&s).unwrap();
        assert!(j.contains("\"kind\":\"project\""));
        assert!(j.contains("\"path\":\"/Users/alice/code/repo-a/.claude\""));
        let back: AiGuardScope = serde_json::from_str(&j).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn ai_guard_reason_external_script_serializes_with_kind() {
        let r = AiGuardReason::ExternalScriptUnscanned {
            hook_event: "PreToolUse".into(),
            script_path: std::path::PathBuf::from("/usr/local/bin/foo.sh"),
        };
        let j = serde_json::to_string(&r).unwrap();
        assert!(j.contains("\"kind\":\"external_script_unscanned\""));
        assert!(j.contains("\"script_path\":\"/usr/local/bin/foo.sh\""));
        let back: AiGuardReason = serde_json::from_str(&j).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn ai_guard_risk_assessed_clean_assessment_empty_reasons_round_trips() {
        let ev = Evidence::AiGuardRiskAssessed {
            tool: AiTool::Codex,
            scope: AiGuardScope::UserGlobal,
            score: 0.0,
            bucket: AiGuardBucket::Low,
            reasons: vec![],
            is_reattestation: false,
            rule_pack_id: None,
            tool_label: None,
        };
        let s = serde_json::to_string(&ev).unwrap();
        assert!(s.contains("\"reasons\":[]"), "got: {s}");
        assert!(s.contains("\"bucket\":\"low\""));
        assert!(s.contains("\"tool\":\"codex\""));
        let back: Evidence = serde_json::from_str(&s).unwrap();
        assert_eq!(back, ev);
    }

    #[test]
    fn host_meta_snapshot_full_round_trips() {
        let snap = HostMetaSnapshot {
            hostname: Some("alice-mbp".into()),
            os_name: Some("macOS".into()),
            os_version: Some("14.5".into()),
            kernel_version: Some("23.5.0".into()),
            architecture: Some("arm64".into()),
            interfaces: vec![NetworkInterface {
                name: "en0".into(),
                mac: Some("00:1b:44:11:3a:b7".into()),
                ipv4: vec!["192.168.1.42/24".into()],
                ipv6: vec!["fe80::1/64".into()],
            }],
            default_gateway_v4: Some("192.168.1.1".into()),
            default_gateway_v6: None,
            dns_servers: vec!["1.1.1.1".into(), "8.8.8.8".into()],
        };
        let ev = Evidence::HostMetaSnapshot {
            snapshot: snap.clone(),
            is_reattestation: false,
        };
        let s = serde_json::to_string(&ev).unwrap();
        assert!(s.contains(r#""kind":"host_meta_snapshot""#), "got: {s}");
        assert!(s.contains(r#""is_reattestation":false"#), "got: {s}");
        let back: Evidence = serde_json::from_str(&s).unwrap();
        match back {
            Evidence::HostMetaSnapshot {
                snapshot,
                is_reattestation,
            } => {
                assert_eq!(snapshot, snap);
                assert!(!is_reattestation);
            }
            other => panic!("expected HostMetaSnapshot, got {other:?}"),
        }
    }

    #[test]
    fn host_meta_snapshot_with_all_nones_round_trips() {
        let snap = HostMetaSnapshot {
            hostname: None,
            os_name: None,
            os_version: None,
            kernel_version: None,
            architecture: None,
            interfaces: Vec::new(),
            default_gateway_v4: None,
            default_gateway_v6: None,
            dns_servers: Vec::new(),
        };
        let ev = Evidence::HostMetaSnapshot {
            snapshot: snap.clone(),
            is_reattestation: true,
        };
        let s = serde_json::to_string(&ev).unwrap();
        let back: Evidence = serde_json::from_str(&s).unwrap();
        match back {
            Evidence::HostMetaSnapshot {
                snapshot,
                is_reattestation,
            } => {
                assert_eq!(snapshot, snap);
                assert!(is_reattestation);
            }
            other => panic!("expected HostMetaSnapshot, got {other:?}"),
        }
    }

    #[test]
    fn snapshot_file_change_event_jsonl() {
        let ev = Event {
            schema_version: SCHEMA_VERSION,
            event_id: Uuid::parse_str("01910f5a-1234-7890-abcd-ef0123456789").unwrap(),
            ts: datetime!(2026-05-08 14:23:45.123 UTC),
            host_id: "5A7C3E91-FIXED-FOR-SNAPSHOT".into(),
            // Pinned (not AGENT_VERSION) so the snapshot stays stable across
            // version bumps — this test asserts the JSONL shape, not the version.
            agent_version: "0.1.0".into(),
            severity: Severity::Warn,
            source: SourceKind::FileSystem,
            subject: Subject::Path {
                value: PathBuf::from("/Users/alice/.claude.json"),
            },
            evidence: Evidence::FileChange {
                change_kind: FileChangeKind::Modified,
                before_hash: Some("a1b2c3".into()),
                after_hash: Some("d4e5f6".into()),
                recheck_hash: Some("d4e5f6".into()),
                rename_from: None,
                size_after: Some(1843),
                evidence_quality: EvidenceQuality::Definitive,
            },
            target_id: Some("claude-desktop-config-macos".into()),
        };
        let line = serde_json::to_string(&ev).unwrap();
        insta::assert_snapshot!(line);
    }

    #[test]
    fn ai_tool_claude_desktop_round_trips_as_snake_case() {
        let t = AiTool::ClaudeDesktop;
        let j = serde_json::to_string(&t).unwrap();
        assert_eq!(j, "\"claude_desktop\"");
        let back: AiTool = serde_json::from_str(&j).unwrap();
        assert_eq!(back, AiTool::ClaudeDesktop);
    }

    #[test]
    fn ai_tool_continue_dev_round_trips_as_snake_case() {
        let t = AiTool::ContinueDev;
        let j = serde_json::to_string(&t).unwrap();
        assert_eq!(j, "\"continue_dev\"");
        let back: AiTool = serde_json::from_str(&j).unwrap();
        assert_eq!(back, AiTool::ContinueDev);
    }

    #[test]
    fn ai_guard_scope_application_round_trips() {
        let s = AiGuardScope::Application {
            app: "claude_desktop".into(),
        };
        let j = serde_json::to_string(&s).unwrap();
        assert_eq!(j, r#"{"kind":"application","app":"claude_desktop"}"#);
        let back: AiGuardScope = serde_json::from_str(&j).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn ai_tool_gemini_cursor_serde_round_trip() {
        let g: AiTool = serde_json::from_value(serde_json::json!("gemini")).unwrap();
        assert_eq!(g, AiTool::Gemini);
        let c: AiTool = serde_json::from_value(serde_json::json!("cursor")).unwrap();
        assert_eq!(c, AiTool::Cursor);
        assert_eq!(
            serde_json::to_value(AiTool::Gemini).unwrap(),
            serde_json::json!("gemini")
        );
        assert_eq!(
            serde_json::to_value(AiTool::Cursor).unwrap(),
            serde_json::json!("cursor")
        );
    }

    #[test]
    fn destructive_in_hook_script_round_trip_empty_chain() {
        let r = AiGuardReason::DestructiveInHookScript {
            pattern: "rm -rf".into(),
            hook_event: "PreToolUse".into(),
            script_path: PathBuf::from("/tmp/hook.sh"),
            snippet: "rm -rf /tmp/foo".into(),
            source_chain: Vec::new(),
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: AiGuardReason = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn destructive_in_hook_script_round_trip_populated_chain() {
        let r = AiGuardReason::DestructiveInHookScript {
            pattern: "rm -rf".into(),
            hook_event: "PreToolUse".into(),
            script_path: PathBuf::from("/tmp/entry.sh"),
            snippet: "rm -rf /tmp/foo".into(),
            source_chain: vec![
                PathBuf::from("/tmp/entry.sh"),
                PathBuf::from("/tmp/helper.sh"),
            ],
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: AiGuardReason = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn new_reason_variants_serialize_with_snake_case_tags() {
        let t = AiGuardReason::TrustedMcpServer {
            server_name: "acme".into(),
        };
        let j = serde_json::to_value(&t).unwrap();
        assert_eq!(j["kind"], "trusted_mcp_server");
        assert_eq!(j["server_name"], "acme");

        let a = AiGuardReason::AutoApprovalEnabled {
            mode: "auto_edit".into(),
        };
        let j = serde_json::to_value(&a).unwrap();
        assert_eq!(j["kind"], "auto_approval_enabled");
        assert_eq!(j["mode"], "auto_edit");
    }

    #[test]
    fn hook_invocation_event_round_trips() {
        let ev = Evidence::HookInvocation(HookInvocationEvidence {
            agent: AiTool::ClaudeCode,
            peer_uid: 1000,
            agent_session_id: None,
            tool_use_id: Some("tu".into()),
            action_kind: "bash".into(),
            other_label: None,
            action_hash: "cd".repeat(32),
            action_preview: Some("ls".into()),
            capture_level: "redacted".into(),
            capture_status: "ok".into(),
        });
        let j = serde_json::to_string(&ev).unwrap();
        assert!(j.contains("\"kind\":\"hook_invocation\""));
        let back: Evidence = serde_json::from_str(&j).unwrap();
        assert_eq!(back, ev);
    }

    #[test]
    fn unknown_evidence_kind_does_not_fail_deserialize() {
        let j = r#"{"kind":"some_future_kind","whatever":1}"#;
        let back: Evidence = serde_json::from_str(j).unwrap();
        assert!(matches!(back, Evidence::Unknown));
    }

    #[test]
    fn unknown_source_kind_does_not_fail_deserialize() {
        let j = r#"{"kind":"some_future_source"}"#;
        let back: SourceKind = serde_json::from_str(j).unwrap();
        assert!(matches!(back, SourceKind::Unknown));
    }

    #[test]
    fn destructive_in_hook_script_old_json_missing_chain_deserializes_empty() {
        // Backward compat: 3b.3-era events have no source_chain field.
        // AiGuardReason uses internally-tagged serde (tag = "kind", snake_case).
        let old_json = serde_json::json!({
            "kind": "destructive_in_hook_script",
            "pattern": "rm -rf",
            "hook_event": "PreToolUse",
            "script_path": "/tmp/hook.sh",
            "snippet": "rm -rf /tmp/foo"
        })
        .to_string();
        let r: AiGuardReason = serde_json::from_str(&old_json).unwrap();
        match r {
            AiGuardReason::DestructiveInHookScript { source_chain, .. } => {
                assert!(source_chain.is_empty());
            }
            other => panic!("expected DestructiveInHookScript, got {other:?}"),
        }
    }

    #[test]
    fn ai_guard_risk_assessed_omits_rule_pack_id_when_none() {
        let ev = Evidence::AiGuardRiskAssessed {
            tool: AiTool::Gemini,
            scope: AiGuardScope::UserGlobal,
            score: 0.0,
            bucket: AiGuardBucket::Low,
            reasons: vec![],
            is_reattestation: false,
            rule_pack_id: None,
            tool_label: None,
        };
        let s = serde_json::to_string(&ev).unwrap();
        assert!(!s.contains("rule_pack_id"));
        let back: Evidence = serde_json::from_str(&s).unwrap();
        assert_eq!(ev, back);
    }
    #[test]
    fn ai_guard_risk_assessed_round_trips_rule_pack_id() {
        let ev = Evidence::AiGuardRiskAssessed {
            tool: AiTool::Gemini,
            scope: AiGuardScope::Project { path: "/r".into() },
            score: 1.0,
            bucket: AiGuardBucket::Medium,
            reasons: vec![],
            is_reattestation: false,
            rule_pack_id: Some("my-pack".into()),
            tool_label: None,
        };
        let s = serde_json::to_string(&ev).unwrap();
        assert!(s.contains(r#""rule_pack_id":"my-pack""#));
        assert_eq!(ev, serde_json::from_str::<Evidence>(&s).unwrap());
    }

    #[test]
    fn hook_decision_evidence_serializes_snake_case() {
        let ev = Evidence::HookDecision(HookDecisionEvidence {
            agent: AiTool::ClaudeCode,
            peer_uid: 501,
            agent_session_id: Some("s".into()),
            tool_use_id: None,
            action_kind: "bash".into(),
            action_hash: "ab".repeat(32),
            action_preview: Some("rm -rf /".into()),
            decision: "deny".into(),
            rule_id: Some("no-rm-rf-root".into()),
            deny_reason: Some("destructive".into()),
            enforcement_mode: "enforce".into(),
            capture_level: "redacted".into(),
        });
        let s = serde_json::to_string(&ev).unwrap();
        assert!(s.contains("\"kind\":\"hook_decision\""));
        assert!(s.contains("\"decision\":\"deny\""));
        let back: Evidence = serde_json::from_str(&s).unwrap();
        assert_eq!(back, ev);
    }
}
