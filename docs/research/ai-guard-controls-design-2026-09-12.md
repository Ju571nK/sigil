# AI Guard Controls Contract

Date: 2026-09-12. Design for #207; implementation contract for #199 gap 6 and
#200 gap 5. Status: mechanism implemented on `codex/issue-207-controls`;
product-specific reporting and manager display remain follow-ups.

## Decision

Record observed hardening settings as `controls` alongside `reasons` in
`Evidence::AiGuardRiskAssessed`. The endpoint supplies observations; the fleet
plane preserves them. Controls are report-only and never subtract risk weights,
change buckets, suppress findings, or authorize actions.

An observation means that a supported configuration source explicitly enables a
recognized restriction. It does not attest that the running product enforced it.
Absent settings are silent. Disabled, malformed, unsupported, or overridden
settings must not be presented as active controls.

This issue settles the representation and delivery contract. Product-specific
parsers and claims about current vendor behavior remain in #199/#200, subject to
the repository's documentation and hardware compatibility gate.

## Repository Baseline

Reviewed sigil `e483f3e`:

- [Parser trait](../../crates/sigil-agent/src/ai_guard/parser/mod.rs) returns only
  `Vec<AiGuardReason>`.
- [Task](../../crates/sigil-agent/src/ai_guard/task.rs) hashes reasons to decide
  whether to emit and whether an emission is a reattestation.
- [Evidence](../../crates/sigil-core/src/event.rs) and
  [RiskEntry](../../crates/sigil-server/src/fleet_index.rs) store findings only.
- [Scan CLI](../../crates/sigil-agent/src/scan_cli.rs) runs parsers independently
  of the daemon; it must use the same assessment contract.
- [Fleet update](../../crates/sigil-server/src/fleet_index_update.rs) stores the
  latest assessment per tool, not per `(tool, scope, rule_pack_id)`.
- The adjacent sigil-manager checkout decodes typed `ToolRisk`, assessment, and
  event payloads in `internal/fleet/client.go`; adding server fields alone does
  not deliver them through every manager response.

## Data Shape

Introduce the following shared type in `sigil-core::event`:

```rust
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct AiGuardControl {
    pub id: String,
    pub source_path: PathBuf,
    pub setting: String,
    pub value: serde_json::Value,
}
```

The enclosing event supplies tool, scope, timestamp, and rule-pack identity.
`id` is a stable, namespaced identifier such as `claude_code.disable_auto_mode`;
it is a string so an unfamiliar future ID does not break deserialization.
Consumers display unfamiliar IDs as observations, without inferring mitigation.

`source_path` identifies the actual configuration source read by the parser.
`setting` is its exact dotted key. `value` contains only the normalized,
allowlisted restriction value: a boolean, enum string, or bounded list of enum
strings. Do not copy whole configuration objects, credentials, environment
variables, commands, or unrelated text. An enabling value can be `false` for a
setting that disables a capability; truthiness alone is not the predicate.

Add this field to the event and its projections:

```rust
#[serde(default, skip_serializing_if = "Option::is_none")]
controls: Option<Vec<AiGuardControl>>,
```

| Wire value | Meaning |
| --- | --- |
| Omitted or `null` | This assessment does not report controls; capability is unknown. |
| `[]` | Supported control inspection completed; no active controls were observed. |
| Nonempty array | Listed controls were observed within this assessment's scope. |

An empty array does not mean all possible defenses were inspected or disabled.
The producer version and documented parser coverage bound that interpretation.
Do not omit `Some([])`: doing so would erase the distinction from an older agent.
Only resolved supported settings qualify. If required source reads fail, use the
existing assessment error path; never convert failure into a successful empty
control snapshot. Retained observations keep their previous assessment timestamp.

## Parser And Event Flow

Add `AiGuardAssessment { reasons, controls }` in the agent parser module and an
`assess_posture(home_dir)` trait method. Its default wraps existing `assess()`
results with `controls: None`, preserving existing parser implementations.
Both daemon and scan call `assess_posture`. A migrated parser computes reasons
and controls from the same parsed inputs; its legacy `assess()` projects the
reasons from that helper without recursive trait calls or duplicate reads.

Normalize controls in a shared assessment helper: sort by their full serialized
tuple and remove exact duplicates. Different sources remain distinct. Parsers
resolve configuration precedence before producing observations; the framework
does not guess vendor precedence or treat a project file as managed policy.

Keep the existing reason hash algorithm and scoring unchanged. Add a separate
canonical controls hash, preserving the `None` versus `Some([])` distinction.
`CachedAssessment` compares both hashes and retains controls for IPC. Controls
appearing, changing, or disappearing trigger a normal assessment event even when
the score stays constant. Reordering or exact duplication does not. An unchanged
heartbeat is a reattestation; a control-only change is not.

Existing dangerous-toggle drift remains reason-driven. Removing a control emits
the replacement assessment, not a new weighted finding or toggle-drift alert.
Keep the existing assessment severity policy for this additive change; generic
event counts can rise when a control changes, but risk alert classification still
depends on the existing bucket. Do not describe this as a new security alert.

## Display And Fleet Delivery

`sigil scan --json` includes the optional controls on each assessment row.
Human output adds a compact `Observed controls` section only when at least one
control is present, grouped by tool and scope with setting, value, and source.
No empty section, missing-control warning, score discount, or extra remediation
entry is added. A control-only row must not be classified as unconfigured.

Carry the same optional array through `RiskSummary` IPC, `RiskEntry`, fleet host
detail and assessment history projections. Existing risk summaries, filters,
rankings, and counts continue to use reasons and scores. Audit explicit JSON
builders as well as typed structs so projections do not silently drop controls.

Each new assessment replaces its predecessor's controls, including an empty or
unreported result. Never retain old controls when newer evidence stops reporting
them. The existing per-tool fleet entry receives only controls from that entry's
exact assessment; never union controls across user/project/rule-pack scopes.
Use scoped event history when all scopes are needed. Fixing the fleet key is a
separate change, and the current projection must not claim complete host coverage.

Update manager's typed decoding and rendering in a companion change before
claiming manager support. Older manager versions may omit the new observations;
they must continue to display existing risk information correctly.

The companion decoder change targets `ToolAiGuard` and `EvidenceAiGuard` in
`sigil-manager/internal/fleet/client.go`. Add `Controls *[]AiGuardControl` with
the JSON tag `controls,omitempty` to preserve absent versus present-empty
arrays; use string IDs/paths/settings and `json.RawMessage` for restriction
values. The host-detail `ai_guard.by_tool` and event history are the sources;
the compact `current_risk.by_tool` rollup remains score-only. Cover omitted,
null, empty, populated, and unknown-ID payloads through decode and reserialize
before enabling display. Manager code is not changed by this sigil branch.

## Compatibility And Rollout

Use additive fields with serde defaults; retain schema version 1. Unknown control
IDs round-trip as strings, and unknown object fields follow normal serde handling.
No new evidence or reason enum variant is required.

| Producer / consumer | Required result |
| --- | --- |
| Old agent / new server | Existing event accepted; controls remain unreported. |
| New agent / old server | Existing risk accepted; unknown controls may be dropped. |
| New agent / new server | Controls survive ingest, history, index rebuild, and API projection. |
| New server / old manager | Existing risk still usable; controls may be omitted by typed decoding. |
| Old server / new manager | Missing controls produce no active-control claim. |

Acceptance is distinct from retention: a consumer ignoring unknown fields may
discard them when reserializing. Upgrade the server before enabling reporting
parsers. Do not promise recovery of observations discarded by an old consumer.
The fleet index rebuild must restore controls from persisted new-format evidence
and tolerate historical events without them; no separate controls database is
needed for this contract.

## Implementation And Acceptance

1. Add the core type, optional event field, default parser adapter, and shared
   normalization. Existing parsers report `None` until explicitly migrated.
2. Wire daemon hashes, cached observations, scan output, and IPC. Use a synthetic
   parser fixture to exercise controls without claiming vendor support.
3. Preserve observations through server ingest/storage, replay, fleet projections,
   and mixed-version fixtures. Prepare the companion manager decoder change.
4. Implement #199/#200 mappings after date-stamped official-source and local
   version checks, including precedence, source trust, and hardware limitations.

Required regression cases for the mechanism implementation:

- Old JSON deserializes with unreported controls; empty and populated arrays
  round-trip distinctly; unknown IDs do not reject an assessment.
- Identical reasons with different controls retain identical scores and buckets.
- Control addition, value/source change, removal, and reporting capability change
  emit; order and duplicate changes do not; heartbeat flags remain correct.
- A failed assessment does not publish an empty successful snapshot.
- An empty personal scan keeps its current human output; a control-only row is
  visible; JSON and daemon use the same normalization.
- Fleet replacement clears stale controls, preserves scope, and survives replay;
  same-tool assessments from different scopes never borrow each other's controls.
- Mixed-version consumers accept fixtures; any field loss is explicitly tested
  and documented. Existing findings and alerts remain unchanged.

The mechanism tests use synthetic control observations. They cover schema
round-trips, daemon change detection, scan rendering, and HTTP ingest through
fleet detail, JSONL history, and replay. No production parser reports controls
yet; #199/#200 must supply product-specific predicates and compatibility evidence.
