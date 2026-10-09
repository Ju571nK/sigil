# P0 contract independent review — 2026-09-27

Task: `P0-contract-review` / reviewer. **Status: needs_changes; scoped review complete, P0 not approved.**

Reviewed the working-tree candidate `contracts/README.md`, `proxy-event.schema.json`,
`invocation-started.example.json`, and `check_schema.py` against `spec.md`, the
2026-09-27 repository survey, and supporting `design.md`/`plan.md`.
Repository baseline: `24eddb26b8810224c95df6812f23b5901c11dff6` (survey baseline).
Line references below refer to the candidate reviewed on this date.
Only this report was edited; no commits were made.

## Findings requiring changes

### R1 — High: metadata fields lack a trusted-source/privacy rule

- **Location:** `contracts/proxy-event.schema.json:72–85`; `contracts/README.md:43–45`.
- **Evidence:** `method`, `protocol_version`, and `tool_name` accept arbitrary bounded
  strings. Actor and upstream identifiers have provenance rules, but these fields
  have no equivalent rule restricting them to accepted protocol values or an
  approved metadata representation. Local schema probes accepted
  `method="canary-secret-in-method"` and `tool_name="canary-secret-in-tool-name"`.
  The checker only rejects additional raw-data properties; it does not test this
  path. This is a contract exposure, not evidence of an implemented leak.
- **Impact:** a rejected/malformed client call or untrusted upstream tool name can
  place secret-bearing text in ordinary audit storage/API/UI if an implementer
  copies these fields directly. Merely allowlisting field names does not establish
  PX-009/010 and AC-05's metadata-only privacy boundary.
- **Fix:** specify provenance and normalization per field. Record only supported
  method/version constants, with a fixed safe representation for unknown values;
  explicitly decide how tool names enter the default audit (trusted registered
  identifier or a separately access-controlled metadata reference). Do not assume
  a regex, truncation, or generic redaction makes arbitrary names non-sensitive.
  Add producer/ingestion canary cases through these fields, including rejected calls.
  A schema alone cannot prove provenance; document the semantic validation layer.

### R2 — Medium: a successful `tools/call` audit need not identify its tool

- **Location:** `contracts/proxy-event.schema.json:82–85,119–126`.
- **Evidence:** deleting `tool_name` from the supplied `tools/call` example still
  validates. There is no conditional requirement or semantic exception described
  for a malformed/rejected call.
- **Impact:** schema-conforming records can omit which tool was invoked, frustrating
  the product's core observation objective and PX-006/012, AC-01. Manager cannot
  recover the name from arguments because those are correctly excluded.
- **Fix:** require the safe tool identifier for valid `tools/call` starts; define a
  separate bounded representation for malformed calls where no valid tool exists.
  Add positive non-tool-method and negative missing-tool cases. Resolve together
  with R1 so requiring a name does not require copying arbitrary client text.

### R3 — Medium: the checker's two valid lifecycle examples conflict at ingestion

- **Location:** `contracts/check_schema.py:13–20`; `contracts/README.md:38,41`.
- **Evidence:** completion is a deepcopy of the start with only `event_type`,
  `sequence`, and payload changed. It retains the start's `event_id`. Both pass
  the checker individually, but the documented identical-ID/different-payload
  rule requires a 409 if the pair is ingested.
- **Impact:** the advertised two valid events cannot serve as a valid lifecycle
  fixture and can teach a producer to reuse an invocation's event ID across stages.
  This undermines PX-006/011 and AC-01/06 contract evidence, though it is not a
  production deduplication defect.
- **Fix:** allocate a distinct completion event ID while retaining invocation ID.
  Explicitly assert that distinct lifecycle events have different event IDs;
  use a separate unchanged retransmission fixture and a conflicting-reuse negative
  fixture when ledger tests are available. Keep schema and ledger validation claims separate.

## Decisions that still prevent P0 completion

These are acknowledged draft gaps, **not claims that the candidate has already
implemented insecure behavior**. `contracts/README.md:86–90` correctly prohibits
declaring P0 complete while these decisions remain. Freeze them before dependent
production implementation; draft/fixture work can continue.

| Area / references | Required resolution and acceptance linkage |
|---|---|
| Authentication / `README.md:54–60,69–71,104–106` | Define the manager-to-server identity/permission mapping, authenticated operator attribution, target scopes for list/read/manage, and audited mutations. Bind every event in a batch to the authenticated proxy, not merely to any registered proxy; define the same binding for config and future heartbeat. Specify browser CSRF/Origin controls and how the manager backend reaches an mTLS listener. Survey findings show existing shared fleet read bearer and equal-permission login cannot supply these guarantees. PX-007–009/012/014; AC-04/08/13. |
| API/secret DTOs / `README.md:52–66,88–89` | Complete registration/upstream/route grants, config, heartbeat/status, inventory and invocation response schemas, including caller-specific secret references only, management audit, and unsupported-type behavior. Existing config GET is proxy-only; specify how an authorized manager obtains a safe editable view without acquiring a proxy identity or secret values. New endpoints may resolve this; the table is explicitly a candidate. PX-005/009/012/016; AC-01/02/05/13. |
| Local versus central durability / `README.md:62,78–82` | Name line 78's `durable ACK` as local spool commit if that is intended. Central durable acceptance at line 62 is a different boundary: waiting for it before dispatch would contradict `design.md`'s valid-config offline relay and AC-06. Define durable sequence allocation/restart, stable proxy identity/state loss behavior, completion-loss recovery and reserved audit-gap reporting. PX-011/013/016; AC-06/12. |
| Ledger semantics / `README.md:37–48,95–98` | Define canonical payload comparison, immutable invocation ownership and correlation invariants, duplicate sequence handling, out-of-order starts/completions, and event/projection/tombstone retention against maximum retry age. `(proxy_id,event_id)` dedup plus transactional ACK is a sound candidate, but does not by itself settle these cases. PX-006/011/015/016; AC-03/06/12. |
| Lifecycle / `proxy-event.schema.json:149–181` | Define permitted outcome/delivery combinations and projection state transitions. The schema currently accepts `success` with `not_sent`; either schema or semantic validation must reject contradictory records. `cancel_requested` must not prove execution stopped or prevent recording a later success/error/unknown result. Define whether it is a nonterminal event/flag or how later completion is represented. State what duration and response byte counts measure on partial delivery. PX-003/006/015; AC-03/07. |
| Traffic / `README.md:75–84,88–89` | Freeze protocol/capability support, downstream auth and principal/session isolation, SSRF/redirect/DNS/Origin rules, and numeric byte/concurrency/time/spool limits. Specify oversized/partial SSE responses, disconnect/cancel propagation, and bounded memory/backpressure/shutdown. A bounded streaming buffer alone does not establish total throughput or concurrency bounds. PX-002–004/008/013/014; AC-04/07/08/12. |
| Baselines / `README.md:100–102` | Preserve comparable complete-pagination/scope rules and explicitly prevent removal inference from incomplete inventories. Separate metadata access controls and immutable first baseline from later snapshots and approvals, as the survey recommends. PX-005/010; AC-02/05. |

D-01 through D-05 and the actual-client/version support evidence remain the
orchestrator's completion gates. This review does not settle SDK/MSRV choice,
configuration TTL/reload/secret-file platform behavior, performance targets, or
hardware compatibility. P2 policy and P3 approval/OAuth decisions can remain
deferred; their absence is not a P1 defect. The candidate's omission of human
actor classification is conservative, not an escalation of self-reported identity.

## Positive contract properties

- Host events and proxy ledger remain separate; current host high-watermark
  ingestion is not misrepresented as sufficient deduplication.
- Explicit registered proxy identity and rejection of the old read credential
  for management/ingestion are sound boundaries pending the concrete mapping.
- Closed objects reject raw argument/result/error additions. Actor IDs must come
  from authenticated mappings; human claims are not accepted by the schema.
- Transactional durable central acceptance, all-or-nothing batches, retained spool
  for unknown versions/types, out-of-order receipt, and safe fixed errors are stated.
- Proxy re-execution is prohibited; client retries are not falsely promised
  idempotent. Disk exhaustion defaults to rejecting new calls, and completion
  storage failure does not claim to roll back upstream effects.
- No compatibility/enforcement gate is removed or declared satisfied by documents.

## Verification performed and limits

Executed:

```text
/tmp/sigil-proxy-schema-check-20260927/bin/python docs/specs/sigil-proxy/contracts/check_schema.py
PASS: schema, 2 valid events, 8 rejected invalid/privacy cases
```

Additional in-memory probes using that interpreter, `Draft202012Validator` and
`FormatChecker` accepted: method canary, tool-name canary, `tools/call` without
`tool_name`, and completion `success/not_sent`. The checker event-ID conflict was
confirmed by source inspection. These are schema/fixture observations, not live
privacy, authorization, relay, or durability tests.

Did not inspect `scripts/proxy-p0` (active writer), change production/manager,
run real clients, contact upstream services, or run server/manager integrations.
No claim of hardware verification, complete P0 verification, or P1 readiness.
Next: contract owner resolves R1–R3 and the applicable freeze decisions, then
targeted independent re-review and separate fixture/protocol verification.
