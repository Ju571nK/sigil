# P0 follow-up review checkpoint

2026-09-27 · **Independent re-review not completed.**

The initial independent [review](review-p0.md) found R1–R3.
The assigned coder changed contracts only and reported fixes, and the coordinator
reran the checker successfully: 24 positive cases, 60 rejected cases, lifecycle IDs,
unchanged retransmission and conflicting-reuse assertions.

This test result is not independent approval of those fixes. The follow-up review
attempt `ctx_ced4fae98e2a` failed to start (terminal showed `zsh: parse error near )`);
retry `ctx_4876e7ff14cd` ended in `app-server session could not be restored`.
Both exact failed executions were stopped. No independent findings report was delivered.

Resume with a new authoritative review of R1–R3, lifecycle semantics and fixture code.
The coordinator independently reran fixture smoke + 14 unit tests successfully,
but real proxy/vendor-client/server/manager E2E remains not_run.
P0 is open; production implementation readiness is not approved.

## P0 targeted independent re-review — 2026-10-10

Task: `P0-targeted-rereview` (resumes failed runs `ctx_ced4fae98e2a` and
`ctx_4876e7ff14cd`) · role: reviewer · base commit `cdd1d1d` (main).
**Verdict: needs_changes. Recommendation: do not close D-03 (or D-02/D-05) on this contract.** Closure decisions belong to the orchestrator.

Scope: [initial review](review-p0.md) findings R1–R3, how the event contract defines the
invocation lifecycle, and the P0 fixture code. Specs: PX-003/006/007/009/010/011/012/015,
AC-01/03/05/06/07, D-01/D-02/D-03/D-05 (scope addition: metadata registry and revision pin). Files reviewed (read-only): `contracts/README.md`,
`proxy-event.schema.json`, `invocation-started.example.json`, `check_schema.py`,
`scripts/proxy-p0/{fixture,smoke,test_fixture}.py` and their README, plus spec/design/validation/decisions
and the 2026-09-27 research notes. Contracts and fixtures are in a single commit (`97db268`), so
there is no separate fix diff to compare. The review covers the current file content.
Only this file was edited. Nothing was committed or pushed.

### R1–R3 status

| ID | Status | Evidence |
|---|---|---|
| R1 metadata provenance/privacy | **Resolved at contract/schema scope.** Enforcement is unimplemented by design | `method` and `protocol_version` are closed enums (`proxy-event.schema.json:73–89`). Free-text `tool_name` was replaced by a closed `tool` object holding an opaque `metadata_ref` or a fixed `unavailable` reason (`:121–161`). The provenance, registry binding and access-controlled lookup rules are in `contracts/README.md:133–199`. Canary negatives for method/version/tool-name on identified and rejected starts are at `check_schema.py:52–95`. Residual issues: registry DTOs, sync and offline resolution are still open (`README.md:197–199`). A UUID-shaped secret passes format validation, which the README acknowledges at `:192–195`. A separate free-text path in the envelope is still open (N1). |
| R2 `tools/call` without a tool | **Resolved** | The conditional `if method=tools/call then required tool else not tool` is at `schema:171–195`. The checker includes `missing tool` (`check_schema.py:70–73`), `tool on <method>` negatives for every non-call method (`:100–106`) and positive unavailable starts (`:78–82`). |
| R3 lifecycle event-ID conflict | **Resolved for the original defect** | Each lifecycle event gets a fresh event ID through `variant()` (`check_schema.py:22–37`). Distinct IDs, increasing sequences and a shared invocation/proxy ID are asserted at `:134–139`. A separate unchanged retransmission and a conflicting reuse are at `:140–146`. New gap: the conflict fixture mutates only the payload, and the dedup rule compares payload only (N2). |

The related initial-review lifecycle item is addressed in the schema. `success/not_sent` is now
rejected (`schema:252–288`), and `cancel_requested` is a separate nonterminal event type with
an ID-only payload (`schema:293–318`, `README.md:203–211`).

### Lifecycle semantics review

- **Outcome taxonomy (PX-006).** The success, tool_error, protocol_error, timeout, unknown and
  denied outcomes are distinct. Cancel-requested is correctly an observation and not a terminal
  outcome. The delivery matrix (`README.md:213–228`) is sound and is enforced by the schema.
  Gaps: the outcome after a cancellation with no response, and task-augmented calls, are undefined (N4).
- **Unknown result (PX-015/AC-03).** "Response loss is unknown, never success or not-run" is
  stated consistently. `unknown/not_sent` is restricted to established non-dispatch
  (`README.md:225–226`). The cross-event restriction on unavailable-tool starts is semantic
  only. That is acceptable if the ledger enforces it, but no test exists yet.
- **Event-ID dedup (PX-011/AC-06).** Dedup uses unique `(proxy_id,event_id)` with transactional
  ACK. A higher sequence does not discard lower missing events (`README.md:37–43`). The equality
  domain is underspecified (N2). Canonicalisation, retention/tombstones, duplicate-sequence
  handling and out-of-order rules are still open. That alone blocks D-03.
- **Principal/actor separation (PX-007/AC-04).** The schema cannot express `human`. A
  `human` value is rejected (`check_schema.py:56`), so self-declared human=true cannot be
  promoted through this contract. `actor_id` must come from the authenticated mapping
  (`README.md:45`). Gaps: no provenance rule exists for `actor_kind` or `credential_owner_id`,
  `evidence_source` from `design.md:46` is dropped, and an unauthenticated or unverified
  downstream cannot be represented (N3).

### Findings

#### N1 — Major: the checker silently skips `date-time` validation; `occurred_at` accepts arbitrary text

- **Location:** `check_schema.py:3,12,18`; `contracts/README.md:113–121`; `schema:22–25`.
- **Evidence:** I installed `jsonschema==4.26.0` exactly as documented (no extras).
  `FormatChecker().checkers` then contains `uuid` but not `date-time`, because
  `rfc3339-validator` is not installed. Probe results: `occurred_at="not-a-date"` and
  `occurred_at="canary-secret"` are **accepted**. The checker still prints PASS because it has
  no `occurred_at` negative.
- **Impact:** a free-text field remains in every event envelope, which is the same class as R1
  (PX-010/AC-05). The documented checker setup also gives false assurance that format
  constraints are enforced.
- **Fix direction:** pin the format extra (`rfc3339-validator`, or `jsonschema[format-nongpl]`
  with exact versions). Fail fast if `date-time`/`uuid` are missing from the active
  FormatChecker. Add bad-timestamp and canary-timestamp negatives. State that ingestion must
  parse `occurred_at` as RFC 3339 independently of JSON Schema format support.

#### N2 — Major: dedup equality covers the payload only, so envelope-level conflicting reuse is treated as a duplicate

- **Location:** `contracts/README.md:39`; `check_schema.py:142–146`.
- **Evidence:** the rule says only "same event_id with the same canonical payload" is a
  duplicate. The conflict fixture changes only `payload.duration_ms`. I probed a record with
  the same event ID and payload but a different `sequence` and `occurred_at`. It is
  schema-valid, and under the written rule it would be ACKed as a duplicate.
- **Impact:** a producer bug or a replayed or modified record that reuses an event ID with a
  different sequence, timestamp, or (if payloads collide) event type would be silently
  merged. That would hide sequence gaps and conflicting reuse (PX-011/AC-06, D-03).
- **Fix direction:** define canonical equality over the full submitted event (all envelope
  fields plus payload, excluding only server-assigned `received_at`). Define the treatment of
  the same sequence with a different event ID. Add envelope-mutation conflict fixtures for
  sequence, occurred_at, event_type and schema_version. Keep these as fixture claims until a
  ledger test exists.

#### N3 — Major: the actor object cannot represent an unverified or unauthenticated downstream, and owner/kind provenance is unstated

- **Location:** `schema:90–120,163–170` (actor required; `authentication_method` is only
  `bearer|mtls`); `contracts/README.md:25,45`; `design.md:46`; `spec.md:27` (PX-007).
- **Evidence:** the README requires TLS and authentication only for external binds, which
  implies a loopback listener may be unauthenticated. No schema-valid start exists for such a
  call. PX-007 requires unverified values to be `unknown`. The README gives the provenance of
  `actor_kind` and `credential_owner_id` nowhere; it only covers `actor_id`.
  `evidence_source` from the design model is absent.
- **Impact:** a producer must either invent an authentication method (a false verification
  claim) or drop the event (a hidden audit gap). An unspecified `credential_owner_id` could be
  displayed as "who acted", which blurs executor and permission owner (PX-007/023, D-02). This
  is not a human-promotion path today, but D-02 cannot close on it.
- **Fix direction:** either make downstream authentication mandatory on every listener,
  including loopback (a D-02 decision), or add an explicit `none`/`unknown` method with
  `actor_kind=unknown` and a fixed actor representation. State that `actor_kind` and
  `credential_owner_id` come only from the authenticated registration, never from client
  input. State that `credential_owner_id` is the permission owner, not evidence of who
  executed. Either restore or explicitly drop `evidence_source`. Any future `human` value
  stays behind D-07.

#### N4 — Major: 2025-11-25 lifecycle cases are undefined (task-augmented calls; cancellation with no response)

- **Location:** `contracts/README.md:133–146,201–228`; `schema:80–89,219–234`.
- **Evidence (official docs, fetched 2026-10-10):** the
  [2025-11-25 changelog](https://modelcontextprotocol.io/specification/2025-11-25/changelog)
  adds experimental [tasks](https://modelcontextprotocol.io/specification/2025-11-25/basic/utilities/tasks)
  (SEP-1686) for deferred result retrieval. The
  [cancellation page](https://modelcontextprotocol.io/specification/2025-11-25/basic/utilities/cancellation)
  says task-augmented requests MUST use `tasks/cancel` instead of `notifications/cancelled`.
  It also says that receivers of a cancellation SHOULD NOT send a response, and the sender
  SHOULD ignore a late response. The contract says nothing about tasks: `tasks/*` would audit
  as `method=unknown`. It also does not say which terminal outcome applies when a cancellation
  is followed by no response.
- **Impact:** a task-augmented `tools/call` that returns a task handle would be recorded as
  `success`, even though no tool result was observed (PX-003/006). The real result would be
  fetched later under an unattributed `unknown` method. After an honoured cancellation the
  proxy would likely record `timeout`, which misattributes a client-requested stop as an
  upstream deadline. It could also hold the invocation open until the 120 s call limit
  (`validation.md:86`).
- **Fix direction:** for P1, explicitly reject or refuse to negotiate task augmentation and the
  tasks capability, with a fixed rejection per PX-003. Do not silently relay it. Otherwise,
  model the task lifecycle before support. Define the terminal mapping after an observed
  cancellation with no response (for example `unknown`/`sent` after a bounded grace period),
  and reserve `timeout` for the proxy-enforced deadline. Record this documented behaviour as
  unverified on real clients (D-01 gate). The research notes also list a newer revision,
  2026-07-28, with different session semantics (`sigil-proxy-compatibility-2026-09-27.md:24–25`).
  The audit vocabulary pin must be revisited when D-01 selects the matrix.

#### N5 — Minor: fixture fault injection does not cover the timeout, cancel and partial-response outcomes

- **Location:** `fixture.py:17,185–188,218–222`; acknowledged in `scripts/proxy-p0/README.md:49–52`
  and `validation.md:59`.
- **Evidence:** there is no slow or hanging tool, so `timeout` cannot be produced. Every
  notification except `initialized` gets HTTP 400, so a relayed `notifications/cancelled` is
  rejected and the cancel flow cannot be exercised. The only drop happens before the
  headers, so partial `response_bytes` and truncated SSE after a 200 are never produced
  upstream. The SSE truncation test covers only the client decoder (`test_fixture.py:118–121`).
- **Impact:** the fixture can exercise only 4 of the PX-006 classes (success, tool_error,
  protocol_error, unknown). AC-03 is partly covered, and AC-07 and cancel/timeout are not.
- **Fix direction:** add `hang` (beyond the timeout), `drop_mid_sse` (headers plus partial data,
  then close), and accept-and-count `notifications/cancelled` (202) with a tool that honours
  cancellation by never responding. Gate each with counter assertions.

#### N6 — Minor: fixture leniencies could let future proxy E2E tests pass falsely

- **Location:** `fixture.py:86–91` with `test_fixture.py:79`; `fixture.py:140`; `fixture.py:217`;
  `fixture.py:96`; `fixture.py:173`.
- **Evidence and impact:**
  - A missing `MCP-Protocol-Version` is accepted on an established session. The spec allows
    this, but a proxy that strips the header would pass undetected.
  - `Accept` is checked by substring, so `application/json-seq` would satisfy it.
  - Retry detection (`by_id`) uses only the JSON-RPC id, not the session. Through a proxy that
    rewrites or multiplexes ids, or with several sessions, duplicates can alias or be masked.
  - The `/_fixture/counters` oracle is served on the same listener as `/mcp`. A proxy that
    forwards arbitrary paths could reach it.
  - `initialize` always answers with the single revision and never exercises an
    unsupported-version error.
- **Fix direction:** for proxy-E2E mode, add a strict option that requires the version header
  after init. Parse `Accept` media types. Key counters by `(session, id)` and also record raw
  arrival order. Serve the oracle on a separate loopback port. Add a variant that rejects
  unsupported versions. The smoke/self-test results remain fixture-only either way.

#### N7 — Minor: unbounded or float-tolerant integers

- **Location:** `schema:18–21,69–72,236–243`.
- **Evidence:** the probe accepted `sequence=2^70`, `route_revision=2^70`, `duration_ms=2^70`
  and `sequence=1.0`.
- **Impact:** values overflow the i64/u64 storage expected for a Rust/SQLite ledger. They also
  invite producer/consumer canonicalisation mismatches that interact with N2.
- **Fix direction:** add `maximum` (for example 2^63−1). Require integer JSON tokens in the
  semantic layer and in the canonical form.

#### N8 — Minor: specification drift and initialize-version clarity

- `design.md:47` still lists `tool_name?` on Invocation, which contradicts the contract's
  prohibition (`README.md:163`).
- The schema accepts `protocol_version="2025-11-25"` on an `initialize` start (probe). The
  revision is negotiated only in the response, so the README should state that initialize
  starts always use `unknown`.

### Scope addition: metadata registry, offline relay and D-05

**Question: does the contract as written require central resolution before forwarding?**
The contract does not state that requirement directly. Its rules combined imply it for any
tool without a locally held reference. Evidence:

1. A valid `tools/call` start must carry `{"status":"identified","metadata_ref"}`. The
   reference is "allocated by the controlled metadata registry", and "the producer resolves
   the parsed tool name against that scoped entry before emitting the reference"
   (`contracts/README.md:165–173`).
2. The start must reach the local spool's durable commit **before** dispatch
   (`README.md:79`).
3. If no reference can be resolved, the only representation is `unavailable/unresolved`. That
   is defined as a pre-dispatch rejection, whose completion must be `not_sent` with
   `protocol_error` or `denied` (`README.md:174–179`).
4. Ingestion must not durably accept unknown or out-of-scope references (`README.md:195`).
   Batches are all-or-nothing (`README.md:61–64`).

Unless the registry can allocate references locally on the proxy, any call to a tool not
already resolved is therefore rejected while the server is unreachable. The same applies when
an offline `tools/list` shows a changed definition and creates a new metadata revision. This
contradicts `design.md:22`, which says relay continues with the last valid configuration while
the server is disconnected. `README.md:197–199` names the risk ("must not silently turn a
central metadata lookup into a pre-dispatch online dependency") but provides no mechanism.
Point 4 adds a liveness risk. If references are allocated locally but registry entries reach
the server after the events, a whole batch is rejected with 422. That batch then sits at the
head of the spool and blocks later events (PX-011/AC-06).

#### N9 — Major: metadata registry allocation, sync ordering and offline resolution are unfrozen

- **Location:** `contracts/README.md:160–199`; `design.md:22`; `decisions.md` D-05 row.
- **Impact:** an implementer must pick one of two silent failure modes. The first is to fail
  closed: reject unresolved calls offline. That breaks the offline-relay design, and because
  "unresolved" means pre-dispatch rejection, it also amounts to a P1 block on tools missing
  from the inventory, which is enforcement behaviour that `README.md:228` disclaims. The
  second is to fail open: forward and invent or omit a reference, which violates R1/R2. The
  ledger can also stall on unknown-reference batches.
- **Fix direction:** freeze the items below for D-05 and add them to the contract before P1.

What must be frozen for D-05 (recommendation, not a closure decision):

| Item | Needs to state |
|---|---|
| Allocation authority | Whether the proxy allocates references locally under its authenticated identity, with central adoption later (needed for offline relay), or only centrally. If only centrally, state explicitly that unseen tools are rejected offline, and record that as an accepted deviation from `design.md:22`. |
| Scope key | The exact tuple, for example proxy visibility, `upstream_id`, credential/visibility scope, protocol revision, observation source, tool name and metadata revision (cf. `README.md:105,169–171`). State whether `route_revision` is part of the key. If it is, every route edit re-mints references for unchanged tools. |
| Fingerprint versioning | The canonicalisation algorithm and its version identifier for the definition fingerprint. It should cover name, description, input/output schema, annotations and the 2025-11-25 icons. Changing the algorithm must not appear as tool drift. State whether the fingerprint is keyed, since a plain hash of secret-bearing descriptions is still derived content, and keep it in the access-controlled store. |
| Offline resolution order | Use the local cache from the last *complete* paginated inventory. Define what happens to a tool name absent from it (reject as unresolved, or forward under a separately defined state). An incomplete inventory must never remove entries (PX-005). |
| Sync ordering | Registry entries must be ingested before, or atomically with, the events that reference them. Define how ingestion treats an event whose reference is not yet registered (a retryable status, not a permanent 422) so the spool cannot deadlock. |
| Retention | A registry entry outlives every event referencing it, together with its dedup tombstones. Deleted metadata displays the fixed unavailable label (`README.md:188`). |

### Does a D-01 revision other than 2025-11-25 invalidate the R1 conclusion?

**The privacy part holds. The provenance part needs a contract revision.** R1 is resolved
because `protocol_version` and `method` are closed vocabularies with a literal `unknown`
fallback, and because tool identity is an opaque reference. None of that depends on which
revision is pinned. Adding another revision, such as an earlier one or the 2026-07-28
revision listed in `docs/research/sigil-proxy-compatibility-2026-09-27.md:24–25`, means
adding another enum constant. If an implementation selects a different revision without
updating the contract, every event degrades to `unknown`. That loses information but leaks
nothing.

Two parts would be invalidated:

1. The provenance rule "emit the revision only from validated *negotiated* protocol context"
   (`README.md:139–142`) and the `initialize`/session vocabulary assume a session-based
   revision. The research notes describe 2026-07-28 as using per-request metadata, with
   session semantics that differ from earlier revisions. Under such a revision the rule would
   need to say which per-request value is validated, and how. The method list would also need
   revisiting, since `initialize` may not apply.
2. The scope key and offline resolution for `metadata_ref` (N9) assume session-level tool
   inventories.

A revision must never be added by turning `protocol_version` into a pattern or a free string,
because that would reopen R1. I did not read the 2026-07-28 documents myself. That part relies
on the repository's research notes and must be rechecked at D-01.

### Commands run (exact results)

```text
# isolated venv outside the repo (session scratchpad):
python3 -m venv <scratch>/venv
<scratch>/venv/bin/pip install -q jsonschema==4.26.0
  -> attrs 26.1.0, jsonschema 4.26.0, jsonschema-specifications 2025.9.1, referencing 0.37.0, rpds-py 2026.9.1
<scratchpad>/venv/bin/python -B docs/specs/sigil-proxy/contracts/check_schema.py
  -> PASS: schema, 24 positive cases, 60 rejected cases; lifecycle IDs, unchanged retransmission
     and conflicting-reuse fixture assertions   (exit 0)
python3 -B scripts/proxy-p0/smoke.py   (Python 3.14.6, Darwin 25.6.0 arm64)
  -> 5 PASS lines incl. "accepted-call drop: outcome=unknown client_attempts=1 fixture_invocations=1",
     "total_invocations=4" (exit 0)
python3 -B -m unittest discover -s scripts/proxy-p0 -p 'test_*.py'
  -> Ran 14 tests in 6.223s, OK (exit 0)
<scratchpad>/venv/bin/python -B <scratchpad>/probe.py docs/specs/sigil-proxy/contracts
  -> FormatChecker date-time=False uuid=True; ACCEPT for: occurred_at "not-a-date"/"canary-secret",
     hex-encoded metadata_ref, same event_id+payload with different sequence/occurred_at,
     initialize start with 2025-11-25, timeout/not_sent, unknown/not_sent, integers 2^70, sequence 1.0
```

The interpreter path `/tmp/sigil-proxy-schema-check-20260927` from earlier runs no longer
exists, so a fresh venv was used. The probe script is a throwaway in the session scratchpad
and is not part of the repository. The test passes above are not independent approval.

### Not verified / limits

- Producer normalization, registry provenance, ledger 409/canonical comparison, transactional
  ACK, restart durability, retention and out-of-order ingestion: no implementation exists to test.
- No real proxy, vendor client, upstream, server or manager was run, and no hardware
  verification was done. The fixture results establish no production or client compatibility.
- The official MCP documents were read for 2025-11-25 changelog and cancellation only. Tasks
  semantics were not exercised. No installed client was checked for tasks or cancel behaviour.
- The open D-02/D-03 items from the initial review (auth mapping, API/DTO, durability
  boundaries, retention/tombstones, traffic limits) are unchanged and still block closure,
  independent of N1–N8.

### Verdict and recommendation

**needs_changes.** R1–R3 are resolved within the contract and schema scope. N1–N4 and N9 are
major, and the ledger/DTO items from the initial review remain open.

My recommendation to the orchestrator:
- do not close D-03 on this contract;
- do not close D-02 until N3 is decided;
- do not close D-05 until the N9 table is frozen;
- treat the revision pin as a D-01 input as described above.

This report closes no P0 or D item; that decision is the orchestrator's. Fixture and draft
work can continue. `scripts/proxy-p0/probes/` (coding-lead's area) was outside this review.

Next: the contract owner addresses N1–N4 and N9 (N5–N8 as convenient), then a targeted
independent re-check, then separate T-01 protocol/client verification.
