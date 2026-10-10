# Proxy ledger, projection and query contract (D-03 candidate)

2026-10-10 · candidate v0.1 · scope: PX-005/006/010/011/012/016, AC-02/05/06/12.
Nothing here closes D-03, claims an implementation, or changes the frozen ingest
contract ([proxy-event.schema.json](proxy-event.schema.json) v0.3, README dedup/epoch/batch-error
rules). Every numeric value is an **initial test value (D-04), not a guarantee**.
The checker models in `check_schema.py` are fixtures, not a ledger.

Status tags: **[DC]** decided-candidate (reviewable, consistent with frozen text),
**[OPEN]** needs a decision or evidence before it can be fixed.

## L0. Item index

| Item | Section | Status |
|---|---|---|
| (1) retention and tombstone durations | L1 | [DC] formulas and P1 initial defaults; O-1 decided (option A) |
| (2) invocation projection | L2 | [DC] |
| (3) query DTOs, cursor, gap rendering | L3, L4 | [DC] DTO shape; [OPEN] gap list endpoint, scope model |
| (4) cross-event semantic validation | L5 | [DC] SV-1..SV-4, SV-6..SV-8; [OPEN] SV-5 (needs config DTO) and the new fixed error codes |
| status endpoint, gap upsert and ACK | L6b | [DC]; endpoint name and codes [OPEN] for README |
| inventory/drift read projections | registry.md R7b | DTO [DC]; endpoint names/permission [OPEN] |
| (5) m6 aggregate counters | L6 | [DC] |

## L1. Retention and dedup tombstones

### Terms

| Symbol | Meaning |
|---|---|
| R | `producer.max_offline_retry_age`: the longest age (now − `occurred_at`) at which the producer still retransmits an unsent event |
| M | safety margin for clock skew and a lost ACK (`ack_loss_margin`) |
| E | `server.event_retention`: how long accepted event rows and projections are kept |
| T | `server.dedup_tombstone_retention`: how long a tombstone is kept after acceptance |
| Q | `producer.quarantine_retention` (README N11: at least E) |

A tombstone is `(proxy_id, event_id, epoch_id, sequence, sha256(canonical event))`.
It carries no payload and is small by design. A resubmission within the window is
recognised as a duplicate (equal canonical event) or a 409 (different).

### Rule

A retransmission of an accepted event happens at most R after its `occurred_at`.
Acceptance happens at or after `occurred_at`, so the server must recognise the
`event_id` for **at least R + M after acceptance**. Therefore:

```
dedup_window = max(E, T)        # event rows also answer dedup lookups
T >= R + M                      # startup invariant; the server refuses to start otherwise
E >= R + M                      # an event must outlive any legitimate retransmission
Q >= E
```

### Parameters (candidate defaults; bounds are configuration validation)

R and E are **server-issued**: they are fields of the applied central configuration
revision, and the proxy echoes the values it applied in its status report
(`config.max_offline_retry_age_seconds`, `config.event_retention_seconds`). The
server validates a configuration before it issues it and refuses (422) any value
outside the bounds below or any combination that breaks the invariants, so the
proxy never runs with `T < R + M` or `E < R + M`. Q is not separately configured on
the proxy: the proxy keeps quarantined originals for `max(configured, E)`, so
`Q >= E` always holds. T and M are server-side. The proxy has no input to T.

| Parameter | Default | Bounds |
|---|---|---|
| `producer.max_offline_retry_age` (R) | 30 days | 1 hour – 90 days |
| `ack_loss_margin` (M) | 7 days | 1 hour – 30 days |
| `server.event_retention` (E) | 90 days | R+M – 365 days |
| `server.dedup_tombstone_retention` (T) | = E | R+M – 730 days |
| `producer.quarantine_retention` (Q) | = E | E – 730 days |
| spool, acknowledged-event retention | 24 hours | per validation.md (existing D-04 row) |

Related lifetimes:

- **Projection** (L2): kept while any constituent event row is kept. An invocation
  expires as one unit at `last_received_at + E`.
- **Registry entry**: at least as long as every referencing event and its
  tombstones (README N9 retention row). The scope-bound stub outlives deleted content.
- **Gap records** (L4): at least E from `detected_at`.
- **Inventory snapshots** (registry.md R7): the latest complete snapshot and the
  immutable first baseline of a `(proxy_id, scope key, canon, key_id)` chain are kept
  for the life of the chain. A superseded non-baseline snapshot is kept at least E
  after it was superseded.
- **Drift records and re-baseline markers**: at least E from `detected_at`.
- **Registry entries** outlive every reference to them: events and tombstones (above),
  snapshot membership, drift records, markers and rotation links. Deleting content
  keeps the stub.
- **Heartbeat state**: latest report per proxy only; counters are cumulative (L6).
- Retention uses server `received_at`, never `occurred_at`. Ledger lookup never
  depends on receipt date (survey T-00 finding on `find_by_id`).

### Expiry of unsent events (O-1, decided: option A)

Decided 2026-10-10 (decisions.md D-02/O-1 row; validation.md updated). After R, an
unsent event is moved unchanged to local quarantine and a `spool_expired` gap
(proxy-status.schema.json) is reported. It is never deleted silently and never
looks normal. This is what bounds retransmission age, so `T >= R + M` has a finite R
and tombstones are bounded. The numbers in this section are the P1 initial
defaults adopted with the D-04 values. They are initial test values to be adjusted
after measurement, not performance or retention guarantees. Option B (never expire,
unbounded per-epoch ranges and hashes) was rejected.

### Cases (mirrored in `check_schema.py`)

| Case | Expected |
|---|---|
| R=30d, M=7d, E=90d, T=90d | valid |
| T < R + M | startup refused |
| E < R + M | startup refused |
| Q < E | startup refused |
| resubmission at occurred_at + R, accepted at occurred_at + 1d, T = R + M | recognised |
| resubmission after tombstone expiry | accepted as new; invocation projection flags `duplicate_completion`/`duplicate_start` (L2) |

## L2. Invocation projection

### Key and inputs

The record key is `(proxy_id, invocation_id)`. Inputs are the accepted
`invocation.started`, `invocation.cancel_requested` and `invocation.completed`
events for that key, each identified by `event_id`. P1 has no decision event, so
`decision` is a reserved field that is always `null` (a decision event is a new
contract; PX-017 is P2).

### Properties **[DC]**

1. **Order independent and idempotent.** The projection is a pure function of the
   *set* of accepted events. Any arrival order, and any repetition of an equal
   event, yields the same semantic fields (checker: all permutations).
2. **No success without a corroborated lifecycle.** `outcome` is set only when both
   the start and a consistent completion are observed (`lifecycle = completed`).
   A start-only record and a completion-without-start both have `outcome = null`,
   so neither can match an `outcome=success` filter or render as success.
3. **No inference.** The server never converts a missing completion into
   `unknown`, `timeout` or `success`. `unknown`/`not_sent` etc. are only what the
   proxy reported (PX-015).
4. **Cancel is nonterminal.** `cancel_requested` sets `cancel_observed`. It does not
   set an outcome, does not finalise, and a late arrival does not replace a
   completed projection (README R3).
5. **Contradictions are flagged, never repaired.** See rules below.

### Fields

| Field | Source / rule |
|---|---|
| `invocation_id`, `proxy_id` | key |
| `lifecycle` | enum below |
| `outcome`, `delivery_state`, `reason?` | the single completion; `null` unless `lifecycle = completed` (a completion whose start was observed and is consistent) |
| `reported_outcome`, `reported_delivery_state`, `reported_reason?` | what a completion claimed when `lifecycle` is `integrity_conflict` or `completion_without_start`. Proxy-reported and uncorroborated; never a headline value and never matched by the `outcome` filter. `null` otherwise |
| `duration_ms`, `response_bytes` | from the completion, else `null` |
| `method`, `protocol_version`, `upstream_id`, `route_revision`, `actor`, `tool` | from the start, else `null` |
| `tool` | `{status:identified, metadata_ref}` or `{status:metadata_unavailable, reason}` or `{status:unavailable, reason}`; never a name (PX-010) |
| `cancel_observed` | true if any `cancel_requested` event exists |
| `decision` | reserved, `null` |
| `started_at`, `completed_at` | proxy `occurred_at` of the start/completion; proxy clock, unverified |
| `first_received_at`, `last_received_at` | min/max server `received_at` over constituent events |
| `start_epoch_id` | the start's `epoch_id`, else `null` |
| `epoch_superseded` | true when `lifecycle=started` and the proxy has since announced a newer epoch (gap `producer_epoch_change`) |
| `flags` | sorted array of fixed codes below |
| `event_count` | number of constituent events |

`lifecycle`:

| Value | Meaning |
|---|---|
| `started` | start observed, no completion. Render as "no completion observed", never as success. With `epoch_superseded` the completion may never arrive (lost epoch) |
| `completed` | start and completion observed and consistent |
| `completion_without_start` | completion arrived first or the start is lost. `outcome` is `null`; the proxy-reported value is shown only in `reported_outcome`. Request details are `null`. It can become `completed` when a consistent start arrives |
| `cancel_without_start` | only cancel observations so far |
| `integrity_conflict` | see flags; headline outcome is withheld |

`flags` (fixed codes, no values): `duplicate_start`, `duplicate_completion`,
`start_binding_conflict`, `completion_contradicts_start`.

### Rules

| Rule | Behaviour |
|---|---|
| P-1 two starts, distinct `event_id`, equal content (ignoring envelope id/sequence/epoch/occurred_at) | `duplicate_start`; headline unchanged |
| P-2 two starts, different content (including a different `tool` binding) | `integrity_conflict` + `start_binding_conflict` |
| P-3 two completions, equal content | `duplicate_completion`; headline unchanged |
| P-4 two completions, different content | `integrity_conflict` + `duplicate_completion` |
| P-5 completion contradicts the start (rules C-1..C-3) | `integrity_conflict` + `completion_contradicts_start`; no success shown |
| P-6 completion arrives before start | `completion_without_start`; becomes `completed` when a consistent start arrives |
| P-7 start-only, then its epoch is superseded | `started` + `epoch_superseded=true`; still `outcome=null` |

Contradiction rules (checked in both arrival orders, so the result is order independent):

- **C-1** start `tool.status=unavailable/malformed` ⇒ completion must be
  `protocol_error` or `denied` with `delivery_state=not_sent` (README R1/R2).
- **C-2** reason ↔ start method: `upstream_capability_unsupported`,
  `upstream_version_unsupported`, `upstream_initialize_unreadable` need start
  method `initialize`; `modern_request_unsupported` needs method `unknown` with
  protocol `unknown`; `task_augmentation_unsupported` with `not_sent` needs method
  `unknown`, and with `sent` needs method `tools/call`.
- **C-3** start `tool.status=unavailable` or `metadata_unavailable` carries no
  reference; the projection never attaches one.

**Flag, not reject (reconciling README R2/R3).** README R2 says semantic validation
must check reference allocation and scope binding and README R3 says a malformed
start "cannot later claim dispatch or success"; both say *restrict*, not *where*.
This contract splits them: checks decidable from one event plus registry/ownership
state (owner, reference known, reference scope; L5 SV-1..SV-5) reject at ingest.
Checks that compare two events of one invocation (C-1..C-3, duplicates) flag in the
projection. Rejecting those would make the outcome depend on arrival order and
would leave the surviving half looking normal. Flagging keeps both events (durable,
audited facts), withholds the headline outcome, and the restriction holds because
the contradicting completion can never be displayed as success. Decision to be
recorded in decisions.md by the orchestrator.

### Cases (mirrored in the checker)

| Case | Expected projection |
|---|---|
| start only | `started`, `outcome=null`, never success |
| completion then start (out of order) = start then completion | identical `completed` |
| cancel after completion | `completed`, `cancel_observed=true`, outcome unchanged |
| completion only (`success`/`sent`) | `completion_without_start`, `outcome=null`, `reported_outcome=success`, request fields `null`; never matched by `outcome=success` |
| equal retransmission applied twice | unchanged |
| malformed start + `success`/`sent` completion | `integrity_conflict`, headline `null` |
| malformed start + `denied`/`not_sent` | `completed` |
| `upstream_version_unsupported` on a `tools/call` start | `integrity_conflict` |
| two starts, different `tool.metadata_ref` | `integrity_conflict` |
| start-only, later epoch announced | `started`, `epoch_superseded=true` |

## L3. Query DTOs

All lists: `limit` default 100, max 500; response `{items, next_cursor}` where
`next_cursor` is `null` on the last page. Errors use the README error object with
fixed messages. Additional fixed codes proposed here, all **[OPEN]** for the README error table:
`invalid_cursor` (422), `invalid_filter` (422), `semantic_invalid` (422 item code),
`invocation_owner_conflict` (409 item code).
Ordering is fixed per endpoint; a client cannot choose it. The cursor is opaque,
base64url of `{v:1, <order key>, filter_hash}`, and `filter_hash` covers the
**endpoint, the sort definition and the normalised filters**. A cursor from another
endpoint, another sort, or another filter set is 422 `invalid_cursor`.

Filters on fields that can change after a row first appears (`connection_state`,
`config_in_sync`, `outcome`, `lifecycle`, `flags`) are **not snapshot-stable**: a
row can move into or out of the filter between pages. The immutable order key
guarantees no duplicate and no re-ordering, but a row that starts matching after the
client has passed its position is missed until the client queries again. Clients
that need completeness re-list from the start. Time and identity filters on immutable
fields are stable.

A filter value naming a `proxy_id` outside the caller's `proxy.read` range returns an
empty list, identical to an unknown `proxy_id` (no existence leak).
Nothing returned contains arguments, results, error text, tool names, session IDs
or tokens (PX-010). Names are available only through the scoped metadata lookup
(registry.md R6).

### GET /v1/proxies

Filters: `connection_state`, `config_in_sync` (bool). Order: `proxy_id` ascending;
cursor `{v:1, after_proxy_id, filter_hash}` (unique key, no tie-breaker needed).

`ProxySummary`:

| Field | Meaning |
|---|---|
| `proxy_id`, `display_name` | registration |
| `connection_state` | `connected` \| `disconnected` \| `never_connected`, derived at read: `connected` when `now − last_seen ≤ stale_after`. Never stored |
| `last_seen` | server time of the last authenticated contact (heartbeat or accepted ingest) |
| `desired_revision`, `applied_revision` | desired is the server's current revision; applied is proxy-reported |
| `config_in_sync` | `desired_revision == applied_revision`; `false` also when applied is null |
| `config_state` | `none` \| `valid` \| `expired` (proxy-reported) |
| `config_expires_at` | proxy-reported |
| `current_epoch_id` | latest announced epoch |
| `spool` | `{state, depth_events, bytes, capacity_bytes, oldest_unsent_age_seconds, as_of}` from the last heartbeat |
| `open_gap_count` | open audit gaps (L4) |
| `status_as_of` | server time of the heartbeat the status fields come from |

`stale_after` default 90 s = 3 × heartbeat interval (30 s; bounds 5–300 s). Initial
test values. Status fields describe the **last report**, not live state; clients
must show `status_as_of` and `connection_state` together (PX-016, AC-12).

### GET /v1/proxies/{id}

`ProxySummary` plus:

| Field | Meaning |
|---|---|
| `registry` | `{pending_entries, sync_stalled}` |
| `routes` | `[{upstream_id, state, reason?}]` route health, fixed enums (proxy-status.schema.json) |
| `central` | `{last_ingest_ack_at, consecutive_failures}` proxy-reported |
| `outages` | recent proxy-reported central outages (`central_outage` gaps), max 16 |
| `counters` | L6 |
| `audit_gaps` | newest-first, max 50, plus `audit_gaps_total` |
| `open_gap_counts` | object kind → count |

404 when the proxy is unknown or outside the caller's `proxy.read` range
(indistinguishable). **[OPEN]** a dedicated gap list endpoint is not added here;
`audit_gaps` (max 50) is the P1 candidate.

### GET /v1/proxy-invocations

Filters (all optional, combined with AND): `proxy_id`, `upstream_id`, `actor_id`,
`method`, `outcome`, `lifecycle`, `tool_ref` (a `metadata_ref`), `from`, `to`,
`time_basis`.

- `outcome` is one of the six completion outcomes. It matches only
  `lifecycle=completed` records. It never matches a record whose `outcome` is `null`
  (start-only, `completion_without_start`, `integrity_conflict`). Use `lifecycle` to
  find those.
- `from`/`to` are RFC 3339 UTC, half-open `[from, to)`. `time_basis=received`
  (default) filters `first_received_at` (server clock); `occurred` filters
  `started_at`/`completed_at` (proxy clock, unverified). Order is unaffected.
- Unknown filter names or values are 422 `invalid_filter`; values are not echoed.

**Order and cursor.** (Cursor binding rules are above.) Ordering is by the ledger commit counter of the invocation's
first accepted event (`created_seq`, unique, immutable once assigned), descending.
A record never moves between pages when later events arrive, and `created_seq`
is total, so no extra tie-breaker is needed. The cursor carries `created_seq`.
Where a future listing joins several sources, `(proxy_id, invocation_id)` is the
tie-breaker, included in the cursor.

`InvocationSummary` = the L2 fields except `event_count`, with `actor` as
`{actor_id, actor_kind, authentication_method, evidence_source, credential_owner_id?}`.
`credential_owner_id` is a permission owner, not an executor (README N3); manager
must label it so.

### GET /v1/proxy-invocations/{id}

`{id}` is `invocation_id` (a UUID). The record is unique because SV-1 binds an
`invocation_id` to the first proxy that submits it. Response: `InvocationSummary`
plus `events`:

```json
{
  "invocation_id": "7d9a2e10-5b3c-4a9f-8d21-0c4e6b8a1f33",
  "proxy_id": "proxy-demo",
  "lifecycle": "started",
  "outcome": null,
  "delivery_state": null,
  "cancel_observed": false,
  "decision": null,
  "epoch_superseded": true,
  "flags": [],
  "events_total": 1,
  "events_truncated": false,
  "events": [
    {"event_type": "invocation.started", "event_id": "…", "epoch_id": "…",
     "sequence": 1, "occurred_at": "2026-10-10T00:00:00Z",
     "received_at": "2026-10-10T00:00:01Z"}
  ]
}
```

`events` lists envelope identifiers only, never payloads, ordered by `created_seq`,
at most 32 items. `events_total` is the number of constituent events and
`events_truncated` is true when `events_total > 32`. Status codes:
401, 403 only when the caller has no `proxy.read` permission at all, and 404 for an invocation that is unknown **or** whose proxy is outside the caller's range (indistinguishable, same as GET /v1/proxies/{id}).

## L4. Audit gaps for rendering (PX-016)

`AuditGap` is an immutable record plus a derived `state`.

| Field | Meaning |
|---|---|
| `gap_id` | UUID; producer-assigned for proxy-reported gaps (stable across retransmission), server-assigned otherwise |
| `proxy_id`, `kind`, `source` (`server_derived` \| `proxy_reported`), `detected_at` | |
| `state` | `open` \| `closed`; only `sequence_gap` can close (when the missing sequences arrive) |
| `details` | fixed fields per kind; identifiers and counts only |

| `kind` | source | `details` |
|---|---|---|
| `producer_epoch_change` | server | `previous_epoch_id`, `epoch_id` |
| `sequence_gap` | server | `epoch_id`, `from_sequence`, `to_sequence`, `tail` (bool). A missing range below the highest accepted sequence (`tail=false`), or the range `(highest accepted + 1 .. last_assigned_sequence)` from the status report (`tail=true`, F13/AC-06). A tail can be events still in flight; it closes when they arrive and manager shows it with `spool.unsent_events` |
| `registry_conflict` | proxy | `metadata_ref`, `key_id`, `event_ids` (≤ 100), `affected_event_count`, `detected_by` |
| `event_quarantined` | proxy | `event_ids`, `code` (`conflict`, `sequence_conflict`, `semantic_invalid`) |
| `local_record_failed` | proxy | `count`, `invocation_ids` (completion could not be stored locally) |
| `spool_expired` | proxy | `epoch_id`, `from_sequence`, `to_sequence`, `count` (events moved to quarantine after R, O-1 option A) |
| `unrecorded_calls` | proxy | `count`, `from_at`, `to_at` (explicit allow-with-gap observe option only) |
| `central_outage` | proxy | `started_at`, `ended_at` (null while ongoing) |
| `inventory_incomplete` | server | `upstream_id`, `credential_scope_id`, `incomplete_reason`, `observed_at` |
| `comparison_inconsistent` | server | `inventory_id` (a deferred comparison whose `changes` did not match the membership difference; registry.md I-3) |

**Overflow.** If more than 100 events depend on the conflicting entry, the proxy
reports several gaps, each with its own `gap_id`, the same `metadata_ref`/`key_id`
and at most 100 `event_ids`, and every chunk carries the same total
`affected_event_count`. A report with `affected_event_count < len(event_ids)` is 422.

**Upsert.** Proxy-reported gaps are keyed by `(proxy_id, gap_id)` and applied
independently of `status_sequence`. See L6b.

Rendering rules for manager: a gap is never hidden by a later successful
retransmission; `sequence_gap` closes but stays listed. A `tool.reason =
registry_conflict` on an invocation is shown with the corresponding gap. Counts of
gaps are shown next to `connection_state` so a connected proxy with open gaps does
not look healthy.

## L5. Cross-event semantic validation at ingest

Schema validation cannot establish provenance or cross-event consistency (README R2).
The ledger runs these checks after schema validation and before the durable commit,
inside the same transaction as dedup (README T-00 boundary). Failures use fixed
codes and echo no values. The identity check comes first: a proxy identity mismatch
or unknown `proxy_id` is 404 `proxy_unknown`, byte-identical for both, evaluated
before body validation (control-plane.md; decisions.md D-02). Then precedence stays
422 > 409 > 424. 403 is unused on ingest (`/v1/proxy-events`), status, registry and
inventory endpoints.

| Rule | Condition | Result |
|---|---|---|
| SV-1 invocation owner | `invocation_id` already bound to another `proxy_id` | 409 item `invocation_owner_conflict` **[OPEN]**; producer quarantines the event (same handling as README N2) |
| SV-2 reference known | start `tool.metadata_ref` not registered for this proxy and not registered for any other proxy | 424 `metadata_ref_pending` (existing rule) |
| SV-3 reference ownership | the ref is registered, but under another proxy | 422 item `semantic_invalid` **[OPEN]** (index only; permanent). The 422-vs-424 difference reveals only that a ref is registered under *some* proxy; refs are keyed (unguessable without K), so this is accepted as a low-risk differential. Neither the ref value nor the owning proxy is echoed |
| SV-4 reference scope | registry entry `upstream_id` ≠ start `upstream_id`, or start `protocol_version` is not `unknown` and ≠ entry `protocol_version`, or the entry's `observation_source` is not `proxy_live` | 422 item `semantic_invalid` |
| SV-5 credential scope | the entry's `credential_scope_id` ≠ the scope the server assigned for `(proxy_id, upstream_id, route_revision)` and the actor's credential binding | 422 item `semantic_invalid` **[OPEN]**: needs the route/credential config DTO and its history (D-02) |
| SV-6 binding preserved | a second start for the same invocation with a different `tool` | accepted; projection P-2 `integrity_conflict` (no reject, order independent) |
| SV-7 completion vs start | C-1..C-3 | accepted; projection P-5 (no reject) |
| SV-8 completion without known start | any | accepted; projection `completion_without_start` |

Producer handling of 422 `semantic_invalid` and 409 `invocation_owner_conflict`:
quarantine the item unchanged, report `event_quarantined`, resubmit the rest.
Never rewrite or re-ID (README N2). A batch with any failing item accepts nothing
(README M2a), so the producer must remove only the named indexes before resend.

### Test cases (mirrored in the checker)

| Case | Expected |
|---|---|
| completion for an unknown invocation | accepted, `completion_without_start` |
| start for an `invocation_id` owned by another proxy | 409 `invocation_owner_conflict` |
| start with a ref registered only under another proxy | 422 `semantic_invalid`, index only, no ref in body |
| start with an unregistered ref | 424 `metadata_ref_pending`, ref listed |
| start whose ref entry has another `upstream_id` | 422 `semantic_invalid` |
| start `protocol_version=unknown` with a 2025-11-25 entry | accepted |
| malformed start, then `success`/`sent` completion | both accepted; projection `integrity_conflict`, never success |
| same malformed start and completion in reverse order | identical projection |
| completion order: second completion with different outcome | accepted; `integrity_conflict` |
| cancel before any start | accepted; `cancel_without_start` |

## L6. Aggregate counters for non-invocation failures (m6)

Authentication failures and cancellations that match no request are not
invocation events and create no actor (README bootstrap and Traffic sections).
Their aggregate form travels in the proxy status report
([proxy-status.schema.json](proxy-status.schema.json)), `POST /v1/proxy-status`.

- Shape: `[{upstream_id|null, reason, count}]`. `upstream_id` is the route the
  request resolved to; `null` means the request matched no route.
- `reason` is a fixed code. Auth failures: `credential_missing`, `credential_invalid`,
  `credential_expired_or_revoked`, `origin_rejected`, `session_principal_mismatch`.
  Unmatched cancels: `no_matching_request`, `window_expired`, `session_mismatch`.
- `count` is cumulative since the current `epoch_id` started and only increases.
  The server keeps the maximum seen per `(proxy_id, epoch_id, upstream_id, reason)`,
  so a lost or reordered heartbeat loses nothing.
- Bounded cardinality: routes × reasons, at most 1536 entries per report. No actor,
  header, token, address, session, request ID or any submitted value is part of the
  aggregate. A new reason code needs a contract update.
- Counters do not prove who attempted access, and the absence of a counter is not
  evidence that no attempt happened. They are not alerts.
- The server DTO (`counters` in GET /v1/proxies/{id}) returns the current epoch's
  values and, per previous epoch, only a total (`previous_epoch_totals`).

Cases: a report with an unknown reason, a reason on the wrong counter, an extra
field (for example `actor_id`, `source_address`, `token`), and a negative count are
rejected by the status schema; a lower later count is ignored by the model.

## L6b. POST /v1/proxy-status: state snapshot and gap upsert

Identity comes from the proxy mTLS certificate (as for `POST /v1/proxy-events`); the
body `proxy_id` must match it. The body is a `proxy_status` document (heartbeat
fields plus `gaps`).

**State snapshot.** Applied only if its `epoch_id` is new for the proxy, or it is the
current epoch with a higher `status_sequence` than the stored one. Otherwise
`state_applied=false` in the response; nothing else is affected.

**Gaps.** Independent of the snapshot. Each gap is upserted by `(proxy_id, gap_id)`:

| Existing | Incoming | Result |
|---|---|---|
| none | any valid gap | stored; id in `acknowledged_gap_ids` |
| canonically equal | equal | `duplicate_gap_ids` |
| `central_outage` with `ended_at = null` | same except `ended_at` is a timestamp | updated (the only allowed mutation); id in `acknowledged_gap_ids` |
| `central_outage` with `ended_at` set | `ended_at` null or another value | 409 `conflict` |
| any other difference | | 409 `conflict` |

A lower `status_sequence` or a stale epoch therefore never drops a gap.

| Status | When | Body |
|---|---|---|
| 200 | whole report valid | `{state_applied, acknowledged_gap_ids, duplicate_gap_ids}` |
| 404 | body `proxy_id` ≠ mTLS identity, or `proxy_id` unknown (byte-identical, evaluated first) | `{error:{code:"proxy_unknown",message}}` |
| 409 | a gap conflicts (table above) | `items:[{index, gap_id, code:"conflict"}]`; nothing from this report is applied |
| 413 / 429 / 503 | size, backpressure, storage | fixed error |
| 422 | schema invalid, `affected_event_count < len(event_ids)`, a `registry_conflict` ref or `key_id` unknown to the registry | `items:[{index, code}]`, index only |

**Gap ACK semantics.** A gap id in `acknowledged_gap_ids` or `duplicate_gap_ids` is
durable; the producer stops resending it. A `central_outage` gap with `ended_at =
null` is resent with the value when the outage ends, until acknowledged. A gap that
was not acknowledged is resent in every report. On 409 the producer quarantines the
named gap unchanged and resends the rest.

## L7. Evidence boundary

Proven by the checker: schema shape, the retention invariants as arithmetic, and
the projection/semantic/cursor rules as fixture models (including all event
permutations). Not proven: SQLite transaction behaviour, restart durability,
ledger performance, real producer behaviour, manager rendering, or any hardware
result. D-03 remains open until a ledger implementation and independent review
cover these rules, and SV-5 is decided.
