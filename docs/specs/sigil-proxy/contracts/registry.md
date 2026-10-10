# Metadata registry, key rotation and inventory/drift contract (D-05 candidate)

2026-10-10 · candidate v0.1 · scope: PX-005/009/010/011, AC-02/05/06.
Builds on the README "D-05 metadata registry (N9)", "Producer epoch (M1)" and N11 text,
which stay authoritative where this file is silent. Nothing here closes D-05 or
claims an implementation. Numeric limits are initial test values (D-04), not guarantees.
Schemas: [registry-entry.schema.json](registry-entry.schema.json) (entry, upload
request/response, read view, inventory report) and
[proxy-status.schema.json](proxy-status.schema.json) (gap reports).

Status tags: **[DC]** decided-candidate, **[OPEN]** needs a decision or evidence.

## R0. Item index

| Item | Section | Status |
|---|---|---|
| Entry DTO and JSON Schema | R1 | [DC] |
| Upload endpoint request/response | R2 | [DC]; identity check decided (404 `proxy_unknown`, D-02) |
| Key-rotation operations | R3 | [DC]; [OPEN] O-2 |
| History links across key_id | R4 | [DC]; [OPEN] O-3 |
| Re-baseline marker projection | R5 | [DC] |
| Scoped content lookup | R6 | [OPEN] (README already lists it as open) |
| Inventory report / drift event contract | R7 | [DC]; [OPEN] O-4 |

## R1. Registry entry

The immutable field set is exactly the README M2b set. The checker asserts that the
schema's `x-immutable-fields` equals the checker's equality set.

| Group | Fields | Rule |
|---|---|---|
| Immutable (identity and equality) | `proxy_id`, `metadata_ref`, `upstream_id`, `credential_scope_id`, `protocol_version`, `observation_source`, `canon`, `key_id`, `fingerprint` | Any difference under the same `(proxy_id, metadata_ref)` is a 409. |
| Volatile | `observed_at` (proxy clock, unverified), `definition` (the observed tool object) | Excluded from equality. First write wins; later values are ignored. |
| Server-assigned (read view only) | `registered_at`, `first_observed_at`, `last_observed_at`, `content_state` (`present` \| `deleted`) | Never submitted. |

The ordinary read view (`entry_view`) carries every immutable field **except
`fingerprint`**: the keyed fingerprint lives only in the access-controlled store
(README N9). The read view keeps `key_id` and `canon`, which are not secret.

- `definition` is untrusted content. It lives only in the access-controlled
  metadata store and is not part of any ordinary audit API (PX-010). The read view
  (`entry_view`) has no definition and no name.
- `fingerprint` is keyed (HMAC with K). The server never has K, so **it cannot verify
  that `fingerprint` matches `definition`**; it only compares fingerprints for
  equality. Integrity of that binding rests on the producer's local hash check
  (README N11 iii). The server must not present the definition as verified.
- A second upload with equal immutable fields and a different `definition` is a
  `duplicate` and the first definition is kept. **[OPEN]** O-5: whether to record a
  server-side integrity flag for this case. Without K the server cannot tell which
  is right.
- `protocol_version` and `canon` are closed enums. Adding a revision or a canon
  version is a contract update.
- Deleted content (privacy request) keeps the immutable stub so that ingest still
  recognises the ref (README retention row). `content_state=deleted` renders as the
  fixed unavailable label plus the reference.

## R2. Upload: POST /v1/proxy-metadata

Authentication: registered proxy mTLS identity; the body `proxy_id` must equal it.
Permission wiring for the manager/management side is not part of this endpoint.

Request (`upload_request`): `{schema_version:1, proxy_id, entries:[entry…]}`,
1–100 entries, 4 MiB body, 256 KiB per entry (initial test values).

Response 200 (`upload_response`): `{registered_metadata_refs, duplicate_metadata_refs}`.
It is durable before it is returned, and the producer records the immutable-field
hash when it receives it (README N11 iii).

Processing is all-or-nothing like `POST /v1/proxy-events`:

| Status | When | Body |
|---|---|---|
| 200 | every entry registered or an equal duplicate | as above |
| 404 | body `proxy_id` or any entry `proxy_id` ≠ mTLS identity, or the identity names an unknown proxy (byte-identical, evaluated first, before body validation) | `{error:{code:"proxy_unknown",message}}` |
| 409 | same `(proxy_id, metadata_ref)`, a different immutable field | `items:[{index, metadata_ref, code:"registry_conflict"}]` |
| 413 / 429 / 503 | size, backpressure, storage | fixed error |
| 422 | schema invalid, or the entry's `credential_scope_id` is not one the server assigned to this proxy and `upstream_id` | `items:[{index, code}]`, index only |

Precedence: the identity 404 first, then 422 > 409. 403 is unused on this endpoint. On 409 the producer follows README M2b: quarantine
the entry unchanged, record the gap, rewrite only dependent never-accepted starts,
and resend the remaining entries. A key or fingerprint value is never echoed.
**[OPEN]** the 409/422 `code` strings are new fixed codes to merge into the README
error table.

Sync ordering, 424 on unregistered refs and retention remain as in README N9.

## R3. Key-rotation operations

K is per-proxy, 256-bit, owner-only in `state_dir`, never transmitted, logged or
backed up. `key_id = "kid-" + hex24(SHA-256("sigil-key-id-v1\0" ‖ K))` is never reused.
A new K therefore re-mints every `metadata_ref`.

| Operation | Trigger | Epoch | Result |
|---|---|---|---|
| **Planned rotation** | operator action on the proxy host | unchanged (`epoch_id` and sequence continue) | New K and `key_id` are made durable. The next complete inventory per scope is reported as `rebaseline` (R7) with `reason=key_rotation` and `links` |
| **Canon version change** | a release that adds a canon version | unchanged | Same, with `reason=canon_version_change` |
| **State loss** | `state_dir`, spool or K unrecoverable (README M1) | **new** | New K/`key_id`. The proxy has no memory of earlier refs, so it reports `initial_baseline`. The server derives the marker (R5) |

Rules:

- A new `key_id` and a new `canon` start a new comparison domain. Drift is computed
  only between snapshots with an equal `(scope key, canon, key_id)`.
- The old K is not needed after rotation. Drift is never computed across keys, and
  refs already minted are in the local registry. The proxy therefore destroys the
  old K once the new K is durable and the first post-rotation inventory has been
  minted. **[OPEN]** O-2: whether a rollback window should keep the old K, which would
  keep a second secret alive.
- Events that reference old-key refs stay valid. Registry entries, tombstones and
  references are retained together (README retention row).
- Rotation is not an approval and does not reset any later policy decision (P2/P3
  would bind approvals to the definition hash; a re-baseline requires re-approval
  there, which is out of P1 scope).

## R4. Linking history across `key_id` without exposing K

The server cannot compute any link (no K, no names), so linking is a producer
assertion carried in the inventory report of a planned rotation:

```json
"comparison": {
  "kind": "rebaseline",
  "previous_inventory_id": "…",
  "reason": "key_rotation",
  "links": [
    {"from_metadata_ref": "…", "to_metadata_ref": "…", "definition_comparison": "identical"}
  ]
}
```

- Pairing is by the proxy's own local tool identity within the same scope key. It is
  not derived from the keyed fingerprint on the server.
- `definition_comparison` is `identical`, `different` or `not_comparable`. The proxy
  compares the old stored definition with the new one locally. It is **unverifiable by
  the server and shown as "proxy-asserted"**. It is not drift and creates no drift record.
- Only the refs, `key_id`s (already non-secret) and the closed comparison code are
  transmitted. K, fingerprints of the old key against the new key, and names are not.
- Under state loss no links exist. The history shows two chains separated by a marker
  and the `producer_epoch_change` gap.
- A tool with no counterpart is simply absent from `links`; it is neither added nor
  removed in the rebaseline.

**[OPEN]** O-3: whether `definition_comparison=different` should raise manager
attention. Without it, rotation could hide a definition change; with it, the server
relies on a producer assertion.

## R5. Re-baseline marker projection

The server derives one `RebaselineMarker` per complete snapshot that starts a new
comparison domain inside an existing `(proxy_id, scope key)` chain.

| Field | Meaning |
|---|---|
| `marker_id` | UUID assigned by the server |
| `proxy_id`, `upstream_id`, `credential_scope_id`, `protocol_version`, `observation_source` | the scope key |
| `inventory_id` | the snapshot that begins the new domain |
| `previous_inventory_id` | latest earlier complete snapshot in the same scope key, or `null` |
| `from_key_id`, `to_key_id`, `from_canon`, `to_canon` | what changed |
| `cause` | `declared_key_rotation`, `declared_canon_change`, `epoch_change_detected`, `key_change_undeclared`, `baseline_restated` |
| `links_present` | boolean |
| `drift_computed` | always `false` |
| `detected_at` | server `received_at` of the report |

Derivation:

1. A report with `comparison.kind=rebaseline` gives the `declared_*` causes.
2. A complete report with `initial_baseline` whose scope key already has an earlier
   complete snapshot under a different `key_id` or `canon` is a marker. The cause is
   `epoch_change_detected` when a `producer_epoch_change` gap exists between the two,
   otherwise `key_change_undeclared`. An `initial_baseline` with the same `key_id`
   and `canon` as an existing snapshot is `baseline_restated`; no drift is derived
   across it.
3. The first complete snapshot of a scope key with no earlier snapshot is the
   **initial baseline**. It is shown as a baseline, not as drift and not as an
   approval (PX-005).
4. A different `credential_scope_id` or `protocol_version` is a different scope key
   and a separate chain. There is **no marker and no comparison** across it. A
   change of visibility must not be shown as removals (AC-02). **[OPEN]** O-6:
   whether a cross-scope link is wanted in P1 (default: no).

A marker never creates `added`/`removed`/`changed` records. Manager shows it as
"baseline reset", with the cause and whether links exist.

## R6. Scoped content lookup (open)

README already records this as open. Candidate: `GET /v1/proxy-metadata/{metadata_ref}?proxy_id=…`,
permission `proxy.metadata.read` for that proxy and upstream/credential scope,
every access audited, content returned as untrusted text with its size bound,
fixed unavailable label when deleted. Possession of a UUID or ordinary
`proxy.read` is insufficient. Not specified further here.

## R7. Inventory and drift events

Transport: `POST /v1/proxy-inventory` (candidate; mTLS proxy identity), body is one
`inventory_report`. Inventory is **not** an invocation event, so the frozen
`proxy-event.schema.json` is untouched.

### Report

`inventory_report` fields: `schema_version`, `report_id` (idempotency key), `proxy_id`,
`epoch_id`, `observed_at`, `scope`, `canon`, `key_id`, `completeness`,
`pages_observed`. Then, by `completeness`:

| `completeness` | Required | Forbidden |
|---|---|---|
| `complete` | `inventory_id` (UUID of the snapshot), `members` (refs, ≤ 10,000), `comparison` | `incomplete_reason` |
| `incomplete` | `incomplete_reason` | `inventory_id`, `members`, `comparison` |

`incomplete_reason` is a closed enum: `page_limit_exceeded`, `tool_limit_exceeded`,
`size_limit_exceeded`, `page_error`, `cursor_invalid`, `access_denied`,
`session_ended`, `canonicalization_failed`, `ambiguous_name`.

A report is complete only under the README m5 definition (one authenticated session,
one scope, a chain from no cursor to a page without `nextCursor`, all pages
successful). Listings are client-driven; the proxy never lists on its own.

`comparison.kind`:

| Kind | Meaning | Extra fields |
|---|---|---|
| `initial_baseline` | no earlier complete snapshot known to the proxy | none |
| `compared` | same `(scope key, canon, key_id)` as `previous_inventory_id` | `changes[]` of `added`, `removed`, `changed` (`metadata_ref`, `previous_metadata_ref` for changed) |
| `rebaseline` | `key_id` or `canon` differs | `reason`, `links[]`; no `changes` |

Names never appear. `changed` pairs a new ref with the old ref the proxy matched by
its own local tool identity. This is producer-asserted.

### Server semantic validation

| Rule | Condition | Result |
|---|---|---|
| I-1 | proxy identity (404 `proxy_unknown`, evaluated first), scope assigned to this proxy (as R2) | 404 / 422 |
| I-2 | every member ref is registered for this proxy | 424 `metadata_ref_pending` listing the refs |
| I-3 | for `compared` with a known previous snapshot: set differences between `members` and the previous snapshot's members are fully covered by `changes` and `changes` contains nothing else (`added` ∈ members ∖ previous; `removed` ∈ previous ∖ members; `changed.metadata_ref` ∈ added side, `changed.previous_metadata_ref` ∈ removed side, each ref used once) | else 422 `semantic_invalid`, index only. When the previous snapshot arrives later (I-5) the same check runs then; a failure never un-ACKs the report. It records a `comparison_inconsistent` gap and derives no drift |
| I-4 | `report_id` seen with an unequal canonical report | 409 `conflict`; equal → duplicate |
| I-5 | `previous_inventory_id` unknown to the server | accepted and stored; comparison state `pending_previous`; no drift is derived until the previous snapshot arrives (order independent, no new status code) |
| I-6 | `previous_inventory_id` is a snapshot of another scope key, or (for `compared`) another canon or `key_id` | 422 `semantic_invalid` |
| I-7 | `rebaseline`: `(canon, key_id)` equals the previous snapshot's (nothing was rebaselined) | 422 `semantic_invalid` |
| I-8 | `rebaseline` links: every `from_metadata_ref` is a member of the previous snapshot, every `to_metadata_ref` is a member of this snapshot, and both are registered for this proxy; a ref used more than once on one side | 422 `semantic_invalid`; unregistered refs are 424 as in I-2 |

I-3, I-6, I-7 and I-8 are checked at ingest when the previous snapshot is known.
When it arrives later (I-5) the same checks run then; a failure there never un-ACKs
the report: it records a `comparison_inconsistent` gap and derives no drift and no
marker.

### Projection

- The **latest complete snapshot** and the **immutable first baseline** are kept
  separately per `(proxy_id, scope key, canon, key_id)` (T-00 and D-05 boundary).
- `DriftRecord`: `{drift_id, proxy_id, scope key, inventory_id, previous_inventory_id,
  change (added|removed|changed), metadata_ref, previous_metadata_ref?, detected_at}`.
  It is created only from a `compared` complete report, never from an incomplete one.
- An `incomplete` report creates one `inventory_incomplete` gap (ledger-and-query.md L4)
  and changes nothing else. The latest complete snapshot stays current, no tool is
  removed, and the next complete report compares against it.
- Evidence source is `proxy_live`. It is never mixed with the daemon HOME cache
  baseline (design.md, survey D-05).
- Every drift record is "observed change", not an approval decision.

### Cases (mirrored in `check_schema.py`)

| Case | Expected |
|---|---|
| first complete listing | initial baseline, no drift |
| second complete listing with one added, one changed, one removed | exactly three drift records |
| incomplete listing with fewer tools after a complete one | no removal; gap; latest snapshot unchanged |
| complete listing after that incomplete one | compared against the earlier complete snapshot |
| complete listing under a new `key_id`, declared rotation | marker `declared_key_rotation`, no drift, links kept |
| complete listing under a new `key_id`, no declaration, new epoch seen | marker `epoch_change_detected`, no drift |
| complete listing under a different `credential_scope_id` | separate chain, no marker, no removals in the old chain |
| `changes` not matching the membership difference | 422 `semantic_invalid` if the previous is known; otherwise no drift plus a `comparison_inconsistent` gap |
| `compared` whose previous is another key/canon (known) | 422 `semantic_invalid` |
| `compared` whose previous is another key/canon, previous arrives later | `comparison_inconsistent` gap, no drift |
| `rebaseline` with the same `key_id` and `canon` as previous | 422 `semantic_invalid` |
| `rebaseline` link whose `from` is not in previous members or `to` not in current members | 422 `semantic_invalid` |
| report B arrives before its previous A | `pending_previous`, then identical result to in-order arrival |
| schema: incomplete + `changes`/`members`/`inventory_id`; complete without `comparison`; rebaseline + `changes`; compared + `links` | rejected |

## R7b. Read projections (AC-02 display)

Candidate endpoints, all `proxy.read` range-checked, base `GET /v1/proxies/{id}/`
(**[candidate]** endpoint names; DTOs are decided-candidate). Permission wiring follows
D-02 M0: manager is read-only for proxy features and any management action goes
through the management credential scopes of control-plane.md, never through these
read endpoints. Lists use the
ledger-and-query.md L3 conventions (`limit`, opaque cursor bound to endpoint, sort
and filters, `{items, next_cursor}`). Order is a ledger commit counter, descending,
so rows never move.

| Endpoint | Item | Fields |
|---|---|---|
| `inventory-snapshots` | `Snapshot` | `inventory_id`, scope key, `canon`, `key_id`, `member_count`, `observed_at`, `received_at`, `is_latest`, `is_first_baseline`, `comparison_state` |
| `drift` | `DriftRecord` | `drift_id`, `inventory_id`, `previous_inventory_id`, scope key, `change` (`added`\|`removed`\|`changed`), `metadata_ref`, `previous_metadata_ref?`, `detected_at` |
| `rebaseline-markers` | `RebaselineMarker` | the R5 fields |

`comparison_state`: `baseline` (initial or restated), `compared`, `rebaseline`,
`pending_previous` (with `awaiting_inventory_id`; no drift is shown yet),
`inconsistent` (deferred checks failed; no drift). Filters: `upstream_id`,
`credential_scope_id`, `change`, `from`/`to` on `received_at`. The read views carry
refs only. Names need the scoped lookup (R6). Incomplete observations are
listed as `inventory_incomplete` gaps (L4), never as snapshots.

## R8. Open questions

| ID | Question |
|---|---|
| O-2 | Keep the old K for a bounded rollback window, or destroy at once (R3)? |
| O-3 | Should a proxy-asserted `definition_comparison=different` be surfaced to attention (R4)? |
| O-4 | `POST /v1/proxy-inventory` as a separate endpoint, or batched with the status report? Report size at 10,000 members is about 450 KB. |
| O-5 | Server-side integrity flag when the same fingerprint arrives with different `definition` (R1)? |
| O-6 | Cross-scope links on `credential_scope_id` change (R5)? |

## R9. Evidence boundary

Proven: schema shape and negative cases, the immutable-field set equality with the
existing registry equality model, and the inventory/marker rules as a fixture model
(including report reordering). Not proven: server persistence, ACK durability,
real `tools/list` pagination behaviour of any upstream or client, K handling on a
real host, manager rendering. D-05 remains open.
