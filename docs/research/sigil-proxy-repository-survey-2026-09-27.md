# Sigil Proxy repository survey — 2026-09-27

Task: **T-00 / researcher**. Status: repository inspection complete; recommendations await T-02 contract review.

Scope: server authentication/routes/events/policy, core compatibility, spool, existing MCP baseline, and read-only inspection of manager. Sigil HEAD: `24eddb26b8810224c95df6812f23b5901c11dff6`; manager HEAD: `41b09b1f76dab25da55c2c5b85dbd2bb78bd6641`. The proxy specification is an uncommitted working-tree input. Existing unrelated changes were left alone; manager was clean when inspected.

**Evidence labels:** “Observed” means local source inspection, not a running-system measurement. “Recommendation” means proposed design, not an implemented contract. No servers, product clients, tests, or hardware probes were run. No remote fetch, push, issue/message posting to manager, commits, or production edits were performed. Current vendor protocol/auth support belongs to T-01; this survey does not certify it.

## 1. Existing server API and authentication (observed)

Route authority: `crates/sigil-server/src/app.rs::build_router` (line 66 onward).

| Surface | Current API | Current boundary |
|---|---|---|
| Host ingestion | `POST /v1/events` | Host allowlist; optional certificate-to-envelope-host binding. No read-bearer middleware. |
| Host configuration | `GET /v1/policy?host_id=…`, `GET /v1/rule-packs?host_id=…` | Host-oriented control routes, outside read-bearer middleware. Policy handler checks host allowlist and serves an operator-provided signed bundle with ETag/304. |
| Fleet reads | `GET /v1/meta`, `/v1/policy/meta`, `/v1/fleet/hosts`, `/v1/fleet/hosts/:host_id`, `/v1/fleet/risk`, `/v1/fleet/compliance`, `/v1/events`, `/v1/events/:event_id` | One shared bearer, no per-user roles or read scopes. |
| Artifacts | `GET /v1/artifacts`, `/v1/artifacts/:filename` | Same read bearer; optional configured artifact directory. |
| Enrollment | `POST /v1/enroll` | Enrollment token in body; optional enrollment state, not read bearer. |
| Liveness | `GET /v1/healthz` | No application bearer. Boot gate allows this route while other routes return 503/Retry-After. |

`auth.rs::ReadToken::from_env` loads `SIGIL_SERVER_READ_TOKEN` once, trims whitespace, and disables protected reads with 404 if absent/empty; wrong/missing bearer produces 401. There is no identity-bearing authorization result: middleware checks token equality only.

Transport matters independently: `main.rs:268` selects a whole-listener mTLS acceptor when all three TLS paths are present; otherwise it starts plain HTTP. `main.rs::build_mtls` uses a client-certificate verifier. Thus “no bearer” does **not** bypass TLS client authentication on an mTLS listener. `config.rs:79,104,128` defaults `events_require_cert_host_match` to false and rejects enabling it without the mTLS triple. `events_route.rs::post_events` optionally matches CN or SAN DNS to host ID before allowlist lookup. That event-specific binding is not a general authorization layer for future proxy configuration routes.

Bootstrap precedent: `cli.rs:22` defaults `--config` to `/etc/sigil-server/server.yaml`; `main.rs:17` loads that YAML, while the read token comes from the environment. This establishes no proxy OS path or CLI/env/file precedence contract.

**Gap:** the router has no proxy registration, route grants, desired/applied config, proxy heartbeat, invocation query, or approval APIs. Existing bearer authentication cannot satisfy PX-008/009/012 and AC-04/13 by simply attaching it to new write routes.

## 2. Events, storage, and compatibility (observed)

- `crates/sigil-core/src/event.rs:737,787`: event schema is 1; `Event` requires host ID, agent version, timestamp, severity, source, subject and evidence. `SourceKind` and `Evidence` have `#[serde(other)] Unknown` (`:29,721`); `Subject` only supports path/self (`:42`), and severity only info/warn (`:12`). Unknown evidence kinds deserialize, but their original discriminator/payload is not retained in the typed fallback. Other enum additions are not automatically compatible.
- `crates/sigil-server/src/events_route.rs::validate` parses payload as `Event`, requires its schema version to equal 1, and checks payload/envelope host equality. Envelope schema version itself is defaulted and unused. The entry event ID is not compared with the payload event ID here. These are existing behaviors, not a suitable new audit validation contract.
- `persist.rs::append_events` stores raw payload JSON in `<host_id>/received-YYYY-MM-DD.jsonl`, flushes with `sync_all`, and skips sequences at/below the previously stored host watermark. It does **not** enforce event-ID uniqueness. Filtering uses the pre-batch watermark, so duplicate sequences within one batch are not individually removed. Watermark storage is a separate tmp/rename operation, and its failure is non-fatal in `events_route.rs`.
- **Inference from those operations:** a crash after JSONL persistence but before watermark persistence can replay duplicate rows; accepting a later sequence first can discard a subsequently arriving lower sequence. Existing storage therefore does not prove PX-011's durable event-ID deduplication requirement.
- `fleet_index.rs` / `fleet_index_update.rs` maintain host summaries; `boot_rebuild.rs::rebuild_from_jsonl` parses typed host events and skips invalid lines. It rebuilds the fleet index, not a transactional proxy invocation/event ledger.
- `routes/events.rs::get_events` exposes cursor, host/time/evidence/severity/source/bucket filters, default limit 100 and clamp 1–1000. `jsonl_scan.rs` returns raw JSON; it can preserve unknown evidence bytes despite typed validation elsewhere. `find_by_id` searches receipt-date files within ±1 day of the UUIDv7 date. **Inference:** long-offline uploads can fall outside that lookup window. Proxy lookup must not inherit this assumption.

Manager compatibility is stronger but limited to the existing envelope: `../sigil-manager/internal/fleet/client.go:430–470` uses raw JSON for source/subject and stores both `Evidence.Kind` and the full `Evidence.Raw`; unknown evidence survives marshal/unmarshal. Its consumer contract `docs/superpowers/specs/2026-05-16-fleet-api-contract.md §8` declares optional fields, evidence variants, and additive endpoints compatible, with breaking changes requiring `/v2/`. This does not make a hostless proxy envelope compatible with the current host `Event` DTO or UI.

## 3. Reusable components and limits (observed → recommendation)

| Existing component | Reuse candidate | Required new work |
|---|---|---|
| `sigil-spool/src/producer.rs::Producer` | Opaque newline-delimited records, append/fsync, rotation, partial-tail truncation on reopen | Dedicated proxy state directory and one writer across processes; bounded event size, durable sequence/identity allocation, invocation recovery semantics. Producer has no cross-process lock. |
| `sigil-spool/src/checkpoint.rs::Checkpoint`, `consumer.rs` | Consumer offsets and atomic checkpoint pattern | Proxy-specific ACK/rejection protocol and restart tests; checkpoint is not itself an event dedup store. |
| `sigil-spool/src/retention.rs::Retention` | Retention below acknowledged consumer floor | Admission/backpressure before capacity exhaustion; reserved gap reporting. Soft retention protects the current segment and floor; `force_gc` can delete unread data. Neither is a strict admission cap. |
| `sigil-sender/src/batch_reader.rs`, `manifest.rs`, `data_task.rs` | Opaque payload batching, ID/byte-range manifest, ACK advancement and backoff patterns | Sender wire/URL currently targets host `/v1/events`; refactor or dedicated transport required. Batch byte check occurs before reading a whole line, so one line can exceed the requested batch size. Audit retry must never re-execute an MCP call. |
| `sigil-core/src/policy/{canonical,pubkeys,verify,atomic_writer,deployment,deployment_store}.rs` | Signing, expiry, monotonic-version and atomic-activation patterns | New proxy audience/identity and route/auth configuration schema. Existing legacy signed envelope is fleet-wide, with no host binding (`signed_envelope.rs:1`). |
| `sigil-core/src/assess.rs` | Selected assessment primitives after extraction | Inputs are shell command or MCP **server definition**, outputs allow/warn/deny. No invocation actor, structured tool argument authorization, delegation or require-approval contract. Do not substitute this for PX-018–022. |
| Manager UI/query components | Existing shell, tables, detail panels, pagination, loading/error/stale presentation | Proxy DTOs, navigation/screens, backend proxy client, access checks, metadata-safe rendering and mutation flows. |

Spool code is useful infrastructure, not evidence that proxy crash recovery or power-loss behavior is already verified. Relevant existing test sources include `sigil-spool/tests/{producer,consumer,retention,crash_props}.rs`, `sigil-sender/tests/{retry_e2e,data_task_e2e}.rs`, and `sigil-server/tests/{events_cert_binding,events_pagination_e2e,boot_rebuild_e2e}.rs`; these were not executed in this survey.

## 4. Manager architecture and scope conflict (observed)

Read manager `AGENTS.md` and its named fleet API contract, UI/UX design, and Plan 02 architecture; also inspected the later fleet-cache design and current code. The Plan 02 status text is not a complete description of current code: fleet/host/settings routes and optional OIDC now exist.

- `internal/api/v1/server.go::Routes`: the browser uses `/api/v1/auth/*`, `/api/v1/fleet/*`, and manager-local `/api/v1/triage/*`. `middleware.go::RequireAuth` verifies `sigil_session` and puts only the subject in request context. `internal/auth/jwt.go` signs HS256 sessions; `internal/config/config.go` defaults TTL to 12 hours. `auth.go` uses HttpOnly, SameSite=Lax and configurable Secure cookies.
- `internal/api/v1/oidc.go` and `internal/auth/oidc.go` provide one configurable provider. UI/UX spec §9 explicitly says admitted OIDC subjects receive the **same console permissions**, with no RBAC. Authentication alone cannot distinguish viewer/operator/approver.
- `internal/fleet/client.go::Client` is read-only; `http.go` uses a server-side shared bearer and a timeout-configured standard HTTP client. That constructor does not configure a client certificate. Direct use against the server's full mTLS listener therefore requires an additional transport/infrastructure arrangement; this survey did not exercise deployment topology.
- `internal/triage/repo.go` / `schema.go` own local SQLite triage. Those writes do not mutate server policy. `internal/fleet/cache.go` uses single-flight and stale-while-revalidate with endpoint/query keys; its design explicitly assumes one global upstream/read scope. New scoped reads need scope-aware isolation; approval/config writes need current-state checks and invalidation, not cached authorization decisions.
- Reusable frontend locations: `web/src/components/Layout/`, `components/Fleet/`, `components/EventDetails.tsx`, `hooks/usePagedFleet.ts`, `api/client.ts`, and `api/fleet.ts`. Host-centric detail/triage types need adaptation; they are not ready-made proxy invocation types.

**Contradictions to resolve in T-02/T-15:** manager AGENTS says “read-only against sigil-server”; UI/UX D5 limits writes to local triage; §9 excludes multi-user RBAC. Proxy PX-012 requires registration/config management and PX-023 later requires separate approvers. The user's authorization for a new management UI concept permits this research and future scoped design, but does not make the old guidance consistent or implement the missing authorization model. Record a narrowly scoped proxy-management exception in manager guidance/specs when manager work is assigned; preserve fleet read-only behavior and avoid expanding into accounts/tenancy/enterprise SSO. Define minimal operation permissions explicitly rather than treating every current session as an approver.

Manager's session-start workflow also calls for fetch/push and issue updates, and names an older `../anti_i` producer path. This dispatch explicitly forbids manager edits, pushes and external posts and is research-only, so those workflow mutations were not performed. No need to block this survey or request the already-authorized UI concept again.

## 5. Recommended decisions and acceptance dependencies

### D-02 — separate identities and bootstrap (recommendation)

Use separate downstream client, proxy control-plane, upstream credential and manager control-plane identities; retain the current fleet read token's read-only meaning. Require proxy identity binding on **every** new ingestion/config/heartbeat route, with permissions limited to the registered proxy. Reuse mTLS verification patterns where deployment supports them, but do not copy the optional host-binding default or assume a certificate authorizes all IDs. Downstream auth mechanism remains contingent on T-01 client support.

Keep manager credentials on its backend; define server-enforced read/manage permissions plus authenticated operator attribution and management audit. Do not trust a browser-supplied human flag or unverified subject header. Approval identity/step-up remains D-07/P3. Specify CSRF/origin controls for new browser-triggered writes and tests for read-token, viewer and agent rejection.

For T-02 bootstrap, recommend an explicit config-file selector (`--config`, optionally a documented env selector, then OS default); central versioned route/auth configuration should replace atomically, not silently merge with local bootstrap. Freeze exact OS paths, selector precedence, secret-file permissions, expiration, reloadable fields and rollback behavior after T-01/D-04 inputs. Existing server paths are precedent only. Traces: PX-007–009/012/014/016; AC-04/05/08/13.

### D-03 — dedicated audit ledger and API (recommendation)

Add proxy DTOs in core and additive server endpoints without modifying the host event envelope or inventing proxy hosts. Use a dedicated transactional event ledger with a unique event ID, authenticated proxy ownership, immutable stored payload and persisted sequence/gap tracking; consider SQLite for a single-instance P1 deployment, subject to D-04 storage/load evidence. Event insertion, duplicate handling and ACK durability must have an explicit commit boundary. Reject conflicting reuse of an ID; tolerate safe retransmission and define out-of-order handling.

Maintain invocation projections keyed by invocation ID plus ownership; persist starts independently of completion and preserve unknown outcomes after restart. Index by proxy/upstream/actor/time/outcome and look up event IDs independently of receipt date. Define retention for ledger, projections and dedup tombstones together. New schemas need bounded allowlisted metadata, explicit unsupported-version behavior, unknown event-type handling, stable cursors and typed errors. Never echo raw rejected payloads/secrets in error details.

Compatibility fixtures should cover old manager + unchanged host events, unknown evidence round-trip through Go/raw reads versus Rust typed fallback, new proxy consumers, delayed upload lookup, duplicate/conflicting IDs, reordered batches, server restart and disk-full admission. Traces: PX-006/010–013/015/016; AC-01/03/05/06/12. Capacity and throughput remain unmeasured.

### D-05 — share algorithms, separate baseline ownership (recommendation)

`sigil-agent/src/ai_guard/mcp_baseline.rs:15,116,154,192` stores bounded fingerprints/property paths, hashes canonical metadata, binds baseline to canonical HOME hash, and uses per-server hashed filenames plus no-clobber first creation. Runtime chooses `state_db_path.with_extension("mcp-baselines")` (`runtime.rs:227`). `parser/codex_tool_cache.rs:125` only assesses the baseline when both local cache inputs are complete. This is local cache evidence, not a currently verified vendor API. The comparator detects changes/new tools by iterating current tools; it does not implement full removal inventory.

Do not share those baseline files with proxy or reinterpret first observation as approval. Extract pure bounded canonicalization/fingerprint/comparison helpers only after defining a versioned hash contract; retain existing daemon behavior. Create proxy-owned baseline/snapshot IDs scoped by registered upstream, credential/authorization scope, protocol version and observation source (plus proxy where visibility differs). Complete all pages before publishing a snapshot; represent incomplete/error observations explicitly, and infer removals only between comparable complete snapshots. Keep immutable first-observed baseline distinct from latest complete inventory and future human approval. Treat tool descriptions/schema as untrusted sensitive metadata in a separately controlled store. Traces: PX-005/007/010; AC-02/05.

## 6. Handoff

T-00 delivers this file only. T-02 must finalize D-02/03/05 schemas, permissions and manager scope amendments with independent security review; T-01 supplies client auth/protocol facts; T-03 supplies measurable durability/limits fixtures. Existing compatibility/enforcement gates remain unchanged. Research completion is not P0 completion, implementation approval, or hardware verification.
