# T-12b2 compatibility research: legacy 2025-11-25 Streamable HTTP sessions, headers, GET/DELETE, initialize, cancel

Date: 2026-10-24 · Role: researcher (task T-12b2-compat) · Repo base: `feat/proxy-invocations-sessions` @ `e5612f8`
Scope: only what T-12b2 needs (session binding, `MCP-Protocol-Version` missing/mismatch, GET/SSE resume,
DELETE status, initialize over SSE, version/tasks capability checks, cancel key with session).
Not a changelog survey. No code, spec, `execution.md` or config was changed. No client was run.

**Product compatibility gate stays pinned.** P1 supports protocol revision `2025-11-25` only (D-01, M2).
Nothing here broadens support, enables enforcement, or changes a decided contract. The official spec has
moved on (2026-07-28); the repo decisions still hold for the pinned legacy path.

**No configuration, permission, hook or unattended-mode change is involved.** T-12b2 is proxy-side
protocol handling only. The one client-behaviour item that matters (retries on a closed connection, §3.2)
feeds a P1 *verification* item, not an implementation input.

Labels: **documented** = official spec/release note read on 2026-10-24 (paraphrased; normative keywords
MUST/SHOULD/MAY kept as in the source); **measured** = repo hardware/fixture record (cited, not re-run);
**local-static** = read-only inspection of the installed binary/version today, no MCP session run;
**inferred** = my reasoning; **decided** = repo contract/decision.

---

## 1. Sources (all fetched 2026-10-24)

| ID | Source | Status of revision |
|---|---|---|
| S1 | [MCP 2025-11-25 Transports (Streamable HTTP)](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports) | Pinned legacy revision (Final; current is 2026-07-28) |
| S2 | [MCP 2025-11-25 Lifecycle](https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle) | same |
| S3 | [MCP 2025-11-25 Cancellation](https://modelcontextprotocol.io/specification/2025-11-25/basic/utilities/cancellation) | same |
| S4 | [MCP 2025-11-25 Base protocol overview](https://modelcontextprotocol.io/specification/2025-11-25/basic) | same |
| S5 | [MCP 2025-11-25 Security Best Practices, Session Hijacking](https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices#session-hijacking) | same |
| S6 | [MCP Versioning (index)](https://modelcontextprotocol.io/specification/versioning) | names 2026-07-28 as current |
| S7 | [MCP 2026-07-28 Versioning and Compatibility](https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning) | current |
| S8 | [MCP 2026-07-28 Streamable HTTP](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http) | current |
| S9 | Claude Code CHANGELOG, local copy `~/.claude/plugins/marketplaces/claude-code-plugins/CHANGELOG.md` (mtime 2026-10-23; top entry 2.1.309) | vendor release notes |
| S10 | [openai/codex rust-v0.163.0](https://github.com/openai/codex/releases/tag/rust-v0.163.0) (2026-10-15) and [rust-v0.164.0](https://github.com/openai/codex/releases/tag/rust-v0.164.0) (2026-10-23), read via `gh release view` | vendor release notes |
| S11 | [docs.rs rmcp 3.5.1 `ProtocolVersion`](https://docs.rs/rmcp/3.5.1/rmcp/model/struct.ProtocolVersion.html) | SDK docs |
| R1 | Repo measurements: [T-01 probe](sigil-proxy-t01-probe-2026-10-10.md) §4/§4b (Claude Code 2.1.296, codex-cli 0.162.0, macOS arm64, fixture, not via proxy) | measured |
| R2 | Repo decisions: [decisions.md](../specs/sigil-proxy/decisions.md) "D-01 후속 결정", "P1 기능 범위"; [contracts/README.md](../specs/sigil-proxy/contracts/README.md) "취소 순서", "P1 method 범위와 route 거절 응답", "Protocol revision, tasks and cancellation (N4)"; [control-plane.md §5.3](../specs/sigil-proxy/contracts/control-plane.md); [support-matrix.md](../specs/sigil-proxy/support-matrix.md); [validation.md](../specs/sigil-proxy/validation.md) D-04 table | decided |

---

## 2. Official behaviour for the pinned 2025-11-25 revision (documented, paraphrased)

### 2.1 Sessions (S1 "Session Management", S4, S5)

- Issuance: a server MAY assign a session id at initialization via the `MCP-Session-Id` header on the HTTP
  response carrying `InitializeResult`. The id SHOULD be globally unique and cryptographically secure and
  MUST use only visible ASCII 0x21–0x7E.
- Echo: once issued, the client MUST send it on every later request. A server that requires sessions SHOULD
  answer a non-initialize request lacking the header with 400.
- Termination: the server MAY end a session anytime and then MUST answer that id with 404; a client getting
  404 MUST re-initialize without a session id.
- DELETE: a client SHOULD send DELETE with the session header when done; the server MAY answer 405 to refuse
  client-driven termination.
- Hijacking (S5): servers with authorization MUST verify every request and MUST NOT treat sessions as
  authentication; ids MUST be secure and non-deterministic; servers SHOULD bind ids to user-specific data
  (e.g. a user-id:session-id key). S5 lists resumable GET + `Last-Event-ID` as an injection vector.
- Request ids (S4): MUST NOT repeat within the same session for that requestor, and MUST NOT be `null`.

### 2.2 Protocol version header (S1 "Protocol Version Header"; S2)

- After initialization the HTTP client MUST send `MCP-Protocol-Version` on every request, and SHOULD use the
  negotiated value.
- If the header is absent and the server has no other way to know the version (the negotiated value counts
  as such a way), the server SHOULD assume `2025-03-26`.
- An invalid or unsupported value MUST get 400.

### 2.3 POST responses, GET streams, resumability (S1)

- POSTed response/notification: accepted → MUST return 202 with no body; otherwise an HTTP error (e.g. 400).
- POSTed request: MUST answer either SSE or JSON. On SSE the server SHOULD send a priming event (event id,
  empty data), MAY close the connection without ending the stream, MAY send requests/notifications first,
  and SHOULD eventually send the response.
- Disconnection SHOULD NOT be taken as cancellation; a client SHOULD cancel explicitly with
  `notifications/cancelled`.
- GET: MUST return SSE or 405.
- Resumption is only via GET with `Last-Event-ID`; the server MUST NOT replay messages belonging to another
  stream. Event ids, if used, MUST be unique across all streams in the session. A message MUST NOT be
  broadcast over multiple streams.
- Legacy fallback: a client that gets 400/404/405 to its initialize POST tries the 2024-11-05 HTTP+SSE GET.

### 2.4 Initialize, version negotiation, capabilities (S2)

- The server MUST echo the requested version if it supports it, else MUST offer another it supports; a client
  that does not support the answer SHOULD disconnect.
- Before the initialize response the client SHOULD send only pings; before `initialized` the server SHOULD
  send only pings and logging.
- Server and client capability tables include `tasks` (task-augmented requests); the example server result
  advertises `tasks` with list/cancel/`tools/call`.
- Initialize is an ordinary request, so §2.3 applies: its answer may be SSE, possibly after other events, and
  the session id is in the HTTP headers, not the body (inferred from §2.1 + §2.3).
- Implementations SHOULD enforce a maximum timeout regardless of progress notifications.

### 2.5 Cancellation (S3)

- A cancel MUST reference only a same-direction request believed still in progress.
- Clients MUST NOT cancel `initialize`.
- Task-augmented requests use `tasks/cancel` instead (P1 refuses `tasks/*` anyway, R2).
- Receivers SHOULD not answer a cancelled request, MAY ignore cancels for unknown or completed requests, and
  SHOULD ignore invalid ones (unknown id, already completed, malformed).

---

## 3. What changed since the repo's 2026-10-10 research

### 3.1 Spec: current revision is 2026-07-28 (documented, S6–S8); legacy rules unchanged

- 2026-07-28 removes protocol-level sessions, the GET stream, server-sent requests on SSE and `Last-Event-ID`
  resumability; a modern-only server SHOULD answer GET/DELETE with 405 and ignore both headers (S8 "Earlier
  Streamable HTTP Revisions").
- 2026-07-28 drops `notifications/cancelled` on this transport: closing the SSE response is the cancel signal
  (S8 "Cancellation"). **This inverts the 2025-11-25 rule (§2.3).** The proxy is pinned to legacy, so the
  legacy rule governs (C-9).
- Dual-era fallback (S8 "Backward Compatibility"): a 400 with an empty or unrecognized body sends the client
  back to `initialize` — the behaviour D-01 B1 relies on (empty-body 400) is unchanged. S7 still says clients
  SHOULD cache the result per HTTP origin and MAY persist it across restarts.
- S8 asks intermediaries that enforce policy on mirrored headers to reject when the version header is old or
  absent. Not applicable to the legacy path (Sigil decides from the body, not mirrored headers); no action.
- No change to the 2025-11-25 pages relevant here versus what the repo already cites (T-01 §4b, contracts
  N13). **D-01 B1, M2, m5, M3 and the P1 feature-scope rows stay consistent with the legacy text.**

### 3.2 Local client versions moved (local-static + documented; NOT hardware-verified)

| Client | Repo measured (R1) | Installed today (`--version`, read-only) |
|---|---|---|
| Claude Code | 2.1.296 | **2.1.310** |
| codex-cli | 0.162.0 | **0.164.0** |

Claude Code (S9; the local changelog ends at 2.1.309, so 2.1.310 notes were unavailable):
- **2.1.308** (documented): fixes duplicate HTTP MCP tool calls when the connection closed mid-call; now only
  read-only/idempotent tools are retried. → **Claude Code retries some `tools/call` on a mid-call close.** R1's
  "no retry" measurement covered only timeout+cancel, not connection close. Impact: the decided fallback of
  closing the connection without an HTTP response if clients retry the event-less 200 SSE close (decisions.md
  "취소 전 dispatch의 HTTP 종료", contracts N13, `server.rs:996` OPEN) could *invite* a retry for read-only/
  idempotent tools. Each retried POST is a new invocation per contract ("각 전달은 별도 invocation"); the proxy
  never re-executes on its own. P1 verification input, not a T-12b2 code change.
- 2.1.299 (documented): fixes headless/SDK tool calls failing or doubling on background reconnect; fixes a
  30 s hang when a server never ends the body of a notification reply (the proxy already returns an empty
  202 — inferred OK); cloud session and Remote Control connectors now negotiate 2026-07-28 by default, with
  `MCP_PROTOCOL_NEGOTIATION=legacy` as opt-out (local CLI behaviour not stated).
- 2.1.302 (documented): modern-path fix for missing `resultType`/`ttlMs`/`cacheScope`; not relevant to legacy.
- Local-static: the 2.1.310 binary contains the literals `2025-11-25` and `2026-07-28` (and older). Literals
  say nothing about wire behaviour.

codex-cli (S10, S11):
- **0.163.0** (documented): upgrades `rmcp` to 3.5.1 (#52972). rmcp 3.5.1 docs: `LATEST = V_2026_07_28`,
  `LATEST_WITH_INITIALIZE = V_2025_11_25`.
- 0.164.0 notes have no item on protocol revision, session, DELETE or version header (searched
  protocol/initialize/rmcp/streamable/DELETE/retry).
- Local-static: the 0.164.0 binary contains `2026-07-28` (21×), `2025-11-25` (8×), `2025-06-18` (12×).
- **Inferred, unverified:** R1's "codex offers `2025-06-18` in `initialize`, no `server/discover`" (basis of
  the M2 known limitation) may not hold for 0.164.0 — it may now offer 2025-11-25 or probe 2026-07-28 first.
  The M2 rule does not depend on it (the proxy judges by the upstream answer). The support-matrix codex row
  stays as measured for 0.162.0; re-measurement belongs to P1 verification.

Neither client was run. No config, credential, `~/.claude.json` or `~/.codex` file was touched.

---

## 4. Facts vs measurements vs inference per T-12b2 topic

| Topic | Official 2025-11-25 (documented) | Repo measurement (R1) | Repo decision (R2) | Assessment |
|---|---|---|---|---|
| Session id issuance | MAY issue on InitializeResult response; visible ASCII; secure | Fixture issued one; both clients echoed it | Proxy issues its own id bound 1:1 to (principal, route, upstream session); upstream id never exposed | Consistent. Proxy id must be 0x21–0x7E and CSPRNG |
| Missing session header (non-initialize) | Session-requiring servers SHOULD 400 | — | Not stated (only foreign/unknown → same 404) | **Gap**, A-1 |
| Unknown/foreign/terminated session | Terminated MUST 404; client MUST re-initialize | — | Same 404 for unknown/foreign principal/route (no oracle) | Consistent |
| Upstream 404 on a session request | Upstream ended the session | — | Defined only for DELETE | **Gap**, A-2 |
| Version header missing after init | Assume 2025-03-26 only if no other way; negotiated value is another way | Claude 2.1.296, codex 0.162.0 sent it on every later request | 400 empty body, deliberate strictness (m5); rmcp 0.16 unsupported | Allowed (SHOULD-level), decided. Keep |
| Header ≠ negotiated (known legacy, e.g. 2025-06-18) | Invalid/unsupported MUST 400 | — | 400 empty body, not modern, reason omitted [OPEN] | Consistent |
| Header unknown (e.g. 2026-07-28) / duplicate | MUST 400 | Claude sent 2026-07-28 on `server/discover` before init | B1 modern: 400 empty body, `modern_request_unsupported` | Consistent; duplicate→modern is an existing code choice (`classify.rs` `HeaderVersion`) |
| GET SSE | SSE or 405 | Both clients tolerated 405 | 405 after auth, upstream untouched | Consistent |
| `Last-Event-ID` resume | GET only; no cross-stream replay | Not observed | M3: resume only inside bound session; P1 GET is 405 | No resume in P1; POST handling is a **gap**, A-3 |
| DELETE | Client SHOULD; server MAY 405 | codex 0.162.0 sent DELETE on exit; Claude 2.1.296 did not | Same principal/route else 404; forward once; upstream 2xx/404 → invalidate; 405/error → relay, keep session | Consistent. Session-less upstream is a **gap**, A-4 |
| Initialize over SSE | Allowed; session id in HTTP headers | Fixture answered JSON (inferred from R1 wire) | Bounded buffer until first response with the initialize id (N12); judge version and `capabilities.tasks`; refuse → `-32603` HTTP 200 JSON + upstream DELETE | Consistent. C-4 on header capture |
| Version negotiation | Echo or offer another; client SHOULD disconnect if unsupported | codex offered 2025-06-18 (0.162.0) | Allowlist {2025-11-25}; judge by upstream answer | Consistent; codex 0.164.0 offer unverified (§3.2) |
| tasks capability | Optional server capability | — | Upstream `capabilities.tasks` → route unsupported / `upstream_capability_unsupported` | Consistent |
| Cancel key | Ids unique per requestor **per session**; same-direction, in-progress only; initialize not cancellable; unknown ids ignorable | Claude sent cancel as a separate POST with the session id | `(session, requestId)` exact JSON value equality | Code still keys `(route, principal, id)` (`cancel.rs:18` OPEN) — T-12b2 must add session |
| Disconnect | SHOULD NOT be read as cancel | — | Not stated explicitly | C-9 |

---

## 5. Exact implementation constraints for T-12b2 (decided contracts + legacy spec)

"Spec" means a 2025-11-25 MUST/SHOULD the decided contract already implies.

- **C-1 Session id minting.** Proxy-issued downstream id from a CSPRNG (≥128 bits), visible ASCII 0x21–0x7E
  (spec S1/S5). Never derived from or equal to the upstream id. Upstream `Mcp-Session-Id` is captured and
  dropped from the downstream response (control-plane §5.3 allowlist).
- **C-2 Binding.** Key is the proxy id; entry stores (principal, route, upstream session id). Every request
  re-authenticates the bearer, then requires the entry's principal **and** route to match; mismatch, unknown
  or invalidated id → the **same** 404 (decided §5.3). Sessions are never authentication (S5).
- **C-3 Downstream → upstream rewrite.** Replace the downstream `Mcp-Session-Id` with the bound upstream id
  (omit if upstream issued none). No other session header crosses.
- **C-4 Initialize capture.** Read the upstream `Mcp-Session-Id` from the initialize **response headers before**
  the bounded body buffer (N12) completes, so the refusal path can DELETE it even on SSE timeout
  (`upstream_initialize_unreadable`). Mint/attach the proxy id **only after** the supported verdict; a refused
  initialize returns no `Mcp-Session-Id`. Refusal stays HTTP 200 JSON `-32603`, fixed message, no data.
- **C-5 Initialize request itself** carries no proxy session id (spec). Version header absence on `initialize`
  is not the m5 case (m5 is "initialize 이후"). D-04 limits apply at initialize: 256 total, 32 per principal →
  refused; idle 15 min, an active call is not idle (validation.md).
- **C-6 Version header after init.** Order: auth (401 first) → session lookup → header check. Absent or ≠
  negotiated → 400 empty body, upstream count 0; known legacy value is not modern; unknown value is B1 modern
  (decided). Negotiated value = upstream's initialize answer (always 2025-11-25 on an established session).
- **C-7 Cancel key.** `CancelKey` = (route, principal, **proxy session id**, `RequestId` exact JSON value).
  Same id in two sessions never cross-matches. A cancel naming the initialize id, or with no session, never
  matches a dispatched call.
- **C-8 Session end clears state.** On invalidation (DELETE success, idle expiry, upstream 404 if A-2 adopts
  it), drop that session's pending early-cancel entries (counted, PX-013) and 404 new requests. In-flight calls
  finish and are audited (consistent with control-plane §6.3 expiry; inferred extension to sessions).
- **C-9 Disconnect ≠ cancel (legacy).** A downstream close after dispatch must not synthesize upstream
  `notifications/cancelled` nor record `cancel_requested` (spec S1). The invocation completes by existing
  outcome rules (response seen, or unknown). Do not adopt the 2026-07-28 close-is-cancel rule.
- **C-10 DELETE.** Auth → same 404 for foreign/unknown → forward **once** with the upstream id, no retry →
  upstream 2xx/404: invalidate, later 404 → 405/other error: relay status (body per allowlist), keep session.
- **C-11 GET.** 405 after auth regardless of `Last-Event-ID` or session header; upstream not contacted; 401 if
  unauthenticated (decided).
- **C-12 Gate.** Allowlist stays `{2025-11-25}`; no 2025-06-18 or 2026-07-28 acceptance, no enforcement change,
  no capability stripping (D-01, M2).

---

## 6. Open contract questions (recommendation follows existing contracts; decision belongs to orchestrator/user)

- **A-1 Missing `Mcp-Session-Id` on a non-initialize request.** Spec: session-requiring servers SHOULD 400;
  contract defines only 404 for unknown/foreign. Recommendation: 400 empty body after auth, upstream count 0,
  no invocation event (aggregate counter) — follows the spec and reveals nothing about other sessions.
  Alternative: same 404 (client re-initializes; also spec-compatible in effect). Test both auth orders.
- **A-2 Upstream 404 on a non-DELETE session request.** Spec meaning: upstream ended the session; clients MUST
  re-initialize on 404. Recommendation: invalidate the binding and answer downstream 404 empty body; audit the
  call as `unknown`/`sent` (non-execution unprovable, as in §5.4 reasoning). Needs a contract line; the
  header allowlist does not cover status mapping.
- **A-3 `Last-Event-ID` on POST.** Spec defines it only on GET; M3 has no reachable path while GET is 405; the
  request-header blocklist does not list it. Recommendation: strip on POST so an upstream cannot replay across
  proxy-bound sessions (S5 vector). Small contract addition.
- **A-4 Upstream issues no session id (spec MAY).** Binding assumes an upstream session. Recommendation: still
  mint a proxy id (binding and cancel scoping need it), store upstream session = none, forward without a
  session header; on DELETE invalidate locally with no upstream call. The DELETE status (2xx vs 204) is
  undefined — flag for decision.
- **A-5 Cancel-before-dispatch HTTP close.** Decision unchanged (event-less 200 SSE); only the Claude 2.1.308
  note (§3.2) raises the risk of the planned fallback. No contract change proposed; P1 verification input.

All other T-12b2 items are covered by decided contracts; no conflict found with the official 2025-11-25 text.

---

## 7. Test list sufficient to start T-12b2 (oracle = fixture upstream counters, as in support-matrix §5)

1. Initialize JSON and SSE answers (SSE with priming event and a non-response event before the result):
   supported → relayed bytes unchanged, proxy `Mcp-Session-Id` present and visible-ASCII, upstream id absent.
2. Initialize SSE refusals (2025-06-18, `capabilities.tasks`, bound/timeout): no proxy session id, `-32603`
   JSON 200, upstream DELETE count 1 with the captured upstream id (C-4), including timeout.
3. Valid proxy id → upstream receives the upstream id, not the proxy id.
4. Foreign principal, foreign route, unknown id, invalidated id → byte-identical 404s; upstream count 0.
5. Missing session header (A-1 outcome) → per decision; upstream count 0.
6. After init: header absent / 2025-06-18 / 2026-07-28 / duplicate → 400 empty body, upstream count 0;
   unauthenticated → 401 first.
7. Two sessions, one principal, one route, same request id `4`: cancel in A affects only A; `"4"` vs `4` never
   match.
8. Cancel naming the initialize id, and cancel without session → no match, not forwarded, counted.
9. Downstream disconnect mid-call → no upstream `notifications/cancelled`, no `cancel_requested` (C-9).
10. DELETE: foreign → 404; upstream 200/204/404 → invalidated, next request 404, that session's early-cancel
    entries dropped; upstream 405/500 → status relayed, session kept; upstream DELETE count exactly 1.
11. Upstream 404 mid-session (A-2 outcome).
12. GET with/without `Last-Event-ID` → 405, upstream count 0; POST with `Last-Event-ID` → per A-3.
13. Session limits: 33rd session for one principal / 257th overall → initialize refused; idle expiry does not
    expire a session with an active call.

---

## 8. Unverified / limits

- No client was run (by instruction). Nothing here is proxy-path or hardware verification. Rocky 9 / SELinux
  untouched.
- Claude Code 2.1.310 notes unavailable locally (S9 ends at 2.1.309); the 2.1.310 delta is unknown.
- codex 0.164.0 initialize offer, `server/discover` use, header and DELETE behaviour: unverified (§3.2).
- rmcp 3.5.1 client wire behaviour (whether it sends `MCP-Protocol-Version` after init, unlike rmcp 0.16):
  unverified; only its constants were read.
- Spec pages are living HTML; paraphrases reflect 2026-10-24 retrieval.
