# Control-plane contract draft (D-02) v0.2

2026-10-10 · W3 + W3-fix (review findings H1–H3, M-1–M-10, L1–L5; mapping in the last section) · Draft. **D-02 is not closed by this document.** Nothing here is implemented, hardware-verified or independently reviewed.
Traces: PX-008, PX-009, PX-012, PX-014, PX-016; AC-04, AC-08, AC-13.
Inputs: [W1 auth-surface research](../../../research/sigil-proxy-auth-surfaces-2026-10-10.md) (cited as W1 §), [contracts v0.3](README.md),
[decisions.md](../decisions.md) "D-01 후속 결정", [T-01 probe](../../../research/sigil-proxy-t01-probe-2026-10-10.md).
Scope: mechanism only. No new SSO, multi-tenancy or per-user RBAC beyond what the options below state.

## Status labels

| Label | Meaning |
|---|---|
| **decided** | Already fixed in decisions.md or contracts/README.md. Cited, not re-decided here. |
| **recommended** | This draft's proposal. Needs review; becomes decided only through decisions.md. |
| **open-for-user** | A user decision is required (section 9). A recommendation is given. |
| **unmeasured** | A number or behaviour with no measurement. Do not publish as a support promise. |

## 0. Credential classes and the separation rule (PX-009)

Four secrets exist. None is valid for another's purpose. Every row of "accepted by" is a deny-by-default list.

| Credential | Held by | Authenticates | Accepted by | Never accepted by |
|---|---|---|---|---|
| Server read bearer (`SIGIL_SERVER_READ_TOKEN`) | manager process (existing) | read-only fleet and proxy reads | existing read routes; proxy read routes (section 3) | management, ingest, proxy config GET (decided, README "P1 API 후보와 권한") |
| Proxy mTLS identity (leaf cert) | proxy | one registered proxy | `GET /v1/proxies/{id}/config`, `POST /v1/proxy-events`, `POST /v1/proxy-metadata` (candidate), `POST /v1/proxy-status` | read routes, management routes, host routes (`/v1/events`, `/v1/policy`, `/v1/rule-packs`) |
| Management credential | manager backend or operator CLI | a management action | `PUT /v1/proxies/{id}/config`, registration, disable | read, ingest, proxy config GET |
| Downstream client bearer | agent client (Claude Code, Codex) | a client principal at the proxy | proxy listener only | server (all routes), upstream |
| Upstream credential | proxy host (local) | proxy to upstream | upstream only | downstream, server, manager |

### 0.1 Transport precondition (H1, recommended)

| Rule | Detail |
|---|---|
| mTLS required | Proxy routes (config GET, `POST /v1/proxy-events`, `POST /v1/proxy-metadata`, `POST /v1/proxy-status`) and management routes are **not served** unless server mTLS is enabled (`tls_cert_path`, `tls_key_path`, `client_ca_path`). Over plain HTTP they answer 404, indistinguishable from an unconfigured route. |
| Same-connection identity | Every proxy route requires a `PeerIdentity` extracted from the **same** connection as the request (`tls_accept.rs:148-172`). No identity extension means 404. A body or header `proxy_id` never substitutes for it. |
| Management bearer | Accepted only on an mTLS-enabled listener. It is never accepted over plain HTTP, including loopback. (A loopback-bind exception was considered and rejected: the bearer is a write secret, and loopback exposure to local processes is exactly what PX-014 distrusts.) Consequence: the manager reaches management routes through the same operator-owned mTLS-fronting path as reads (W1 §3.3), and an operator CLI on the server host must present a client cert too. |
| Management-caller cert class (N-2) | Management routes require a **management-caller cert**, in addition to the bearer. It is a third cert class. Issuer options: **(a)** the host CA plus an entry in a caller fingerprint list (the pattern of `enroll_issuer_fingerprints`, `routes/enroll.rs:108-129`), or **(b)** a separate management CA. The **proxy CA must not** issue management-caller certs. A management cert is rejected on host and proxy routes, and the reverse (section 1.2 separation extends to this class). Sub-choice: §9 item 1. A host cert, a proxy cert, or an unregistered cert with a valid bearer is rejected (404). Recommended: fingerprint list in the same verifier file, entry = (`key_id`, scope, caller cert fingerprint), so the bearer is bound to one cert. Cost: manager's fronting layer must present that cert (section 8). |
| Terminator topology (N-2) | A deployment where sigil-server binds loopback behind a TLS terminator (`docs/install-server.md:255`) **cannot serve proxy or management routes**: the server sees no client cert, or the terminator's, not the proxy's or manager's. Such routes work only if the fronting layer re-originates mTLS toward the server with a registered cert and the real client identity is preserved end-to-end. Otherwise the routes stay 404. Identity is never read from a forwarded header. |
| Boot | Server refuses to enable proxy or management routes when the mTLS triple is absent, and logs why. It does not silently fall back. |

## 1. Proxy ↔ server identity (D-02 part 1)

### 1.1 Options

| Option | Mechanism | Assessment |
|---|---|---|
| A1a | Separate **proxy client CA**, appended to the server's single client-CA bundle. Role comes from a server-side proxy registry, not from the CA alone. | The listener takes one `client_ca_path` (W1 §1.1, `main.rs:256-262`), so TLS cannot tell host certs from proxy certs. The separate CA still earns its place: the host enrollment path cannot mint a proxy cert, and the proxy issuance path never touches the host allowlist. Role is then read from the cert's **issuer** (section 1.2). The CA subject DNs of the host and proxy CAs must differ. **The bundle is read only at boot (`main.rs:256-262`), so adding the proxy CA requires a server restart**; there is no live reload (M-7). |
| A1b | Second listener or port with its own client-CA bundle | Real TLS-layer separation. Needs server code (`main.rs` has one bind). More operator surface. Candidate later hardening. |
| A2 | Reuse the host CA and `/v1/enroll`, separate by registry only | Enrollment writes the id into the host allowlist and requires a UUID (W1 §1.3). A proxy would become an allowlisted *host*. **Not recommended.** |
| A3 | Static bearer per proxy | Adds a secret path on a leg that already has mTLS. **Not recommended.** |

**Recommended: A1a**, with A1b recorded as an optional hardening step. (open-for-user, section 9 item 1)

### 1.2 Identity binding (recommended)

| Rule | Detail |
|---|---|
| Binding | `proxy_id` is bound to **both** (i) a DNS SAN on the leaf and (ii) the leaf fingerprint held in the registry. Request is accepted only if both match the path/envelope `proxy_id`. |
| SAN form | Proxy SAN is distinguishable from a host SAN: a reserved suffix such as `<proxy_id>.proxy.sigil.invalid` (exact form open). A bare host_id-shaped SAN is never a proxy identity. `proxy_id` must be a DNS-label-safe string (check against the schema's `$defs/id` pattern). |
| Fingerprint | blake3 hex of the leaf DER, the same value `PeerIdentity.fingerprint` already carries (`tls_accept.rs:58-60`). A registry entry holds up to **two** (current, next) so renewal has no gap. |
| Issuer field | `PeerIdentity` gains an issuer identity: the issuer subject DN and/or the fingerprint of the issuing CA cert (the leaf's issuer is compared to configured CA fingerprints). Today it is `{fingerprint, cn, san_dns}` (`tls_accept.rs:45-52`). **sigil-server change.** Role is derived from it: issuer == proxy CA ⇒ proxy-class cert; anything else under the bundle ⇒ host-class. |
| Signing profile | The proxy signer pins the subject and extensions and copies nothing from the CSR: `CA:FALSE`, `clientAuth` only, CN absent or equal to `proxy_id`, exactly one DNS SAN (the proxy SAN above), no `copy_extensions`. It mirrors the host profile (`enroll/sign.rs:126-129`). A CSR carrying other names or extensions is rejected, not trimmed silently. |
| Check order | Identity is checked before any registry-state or existence lookup (same oracle rule as `events_route.rs:76-86`). An identity mismatch and an unknown `proxy_id` return the **byte-identical** answer. **Recommended/candidate (D-02 미결): 404** with the fixed body `{error:{code:"proxy_unknown" [candidate],message}}` on config GET, events, status and metadata (M-3). Until this is adopted, the **frozen ingest 403** for identity mismatch (README v0.4) is the baseline. The 404 is proposed because a distinct 403 would let a caller enumerate registered `proxy_id`s; adopting it changes that README row. Precedence against README 422>403>409>424: the identity 404 is evaluated **first**, before body validation, so it outranks all four, and a caller without a matching identity never sees 422/409/424 detail. A proxy cert used on a management route (e.g. `PUT /v1/proxies/{id}/config`) gets the same recommended **404** (candidate). A non-matching management credential gets 401 (section 3). |
| No reuse | Proxy routes never fall back to "any authenticated cert" and never consult `hosts.json`. The host allowlist's default-open behaviour (`allowlist.rs:54-60`) is not copied: an unregistered proxy is rejected. |
| Host/proxy separation (H2) | Both directions are **unconditional** and independent of `events_require_cert_host_match` (default false, W1 §1.1). Host routes (`/v1/events`, `/v1/policy`, `/v1/rule-packs`) reject any cert whose issuer is the proxy CA or whose fingerprint is in the proxy registry. Proxy routes reject host-class certs. Same answer as an unknown principal. Implementation needs the issuer field above, the new middleware, and distinct CA subject DNs. All of it is a **sigil-server change**. |
| Persisted | Registry entry: `proxy_id`, `display_name`, `state`, fingerprints, `created_at`, `disabled_at?`, `desired_revision`, `applied_revision`, `last_seen`. `proxy_id` is never reused after retirement (same rule as `key_id`). |

### 1.3 Lifecycle

| Step | Mechanism (recommended) |
|---|---|
| Registration | Operator, using the management credential, creates a registry entry (`pending`) and receives a `proxy_id`. The proxy generates its key and CSR locally. The operator submits the CSR; the signer (proxy CA) returns the cert. The private key never leaves the proxy host. State becomes `active` when the first cert is issued. CA key locality follows the host enrollment precedent (CA key on the server host) unless the user chooses an offline CA. |
| Not used | Enrollment tokens and `/v1/enroll`. |
| Revocation | `disabled` state in the registry. The registry is consulted **per request** and written by the server itself, so disabling is immediate for server-side routes without a restart. Short cert lifetime is the backstop if the registry were bypassed or lost, not the primary mechanism. |
| Cert lifetime | Proposed default 30 days, matching host enrollment (`enroll/mod.rs:28`). **unmeasured.** |
| Rotation (renewal / re-key) | Operator submits a new CSR for the same `proxy_id`. Server records the new fingerprint as `next` atomically with signing. The old fingerprint is dropped at the **first request authenticated with `next`**, or at a hard deadline (proposed 7 days, unmeasured), whichever comes first. The server raises an **operator alert** before the deadline (proposed at 50% and 90% of it) while the old fingerprint is still the only one in use, since silently dropping it would lock the proxy out. `disable` removes both (M-8). `proxy_id`, `epoch_id`, spool and key K are unchanged. |
| Offline CA option | If the user chooses an offline proxy CA, signing happens off the server. A separate **register fingerprint** step then records the issued cert's fingerprint (and its `proxy_id`) through the `identity` scope (section 2.2). A cert never reaches `active` use without that step, so possession of a CA-signed cert alone is not access. |
| Disable then re-enable | Same `proxy_id`, spool retained. The proxy's events are rejected while disabled and retried from the spool. After re-enable they are accepted. The ledger stores the presenting fingerprint per batch so the period is traceable. Whether events produced during a suspected compromise are accepted is open-for-user (item 6). Spool growth while disabled is bounded by the existing disk-limit rule (new calls blocked at the limit, PX-013); a long disablement therefore turns into an outage of that proxy, which is stated, not hidden (L5). |
| Re-registration with a new `proxy_id` | The proxy refuses to start if its `state_dir` is bound to a different `proxy_id`. Spool events carry the old id and would fail ownership. The operator must drain the spool or explicitly abandon it: abandoned spool is quarantined, never deleted, and a gap is reported. A new `proxy_id` gets a new `epoch_id`. |
| `state_dir` loss, same `proxy_id` | Existing README rule: new `epoch_id`, new K and `key_id`, server records `producer_epoch_change`. The registry entry persists and no re-registration is required. |
| Retirement | State `retired`. Ledger and registry stub are kept per retention. The id is not reissued. |
| State answers (to an authenticated proxy identity) | `active`: normal. `disabled`: config GET answers the fixed `disabled` code (config.state `disabled`); events/status are rejected with the same code; the server serves this answer **before** it closes the connection. `retired`: the same `disabled`-class answer with code `retired`, and no re-enable path (a new `proxy_id` is required). `pending` (no cert issued yet) cannot present an identity, so the question does not arise; a pending entry with a registered fingerprint answers 404 until activated. Unknown/mismatch: the recommended 404 above (candidate; baseline is the frozen 403). |

## 2. Management credential for server write APIs (D-02 part 2)

### 2.1 Options

| Option | Mechanism | Assessment |
|---|---|---|
| B1 | Separate **manage bearer**, distinct from the read token | Smallest change on both sides. Weakness: one shared secret with write power, no human identity at the server, restart to rotate if implemented like `SIGIL_SERVER_READ_TOKEN`. |
| B1′ | B1 stored as a **verifier file** (key_id, name, SHA-256 of a 256-bit token, optional `not_after`), re-read on file change or SIGHUP, at most two active entries per scope | Same wire shape as B1. Allows rotation with overlap and no restart. Server never stores the token itself. |
| B2 | mTLS client cert for the manager backend, registered as a "manager" principal | Strong machine identity. Needs a TLS client in manager (`fleet/http.go:34` has none). Can be added later; compatible with B1′. |
| B3 | Per-user delegation verified by the server | Largest scope; moves manager into the area its AGENTS.md lists as out of scope. Not recommended for P1. |
| B4 | B1′ or B2 plus `requested_by` carried as an **asserted** field | Gives an audit trail without claiming verification. |

**Recommended: B1′ + B4.** B2 is an optional later hardening. (open-for-user, item 2)

### 2.2 Rules

| Topic | Rule |
|---|---|
| Transport | `Authorization: Bearer <token>` on the management routes, **only on an mTLS-enabled listener** (section 0.1). The manager reaches it through the operator's fronting path (W1 §3.3). |
| Scopes (H3) | Each verifier entry carries exactly one scope: `config` (`PUT /v1/proxies/{id}/config`, `disable`) or `identity` (registration, CSR signing, fingerprint registration, `enable` (re-enable), retirement). A `config` credential cannot issue or register certs, and cannot **re-enable** a disabled proxy: disable is safe-direction and stays in `config`, re-enable restores trust and needs `identity`. What a `config` credential **can** do is add a principal with its own verifier to a route, so it can create a new, attributed (audited) client principal. It cannot forge an existing principal's token, and it cannot make the proxy hold an upstream credential the proxy host does not already hold (section 5.5). Reason: a holder of `identity` can mint a proxy identity and then post events that the ledger accepts as that proxy, so a config-only holder must not be able to forge the audit trail (ledger-integrity risk). `identity` is expected to be held by the operator CLI on the server host, not by manager. Default: manager receives `config` only (in M1) or nothing (M0). |
| Scope | Management credential is valid only on management routes. Valid on no read, ingest or proxy-config GET route. |
| Absent/unset | No management entries configured means management routes answer 404, same pattern as the read token. Fail closed. |
| Reload failure (M-5) | If the verifier file is unreadable, malformed, or fails the owner-only/ownership check on reload, the server **denies all management requests** (404/401 as for no entries), raises an alert, and keeps denying until a valid file loads. It never keeps serving from the previous in-memory set. A failure at boot is the same. |
| Storage (server) | Verifier file, owner-only mode (0600) owned by the server user. Mode, owner and non-symlink are checked at load and on every reload. Never logged. Token appears once at creation, on the operator terminal. |
| Storage (caller) | Environment or owner-only file on the manager host, never in the DB, API responses, or the web bundle. |
| Compare | Constant-time compare of the verifier, as `auth.rs:39-48`. |
| Rotation | Add entry 2, switch caller, remove entry 1. No restart. Recommended maximum validity per entry via `not_after` (value unmeasured/operational). |
| Subject | Valid management auth yields a server-verified principal `{key_id, name, scope}`. The server has no human identity. With at most two entries per scope (overlap for rotation) the verified identity is a **machine** (manager or operator tool), so the human is always only *asserted*. Per-operator keys are allowed: one entry per operator, raising the cap. They give a verified key per operator at the cost of more secrets. (open-for-user, item 2) |
| Audit ordering (M-2) | The audit record is appended **before** the effect. If the append fails, the action has no effect and the caller gets 503. This is the enrollment precedent (`routes/enroll.rs:224-232`). Denied attempts (bad credential, wrong scope, 409, 422) are recorded too, with the result code, and with no secret material. |
| Audit read (AC-13) | A `GET /v1/proxy-management-audit` route (candidate; cursor and limit as other lists) under `proxy.read` returns the records, so AC-13 evidence is inside the API rather than out-of-band. It never returns config bodies, verifiers or tokens. If this route is not built, the evidence is out-of-band (the log file on the server host) and the AC-13 verification must say so. |
| Audit record | Append-only log, same signed append-only mechanism as the enrollment audit in a separate stream. Fields: sequence, `occurred_at`, action (`proxy.register`, `proxy.identity_issue`, `proxy.config_put`, `proxy.disable`, `proxy.enable`, `proxy.retire`), `proxy_id`, from/to revision, config hash, result code, `management_key_id` and `scope` (**verified**), `requested_by` (**asserted**, see below), request id. Never the verifier, token, or config secrets. |
| `requested_by` | Optional header from manager carrying the console subject. Stored with `requested_by_assurance: "asserted_by_caller"`. UI and API must label it "asserted", never "authenticated user". A compromised manager can claim any subject. This follows PX-007: self-asserted values are not promoted to verified facts. |
| AC-13 evidence | "Who performed it" is answered as: *verified* management key identity, *asserted* operator subject. The record states which is which. |

## 3. Manager permission mapping (D-02 part 3)

Manager today: one admin, OIDC subjects get identical rights, no roles, JWT carries only `sub` (W1 §3.2, §3.5).
Manager's own rules: read-only against sigil-server, no RBAC, stop and confirm before expanding auth (W1 §3.1).
PX-012 asks manager only for **observation** screens. Management writes are not required of manager by the spec.

### 3.1 Options

| Option | Description | AC-13 | Manager change |
|---|---|---|---|
| M0 | Manager stays read-only for proxy features (`proxy.read` only). Management is done against the server API with the management credential by an operator CLI/script. | Viewer and agent cannot change config: manager has no write route, and the server rejects read bearer, proxy cert and downstream bearer. | Read screens and client methods only. No auth change, no scope exception for writes. |
| M1 | Manager gets write routes with a static manage list (C2): `PROXY_MANAGE_SUBJECTS` (env), default empty. Checked per request, not stored in the JWT. | Console users not in the list get 403 at manager. Server still authoritative. | Adds write path, permission middleware, CSRF work (section 4), scope amendment. |
| M2 | One role (C1): every console login manages | A "viewer" cannot exist at the console. | Smallest, but conflicts with PX-023 and the stated viewer requirement. **Not recommended.** |

**Recommended: M0 for P1 as the minimum that satisfies AC-13**; M1 specified below as the conditional design if the user wants console management. (open-for-user, item 3)

**M0 is a deliberate deviation** from README ("Bootstrap/T-00 반영", lines 137–139: manager gets viewer/operator mapping and CSRF/Origin work, and README lines 70–72 defer "관리 인증 mapping") because PX-012 asks manager only for observation. README needs amending: lines 70–72 should reference this document, and lines 137–139 should say mapping and CSRF apply only if M1 is chosen. M0's cost: **no owner for an operator CLI** is defined yet. Someone must build and ship the tool that calls the management routes (and holds the `identity` scope). That is a sigil-server/proxy-side deliverable, not manager.

### 3.2 Permission table

| Permission | Granted to | Enforced where | Notes |
|---|---|---|---|
| `proxy.read` | Every authenticated console session (matches today's single class) | Manager `RequireAuth`; server read bearer | Covers list, detail, invocation reads. Secrets are never in these responses (section 5.5). Tool-name/metadata display needs a separate permission (README R1/R2). Endpoint and permission are D-05; this draft does not widen `proxy.read` to it. |
| `proxy.manage` | M0: nobody at manager. M1: subjects in `PROXY_MANAGE_SUBJECTS` | Manager middleware (defence in depth) **and** server management credential (authority) | Local admin gets it only if listed. Empty list = nobody. |
| `proxy.metadata` | Not defined here | D-05 | Open. |

Honest limit: in M1 the server sees one shared management credential for every operator. The per-user gate is manager's check alone, and attribution to a human is asserted (section 2.2). Per-user verification at the server would be B3.

Management route check order, pinned once: **(1)** mTLS peer whose cert is in the management-caller class, else **404**; **(2)** management bearer valid, else **401**; **(3)** scope sufficient for the action, else **403**. Each later step runs only after the earlier one passed, so the answers below follow from it.

Rejection tests (AC-13), independent of option:
| Caller | Route | Expected |
|---|---|---|
| Read bearer (caller cert in management class) | `PUT /v1/proxies/{id}/config` | 401, no state change |
| Proxy mTLS identity (any proxy) | `PUT /v1/proxies/{id}/config` | 404 (recommended/candidate, same as unconfigured), no state change |
| Proxy mTLS identity **plus** a valid management bearer | `PUT /v1/proxies/{id}/config` | 404, no state change |
| Host cert **plus** a valid management bearer | any management route | 404, no state change (N-2) |
| Valid bearer, cert not in the management-caller class | any management route | 404, no state change |
| `config`-scope credential (caller cert in management class) | `enable` (re-enable) | 403, no state change |
| Management credential over plain HTTP | any management route | 404, no state change |
| `config`-scope credential (caller cert in management class) | registration / CSR signing / fingerprint registration | 403, no state change |
| Downstream client bearer (caller cert in management class) | server management routes | 401 |
| Management credential | `GET /v1/proxies/{id}/config`, `POST /v1/proxy-events` | rejected |
| (M1) console user not in list | manager write route | 403, no upstream call |

## 4. CSRF / Origin rules for manager write routes (D-02 part 4)

Applies only if M1 is chosen. In M0 manager has no new write route and this section is inactive.

### 4.1 Rules (recommended, M1)

| # | Rule | Exists today? (W1 §3.4) |
|---|---|---|
| R1 | `Origin` required on every non-GET `/api/v1/proxy*` route and must equal the configured public origin. Missing or `null` is rejected. `Referer` is not a fallback. | **No.** No Origin/Referer check in non-test code. |
| R2 | `Sec-Fetch-Site`, when present, must be `same-origin`. Additional to R1. | **No.** |
| R3 | `Content-Type: application/json` exactly; other types 415. | **No.** Handlers decode directly. |
| R4 | Per-session CSRF token (double submit) in a custom header (e.g. `X-Sigil-CSRF`), derived statelessly from the session so the JWT remains stateless. Header forces a CORS preflight; no CORS is configured. | **No.** No CSRF token anywhere. |
| R5 | Request body limit on proxy write routes. Proposed 64 KiB for config PUT. **unmeasured.** | **No.** No `MaxBytesReader`. |
| R6 | No state change on GET. | Holds for the two existing writes (both POST). |
| R7 | Management failures are never retried silently and never gated on the fleet cache (stale-while-revalidate, `cache.go:149-162`). Proxy writes use a path that bypasses or invalidates the cache. | n/a |
| R8 | `SameSite=Lax` cookie kept. Not a sufficient control alone (W1 §3.4). | **Yes.** Only protection today. |
| R9 | Step-up re-authentication for manage actions. | **No.** Deferred to D-07/P3. |
| R10 | The public origin for R1 comes from an explicit config value (`PUBLIC_ORIGIN`), never from the request `Host` or `X-Forwarded-*` (manager sits behind `RealIP`/a terminator). Unset means proxy write routes are disabled. | **No.** |
| R11 | The CSRF token key is **separate from `JWT_SECRET`** (derived with its own context string or its own secret), so a token cannot be replayed as a session and rotation is independent. | **No.** |
| R12 | Proxy API responses carry `Cache-Control: no-store`. The CSRF-token endpoint too. | **No.** |
| R13 | Session lifetime: cookies last up to 12 h and logout only clears the cookie (W1 §3.2). A management action therefore may run on a stolen 12 h session. R9 is the real mitigation; until then this is a stated residual risk. | stated |

### 4.2 Existing writes

`POST /api/v1/triage/upsert` and `/note` lack R1–R5 today. Hardening them is a **separate sigil-manager issue** and is not a precondition for or part of this contract. New proxy routes must not inherit the old posture. (recommended)

## 5. Proxy downstream client auth (PX-008) and header policy (M3)

### 5.1 Client authentication (measured facts, mechanism recommended)

| Fact | Evidence |
|---|---|
| Claude Code 2.1.296 sends a static `Authorization: Bearer` from MCP config `headers` on every request incl. GET/DELETE and `server/discover` | measured (T-01) |
| Codex 0.162.0 sends a bearer from `bearer_token_env_var`; the value stays in the environment | measured (T-01) |
| OAuth discovery and client mTLS for HTTP MCP | not measured. Out of P1 for these clients. |

Recommended: **one static bearer per client principal**, 256-bit random, verified by constant-time compare against the applied config. No client OAuth in P1. (open-for-user, item 4 only for the secret generation point)

### 5.2 Principal provisioning through the config DTO

| Field | Rule |
|---|---|
| `principal_id` | Becomes `actor_id`. Server-assigned or operator-chosen, unique per proxy. Never taken from client input. |
| `actor_kind` | Declared at provisioning. `human` is not representable (README N3). Omitted means `unknown`. |
| `credential_owner_id` | Optional. Permission owner, not evidence of the executor. |
| `evidence_source` | Fixed `proxy_credential_mapping`. |
| `verifiers[]` | `{key_id, verifier, not_after?}`. `verifier` = SHA-256 of the 256-bit token. At most two entries per principal for overlap. |
| `routes[]` | Route ids this principal may use. Others are rejected (PX-008, AC-04). |

Recommended token generation: the **proxy host CLI generates the token and prints it once**; only the verifier is submitted in the config. Then server and manager never see the token. Server/manager responses show `verifier_fingerprint` (first 8 hex) only; the full verifier is returned only to the proxy's own config GET.
Alternative (server generates and shows once): simpler for operators, but the server and, in M1, manager process the secret. Item 4 in section 9.

Cross-principal isolation: a session, stream, and `Last-Event-ID` resume are bound to the principal and route that created them (5.3). Another principal presenting a valid bearer and a foreign session id is rejected (AC-04).

### 5.3 Header and session policy (decided: M3 row in decisions.md; unlisted details recommended)

| Direction | Item | Handling | Status |
|---|---|---|---|
| Request | Downstream `Authorization` | Verified, then removed | decided |
| Request | `Cookie` | Removed | decided |
| Request | Proxy auth headers (any proxy-defined auth header) | Removed | decided |
| Request | Upstream credential | Injected per route from the route's `credential_ref` | decided |
| Request | `Origin` | Checked per PX-014 (present and not in `allowed_origins` → 403); not forwarded. Absent is allowed, since non-browser bearer clients send none (browser-less clients: unverified). | decided (check, no forward); absent-allowed recommended |
| Request | `Host` | Must match the configured listen names (DNS rebinding) | recommended |
| Request | `Forwarded`, `X-Forwarded-*`, `X-Real-IP`, `Via` | Inbound removed; proxy does not synthesise them | recommended |
| Request | `User-Agent` | Replaced by a fixed proxy value upstream | recommended |
| Request | `MCP-Protocol-Version` missing after initialize | 400 | decided (m5) |
| Request | Hop-by-hop headers | Removed | recommended |
| Response | Header policy (M-4) | **Allowlist**, not a blocklist. Only these upstream response headers are forwarded: `Content-Type`, `Content-Encoding`, `Vary`, `Content-Length` (or chunked framing set by the proxy), `Cache-Control`, `Date`. `Content-Encoding` and `Vary` are allowed because forcing `Accept-Encoding: identity` upstream would alter the request the client intended and some upstreams ignore it; relay-first (D-01) keeps the bytes unchanged and the client decodes. Limits still apply to decoded size (validation.md D-04 note) and `response_bytes` counts bytes before decompression (README). Everything else is dropped, including `Access-Control-*`, `Proxy-Authenticate`, `WWW-Authenticate`, `Set-Cookie`, `Set-Cookie2`, `Content-Location`, `Location`, `Refresh`, `Alt-Svc`, `Link`, `Mcp-Session-Id` and `Strict-Transport-Security`. The proxy sets its own security headers. Adding a header requires a contract change. | allowlist recommended; removal of `WWW-Authenticate`/`Set-Cookie` decided |
| Session | Foreign session | A foreign principal, route or session id gets the **same 404** as an unknown session id (no oracle). | recommended |
| Response | Upstream `Mcp-Session-Id` | Not exposed. Proxy issues its own id. | decided (1:1 binding) |
| Response | 3xx / `Location` | Not followed, not relayed. Fixed error. | recommended (PX-014 redirect) |
| Response | Upstream 401/403 | Fixed proxy error (5.4); route health records `upstream_auth_rejected` | mapping decided; shape recommended |
| Session | Binding | Proxy-issued downstream session id bound 1:1 to (principal, route, upstream session). `Last-Event-ID` resume only inside the bound session. | decided |

Each row requires a rejection or stripping test (decisions.md M3).

### 5.4 Upstream 401/403 mapping (recommended)

Return HTTP 200 `application/json` with a JSON-RPC error `-32603`, a fixed message, no `data`, echoing nothing except the request `id`.
This is the same shape as the runtime route refusal (section 7), so clients see one failure class. Never HTTP 401 to the downstream client: a 401 without `WWW-Authenticate` is indistinguishable from "your proxy bearer is wrong".
Audit label (L3): the earlier `protocol_error` label is withdrawn. An upstream rejecting the proxy's credential is not a protocol violation, and `protocol_error` is used elsewhere for unsupported capability/version. Recommended: completion `unknown`/`sent` with no reason, since the proxy cannot establish that no execution occurred. The alternative, `denied`, is rejected because `denied` means a pre-dispatch refusal (`not_sent`). A new reason such as `upstream_auth_rejected` would be a schema change (open, item 7).
The fixed message text is not yet defined anywhere in the repo (open question 3).

### 5.5 Upstream credential distribution and secrecy (PX-009)

| Option | Mechanism | Assessment |
|---|---|---|
| U1 | Upstream secrets live **only on the proxy host** (owner-only file or environment). Config carries a `credential_ref` name; the proxy resolves it locally. | Secret never crosses the control plane, server, or manager. Rotation is local. **Recommended for P1.** |
| U2 | Server stores and distributes upstream secrets in config | Server becomes a secret store and distribution point; needs encryption at rest and in transit, and manager must never read it. Larger surface. Not P1. |

| Rule | Detail |
|---|---|
| Never returned | Upstream secrets, downstream tokens, verifiers (except to the owning proxy), management tokens and K never appear in any API response, log, event, error or manager screen. |
| Never in events | Events carry fixed codes only (README). `credential_scope_id` is a server-assigned opaque id, not derived from the secret. |
| Missing ref | A route whose `credential_ref` cannot be resolved at apply time fails the whole config apply (section 6.2) and reports `last_update_error = apply_failed`. Config is not partially applied. |
| Origin binding (N-1) | Every local `credential_ref` is bound, in the proxy's **local bootstrap** (not in remote config), to the upstream origin(s) it may be sent to: `credentials: { <ref>: { upstream_origins: [scheme://host:port] } }` (or an equivalent local upstream allowlist). The remote-config `allowed_origins` (downstream `Origin` check) keeps its name and is a different list. The remote config may pair a ref only with a route whose `upstream_url` origin is in that list. Any mismatch fails the **whole** apply (`apply_failed`), and the previous config stays. Without this, a `config`-scope holder could point a route at an attacker origin and make the proxy send the upstream secret there. Binding is checked at apply and again per request after DNS resolution (PX-014). Unbound refs are a boot error. |
| Origin binding tests | (a) route origin not in the ref's local list ⇒ whole apply fails, old config kept; (b) config adds a new route using an existing ref with a different origin ⇒ fails; (c) redirect to another origin ⇒ credential not sent (no redirects followed); (d) unbound ref in bootstrap ⇒ proxy refuses to start. |
| Rotation | Replace the local secret and signal reload, or restart. `credential_scope_id` changes when the upstream credential binding changes (D-05 scope key), so refs re-mint. Mechanism for reload is open (question 4). |

## 6. Config DTO and lifecycle

### 6.1 DTO (candidate, not a JSON Schema yet)

```text
ProxyConfig {
  proxy_id, revision (int, server-assigned, monotonic, <= 2^63-1),
  issued_at, ttl_seconds, expires_at,
  mode: "observe",                      # P1 only
  allowed_origins: [string],
  routes: [ { route_id, upstream_id, upstream_url,
              upstream_protocol: "2025-11-25",
              credential_ref, credential_scope_id,   # scope id server-assigned
              limits? } ],
  principals: [ { principal_id, actor_kind?, credential_owner_id?,
                  verifiers: [ {key_id, verifier, not_after?} ],
                  routes: [route_id] } ]
}
PUT /v1/proxies/{id}/config  { expected_revision, config }   (management credential)
  200 { revision }      409 revision_conflict (re-GET and retry)   422 invalid
GET /v1/proxies/{id}/config                                   (proxy identity == {id})
```

Error bodies use the README structure `{error:{code,message,...}}` with fixed messages. 409 is never auto-retried by manager.
`upstream_url` is validated at PUT and again at apply against the SSRF/private-network policy (PX-014), and private destinations need an explicit management flag.
M-6: `upstream_url` **must not carry userinfo or a secret-bearing query or fragment**. PUT rejects (422) a URL with `user:pass@`, a query string, or a fragment. Credentials only travel via `credential_ref`. Read DTOs for manager (`GET /v1/proxies/{id}`) expose only scheme, host and path of an upstream, never a query (PX-009, AC-05).
**Known limit:** rejecting the query is a rule on the URL string, not a secret detector. A secret embedded in a **path** segment, or in the host (a per-tenant subdomain), still passes and would be visible in read DTOs and config GET. Operators must keep secrets in `credential_ref`. This is stated rather than hidden.

### 6.2 Revisions and apply

| Rule | Detail |
|---|---|
| desired / applied | `desired_revision` is the latest accepted PUT. `applied_revision` is what the proxy last reported as applied. PX-016 shows both and the difference. |
| Lost update | PUT requires `expected_revision == current desired`; otherwise 409. |
| Atomic apply | Proxy validates the full DTO, resolves every `credential_ref`, then swaps the whole config at once. Any failure keeps the previous config and reports a fixed code. No partial application. |
| Monotonic | Revision lower than the applied one is not a new apply (README). |
| Same-revision refresh (M-1) | The same revision with the **same config hash** is a refresh: it extends the TTL deadline and applies nothing. The same revision with a **different hash** is a fault: the proxy keeps its current config, does not extend, and reports `last_update_error = config_hash_mismatch`. |
| Server counter restored lower | If the server answers with a revision **lower** than the proxy's applied one (state restore, rollback), the proxy keeps its applied config but does **not** extend the deadline, and reports `last_update_error = stale_revision`. Config then expires at TTL and forwarding stops until an operator resolves it. This is an outage, deliberately, rather than silently trusting an old config. |
| Disabled answer (M-10) | `GET config` for a disabled proxy returns an explicit `disabled` answer (a fixed code, distinct from transport failure). On it the proxy stops forwarding new calls **immediately**, so the delay for disable is bounded by the poll interval when the server is reachable. An unreachable server falls back to TTL. This answer is given only to an authenticated proxy identity whose registry state is `disabled`; an unknown or mismatched identity gets the section 1.2 answer (recommended 404, candidate). A disabled proxy's `POST /v1/proxy-status` is rejected, so `config.state = disabled` is visible only locally (and in the `GET config` answer). The server derives "disabled" for PX-016 from its **registry**, not from a status report. |
| Status names (W2 alignment) | Only these names are used here, matching `proxy-status.schema.json`: status carries `config_hash`; `last_update_error` ∈ {`stale_revision`, `validation_failed`, `fetch_failed`, `apply_failed`, `config_hash_mismatch`}; `config.state` ∈ {`none`, `valid`, `expired`, `disabled`}. A revision regression is reported as `stale_revision`. |
| Status report | Proxy reports `applied_revision`, apply result, and config hash through `POST /v1/proxy-status`. The proxy identity comes from the mTLS peer, as for `POST /v1/proxy-events`; there is no `proxy_id` in the path, and a body `proxy_id` must equal the peer's. A GET must not carry the side effect. This is also the heartbeat/`last_seen` source. The DTO is owned by W2 (`proxy-status.schema.json`) and is cross-referenced, not defined here. |
| No merge | Remote config is never merged with local bootstrap (README). The local `upstream_origins` binding is a **constraint** checked against the remote config, not a merge: it adds no route, principal or limit, and a remote config cannot widen it. |

### 6.3 TTL and expiry

| Rule | Detail |
|---|---|
| Source | Server stamps `ttl_seconds` and `expires_at` at issue. |
| Clock | Proxy computes its deadline on a **monotonic clock from receipt** (`receipt + ttl_seconds`), so wall-clock skew cannot extend it. `expires_at` is for display. |
| Expiry | After the deadline the proxy forwards **no new calls**. In-flight calls finish and are audited. New sessions and new requests on existing sessions are refused with the fixed error. |
| Refresh | Proxy polls at an interval well under TTL, with jitter. The 503 boot gate of the server (`app.rs:140-154`) is treated as a retryable miss, not an apply failure. |
| Restart | The monotonic deadline does not survive restart. Recommended: a restarted proxy **requires a fresh fetch** before forwarding (fail closed). Alternative: honour a persisted copy until its wall-clock `expires_at`. (open-for-user, item 5) |
| Proposed values | poll 30 s ± jitter, default TTL 300 s, bounds 60–900 s. **unmeasured**, proposals only. |

### 6.4 Maximum revocation delay (stated honestly)

| Action | Server-side effect | Proxy-side effect | Maximum delay until the proxy stops using the old state |
|---|---|---|---|
| Disable proxy | Immediate for all server routes (registry per request); `GET config` answers `disabled` | Proxy stops new calls on the `disabled` answer | At most the **poll interval** if the proxy can reach the server and its connection is accepted; otherwise at most **TTL** after its last successful fetch, plus response transit. Already-forwarded calls are not recalled. |
| Remove a principal / rotate its bearer | Next config revision | Applied at next successful poll | At most **poll interval** if reachable, otherwise at most **TTL** since last successful fetch. |
| Change a route | Same | Same | Same |
| Rotate an upstream credential | None (U1) | Local operation | Local; no central bound |
| Revoke a cert | Registry disable (above) | — | Same as disable. Cert expiry (unmeasured, 30 d proposed) is only a backstop and does not cut open connections. |
| **Compromised proxy host (N-3)** | Disable cuts only the **control and ingest planes**: config GET answers `disabled`, events/status are refused, no new config | A compromised host can ignore `disabled` and TTL, keep forwarding, and keep using the upstream credentials it holds locally (U1). Nothing the server does reaches that process. | **No bound from the server.** Recovery requires rotating the upstream credentials **locally** at the upstream (and the downstream client tokens), then re-registering or retiring the proxy. Disable is necessary, not sufficient. |

Not immediate. **TLS connections outlive cert expiry** (M-7): an established connection is not re-validated, so an expired or disabled cert's open connection can continue until the server or proxy closes it. The server therefore checks the registry per request and closes connections of a disabled proxy where it can; it does not rely on cert expiry. Adding the proxy CA to the trust bundle needs a restart (section 1.1), so the initial rollout has an outage window. Long-lived SSE streams and sessions established before the change continue until their calls end or the proxy's own session rules end them; new calls stop at expiry. Real client behaviour at expiry is unverified.

## 7. Cross-references (not restated)

| Topic | Where it is defined | Status |
|---|---|---|
| Runtime route refusal answer (`-32603`, fixed message, no `data`, no echo; HTTP 200 `application/json` on the initialize id; reasons in audit/health only) | [decisions.md](../decisions.md) "런타임 route 거절 응답"; reasons in README "Protocol revision, tasks and cancellation" | decided. The message **text** is not yet fixed anywhere. |
| B1 modern request answer (HTTP 400, empty body, authentication first) | decisions.md "B1 modern 요청"; README N4 correction 4 | decided |
| Pre-dispatch refusals (`-32602`, `-32601`) | README m4 table | decided |
| Cancel before dispatch HTTP shape | README M3 / N13 | decided, P1 to verify |

## 8. sigil-manager change requests (to file later as one issue; **not filed**)

All items are conditional on the option noted. Manager's AGENTS.md requires user confirmation before expanding auth.

| # | Request | Needed for |
|---|---|---|
| 1 | Scope amendment in AGENTS.md/CLAUDE.md and UI/UX §9/D5: a proxy-only, narrow exception to "read-only against sigil-server" and "no RBAC". M0 needs only the read side. | M0 (read part), M1 (write part) |
| 2 | Server client: read methods and DTOs for `/v1/proxies*`, `/v1/proxy-invocations*`; typed errors for 403/409/422/424; do not map 404 to `ErrReadAPIDisabled` for these routes | M0, M1 |
| 3 | Cache: separate keys for proxy reads; write bypass or invalidation | M0, M1 |
| 4 | Rendering safety for upstream-controlled strings; CSP stays `script-src 'self'` | M0, M1 |
| 5 | UI: proxy list/detail, desired vs applied revision, `expires_at`, ingest gap and connection state (PX-016); mutation controls hidden for non-managers (server stays authority) | M0 (read), M1 (write) |
| 6 | Management credential config and validation; document rotation | M1 |
| 7 | `PROXY_MANAGE_SUBJECTS` and a per-request permission middleware beside `RequireAuth`; defined behaviour for the local admin | M1 |
| 8 | CSRF/Origin rules R1–R5 and R10–R12 on new write routes (section 4) and SPA `api()` helper change | M1 |
| 9 | Send the verified subject as `requested_by`; never accept a subject from the browser | M1 |
| 10 | Tests: read-token/viewer/agent rejection, cross-origin write rejection, session expiry mid-write | M1 |
| 11 | Deployment docs: how manager reaches an mTLS-enabled server | M0, M1 |
| — | **Separate issue:** harden the existing triage writes (R1–R5) | independent |

## 9. Decisions needed from the user

| # | Decision | Options | Recommended | Consequences |
|---|---|---|---|---|
| 1 | Proxy identity model | A1a separate proxy CA merged into the bundle with registry authority · A1b second listener · A2 host CA reuse | **A1a** (A1b later) | **Also decides the management-caller cert class (N-2). Sub-choice: separate management CA vs host CA plus fingerprint list (recommended: fingerprint list, fewer CAs; a separate CA if manager and operator CLI certs must rotate independently).** It also fixes that the loopback-behind-terminator topology cannot serve proxy/management routes without re-originated mTLS. A1a needs a **server restart** to load the new CA bundle (`main.rs:256-262`), plus the issuer field, unconditional host/proxy rejection and a proxy signer: all sigil-server changes. A1b adds listener code and operator surface. A2 makes proxies hosts and is not recommended. |
| 2 | Management credential | B1′ verifier file with rotation · B1 env token (restart to rotate) · B2 manager mTLS | **B1′ + B4** | Adds the H3 `config`/`identity` scopes and a reload path with fail-closed behaviour. At most two entries per scope means the human stays only asserted unless per-operator keys are chosen. B1 needs restarts to rotate. B2 needs a TLS client in manager. |
| 3 | Manager write scope in P1 | M0 read-only manager · M1 static manage list · M2 single role | **M0** (M1 specified) | M0 leaves **no owner for the operator CLI** that calls management routes and holds `identity`; that deliverable must be assigned. M0 deviates from README lines 70–72 and 137–139 (amendment needed). M1 needs the manager scope amendment, CSRF R1–R13 and the manage list. M2 removes any viewer. |
| 4 | Where downstream tokens are generated | Proxy host CLI, verifier only submitted · server generates and shows once | **Proxy host CLI** | Server and manager never hold the token, but operators must run a tool on the proxy host. Server generation is simpler and exposes the secret to the server (and to manager under M1). |
| 5 | Restart with server unreachable | Fail closed until a fresh fetch · honour persisted config to wall-clock expiry | **Fail closed** | Fail closed makes a server outage plus a proxy restart an outage of forwarding. Honouring the persisted copy keeps service up but trusts the wall clock and the file, and a rolled-back clock extends the config. |
| 6 | Events from a disabled-then-re-enabled proxy | Accept, tagged with presenting fingerprint · quarantine until operator releases | **Accept, tagged** | Accepting includes events from a possibly compromised window, which the ledger then holds as ordinary events (traceable by fingerprint, not distinguished in views). Quarantine needs an operator release step and a quarantine store. |
| 7 | Upstream 401/403 audit | `unknown`/`sent`, no reason · new reason constant (schema change) | **`unknown`/`sent`, no reason** | A new constant needs a schema/contract version bump and checker cases. The no-reason form cannot separate this cause from other `unknown` results in queries. |
| 8 | `credential_ref` origin binding (N-1) | Local bootstrap binds each ref to its allowed upstream origin(s); mismatch fails the whole apply · unbound (any config-paired ref is sent to whatever origin config names) | **Local binding** | Local binding costs a bootstrap entry per credential and a restart or reload when an upstream origin changes. Unbound lets a `config`-scope holder (or a manager compromise under M1) redirect upstream secrets to an attacker origin. |

## 10. Open questions

1. Exact proxy SAN form and whether the extractor change (URI or suffixed DNS) is acceptable; compatibility with `$defs/id`.
2. Proxy CA key locality (server host vs offline) and the operator tooling that signs CSRs. Same question for the management-caller class: separate management CA vs host CA plus fingerprint list (§9 item 1).
3. The fixed `-32603` message text. Proposed: `Internal error` (the standard JSON-RPC name for the code).
4. How a proxy reloads a rotated upstream secret or verifier file: signal, file watch, or restart.
5. `last_seen` semantics beyond what `proxy-status.schema.json` (W2) defines, shared with PX-016 and the gap/heartbeat channel.
6. Metadata lookup permission (`proxy.metadata`), tied to D-05.
7. Real-client behaviour at config expiry for open SSE streams (unverified).
8. Whether server management routes need rate limiting and what the 503 boot gate means for a management write in flight. Also the exact route and DTO of the management-audit read (section 2.2).
9. TTL, poll, cert lifetime and body-limit numbers are proposals and need measurement (validation.md D-04 has none for the control plane).
10. Manager's session lifetime (12 h, no server-side revocation) bounds how long a demoted subject keeps console access if the list is changed without a restart. M1 mitigates by checking per request; list reload mechanism is open.

D-02 stays **open** until the items in section 9 are decided and the contract is independently reviewed.

## 11. Review mapping (W3-fix): finding → change

| Finding | Change | Where |
|---|---|---|
| H1 | Proxy and management routes 404 without server mTLS; same-connection `PeerIdentity` required; management bearer never over plain HTTP, loopback included (stated and justified) | 0.1, 2.2 |
| H2 | Unconditional two-way host/proxy rejection; `PeerIdentity` issuer field; distinct CA subject DNs; signing profile with CN/SAN pinned and no `copy_extensions`; all listed as sigil-server change | 1.1, 1.2 |
| H3 | `config` vs `identity` scopes with the ledger-integrity reason; offline-CA "register fingerprint" step | 2.2, 1.3 |
| M-1 | Same revision and hash extends TTL; same revision, different hash is a fault; lower server revision does not extend | 6.2 |
| M-2 | Audit appended before the effect, failed append means no effect, denied attempts recorded; audit-read route or explicit out-of-band statement | 2.2 |
| M-3 | Identical answer for mismatch and unknown; proxy cert on PUT recommended 404 (candidate; D-02 미결, frozen ingest 403 is the baseline until adopted) | 1.2, 3 |
| M-4 | Response header allowlist; foreign principal/route/session same 404 as unknown session | 5.3 |
| M-5 | Reload failure denies all and alerts; owner-only/ownership checks; two-entry cap means human only asserted, or per-operator keys | 2.2 |
| M-6 | `upstream_url` rejects userinfo/query/fragment; read DTOs show scheme/host/path only | 6.1 |
| M-7 | CA bundle read only at boot, restart required; established TLS connections outlive cert expiry | 1.1, 6.4 |
| M-8 | Old fingerprint dropped at first `next` request or hard deadline; disable removes both | 1.3 |
| M-9 | Consequences column | 9 |
| M-10 | Explicit `disabled` config answer; proxy stops immediately, bound = poll interval | 6.2, 6.4 |
| L1 | Public-origin config source, CSRF key separate from `JWT_SECRET`, `Cache-Control: no-store`, 12 h cookie residual risk | 4.1 R10–R13 |
| L2 | M0 stated as a deliberate deviation from README lines 137–139 | 3 |
| L3 | `protocol_error` label withdrawn; `unknown`/`sent` recommended with justification | 5.4, 9 item 7 |
| L4 | Registry fingerprint = blake3 of leaf DER | 1.2 |
| L5 | Spool growth while disabled cross-referenced to the PX-013 disk limit | 1.3 |

### W3-fix-2 mapping (finding → change)

| Finding | Change | Where |
|---|---|---|
| N-1 | Local-bootstrap `credential_ref` → allowed-origin binding; mismatch fails the whole apply (`apply_failed`); four rejection tests; `config` scope may add a principal with its own verifier (attributed, not forged); §9 item 8 | 2.2, 5.5, 9 |
| N-2 | Management-caller cert class (separate issuer or fingerprint list); terminator topology cannot serve proxy/management routes without re-originated mTLS; folded into §9 item 1 | 0.1, 9 |
| N-3 | Disable cuts only control and ingest planes; recovery needs local rotation of upstream credentials | 6.4 |
| `enable` scope | Re-enable moved to `identity`; disable stays in `config`; test row | 2.2, 3 |
| Mismatch/unknown status | Recommended/candidate 404 `proxy_unknown` (D-02 미결; frozen ingest 403 is the baseline); evaluated before 422>403>409>424 | 1.2 |
| State answers | `disabled` served before closing the connection; `retired` and `pending` defined | 1.3 |
| Old-fingerprint deadline | Operator alert before the deadline | 1.3 |
| Proxy cert + valid bearer on PUT | Test row ⇒ 404 (plus host cert + bearer) | 3 |
| Response allowlist | `Content-Encoding` and `Vary` allowed (relay-first), justified | 5.3 |
| `upstream_url` limit | Query rejection documented as a known limit (path/host secrets pass) | 6.1 |
| §8 item 8 | "R1–R5 and R10–R12" | 8 |
| Status names | `config_hash`, `last_update_error` set, `config.state` set; regression → `stale_revision` | 6.2 |

### W3-fix-3 mapping

| # | Change | Where |
|---|---|---|
| 1 | Check order pinned once (cert class 404 → bearer 401 → scope 403); 401/403 rows annotated | 3 |
| 2 | Management-caller issuer options, proxy CA excluded, cross-class rejection; sub-choice in §9 item 1 and open question 2 | 0.1, 9, 10 |
| 3 | Bootstrap key `upstream_origins`; binding is a constraint, not a merge | 5.5, 6.2 |
| 4 | Disabled proxy's status POST is rejected; PX-016 disabled derived from registry | 6.2 |
| — | `proxy_unknown` marked [candidate] | 1.2 |
