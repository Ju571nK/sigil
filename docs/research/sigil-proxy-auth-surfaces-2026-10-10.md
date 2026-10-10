# Sigil Proxy auth surfaces — D-02 input research, 2026-10-10

Task: **W1 / D-02 input**, role researcher. Status: source inspection complete; no running system was exercised.
Decision authority: none. Section 5 lists options, not a decision. Traces: PX-008, PX-009, PX-012, PX-014, PX-016; AC-04, AC-08, AC-13.

## Commits examined

| Repo | SHA | Note |
|---|---|---|
| sigil (producer) | `46cc990e2e0c647b2814e3a1dcf6dff2b172f882` | main; server code compared against `24eddb26b8810224c95df6812f23b5901c11dff6` (2026-09-27 survey) |
| sigil-manager (consumer, read-only) | `e5e116e4d7c89d6644d8c5704c3d903651072b67` | main; compared against `41b09b1f76dab25da55c2c5b85dbd2bb78bd6641` (survey) |

Manager was inspected with read/grep/log/diff only. Nothing was written there or fetched from a remote.

## Evidence labels

- **source** — read the code at the cited file:line.
- **documented** — stated in a repository document, not checked against code.
- **measured** — a command was run and its output observed. In this task only `git`/`grep` inspection ran; the T-01 probe's measurements are cited as such, not re-run.
- **inferred** — conclusion drawn from source/documents, not observed.

Paths without a prefix are in the sigil repo. `manager:` paths are in sigil-manager.

---

## 1. sigil-server today

### 1.1 One listener, three credential types, one allowlist

There is a single `bind` address (`crates/sigil-server/src/config.rs:25`). Transport is chosen once at startup:
mTLS if `tls_cert_path`, `tls_key_path` and `client_ca_path` are all set (`config.rs:177-179`, `main.rs:213-223`),
otherwise plain HTTP with a warning (`main.rs:224-230`). *source*

When mTLS is on it covers **every route**, not only ingestion. The verifier is built with
`WebPkiClientVerifier::builder(roots).build()` (`main.rs:258-264`) with no anonymous-client option, and
the trust store is the single `client_ca_path` bundle (`main.rs:256-262`). A client without a certificate chained
to that bundle cannot reach `/v1/healthz`, the read API, or `/v1/enroll`. *source* (that the rustls default
rejects anonymous clients is *inferred* from the builder call; the module doc also states it, `tls_accept.rs:28-30`).

| Credential | Where checked | Guards | Evidence |
|---|---|---|---|
| mTLS client cert, chain to `client_ca_path` | TLS handshake, whole listener | every route when mTLS is configured | `main.rs:213-223,258-264` |
| Read bearer `SIGIL_SERVER_READ_TOKEN` | `require_bearer` route_layer | `/v1/meta`, `/v1/policy/meta`, `/v1/fleet/hosts[/:id]`, `/v1/fleet/risk`, `/v1/fleet/compliance`, `GET /v1/events[/:id]`, `/v1/artifacts[/:file]` | `app.rs:78-129`, `auth.rs:64-82` |
| Enrollment token (body) + optional issuer-cert fingerprint list | `post_enroll` | `POST /v1/enroll` | `app.rs:130-133`, `routes/enroll.rs:5-6,108-129` |
| Host allowlist (`hosts.json`) | handler | `POST /v1/events`, `GET /v1/policy`, `GET /v1/rule-packs` | `events_route.rs:110-116`, `policy_route.rs:24-30`, `rule_packs_route.rs:22-28` |
| none (liveness) | — | `GET /v1/healthz` | `app.rs:77`, `routes/healthz.rs:6-13` |

Details that matter for D-02: *source*

- **Read bearer.** Loaded once from the environment, trimmed; unset/empty makes every guarded route return 404, wrong or missing
  returns 401 (`auth.rs:19-31,69-81`). Constant-time compare (`auth.rs:39-48`). One shared secret: no identity,
  no scope, no per-consumer token. `require_bearer` passes through without producing any subject (`auth.rs:77-78`).
  The value is read at boot only (`main.rs:96`); I found no reload path (grep for `sighup|reload|signal` in `crates/sigil-server/src` returned only unrelated fleet-index names). *inferred*: rotation needs a restart.
- **`POST /v1/events`, `GET /v1/policy`, `GET /v1/rule-packs` are outside the bearer layer** (`app.rs:71-76`).
  Their only gate besides TLS is `allowlist::permits`, which returns true for everything when no allowlist
  file exists (`allowlist.rs:54-60`).
- **Policy and rule-pack routes ignore the TLS peer.** The handlers take `host_id` from the query string and never extract
  `PeerIdentity` (`policy_route.rs:14-30`, `rule_packs_route.rs:12-28`). Any certificate chaining to the client CA can request
  any allowlisted host's bundle. *source*
- **Events route** can additionally bind the peer cert to the envelope `host_id`, but only when
  `events_require_cert_host_match: true`; default is false (`config.rs:78-83`, `events_route.rs:87-108`).
  Boot refuses that flag without the mTLS triple (`config.rs:157-167`).
- **Enrollment** (`POST /v1/enroll`) signs a CSR with the operator's intermediate CA after a single-use per-host token
  and requires CN == `host_id` (UUID) (`routes/enroll.rs:74-80,146-158`). It also adds the host to the allowlist
  (`routes/enroll.rs:256-268`). The issued profile is fixed: `CA:FALSE`, `clientAuth`, `subjectAltName=DNS:<host_id>`
  (`enroll/sign.rs:126-129`); default validity 30 days (`enroll/mod.rs:28`). The caller may be limited to a fingerprint list
  `enroll_issuer_fingerprints` (`config.rs:63-68`, `routes/enroll.rs:108-129`).
- **Boot gate.** Until the fleet index is rebuilt, every route except `/v1/healthz` answers 503 + `Retry-After: 5`
  (`app.rs:140-154`). A proxy control-plane route added behind the same router would inherit this unless exempted.

### 1.2 How the mTLS client identity is extracted and bound

`PeerCertAcceptor` wraps axum-server's rustls acceptor, reads the first peer certificate after the handshake and injects
`Arc<PeerIdentity>` into every request's extensions (`tls_accept.rs:113-143,148-172`). *source*

`PeerIdentity` = `{fingerprint, cn, san_dns}` (`tls_accept.rs:45-52`):

- `fingerprint`: blake3 hex of the leaf DER, always set (`tls_accept.rs:58-60`).
- `cn`: the **first** subject CN, if the cert parses (`tls_accept.rs:72-79`).
- `san_dns`: all DNS SANs; other SAN types ignored (`tls_accept.rs:80-94`).
- Parse failure degrades to `None`/empty, fingerprint stays (`tls_accept.rs:60`).
- Over plain HTTP the extension is absent; handlers see `None` (`tls_accept.rs:16-18`).

Binding rule today: a request passes `events_require_cert_host_match` when CN **or** any SAN DNS equals the envelope `host_id`,
ASCII case-insensitive (`events_route.rs:90-94`). A mismatch returns 404 `host_unknown`, byte-identical to the
allowlist rejection (`events_route.rs:102-106`). The issuer gate for enrollment uses fingerprint equality instead
(`routes/enroll.rs:109-111`). The `host_id` is a UUID in practice (enrollment enforces it, `routes/enroll.rs:74-80`; the
events path does not).

Not present: an identity registry (cert → principal), per-route CA, CRL/OCSP or any live revocation. The operator guide lists
"per-host cert↔host_id binding, CRL/OCSP revocation" as follow-ups and calls short cert lifetimes "the MVP's revocation
substitute" (`docs/install-server.md:217-220`; `enroll_cert_days` comment at `:184`). *documented*

### 1.3 What a proxy identity can reuse, and what must be new

| Piece | Reuse? | Why / evidence |
|---|---|---|
| mTLS listener + `PeerIdentity` extractor | reusable | Already puts `{fingerprint, cn, san_dns}` on every request (`tls_accept.rs:45-52,148-172`) |
| Enrollment CA, `/v1/enroll`, enrollment tokens | reusable only with care | Handler validates `host_id` as a UUID and writes it into the **host** allowlist (`routes/enroll.rs:74-80,256-268`); a proxy enrolled this way would become an allowlisted *host* for `/v1/events`, `/v1/policy`. *inferred* |
| `client_ca_path` trust bundle | one bundle only | Host and proxy certs under the same bundle are indistinguishable at the TLS layer (`main.rs:256-262`). Role separation must therefore come from a post-handshake registry, not from the CA. *inferred* |
| `allowlist` (`hosts.json`) | no | Host-only, flat set of strings, loaded at boot; mutated at runtime only by enrollment (`app.rs:28-31`, `allowlist.rs:11-14`) |
| Read bearer | no | Grants all fleet reads; no identity; PX-009 forbids reuse (`contracts/README.md:80`) |
| Fingerprint equality (issuer gate pattern) | reusable pattern | `routes/enroll.rs:108-129` |
| New: proxy registry (proxy_id → fingerprint/CN, state, revision), proxy-route authz middleware, management credential check, management audit | **new** | None exist; the router has no proxy routes (`app.rs:65-135`) |

---

## 2. Delta since the 2026-09-27 survey

### 2.1 sigil (`24eddb2` → `46cc990`)

`git diff --stat 24eddb2 HEAD -- crates/sigil-server/src` touched 10 files (measured). Auth-relevant outcome: none.
`app.rs`, `main.rs` diffs only drop the license state and add `audit_head` loading (diff inspected; `auth.rs` and
`tls_accept.rs` have no changes in that diff). *measured + source*

| Change | Commit | Effect on D-02 |
|---|---|---|
| License verification removed; `/v1/meta` drops `license`, adds `fleet: {active_host_count, active_window_days}` | `66f690a` (v0.9.0) | Consumer shape change only (`routes/meta.rs:56-68`). No auth change |
| `audit_head.pubkey` reported only when the key ids match | `ad3ba8b` | Cosmetic for D-02 (`routes/meta.rs:44-50`) |
| Config: top-level `active_window_days`, deprecated `license:` block still parsed | `66f690a` | `config.rs:8-20,92-96`; no bearing on auth |
| Declared MSRV raised to 1.88 | `5c77458`, PR #241 | Build only |
| Auth model: read bearer, mTLS listener, enrollment, peer identity | unchanged | Survey section 1 remains accurate; section 1 above adds line-level citations |

The survey's claim that the read bearer has no identity result and that host binding is optional by default still holds
(`auth.rs:64-82`, `config.rs:78-83`).

### 2.2 sigil-manager (`41b09b1` → `e5e116e`)

`git log 41b09b1..HEAD` shows two commits: `6c71aaf` fix(fleet): read active host count from `/v1/meta.fleet`, and merge `e5e116e`
(measured). The diff touches 19 files: fleet client/mocks, a removed license banner, the contract doc and web tests
(`git diff --stat`, measured). Nothing under `internal/api/v1`, `internal/auth`, `internal/config` or `internal/server`
changed in auth behavior (the `handlers_test.go` edit is a test fixture). *measured + source*

Consumer-API effect: `HTTPClient.Meta` maps legacy `license.*` to `fleet.*` when `fleet` is absent
(`manager:internal/fleet/http.go:56-77`). Contract §14.13 records this
(`manager:docs/superpowers/specs/2026-05-16-fleet-api-contract.md`). No new endpoints are consumed.

OIDC (single provider, subject allowlist) already existed at `41b09b1`; the survey recorded it. Re-read below for detail.

---

## 3. sigil-manager today

### 3.1 Repository rules that constrain D-02

`manager:AGENTS.md:67-70`, `manager:CLAUDE.md:84-87`: the console is "**read-only** against `sigil-server`".
`manager:AGENTS.md:72-86` / `CLAUDE.md:89-103`: out of scope include "API token rotation/scoping/revocation", multi-tenancy,
SSO beyond one basic provider, and "Auth in this repo should be **at most** simple username/password or a single basic SSO ...
stop and confirm with the user before expanding it." UI/UX D5: "Fleet data is read from `sigil-server`; triage state ... is owned
by `sigil-manager` in its own DB" (`manager:docs/superpowers/specs/2026-05-16-ui-ux-design.md:44`). §9: single admin; OIDC
subjects "receive the same console permissions. No user management or RBAC is added ... multi-user RBAC remain outside this
repository's scope" (`ui-ux-design.md:277-286`). *documented*

Consequence (*inferred*): proxy management writes and a viewer/operator split are outside the written scope of the repo.
Manager's own instructions require stopping and confirming with the user before expanding auth. The survey (`§4`) had already
named this contradiction.

### 3.2 How users authenticate

| Aspect | Today | Evidence |
|---|---|---|
| Local login | One admin: `ADMIN_USERNAME` + bcrypt `ADMIN_PASSWORD_BCRYPT`; both checks always run, fixed 250 ms fail delay | `manager:internal/config/config.go:38-39,136-140`, `manager:internal/api/v1/auth.go:37,48-56` |
| Login throttling | 10/min per remote IP; loopback exempt; key from `RealIP` (X-Forwarded-For) | `manager:internal/api/v1/server.go:56-59`, `ratelimit.go:11-16,69-83`, `internal/server/server.go:20` |
| OIDC | One discovery-based provider, optional; admission = exact match of provider `sub` in `OIDC_ALLOWED_SUBJECTS`; redirect path fixed | `manager:internal/auth/oidc.go:23-52,169`, `manager:internal/config/config.go:90-98` |
| OIDC subject in session | `oidc:` + sha256 of `[issuer, sub]`; email/name never used | `manager:internal/auth/oidc.go:185` |
| Session | HS256 JWT, issuer `sigil-manager`, claims: `iss, sub, iat, nbf, exp` only; TTL `JWT_TTL_HOURS` default 12 h; OIDC sessions capped at ID-token expiry | `manager:internal/auth/jwt.go:13-18,92-98`, `config.go:100-104`, `internal/api/v1/oidc.go:62` |
| Cookie | `sigil_session`, HttpOnly, `SameSite=Lax`, `Secure` unless `SIGIL_INSECURE_COOKIE=1`, Path `/` | `manager:internal/api/v1/middleware.go:15`, `auth.go:64-73`, `cmd/sigil-manager/main.go:72-76` |
| Logout | Clears the cookie only; the JWT stays valid until `exp`. No server-side session store | `manager:internal/api/v1/auth.go:83-95`, `manager:docs/operations/oidc.md:74-79` (documented: rotate `JWT_SECRET` and restart to invalidate all) |
| Authorization | `RequireAuth` verifies the cookie and stores only the subject string in context; no roles, no claims beyond `sub` | `manager:internal/api/v1/middleware.go:57-78`, `server.go:66-84` |

There is no role or permission concept anywhere in the request path. *source*

### 3.3 How manager calls sigil-server

- Transport object: `&http.Client{Timeout: timeout}` — no TLS config, no client certificate, no custom transport
  (`manager:internal/fleet/http.go:27-36`). *source*
- Auth: `Authorization: Bearer <SIGIL_SERVER_READ_TOKEN>` on every request except healthz (`http.go:136,147`;
  token from env, `config.go:31,82`). One shared secret, process-wide. *source*
- Methods: only GET (`http.go:44-123`); the `fleet.Client` interface is read-only (`manager:internal/fleet/client.go`, package comment
  and method set). *source*
- Topology: contract §3.3 puts mTLS on the read side with the operator: "put `sigil-server` behind their own reverse proxy + TLS"
  (`fleet-api-contract.md:104-111`, again at `:680`: "mTLS on the read side | Reverse proxy + TLS = operator responsibility").
  *documented*
- Inferred consequence: against a sigil-server with mTLS enabled (`main.rs:213-223`), manager's client presents no certificate
  and the handshake fails (`main.rs:258-264`). An mTLS-enabled server is reachable by manager only through a
  fronting proxy that terminates mTLS toward the server or holds a client cert on manager's behalf. This matches
  `docs/install-server.md:255` (the `bind` comment advises a loopback bind "if behind a proxy"). *inferred*
- Cache: `endpoint + "|" + suffix` keys, single-flight, stale-while-revalidate, one global upstream scope
  (`manager:internal/fleet/cache.go:149-162`). A permission-scoped read or a write path needs different keys/invalidations. *source*

### 3.4 Existing write endpoints and their protections

Only two: `POST /api/v1/triage/upsert` and `POST /api/v1/triage/note`, both under `RequireAuth`
(`manager:internal/api/v1/server.go:81-82`), plus `POST /auth/login` and `POST /auth/logout`.

| Protection | Present? | Evidence |
|---|---|---|
| Session cookie required | yes | `middleware.go:57-78` |
| `SameSite=Lax` cookie | yes | `auth.go:72` |
| CSRF token (double submit / header) | **no** | grep `csrf` in `manager:internal` and `manager:web/src` → no hits (measured) |
| `Origin` / `Referer` / `Sec-Fetch-Site` check | **no** | grep `origin\|referer\|sec-fetch` in non-test `manager:internal`, `cmd` → only CSP comments and `Content-Type` setters (measured) |
| `Content-Type` enforcement | no | handlers `json.NewDecoder(r.Body).Decode` directly (`manager:internal/api/v1/triage.go:72,105`) |
| Body size limit | none found | no `MaxBytesReader` in non-test code (measured) |
| CSP `connect-src 'self'`, `frame-ancestors 'none'`, `form-action 'self'`, X-Frame-Options DENY | yes (browser-side) | `manager:internal/server/headers.go:11-36` |
| Actor attribution | subject string from the verified cookie | `triage.go:85-94,114-115`; stored in `triage_log.actor` (`manager:internal/triage/schema.go:52`) |
| Effect on sigil-server | none; writes go to manager's SQLite | `manager:internal/triage/repo.go:77-153` |

*Inferred*: today's CSRF posture rests entirely on `SameSite=Lax` blocking cross-site POST cookies. That does not cover
same-site attackers (sibling subdomain, or any origin sharing the registrable domain), does not cover `SameSite` downgrade in older
browsers, and was acceptable only because the writes are low-impact local triage. It is not a sufficient basis for routes that
change what the proxy is allowed to forward (PX-012, AC-13).

### 3.5 Where a proxy.read / proxy.manage split could attach

- **Identity input exists:** `Subject(ctx)` already yields a stable per-principal string (`middleware.go:25-28,74`). For OIDC it
  is a hash of issuer+sub; for local login it is the admin username (`oidc.go:185`, `auth.go:58`).
- **Permission input does not exist.** The JWT carries no role claim (`jwt.go:92-98`) and `AuthConfig` has two fields
  (`manager:internal/api/v1/server.go:15-23`). A split would need one of: a role claim added at `Sign`/`SignUntil`
  (`jwt.go:72-105`), a static subject→role map from config (extends `OIDC_ALLOWED_SUBJECTS`-style env), or a role lookup done
  server-side by sigil-server on each call.
- **Attachment point:** a second chi middleware beside `RequireAuth` inside the authenticated group
  (`server.go:66-84`), applied to new `/proxy/*` read and write routes.
- **Local admin vs OIDC:** local admin is "recovery access" with the same permissions (`ui-ux-design.md:281-283`); any mapping
  must say which role the local admin gets, and whether an allowlisted OIDC subject defaults to read-only. *documented + inferred*

---

## 4. Facts about clients and credentials that D-02 builds on

- Claude Code 2.1.296 sends a static `Authorization: Bearer` header from its MCP config on every POST/GET, including `server/discover`.
  Codex 0.162.0 sends a bearer from `bearer_token_env_var`, with the value kept in the environment. *measured*
  (`docs/research/sigil-proxy-t01-probe-2026-10-10.md:331,345,437-441`).
- Neither client's mTLS client-certificate support for HTTP MCP is recorded in the probe; OAuth was not measured
  (`...t01-probe...:333,346,453`). *unverified*
- Client-supplied `_meta` (`claudecode/toolUseId`) is correlation metadata, not identity (`...t01-probe...:443-444`;
  `contracts/README.md:359-363`). *documented*
- The contract fixes that every actor field comes from server-issued route/credential configuration and that "`human` is not
  representable" (`contracts/README.md:346-357`), and that the concrete mechanism and its mapping DTO remain D-02
  (`contracts/README.md:364-365`). *documented*
- The M3 header policy already decided (to be included in the D-02 contract): strip downstream `Authorization`, `Cookie`
  and proxy auth headers; inject upstream credentials per route; check `Origin` per PX-014 and do not forward it; remove upstream
  `WWW-Authenticate`/`Set-Cookie`; issue a proxy session id bound 1:1 to (principal, route, upstream session)
  (`docs/specs/sigil-proxy/decisions.md:24`). *documented*

---

## 5. D-02 options (no decision)

Common constraints from the spec: separate downstream/upstream/control-plane credentials (PX-009), the read bearer must not
manage or ingest (`contracts/README.md:80`), config expiry with an explicit revocation-delay bound (`contracts/README.md:30-32`),
and an authenticated attribution for management actions (AC-13).

### 5a. proxy ↔ server identity

| Option | Mechanism | Pros | Cons / risks | Evidence |
|---|---|---|---|---|
| A1 | New mTLS CA for proxies (a second trust bundle) | Role separation at the TLS layer: a host cert cannot present as a proxy and the reverse | The listener takes one `client_ca_path`; two roots must be merged into that bundle, so the TLS layer still cannot distinguish them — separation is still a registry check. Or a second listener/port (code change; `main.rs` has one bind). More operator PKI | `main.rs:256-262`, `config.rs:25,33-35` |
| A2 | Reuse the host CA; separate role by **registered identity** in a server-side proxy registry (fingerprint and/or CN→proxy_id) | No new PKI; reuses `PeerIdentity` and enrollment | A valid host cert reaches the TLS layer for proxy routes, so every proxy route must check the registry and must not fall back to "any authenticated cert"; and the allowlist default-open behavior (`allowlist.rs:54-60`) must not be copied. Enrollment would put the proxy_id into the host allowlist unless the handler is extended | `routes/enroll.rs:74-80,256-268`, `allowlist.rs:54-60`, `tls_accept.rs:45-52` |
| A3 | Static bearer per proxy (no client cert) | Matches what the real clients support for the client side; trivial rotation | Not a downstream-client option — this is the proxy→server leg, where mTLS already exists; adds a secret path and server-side token store; weaker than the existing channel | `app.rs:65-135` |
| Binding of `proxy_id` | (i) cert SAN DNS == proxy_id (enroll profile precedent); (ii) registry maps fingerprint → proxy_id; (iii) both | (i) reuses the CN/SAN comparison code (`events_route.rs:90-94`) and survives renewal; (ii) pins one leaf and breaks at each 30-day renewal unless re-registered | CN/SAN comparison is case-insensitive string equality; the first CN only is read (`tls_accept.rs:72-79`) — binding to SAN alone is more precise. Identity must be checked **before** allowlist lookup, as the events path does, to avoid an oracle (`events_route.rs:76-86`) | |

Cross-cutting for 5a: no revocation exists. Whatever option is chosen, "remove a proxy" is bounded by cert lifetime (default 30 days,
`enroll/mod.rs:28`) **unless** the registry check is live. A registry that is read per request makes disable-proxy immediate
for the server side; the allowlist cannot do this today because it is read at boot (no reload path, section 1.1). *inferred*

### 5b. Management credential for server write APIs (`PUT /v1/proxies/{id}/config` and registration)

| Option | Mechanism | Pros | Cons / risks |
|---|---|---|---|
| B1 | Separate **manage bearer** (new env, e.g. `SIGIL_SERVER_MANAGE_TOKEN`), distinct from the read token | Smallest change on both sides; same pattern as `require_bearer` (`auth.rs:64-82`); manager already holds one secret per process | One shared secret with write power; no per-user identity at the server; attribution depends on manager passing the operator subject in a header the server cannot verify (a compromised manager can claim any actor); rotation needs a restart (`main.rs:96`) |
| B2 | **mTLS client cert for the manager backend**, registered in the server registry as the "manager" principal | Strong machine identity, no shared string; uses existing extractor | Manager's HTTP client has no TLS configuration today (`manager:internal/fleet/http.go:34`) → manager change; still only machine-level identity, not the human; cert renewal handling in manager |
| B3 | **Per-user delegation**: manager forwards a signed assertion about the operator (e.g. a short-lived token it signs, or the OIDC ID token) and sigil-server verifies it | Server-side attribution and per-user revocation | Needs a trust anchor and verification code on the server; extends manager's auth beyond "single basic SSO" and into the "API token ... scoping" area its AGENTS.md lists as out of scope (`manager:AGENTS.md:79-86`); largest scope |
| B4 | B1 or B2 for the machine, plus **operator identity as an unverified-but-logged field** (`requested_by`) | Cheap; gives an audit trail | The server must label it "asserted by manager", not "authenticated user" — otherwise the PX-007 self-assertion rule is violated by analogy (`contracts/README.md:359-363`) |

Facts relevant to all: sigil-server has no management write route at all today (`app.rs:65-135`), no subject in
`require_bearer`, and no management audit log. The only append-only signed log it writes is the enrollment audit
(`main.rs:135`, `routes/enroll.rs:224-232`), which could be a model for management audit. *source*

### 5c. Manager viewer/operator mapping from a single-admin model

| Option | Mechanism | Pros | Cons / risks |
|---|---|---|---|
| C1 | Keep one role. Every console user can manage; `proxy.read`/`proxy.manage` exist only at the server | No manager auth change | AC-13 "viewer cannot call management API" is satisfiable only at the server-token level; every console login is an operator. Conflicts with the stated need for separate approvers at P3 (PX-023) |
| C2 | Static role map in manager env/config: `ADMIN_USERNAME` → manage; OIDC subjects listed per role | Smallest real split; fits existing `OIDC_ALLOWED_SUBJECTS` style (`config.go:91-95`) | Two env lists to keep in sync; role changes need restart and session lifetime (12 h, no revocation) means a demoted subject keeps its role until `exp` unless the role is looked up per request instead of stored in the JWT. Manager rules require user confirmation before expanding auth (`manager:AGENTS.md:84-86`) |
| C3 | Role claim in the JWT, set at login from the map in C2 | Cheap per-request check | Staleness as above; role frozen for up to 12 h (`config.go:100-104`) |
| C4 | Two manager credentials, one console-wide read-only token for the server and a manage path used only by a separate manage identity | Keeps manager's browser sessions read-only | Splits the console into two apps/entry points; not a viewer/operator model |

### 5d. CSRF/Origin rules for new manager write routes (candidates, to compose)

These are additions, since none exist today (section 3.4). Facts: the SPA uses same-origin `fetch` with `credentials: 'include'`
and `Content-Type: application/json` only when a body exists (`manager:web/src/api/client.ts:81-85`).

| Rule | Defends | Cost / note |
|---|---|---|
| D1 Require `Origin` (or `Referer` fallback) to equal the configured public origin on every non-GET `/api/v1/*` route; reject absent/null | Cross-site and same-site-sibling forms and fetches | Needs a configured public origin (manager sits behind a TLS terminator, `main.go:71-76`); behind `RealIP`/proxy the Host header may differ |
| D2 `Sec-Fetch-Site: same-origin` required where sent | Browser-enforced, unforgeable by page script | Older browsers omit it; use as an additional check with D1 |
| D3 Require `Content-Type: application/json` and a custom request header (e.g. `X-Sigil-CSRF`) the SPA adds | Forces a CORS preflight for any cross-origin caller; no CORS is configured | SPA `api()` helper (`client.ts:81-85`) is the single place to add it |
| D4 Per-session CSRF token (double submit) | Strongest | New state; stateless JWT (`jwt.go:92-98`) would need a derived token |
| D5 Keep `SameSite=Lax`; consider `Strict` on the session cookie | Cross-site cookie suppression | Lax already blocks cross-site POST cookies; Strict breaks OIDC redirect landing and links from other sites (callback sets the cookie then redirects, `oidc.go:67-68`) |
| D6 No state change on GET | Lax permits top-level GET navigations with cookie | Rule to state in the contract |
| D7 Re-authentication or step-up for manage operations | Session theft / XSS | Not available today; D-07 is P3 |

The contract text only asks for "CSRF/origin controls for new browser-triggered writes and tests for read-token, viewer and agent
rejection" (survey `§5 D-02`); the combination is open.

### 5e. Config TTL and revocation-delay facts

- Contract already says: central versioned config applies atomically, lower or equal versions are not new, expiry stops forwarding new
  calls, and TTL is the stated maximum for revocation lag, "not immediate" (`contracts/README.md:30-32`). The TTL value, the proxy's polling
  interval and clock-skew rules are not defined. *documented*
- Existing analogues, all measured or source facts, with no proxy-specific number:
  - Host cert lifetime default 30 days, "re-enroll replaces revocation" (`enroll/mod.rs:28`, `docs/install-server.md:184`).
  - Server allowlist and read token and CA bundle are boot-time only; no reload (section 1.1, `main.rs:92-96,256-262`). Revoking by editing
    the allowlist needs a restart. *inferred*
  - Manager session: 12 h default, no server-side revocation, `JWT_SECRET` rotation + restart invalidates all (`config.go:100-104`,
    `manager:docs/operations/oidc.md:74-79`).
  - Fleet cache in manager is stale-while-revalidate with its own TTLs (`manager:internal/fleet/cache.go:149-162`), so a read
    shown in the console can lag the server; a manage action must not be gated on cached authorization state (survey `§4`).
  - Server boot gate returns 503 while rebuilding (`app.rs:140-154`); a proxy that relies on `GET /v1/proxies/{id}/config`
    needs a documented retry/expiry behavior across that window.
- The delay chain for "revoke a proxy's access" under a live-registry design is: operator action → server registry
  write (immediate for new TLS requests only if the registry is consulted per request) → proxy's cached config expires at TTL →
  already-established streams/sessions end per the proxy's own session rules. Only the first two are server-side; the proxy
  portion is the new config TTL. No measured value exists. *inferred*

---

## 6. sigil-manager changes D-02 would require (for a future change-request issue; not filed)

Each item is conditional on the option chosen in section 5.

1. **Scope amendment** in `AGENTS.md`/`CLAUDE.md` and UI/UX §9/D5: narrow, proxy-only exception to "read-only against sigil-server"
   and to "no RBAC". Required regardless of option (`manager:AGENTS.md:67-70,84-86`).
2. **Fleet/server client**: add write methods and DTOs for `/v1/proxies*`, `/v1/proxy-invocations*`, `/v1/proxy-events` read side;
   add typed errors for 403/409/422 (currently 401/404/503 only, `http.go:129-135`); no 404→`ErrReadAPIDisabled` mapping for the new
   routes.
3. **Server credential handling**: one more secret (B1) or TLS client-cert support in `NewHTTPClient` (B2; `http.go:27-36`);
   config fields and validation in `config.go:24-51,125-166`; document rotation.
4. **Authorization layer**: a permission model on the session (C2/C3) or an explicit "single role" statement (C1), a middleware
   next to `RequireAuth` (`server.go:66-84`), and a defined role for the local admin vs OIDC subjects.
5. **Browser-write protections**: Origin/Sec-Fetch-Site/header checks (5d) for all non-GET routes including the existing triage routes;
   body-size limit; content-type enforcement; SPA `api()` helper change (`client.ts:81-85`).
6. **Attribution**: pass the verified `Subject` as a labeled field with each management call (B4) or a verifiable delegation (B3);
   never accept a subject from the browser (`middleware.go:74` is the only source today).
7. **Cache**: separate or bypass `fleet` cache keys for proxy reads and invalidate on writes (`cache.go:149-162`).
8. **Rendering safety** for tool names/descriptions and other upstream-controlled strings (PX-010 metadata); CSP stays
   `script-src 'self'` (`headers.go:11-20`).
9. **UI**: navigation, list/detail, config edit with `expected_revision` conflict handling (409), applied vs desired revision and
   `expires_at`; viewer mode hides mutation controls but the server remains the authority.
10. **Tests**: viewer/agent/read-token rejection for management routes (AC-13), cross-origin write rejection (AC-08 analogue for
    the console), session-expiry mid-write.
11. **Deployment docs**: how manager reaches an mTLS-enabled server (fronting proxy or client cert), per
    `fleet-api-contract.md:104-111,680`.
12. **Cross-repo workflow**: manager's session-start steps (fetch, push, progress log) apply to the implementer there
    (`manager:AGENTS.md:23-56`); not done in this research.

---

## 7. Unverified / limitations

- Source inspection only; no server was started, no TLS handshake or request was sent. "mTLS covers every route" rests on source plus the
  rustls builder default; I did not attempt a connection without a client cert. *inferred*
- No test suite was run. The server tests named in the survey (`events_cert_binding` etc.) were not executed.
- Manager-to-mTLS-server failure (section 3.3) is derived from the absence of any client TLS configuration, not observed.
- Neither real client's behavior with an mTLS-fronted MCP URL or OAuth was probed (T-01 left both open).
- The survey's contradiction notes on manager scope were re-read, not re-adjudicated; the scope question is a user decision.
- Cert renewal/rotation behavior for a proxy identity, revocation latency, and TTL numbers have no measured data.
- Linux/Rocky 9 behavior (D-04 target) was not exercised here; all citations are platform-independent source.
- Manager `docs/operations/oidc.md` was read only for session/revocation statements.
- This document contains no secret values; the environment variable *names* are cited.
