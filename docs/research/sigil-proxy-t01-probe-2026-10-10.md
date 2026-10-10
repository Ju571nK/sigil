# T-01 resume: SDK, raw relay, MSRV and real-client probes

Date: 2026-10-10. Base commit `cdd1d1d`. Host: macOS 26 arm64 (Darwin 25.6.0).
Task: T-01 resume (researcher task per plan.md, probe work only; executed by the coding lead
following researcher.md). Spec: PX-002, PX-003, PX-004, PX-008, PX-015; AC-01, AC-07; D-01, D-02 (client side).
Continues the [2026-09-27 recovery checkpoint](sigil-proxy-protocol-probe-2026-09-27.md).
Status: **evidence only**. No product compatibility approval, no workspace dependency/MSRV change,
no product client configuration entry added, no enforcement gate change. This supplies
client-side facts for D-02 but **does not close D-02**.

Labels: **measured** = observed by running a command on this host today;
**source** = read from local crate source (not executed behaviour);
**documented** = official documentation, not verified here; **inferred** = reasoning from the above;
**unverified** = not tested.

Tool versions (measured): rustc/cargo 1.95.0 stable (default, unchanged); Python 3.14.6;
Claude Code `2.1.296`; codex-cli `0.162.0`; rmcp `=0.16.0` (crates.io index reports `2.2.0` as the newest available).

Toolchains installed additively with `rustup toolchain install <v> --profile minimal` (measured,
`rustup toolchain list` after the work): `1.78-aarch64-apple-darwin` (rustc 1.78.0),
`1.85-aarch64-apple-darwin` (rustc 1.85.1), `1.88-aarch64-apple-darwin`, `1.89.0-aarch64-apple-darwin`.
Default remains `stable-aarch64-apple-darwin`. rustup self-updated 1.29.0 → 1.29.1 during an install.

All probes live in [`scripts/proxy-p0/probes/`](../../scripts/proxy-p0/probes/). Each Cargo project is
standalone (empty `[workspace]`, own `Cargo.lock`, `target/` ignored), so the root workspace is never
resolved: `git diff --stat Cargo.lock Cargo.toml` is empty (measured). No `test_*.py` or `__init__.py`
exists under `probes/`; `python3 -B -m unittest discover -s scripts/proxy-p0 -p 'test_*.py'` still runs
14 tests, OK (measured). The original `scripts/proxy-p0/*.py` files and the fixture revision string
`2025-11-25` were not modified.

## 0. Existing workspace MSRV baseline (measured; not a proxy finding)

Separate from probe results. The root `Cargo.toml` declares `edition = "2021"`, `rust-version = "1.78"`,
and `rmcp = { version = "0.16", features = ["server","transport-io"] }`; the committed root
`Cargo.lock` resolves `rmcp 0.16.0` (edition 2024). Measured on a detached `git worktree` of `cdd1d1d`
in a scratch directory (removed afterwards), committed lock, separate target dirs:

```sh
git worktree add --detach <scratch>/ws-msrv cdd1d1d
cargo +<tc> check --locked -p sigil-mcp --target-dir <scratch>/ws-target-<tc>
cargo +<tc> check --locked --workspace  --target-dir <scratch>/ws-target-<tc>
git worktree remove --force <scratch>/ws-msrv
```

| Toolchain | `-p sigil-mcp` | `--workspace` | First blocking error |
|---|---|---|---|
| 1.78.0 | **fail** (101) | **fail** (101) | `feature 'edition2024' is required` while parsing a dependency manifest (`idna_adapter 1.2.2`; rmcp 0.16.0 is likewise edition 2024) |
| 1.85.1 | **fail** (101) | **fail** (101) | `rustc 1.85.1 is not supported`: `darling* 0.23.0` require 1.88.0, `icu_* 2.2.0` require 1.86 |
| 1.88 | **pass** | **pass** | — (`check` only; `build`/`test` not run) |

Lockfile metadata: highest declared `rust_version` is 1.88.0 (`darling_core/darling_macro 0.23.0`,
`time 0.3.47`, `time-core`, `time-macros`); 23 locked packages use edition 2024. With the committed lock,
**1.88 is the lowest toolchain that checks the current workspace**; 1.86/1.87 were not run (they are
excluded by the `rust-version` gates above). The declared workspace MSRV 1.78 is therefore already not
buildable with the committed lock, independent of the proxy. Trimmed logs:
`probes/msrv/workspace/check-workspace-{1.78,1.85,1.88}.txt`. No workspace file was changed.

Exact 1.78.0 error lines (measured, `--workspace`; `-p sigil-mcp` gives the same class of error):

```text
error: failed to download `idna_adapter v1.2.2`
  feature `edition2024` is required
  The package requires the Cargo feature called `edition2024`, but that feature is not stabilized in this version of Cargo (1.78.0 (54d8815d0 2024-03-26)).
```

Cargo 1.78 stops at the first edition-2024 manifest it parses, which is `idna_adapter 1.2.2` (a transitive
`url`/`idna` dependency). It is not the only blocker: `rmcp 0.16.0`, which `sigil-mcp` depends on directly,
also declares edition 2024, as do 21 other locked packages. So declared MSRV 1.78 is broken by several
crates, not by rmcp alone (**measured** for the first error; the rest is from lockfile metadata). 1.89.0
was not needed because 1.88 passed. The worktree was removed with `git worktree remove --force`, then
`git worktree prune`, and its scratch target dirs were deleted.

## Reproduce

From the repository root:

```sh
# 1. rmcp 0.16.0 SDK probe
cargo build --release --locked --manifest-path scripts/proxy-p0/probes/rmcp-sdk/Cargo.toml
scripts/proxy-p0/probes/rmcp-sdk/target/release/rmcp-sdk-probe serde \
  > scripts/proxy-p0/probes/rmcp-sdk/output/serde-roundtrip.json
python3 -B scripts/proxy-p0/probes/rmcp-sdk/server_probe.py [--out DIR]   # -> DIR/server-report.json
# client mode: start the capture fixture, then point the probe at it
python3 -B scripts/proxy-p0/probes/capture/capture_fixture.py --log OUT.jsonl \
  --bearer-file "$TMPDIR/t01tok" --slow-seconds 8 &
scripts/proxy-p0/probes/rmcp-sdk/target/release/rmcp-sdk-probe client <endpoint> "$TMPDIR/t01tok"

# 2. raw relay
cargo build --release --locked --manifest-path scripts/proxy-p0/probes/raw-relay/Cargo.toml
python3 -B scripts/proxy-p0/probes/raw-relay/compare.py [--out DIR]       # -> DIR/compare-report.json

# 3. MSRV (never changes the default toolchain)
rustup toolchain install 1.78 --profile minimal   # likewise 1.85, 1.88, 1.89.0
cargo +1.78 build --release --locked --manifest-path <probe>/Cargo.toml --target-dir <probe>/target/msrv-1.78
#    MSRV-aware lock variants: copy Cargo.toml, add rust-version, then
CARGO_RESOLVER_INCOMPATIBLE_RUST_VERSIONS=fallback cargo +stable generate-lockfile
#    (resulting manifests/locks kept in probes/msrv/*-rust-<ver>.Cargo.{toml,lock})

# 4. real clients (ONE client invocation each; isolated temp config, synthetic bearer)
sh scripts/proxy-p0/probes/client-probe/run_client_probe.sh claude [--out DIR]
sh scripts/proxy-p0/probes/client-probe/run_client_probe.sh codex  [--out DIR]
```

Without `--out`, every script writes to a new `mktemp` directory outside the repository and prints its
path, so a re-run never overwrites the committed `output/` files or the committed wire logs.
`run_client_probe.sh` refuses to run if `DIR/<client>-wire.jsonl` already exists. It scrubs every output
file, including the capture log (bearer, `toolu_*` ids, vendor request ids, `cf-ray` values with their
PoP suffix), and then fails if any of those patterns remain in the outputs or in the fixture's stdout.
`compare.py` builds with `--locked`. After these script changes, `compare.py` and `server_probe.py` were
re-run (measured, 2026-10-10). compare: `ok: true`, 2 invocations per tool. server: same version table
as §1b. `run_client_probe.sh` was **not** re-run, to stay within the 3-invocation budget; its
changes are checked with `sh -n` only.

`capture/capture_fixture.py` is the probe-local fixture variant. Instead of a file copy it imports
the unmodified base module and subclasses its handler, so every base check (Host/Origin, Content-Length,
Accept, Content-Type, session, revision, initialization order) still runs. Complete list of
behavioural differences from the base fixture:

1. JSONL wire log: receive/finish times, verb, path, allow-listed headers (Accept, Content-Type,
   MCP-Protocol-Version, User-Agent, Origin, Last-Event-ID, Content-Length, Transfer-Encoding), request
   body, status. Session ids are aliased `sid#N`; Authorization is reduced to scheme + match flag.
2. Optional bearer (`--bearer-file`): a random `secrets.token_hex` value generated per run, written to a
   0600 temp file. Missing/wrong → 401 + `WWW-Authenticate: Bearer realm="sigil-t01-probe"`. A matching
   header is **removed before delegating**, because the base fixture rejects any Authorization header
   with 400 (`scripts/proxy-p0/README.md:29`). The counters oracle also requires the bearer.
3. A fifth tool `slow_ok` (appended to `TOOLS`, so it appears on tools/list page 2): counts the
   invocation, waits up to `--slow-seconds`, and returns a normal result, or closes the connection without
   a response if cancelled.
4. `notifications/cancelled` with a valid session → 202, and it cancels a matching in-flight `slow_ok`.
   The base fixture answers every notification except `notifications/initialized` with 400
   (`--strict-cancel-400` restores that; not used in the runs below).

It serves only `2025-11-25`, the same as the base fixture. `GET /mcp` → 405 as in the base fixture. The
revision each client actually negotiated is recorded below without relabelling.

## 1. rmcp 0.16.0 SDK probe

### 1a. Typed serde round-trip (measured; `rmcp-sdk/output/serde-roundtrip.json`)

Raw JSON → `ClientJsonRpcMessage` / `ServerJsonRpcMessage` → JSON:

| Input | Parsed | Round-trip |
|---|---|---|
| `initialize` with protocolVersion 2024-11-05, 2025-03-26, 2025-06-18, 2025-11-25, 2026-07-28, `1999-01-01`, `not-a-version` | all yes | identical (string kept verbatim) |
| `tools/call` request with unknown params field, unknown envelope field, `_meta` with unknown key | yes | **lost** `/params/x-param-unknown`, `/x-envelope-unknown`; `_meta` kept intact |
| `tools/call` result with unknown result field, unknown content-item field, unknown envelope field | yes | **lost** all three; `structuredContent`, `isError`, `_meta` kept |
| `initialize` result with unknown capability and unknown `serverInfo` field | yes | **lost** both |
| `tools/list` result with unknown tool field | yes | **lost** |
| `notifications/cancelled`; unknown request method `x-vendor/thing` | yes | identical (custom method kept) |
| JSON-RPC batch array | **no** | `data did not match any variant of untagged enum JsonRpcMessage` |

This **reproduces and confirms** the earlier unreproduced hypothesis: rmcp 0.16.0 typed
messages accept any version string and drop unknown fields in tool-call requests and results.

### 1b. rmcp as Streamable HTTP server (measured; `rmcp-sdk/output/server-report.json`)

Raw `initialize` requests against `StreamableHttpService` (stateful mode, default config):

| Client offered | Server answered |
|---|---|
| 2024-11-05 / 2025-03-26 | same |
| 2025-06-18, 2025-11-25, 2026-07-28, 9999-12-31, `not-a-version` | `2025-03-26` |
| `1999-01-01` (unknown) | **`1999-01-01`** (echoed) |

Source (`src/service/server.rs:228–237`, `src/model.rs:152–157`): the answer is
`min(client, LATEST)` by **lexicographic string comparison**, `LATEST = 2025-03-26`. No allowlist.
Any lexicographically smaller unknown string is echoed back as "negotiated".

Other measured server behaviour: `MCP-Protocol-Version` request header is not validated
(`2099-01-01` and `garbage` accepted, 200); unknown session id → **401** "Session not found"
(2025-11-25 documents 404); batch body → **415**. The typed handler received
`{"name","arguments"}` only: the unknown param was dropped and `_meta` was not present in the
params struct (source: moved into request context extensions).

### 1c. rmcp as Streamable HTTP client against the fixture (measured; `rmcp-sdk/output/client-*.json*`)

- Offered `2025-03-26`; the fixture answered `2025-11-25`; rmcp **accepted silently** and continued
  (source: `service/client.rs` stores peer info without a version check).
- **No `MCP-Protocol-Version` header** on any request (source: reqwest client never sets it; it is
  only in the reserved-header list). The fixture accepts a missing header, so the session worked.
- Bearer via `auth_header` sent on every POST/GET/DELETE. GET `/mcp` → 405 tolerated.
- `tools/list` pagination (2 pages), `json_ok`, `sse_ok` (comments, CRLF, multi-line data), and
  `tool_error` (`isError: true`) all worked. `drop_after_accept` → transport error, no retry
  (fixture counter 1); the session continued afterwards.
- **Cancellation:** with a 2 s per-request timeout on `slow_ok`, rmcp emits
  `notifications/cancelled` (`reason: "request timeout"`), but the fixture **received it at t=9.001 s,
  after the slow call finished (t_recv 0.994, t_done 9.0)**. Source (`transport/streamable_http_client.rs`
  main loop ~l.475): the worker `await`s each POST, including the full JSON body, inline, so the
  cancel queues behind the in-flight request. With a server that returns SSE headers immediately the
  POST would not block (**inferred, unverified**). Session closed with DELETE → 204.

## 2. Raw byte-preserving relay (measured; `raw-relay/output/compare-report.json`)

`raw-relay` (hyper 1, ~150 lines) streams request and response bodies frame by frame, strips
hop-by-hop headers, rewrites `Host` to the upstream authority, never retries, and aborts the
downstream connection without a response if upstream closes before headers. `compare.py` runs the
same 10-step sequence directly and through the relay (each with its own session), including
unknown fields in `initialize` and `tools/call` params.

Result `ok: true, failures: []`:

- Status, Content-Type, session-header presence and **body bytes (sha256) identical** for all 10 steps.
  Tee captures show the relayed request bodies equal the client bytes (unknown fields and `_meta` intact).
- SSE through the relay: `: fixture comment`, `event: message`, two `data:` lines, CRLF, final
  `\r\n\r\n` are byte-identical (169 bytes). HTTP framing differs: the upstream close-delimited
  body is re-framed as `Transfer-Encoding: chunked` downstream; chunk boundaries are not preserved.
- `drop_after_accept`: client sees `RemoteDisconnected` on both legs, no synthesized 502; fixture
  counters show 2 invocations (one per leg), so **no relay retry** (PX-015/AC-03 shape).
- DELETE 204 loses `Content-Length: 0` (hyper omits it; valid HTTP).

Limitations: one upstream connection per exchange; no TLS/HTTP/2; mid-body upstream failure not
exercised; header values compared by name only. Header forwarding was not tested.
`raw-relay/src/main.rs:26–36,76` forwards **every end-to-end request header** unchanged, including
`Authorization`, `Cookie` and `Origin`, and `compare.py` sends no such headers (source).

SSE limits: only a **single, finite SSE event** per response was measured (`sse_ok`). Not measured:
- multi-event streams, and how upstream event or chunk boundaries map downstream (only the decoded
  byte stream was compared);
- buffering and flush latency, including `X-Accel-Buffering: no`
  ([documented](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http)
  as a SHOULD for SSE responses);
- long-lived `GET` SSE streams;
- resumption with `Last-Event-ID`.

### SDK vs raw relay (D-01 comparison)

| Property | rmcp 0.16 typed path | raw relay |
|---|---|---|
| Unknown fields in requests/results | dropped (measured) | preserved byte-for-byte (measured) |
| `_meta` | preserved in serde; hidden from server handler params | preserved |
| SSE comments / event names / CRLF | re-encoded by SDK (not byte-preserving; inferred) | preserved at SSE byte level (measured) |
| Version allowlist | none; lexicographic min; echoes unknown older strings | none by itself; must be added on parsed body + header |
| `MCP-Protocol-Version` header | client never sends; server never validates (measured) | passed through unchanged (source: header filter in `main.rs`; inferred, not tested) |
| Cancellation timing | client-side cancel head-of-line blocked | independent POST, not blocked (inferred; same transport behaviour as the client) |
| Batch arrays | rejected (415) (measured) | passed through (source/inferred; not tested) |
| MSRV of dependency set | ≥1.88 (see §3) | builds on 1.78 with MSRV-aware lock |

## 3. Probe MSRV (measured; `probes/msrv/`; probe-specific, compare with §0 baseline)

Full log: [`msrv-results.txt`](../../scripts/proxy-p0/probes/msrv/msrv-results.txt). Default toolchain
stayed `stable-aarch64-apple-darwin`; rustup self-updated 1.29.0 → 1.29.1 during installs.

| Dependency set | 1.78 | 1.85 | 1.88 | 1.89.0 | stable 1.95 |
|---|---|---|---|---|---|
| rmcp-sdk, committed lock (latest deps) | fail: `edition2024` manifest | fail: icu 2.3 needs 1.88 | not run | **build** | build |
| rmcp-sdk, MSRV-aware lock `rust-version=1.85` | — | fail: rmcp 0.16 uses `let` chains (E0658) | — | — | — |
| rmcp-sdk, MSRV-aware lock `rust-version=1.88` | — | — | **build** (serde probe re-run OK) | — | — |
| raw-relay, committed lock | fail: hyper-util 0.1.21 is edition 2024 | **build** | — | — | build |
| raw-relay, MSRV-aware lock `rust-version=1.78` (hyper-util 0.1.20) | **build** | — | — | — | — |

rmcp 0.16.0 declares edition 2024 and no `rust-version`; its own source needs ≥1.88. 1.86/1.87 not
tested; 1.88 is the lowest measured passing toolchain for any rmcp 0.16 dependency set. The raw-relay
1.78 build was build-only; `compare.py` ran on the stable build.

## 4. Real clients against an isolated fixture (measured; `client-probe/output/`)

Invocation budget: 3 used. (1) Claude, failed at argument parsing — `--allowedTools` is variadic and
consumed the prompt; no MCP traffic (kept in `attempt1-argv-error/`). (2) Claude, success.
(3) Codex, MCP handshake then model auth failure (expected).

Isolation: a temp `mktemp -d` dir (0700) holding the MCP config, deleted on exit, and a synthetic
per-run bearer. **Claude: existing login + `--strict-mcp-config --mcp-config <tmpfile>`** (no temporary
HOME, which would have lost the keychain login), plus `--restricted --no-session-persistence`, run from
the temp cwd. Codex: temporary `CODEX_HOME` with no credentials. No token was copied into any artifact.

Hash snapshots (contents never printed; `client-probe/output/*-config-{before,after}.txt`):
`~/.claude/settings.json` and `~/.codex/config.toml` unchanged; the `mcpServers` subsets of
`~/.claude.json` unchanged. **Deviation: `~/.claude.json` as a whole changed on both Claude starts,
including the argv-error run.** Claude Code 2.1.296 itself rewrites its state file on startup even with
`--restricted`/`--strict-mcp-config`; no MCP entry was added. These runs happened before the instruction
"never write to ~/.claude.json" arrived, and no further client runs were made. A later probe that must
leave `~/.claude.json` byte-identical cannot use the existing login this way (**measured**); whether any
flag prevents the write is **unverified**.

### Claude Code 2.1.296 (`claude -p --model haiku`, `MCP_TOOL_TIMEOUT=5000`)

Wire sequence (`claude-wire.jsonl`, tool-use ids redacted):

1. `POST server/discover` with header `MCP-Protocol-Version: 2026-07-28`, no session, body `_meta`
   carrying `io.modelcontextprotocol/protocolVersion: 2026-07-28`, clientInfo and capabilities.
   The fixture answered **HTTP 400** (version header mismatch).
2. Fell back to `POST initialize` with `protocolVersion: 2025-11-25`, no version header; capabilities
   `elicitation{form,url}`, `roots{listChanged}`. Received `Mcp-Session-Id`.
3. `notifications/initialized` (202), then `GET /mcp` `Accept: text/event-stream` (405 tolerated),
   `tools/list` ×2 (pagination followed). From step 3 on every request carried
   `MCP-Protocol-Version: 2025-11-25` and the session id.
4. `tools/call json_ok` → result. Request `_meta` has `progressToken` and a vendor key
   `claudecode/toolUseId`.
5. `tools/call slow_ok` sent in parallel (separate POST); at the 5 s timeout Claude sent
   **`notifications/cancelled` `{requestId: 4, reason: "SdkError: Request timed out"}`** as a
   separate POST (t 6.512 → 11.521); the fixture matched it to the in-flight call. Model reported
   the timeout; fixture counters `json_ok 1, slow_ok 1` → no retry.
6. `Authorization: Bearer <token>` from the config `headers` on every request, including discover;
   `User-Agent: claude-code/2.1.296 (sdk-cli)`. No DELETE observed before process exit.

Interpretation (documented, [2026-07-28 versioning](https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning)):
this matches the "dual-era client" path — modern request first, then fall back to `initialize`
when a `4xx` arrives without a recognized modern error body. The fixture's 400 came from header
validation, not a designed era signal (**inferred**).

### codex-cli 0.162.0 (`codex exec`, temporary `CODEX_HOME`)

Config: `[mcp_servers.probe] url=…, bearer_token_env_var="T01_PROBE_TOKEN"`.
`initialize` offered **`2025-06-18`** (no `server/discover`), capabilities `elicitation{form,url}`,
`User-Agent: codex-mcp-client/0.162.0`, `Accept: text/event-stream, application/json`. It **offered
`2025-06-18` and tolerated a `2025-11-25` answer**: the fixture answers `2025-11-25` regardless of the
offer (`scripts/proxy-p0/fixture.py:173`). Codex then sent `MCP-Protocol-Version: 2025-11-25` on later
requests. Only the handshake and `tools/list` were observed for Codex.
`GET /mcp` (405 tolerated), `tools/list` ×2, `DELETE` on exit. Bearer from the env var on every request.
No tool call: the model request failed with 401 (no credentials in the temp home, by design).
Cancellation therefore **unverified** for Codex.

## 4b. Client compatibility records (dated 2026-10-10)

Sources: Claude Code [MCP docs](https://code.claude.com/docs/en/mcp) and `claude --help` (2.1.296);
Codex [MCP docs](https://learn.chatgpt.com/docs/extend/mcp?surface=cli) (redirect target of
developers.openai.com/codex/mcp) and `codex mcp --help` (0.162.0); MCP
[2026-07-28 versioning](https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning) and
[2025-11-25 transports](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports).

### Claude Code 2.1.296, macOS arm64

| Area | Record | Label |
|---|---|---|
| HTTP MCP config path/scope | Scopes local (default) and user stored in `~/.claude.json`; project in `.mcp.json` at the project root. `type: "http"`, `url`, `headers`; `${VAR}`/`${VAR:-default}` expansion in `.mcp.json` | documented |
| Precedence | Same server name: local > project > user > plugin > claude.ai connectors; whole entry from the winning source, no field merge | documented |
| Isolation used | `--strict-mcp-config` ("use only the MCP servers you pass with `--mcp-config`") + temp `--mcp-config` file. The fixture saw only the expected traffic; that no other MCP server was contacted follows from the documented flag, not from a network-level measurement | documented + inferred |
| Negotiated revision | Tries `server/discover` with `2026-07-28` first; after HTTP 400 it sends `initialize` with `2025-11-25`, and the fixture answered `2025-11-25`. Header `MCP-Protocol-Version: 2025-11-25` on every later request | measured |
| Fallback rule | Spec ([streamable-http, Backward Compatibility](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http#backward-compatibility)): on `400`, a recognized modern JSON-RPC error body means "modern server, retry or correct, do not fall back"; an empty or non-modern body means "fall back to `initialize`". Clients SHOULD cache the era per origin ([versioning](https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning#backward-compatibility-with-initialization-based-versions)). Measured: the fixture's `400` with an **empty body** (`Content-Length: 0`) to `server/discover` made Claude fall back to `initialize` with `2025-11-25` | documented + measured |
| GET SSE 405 | `GET /mcp` (`Accept: text/event-stream`) after `initialized` → 405; Claude continued normally, with no retry of the GET observed during the run | measured |
| Auth: static header | `headers.Authorization: Bearer …` in the temp config, sent on every POST/GET incl. `server/discover` | measured |
| Auth: dynamic / env | `headersHelper` (overrides same-name static headers); env expansion in headers | documented, not measured |
| Auth: OAuth | Supported via `/mcp` (interactive) or `claude mcp login <name>`; "In non-interactive mode there's no `/mcp` panel" so `-p` cannot run the OAuth flow | documented, not measured |
| Headless tool permission | `-p` with `--allowedTools mcp__probe__json_ok,mcp__probe__slow_ok`: both tools ran with no prompt. Behaviour without `--allowedTools` not tested. `--allowedTools` is variadic and swallowed a trailing prompt (invocation 1) | measured |
| Timeout | `MCP_TOOL_TIMEOUT=5000` → slow call failed at ~5 s with `timed out after 5s`. Per-server `timeout` overrides it; default ~28 h; idle timeout 5 min for HTTP | measured / documented |
| Cancellation | On timeout it sent a separate POST `notifications/cancelled` `{requestId, reason:"SdkError: Request timed out"}` while the call was in flight | measured |
| Retry (PX-015/AC-03) | No tool-call retry: fixture `slow_ok` count 1, `json_ok` count 1. The docs describe **connection** retries (reconnect up to 5 attempts with backoff; up to 3 retries on a transient first-connection error) — a proxy must not treat a reconnect as permission to re-execute | measured / documented |
| Session end | No `DELETE` observed before exit | measured (1 run) |

### codex-cli 0.162.0, macOS arm64 (handshake only)

| Area | Record | Label |
|---|---|---|
| Config path/scope | `~/.codex/config.toml`; project `.codex/config.toml` (trusted projects only). `CODEX_HOME` relocation is not mentioned on the MCP page, but it worked here: the temp config was used and `~/.codex/config.toml` was unchanged | documented / measured |
| HTTP keys | `url`, `bearer_token_env_var`, `http_headers`, `env_http_headers` | documented; `bearer_token_env_var` measured |
| OAuth | `codex mcp login <server-name>` | documented, not measured |
| Negotiated revision | Offered `2025-06-18` (no `server/discover`) and tolerated a `2025-11-25` answer; the fixture answers `2025-11-25` regardless (`fixture.py:173`). Later requests sent `MCP-Protocol-Version: 2025-11-25`. Only the handshake and `tools/list` were observed | measured |
| GET SSE 405 | `GET /mcp` → 405; tools/list (both pages) followed; `DELETE` on exit | measured |
| Approval | `default_tools_approval_mode`, `tools.<tool>.approval_mode` | documented, not measured |
| Timeouts | `startup_timeout_sec` (default 10), `tool_timeout_sec` (default 60) | documented, not measured |
| Cancellation/retry | Not reached: the model call failed with 401 because the temp home has no credentials | unverified |

## 5. Recommendation

### D-01

- **Hybrid, relay-first.** The data path should be a raw byte-preserving relay (measured to keep
  unknown fields, `_meta`, SSE framing at byte level, and to avoid retries). The proxy parses a copy of
  each message for observation and policy (method, id, tool name, version, cancellation), but never
  re-serializes what it forwards. Do **not** build the forwarding path on **rmcp 0.16.0** typed
  messages (measured field loss; no version allowlist; echoes unknown versions; no client version
  header; head-of-line-blocked cancellation). This applies to rmcp 0.16.0 only. rmcp 2.2.0 (newest on
  crates.io) was not evaluated.
- rmcp types (or plain `serde_json::Value`) may be used read-only for parsing the observed copy;
  that use must tolerate unknown fields and is not a compatibility claim.
- **Supported revision list for P1 (proposal):** `2025-11-25` only. It is the fixture revision. Claude
  Code 2.1.296 offered it in `initialize` and the session ran on it. Codex 0.162.0 offered
  `2025-06-18` and tolerated the fixture's `2025-11-25` answer (the fixture never negotiates). Adding
  `2025-06-18` needs an explicitly versioned fixture variant (no silent rename).
- **Modern (2026-07-28) requests in P1 (legacy-only proxy):** the proxy intercepts them and **never
  forwards them upstream**. A request counts as modern if any of these hold:
  - its method is `server/discover`;
  - its params `_meta` contains `io.modelcontextprotocol/protocolVersion`;
  - it carries an `MCP-Protocol-Version` header outside the allowlist.

  The proxy answers with **HTTP 400 and an empty body**. While the proxy is legacy-only it emits no
  `-32022` (`UnsupportedProtocolVersionError`), `-32020` (`HeaderMismatch`) or `-32601`. Reason
  (documented, streamable-http Backward Compatibility): a recognized modern JSON-RPC error in a 400
  body tells the client the server is modern, so it retries or corrects instead of falling back, and
  it may cache that era per origin. An empty or non-modern body makes it fall back to `initialize`.
  Evidence (measured): the fixture's empty-body 400 to Claude Code 2.1.296's `server/discover` led to
  a fallback to `initialize` with `2025-11-25`. That 400 came from the fixture's header check, not
  from a proxy. **Re-measuring this through the real proxy is a P1 verification item.** No client was
  re-run for this revision of the document.
- The proxy must enforce its own allowlist on both the body version and the `MCP-Protocol-Version`
  header and reject mismatches; neither rmcp 0.16 nor the measured relay does this.
- **MSRV:** the existing workspace already fails on its declared 1.78 and needs 1.88 with the
  committed lock (§0; baseline issue, independent of the proxy). For the proxy itself, a relay on
  hyper 1 adds no requirement above that: it builds on 1.85 with the latest lock and on 1.78 with an
  MSRV-aware lock. Putting rmcp 0.16 in the proxy would need ≥1.88, which equals the current measured
  baseline. rmcp 2.2.0 exists but was not evaluated. The MSRV decision itself belongs to the orchestrator.
- Cancellation: legacy (2025-11-25) cancellation is a separate `notifications/cancelled` POST
  (measured from Claude). The ordering follows the reviewed M4 decision in
  [decisions.md, "D-01 후속 결정"](../specs/sigil-proxy/decisions.md#d-01-후속-결정-2026-10-10-독립-리뷰-반영):
  - **Cancel observed after dispatch:** forward it promptly, independently of the in-flight call, and
    record `cancel_requested` without assuming the upstream stopped. Reason: rmcp 0.16's client held
    its cancel behind the in-flight POST for about 6 s (measured, §1c).
  - **Cancel observed before dispatch:** the request is not dispatched. Record it as completion
    unknown / `not_sent` / `cancelled_before_dispatch`.
  - **Cancel whose request has not arrived yet:** hold it only for a bounded wait, then discard it
    (PX-013).

### Upstream version (open item; decision belongs to the orchestrator)

- Measured (§1b): an rmcp 0.16.0 server with its default config answers **`2025-03-26`** to a
  `2025-11-25` offer, and it echoes unknown older strings such as `1999-01-01`.
- Inferred: a byte-preserving relay cannot rewrite the version in the upstream `initialize` result.
  When the upstream answers a version outside the allowlist, the `initialize` has already been sent
  upstream. The only allowlist-consistent outcome is to end that attempt **with no session
  established** downstream. Open questions: what the downstream client sees in that case, and whether
  to DELETE an upstream session that was already minted.

### Open P1 requirements (listed, not decided)

- **M3, header policy.** Which headers to strip, inject or rewrite on each route. Candidates:
  - strip downstream `Authorization` and `Cookie`;
  - inject per-route upstream credentials;
  - handle `Origin` (validate downstream, decide what goes upstream);
  - bind the upstream `Mcp-Session-Id` to the authenticated downstream principal.

  Current probe state (source): `raw-relay/src/main.rs` forwards every end-to-end header, and
  `compare.py` does not test forwarded headers. PX-008/009/014.
- **M4, cancel ordering under spool-before-forward.** If the proxy spools an audit record before
  forwarding, a `notifications/cancelled` must not queue behind the in-flight call. rmcp 0.16's
  client shows this head-of-line blocking (measured, §1c). The ordering between the spool write, the
  forwarded call and the forwarded cancel needs a rule and a test. PX-006/015; AC-03/07.
- **m5, missing `MCP-Protocol-Version` header.** Policy for a legacy request without the header:
  - the rmcp 0.16 client never sends it (measured);
  - the base fixture tolerates it;
  - the 2026-07-28 text allows a server to treat a missing header as `2025-03-26` if it supports such
    clients, and otherwise to reject (documented).

  The decision needs to cover sessions where the version was already negotiated via `initialize`.

### D-02 (client side; facts only, D-02 stays open)

- Both clients can send a static bearer to an HTTP MCP endpoint without OAuth:
  Claude Code via `headers` in the MCP config (measured), Codex via `bearer_token_env_var`
  (measured; token stays in the environment, not the config file).
- Both send the bearer on every request including GET/DELETE, and Claude also on `server/discover`
  (measured). The proxy can therefore authenticate per request and bind sessions to the authenticated
  principal (PX-008) (**inferred**; no proxy exists yet to measure it).
- Claude Code attaches a per-call vendor id `_meta.claudecode/toolUseId`; it is client-asserted
  correlation metadata, not authenticated identity (PX-007).

### Open questions

1. Does the real proxy's empty-body 400 for modern requests produce the same Claude Code fallback that
   was measured against the fixture, and does a cached era survive across runs? This is a P1
   verification item through the real proxy. It deliberately does not test a `-32022` body, which the
   P1 rule never emits.
2. Codex cancellation and real tool calls need an authenticated Codex run (out of scope: no credential copying).
3. OAuth / 401 + `WWW-Authenticate` discovery behaviour of both clients (only static bearer tested).
4. Relay behaviour for long-lived GET SSE streams, resumption (`Last-Event-ID`), mid-body upstream
   failure, TLS upstreams, large bodies and concurrency (AC-07) not tested.
5. rmcp 2.x suitability and MSRV were not evaluated; Linux (D-04 Ubuntu 24.04 x86_64) not tested.

## Unverified / limitations

Single macOS host; loopback only; synthetic fixture; one invocation per client. The Codex run did not
reach a model, so only handshake and listing are evidence. The rmcp HOL-blocking conclusion is for
JSON-response servers that delay headers. Wire logs keep request bodies of synthetic calls; bearer
values, session ids, Claude tool-use ids and OpenAI request ids are redacted.
