# P0 local MCP fixture

T-03 preparation, 2026-09-27. **2025-11-25 is a candidate awaiting T-01**;
this fixture does not establish Sigil proxy or vendor-client compatibility.
Python 3.9+ standard library only; tested with Python 3.14.6 on macOS 26.6.2 arm64.
No installation, credentials, real MCP server, or external network access is needed.

Run from the repository root:

```sh
python3 -B scripts/proxy-p0/smoke.py
python3 -B -m unittest discover -s scripts/proxy-p0 -p 'test_*.py' -v
```

Both commands start their own fixture on `127.0.0.1` with an OS-assigned ephemeral
port and close it afterward. The runner connects directly through `http.client`;
it does not use environment proxies, follow redirects, load credentials, or retry.
Success exits zero; assertion/test failure exits nonzero. `-B` avoids bytecode files.

For a separately managed local fixture:

```sh
python3 -B scripts/proxy-p0/fixture.py
```

The first output line gives the ephemeral `/mcp` endpoint and candidate revision.
Stop it with Ctrl-C. This service is deliberately unauthenticated and only suitable
for synthetic local tests. Do not configure real clients or pass secrets to it.
It checks Host/Origin, rejects Authorization, does not log requests, and keeps only
synthetic session/counter state in memory. These guards are not production security.

## Exercises

- `initialize` returns the candidate revision, tools capability and session header;
  `notifications/initialized` returns an empty HTTP 202.
- `tools/list` returns two pages of two tools; `page-2` is the only continuation cursor.
- `json_ok` returns JSON; `sse_ok` returns a finite SSE response with comments,
  CRLF, and multi-line data; `tool_error` returns `result.isError=true`.
- `drop_after_accept` increments the invocation counter under a lock, then closes
  the socket before sending HTTP headers. The runner records an unknown outcome.
- `GET /_fixture/counters` is an out-of-band test oracle, not an MCP API. The smoke
  runner checks one attempt and one accepted invocation for the dropped call,
  four total invocations, and unchanged counters after a subsequent ping.
  Explicit duplicate dispatch is counted twice so accidental retry is not hidden.
- Tests also cover invalid calls/cursors, request size and content negotiation,
  invalid sessions/versions, session deletion, initialization order, Host/Origin,
  unsupported GET streams/methods, and truncated/oversized SSE decoding.

No retry is proved only for this runner during the test. In-memory acceptance is a
synthetic side effect, not proof of external tool execution. The fixture offers no
resume/replay, cancellation, server requests, long-lived streaming, authentication,
inventory drift, proxy, audit persistence, or manager integration. The bounded SSE
decoder is a fixture helper, not a general MCP client. A 64 KiB fixture body/decoder
cap and 3-second socket timeout are test settings, not proposed production limits.

See [validation evidence and proposed D-04 limits](../../docs/specs/sigil-proxy/validation.md)
for actual results, acceptance gaps, and the unmeasured P1 benchmark plan.
