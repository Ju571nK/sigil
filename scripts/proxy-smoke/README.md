# Sigil Proxy smoke-test tools

Tools for the [AWS two-instance smoke runbook](../../docs/specs/sigil-proxy/aws-smoke-test.md).
They need only the Python 3.9+ standard library: no installation, credentials or external network.

| File | Purpose |
|---|---|
| `mcp_fixture.py` | Trusted test MCP server. MCP Streamable HTTP, revision 2025-11-25 only, advertises `tools` only. Its tools are deterministic: `smoke_echo` (JSON), `smoke_sse` (SSE), `smoke_fail` (`isError`), `smoke_wait` (cancellable, at most 30 s), `smoke_inventory_toggle` (adds or removes `smoke_inventory_extra`). `GET /_fixture/counters` is an out-of-band oracle and needs the bearer. |
| `smoke_client.py` | `scenario` (full MCP flow through the proxy), `call` (N calls, for outage and spool tests), `counters`, `query` / `ledger` (sigil-server read API over mTLS + read bearer), `scan` (counts canary and secret occurrences in files). |
| `b3fp.py` | blake3 fingerprint of a PEM certificate's DER, as sigil-server expects for `caller_cert_fingerprint` and proxy fingerprints. Pure Python, cross-checked against the Rust `blake3` crate. |
| `test_proxy_smoke.py` | Local checks. No proxy is involved. |

```sh
python3 -B -m unittest discover -s scripts/proxy-smoke -p 'test_*.py' -v
```

Fixture safety rules: it binds `127.0.0.1` by default, and a non-loopback bind needs `--tls-cert/--tls-key`. Tokens come
only from owner-only files (0600, not a symlink, owned by the caller) and are never arguments. The fixture never logs
requests, headers, arguments or results. Connections, sessions, waits and body size are all bounded. The fixture
checks `Host` and rejects any `Origin`. These guards suit a synthetic test, not production use. Never point a
real client or real secrets at it.

The tests prove only that the tools work against themselves. Proxy behaviour is shown by running the runbook.
Vendor-client compatibility is out of scope.
