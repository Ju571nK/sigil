# Sigil Proxy compatibility preparation

Date: 2026-09-27. Scope: specification preparation, not implementation or enforcement certification.
Related: [specification package](../specs/sigil-proxy/README.md).

## Local evidence

- Repository HEAD: `24eddb2`; workspace version `0.8.3`, Rust MSRV `1.78`.
- Workspace declares `rmcp = 0.16` with server and transport-io features.
  This does not prove suitability for an HTTP client/server proxy or a newer protocol revision.
- `codex --version`: `codex-cli 0.156.1`; executable resolved to `/opt/homebrew/bin/codex`.
  Version discovery only: no Codex MCP connection, approval, or unattended execution was tested.
- Existing sigil-mcp provides read/assess tools; sigil-hook has opt-in enforcement paths.
- Existing [metadata baseline research](mcp-metadata-compatibility-2026-09-12.md)
  separates cached observations from runtime evidence. Preserve that distinction.
- The adjacent sigil-manager checkout exists, but its implementation was not inspected in this preparation.

## Official documentation checked

The following are documentation observations, not hardware measurements.

| Source | Observation and implementation consequence |
|---|---|
| [2026-07-28 transport overview](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports) | Describes per-request metadata and client-initiated requests. Earlier session-based revisions differ. Use version-specific adapters; do not assume universal initialize/session/server-request semantics. |
| [2026-07-28 changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog) | Identifies changes from 2025-11-25. P0 must record which revision each actual client/server supports before selecting the release matrix. |
| [2025-11-25 transports](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports) | Documents initialize/session IDs, GET/POST SSE, explicit cancellation, Origin checks and resumability. Reconnect/replay is not permission to re-execute tools. |
| [2026-07-28 authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) | HTTP authorization, least privilege, resource-bound tokens and audience validation require separate downstream/upstream credential handling. Login is not request-specific human approval. |
| [Tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools) | Tool inventory and calls are relevant observation surfaces. The proxy contract must explicitly state supported capabilities and inspection scope. |
| [Security best practices](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices) | Treat proxy authorization, token forwarding, destination access and session isolation as security boundaries to validate. |

## Compatibility gate record

| Area | Current preparation | Required before affected implementation |
|---|---|---|
| Configuration paths/precedence | No vendor configuration changed; proxy paths not fixed | D-02: inspect target client settings and precedence, define proxy bootstrap paths per OS |
| Permissions/approval modes | No existing mode changed or gate removed | Record client authentication support, retries/timeouts and human approval evidence |
| Hook events/payloads | No hook integration or payload change proposed for P1 | Preserve existing measured gates; re-research if future integration changes them |
| MCP/tool behavior | Official revisions differ; installed SDK/client support unverified | D-01: client/server/SDK matrix, capability fixtures and actual round-trip probe |
| Unattended mode | Not tested, no enforcement claim | Verify credential renewal, no-approver handling and bounded failure behavior |
| Platform behavior | Local CLI version only | D-04: select deployment OS, validate service/secret storage/streaming/shutdown |
| Enforcement | Existing gates unchanged; proxy unimplemented | P2/P3 tests and direct-access boundary evidence before enabling claims |

No compatibility conclusion is inherited solely from the installed Codex version or the website's revision date.
Future product-specific work must add dated official release/configuration references and local results.
No production MCP was contacted and no external tool action was executed by this preparation.

## P0 result template

Product + version; date; OS; protocol revision; official source/release note;
configuration paths and precedence; auth/approval; hook applicability; supported methods/capabilities;
unattended behavior; commands/fixtures; documented expectation; observed result;
contradictions; enabled scope; limitations. Use redacted evidence only.
