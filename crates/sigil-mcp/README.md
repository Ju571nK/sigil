# sigil-mcp

Read-only fleet MCP server. Exposes a `sigil-server`'s GET read API as
Model Context Protocol tools so an MCP client (Claude Desktop/Code, etc.)
can read and reason over fleet security posture. Read-only by construction:
GET only, no write/remediation tools.

## Tools
`list_hosts`, `get_host`, `fleet_risk`, `fleet_compliance`, `query_events`,
`get_event`, `get_policy`, `server_meta`, `healthz`.

## Configuration (env)

| Var | Meaning |
|-----|---------|
| `SIGIL_SERVER_BASE_URL` | read API base, e.g. `http://127.0.0.1:9090` (proxy) or `https://host:8443` |
| `SIGIL_SERVER_READ_TOKEN` | bearer token |
| `SIGIL_CLIENT_CERT` / `SIGIL_CLIENT_KEY` / `SIGIL_CA_CERT` | optional, for direct mTLS to `:8443` (omit when using a bearer-only reverse proxy) |

## Claude Desktop / Code (stdio)

```json
{
  "mcpServers": {
    "sigil-fleet": {
      "command": "sigil-mcp",
      "env": {
        "SIGIL_SERVER_BASE_URL": "http://127.0.0.1:9090",
        "SIGIL_SERVER_READ_TOKEN": "..."
      }
    }
  }
}
```

## Note for operators
Configuration is validated at startup, but connectivity is not probed — an
unreachable `SIGIL_SERVER_BASE_URL` or bad token surfaces on the first tool
call (with a clear error), not at launch. Logs go to stderr; stdout is the
MCP JSON-RPC channel.
