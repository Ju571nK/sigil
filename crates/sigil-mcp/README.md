# sigil-mcp

Read-only MCP server for Sigil security posture. Two modes, auto-detected from
the environment — both read-only by construction (no write/remediation tools):

- **Fleet mode** (`SIGIL_SERVER_BASE_URL` set): exposes a `sigil-server`'s GET
  read API as MCP tools so an MCP client (Claude Desktop/Code, etc.) can read
  and reason over **fleet** security posture.
- **Local mode** (no server URL): reads the local `sigil-agent`'s control socket
  and exposes **this machine's** AI Guard posture — no server, no fleet. See
  [Local mode](#local-mode-individual-self-assessment-no-server) below.

## Tools
Fleet mode: `list_hosts`, `get_host`, `fleet_risk`, `fleet_compliance`,
`query_events`, `get_event`, `get_policy`, `server_meta`, `healthz`.
Local mode: `my_risk`, `my_guard_detail`, `my_findings`.

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

## Local mode (individual self-assessment, no server)

With `SIGIL_SERVER_BASE_URL` unset, `sigil-mcp` reads the running local
`sigil-agent`'s control socket and exposes this machine's AI Guard posture as
`my_risk` (per-tool risk band/score), `my_guard_detail` (rubric, parsers, rule
packs), and `my_findings` (per-repo discovery + watched hook scripts).

```json
{
  "mcpServers": {
    "sigil-local": { "command": "sigil-mcp" }
  }
}
```

The socket path defaults to the same location `sigil-agent` uses
(`$XDG_RUNTIME_DIR/sigil/control.sock`, `/var/run/sigil/control.sock` as root,
or `/tmp/sigil-<uid>/control.sock`); override with `SIGIL_AGENT_CONTROL_SOCKET`.
v1 expects the agent and `sigil-mcp` to run as the **same user** (the control
socket is `0660`); root-daemon + group access is tracked in #10.

## Note for operators
Configuration is validated at startup, but connectivity is not probed — an
unreachable `SIGIL_SERVER_BASE_URL` or bad token surfaces on the first tool
call (with a clear error), not at launch. Logs go to stderr; stdout is the
MCP JSON-RPC channel.
