# Sigil integrations — call `assess` as an agent pre-flight

These examples wire an AI agent runtime to Sigil's **`assess`** capability so the
agent can ask *"is this action risky — would Sigil block it?"* **before** it runs
a shell command or wires up an MCP server.

Where Sigil's other read tools report *standing* posture ("what is my risk right
now?"), `assess` evaluates a **proposed** action against this host's loaded policy
(the same rubric + rule-pack deny rules the agent enforces) and returns:

```json
{ "bucket": "High", "score": 5.5, "reasons": [ … ], "deny_match": { "rule_id": "…" }, "decision": "deny" }
```

## The pre-flight contract

Encode this in whatever drives your agent (a skill, a system prompt, a wrapper):

> Before running a risky shell command, or before adding/launching an MCP server,
> call Sigil `assess` with the proposed command / server definition.
> - `decision: "deny"` → **do not run it.** Surface `reasons` / `deny_match` to the user.
> - `decision: "warn"` → proceed only with explicit caution; show the reasons.
> - `decision: "allow"` → proceed.

## Two ways to call it

| Path | How | Policy basis | Setup |
|------|-----|--------------|-------|
| **CLI** | `sigil assess --command "<cmd>"` (exit 0 = allow/warn, 2 = deny) | cold-disk (`policy.yaml` + `rule-packs.yaml`) | none — just the `sigil` binary |
| **MCP** | the `assess` tool on `sigil-mcp` (sigil-check, local mode) | the **running** agent's live policy | register `sigil-mcp` as an MCP server |

The CLI works with no daemon and no MCP wiring — ideal for a shell-driven skill.
The MCP path reflects the daemon's live policy and returns structured fields.

`sigil-mcp --print-config <client>` stamps a ready-to-paste MCP block with the
binary's absolute path for `codex`, `claude`, `hermes`, and `openclaw`.

## Examples

- [`openclaw/SKILL.md`](openclaw/SKILL.md) — an OpenClaw skill that pre-flights
  commands via the `sigil assess` CLI (zero-setup), with notes for the MCP path.
- [`hermes/config.yaml`](hermes/config.yaml) — a Hermes Agent `config.yaml`
  snippet that registers `sigil-check` as an MCP server, exposing `assess` as the
  `mcp-sigil-check` toolset.

## Note on policy

For the verdict to mean anything, this host must have a Sigil policy with
`hook_deny_rules` and/or rubric overrides (a `rule-packs.yaml` beside
`policy.yaml`). With no rules loaded, `assess` still scores intrinsic risk
(destructive commands, suspicious MCP launchers) but `deny_match` will be empty.
See [../../docs/install-personal.md](../../docs/install-personal.md).
