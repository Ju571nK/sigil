# sigil agent — Install Guide (macOS)

The `sigil` agent watches AI-tool config and posture files (MCP allowlists,
credential files, agent settings, …), hashes them, and emits **JSONL posture
events**. It measures; it does not block. Events can be read locally by a SIEM
agent, or shipped to a [`sigil-server`](install-server.md) by the companion
`sigil-sender`.

> **Just want your own machine's score? (30 seconds)**
> Install the personal profile and run a one-shot scan — no daemon, no Full Disk
> Access, no launchd:
>
> ```sh
> curl --proto '=https' --tlsv1.2 -fsSL \
>   https://raw.githubusercontent.com/Ju571nK/sigil/main/install.sh | sh
> sigil scan
> ```
>
> That installs three binaries (`sigil`, `sigil-mcp`, `sigil-hook`) and prints a
> posture score. For the full personal guide (local rule packs, MCP, hook
> enforcement) see [install-personal.md](install-personal.md).

This guide covers a **production / operator** macOS deployment — running the
agent persistently (root launchd), granting Full Disk Access for fleet-wide
coverage, and shipping events to a [`sigil-server`](install-server.md). For the
server side, see [install-server.md](install-server.md).

---

## 1. Install

### Option A — `install.sh` (recommended)

```sh
curl --proto '=https' --tlsv1.2 -fsSL \
  https://raw.githubusercontent.com/Ju571nK/sigil/main/install.sh | sh
```

Installs the **personal** profile by default — `sigil`, `sigil-mcp`, and
`sigil-hook` — to `~/.local/bin` (verifies SHA-256). Make sure `~/.local/bin` is
on your `PATH`.

This operator deployment also ships events with `sigil-sender` (§7). It is part
of the **fleet** profile, so install that instead to add the server-side
binaries on top of the personal three:

```sh
SIGIL_PROFILE=fleet curl --proto '=https' --tlsv1.2 -fsSL \
  https://raw.githubusercontent.com/Ju571nK/sigil/main/install.sh | sh
```

`fleet` adds `sigil-sender`, `sigil-server`, and `sigil-sign`.

### Option B — build from source

```sh
cargo build --release -p sigil-agent   # → target/release/sigil
```

> **Intel Macs** are not shipped as prebuilt binaries — build from source.
> Apple Silicon prebuilt binaries are provided by `install.sh`.

---

## 2. Grant Full Disk Access (FDA)

The agent reads files across the system (including other users' home dirs and
`~/Library`). Without **Full Disk Access** its coverage is silently limited and
it emits a `PermissionMissing` event per affected target.

1. **System Settings → Privacy & Security → Full Disk Access.**
2. Add the program that runs the agent:
   - running by hand → add your **terminal app** (Terminal / iTerm);
   - running via launchd → add the **`sigil` binary** itself.
3. `sigil doctor` reports the FDA state — run it after granting (section 5).

---

## 3. Configure

A policy file is **optional** — built-in defaults apply if absent. To customize,
start from [`config/policy.example.yaml`](../config/policy.example.yaml):

```yaml
version: 1
host_id_strategy: machine_id
targets:
  - id: team-mcp-allowlist
    tier: critical
    platform: any
    paths: ["~/.config/example/mcp-allowlist.json"]
```

### Paths: root vs. your user

Default paths depend on whether the agent runs as **root** or as **your user** —
this matters on macOS because the system locations aren't user-writable:

| Item | Default as root | Default as non-root user |
|---|---|---|
| state.db | `/var/lib/sigil/state.db` | pass `--state-db ~/.local/state/sigil/state.db` |
| events dir | `/var/log/sigil` | pass `--events-dir ~/.local/state/sigil/events` |
| control socket | `/var/run/sigil/control.sock` | `$XDG_RUNTIME_DIR/sigil/control.sock` → else `/tmp/sigil-<uid>/control.sock` (auto) |
| keystore | `/etc/sigil/policy-signing-pubkeys.pem` | `$XDG_CONFIG_HOME/sigil/...` → else `~/.config/sigil/...` (auto) |

The **control socket** and **keystore** now fall back to user-writable
locations automatically when you're not root, so the control plane and policy
verification work without `sudo`. Override any path explicitly:

```sh
sigil --control-socket /tmp/sigil.sock --keystore ~/.config/sigil/pubkeys.pem run
```

`--state-db` and `--events-dir` have **no** auto-fallback — point them at
writable paths when running as your user.

### Run as root (full coverage) or as your user (own posture)

- **Full fleet coverage** (reads every user's AI configs): run as **root** via a
  launchd `LaunchDaemon`. Uses the system default paths above.
- **Your own posture only** (no sudo): run as **your user**, passing
  `--state-db`/`--events-dir` to writable paths.

---

## 4. Run

### Foreground (testing)

```sh
sigil doctor                 # check config + FDA first
sigil --state-db ~/.local/state/sigil/state.db \
      --events-dir ~/.local/state/sigil/events run
```

### Persistent (launchd LaunchDaemon, runs as root)

`/Library/LaunchDaemons/com.sigil.agent.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.sigil.agent</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/sigil</string>
    <string>run</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardErrorPath</key><string>/var/log/sigil/agent.err.log</string>
</dict></plist>
```

```sh
sudo cp target/release/sigil /usr/local/bin/sigil
sudo launchctl load -w /Library/LaunchDaemons/com.sigil.agent.plist
```

Set the diagnostic log level with `SIGIL_LOG` (e.g. `SIGIL_LOG=debug`).

---

## 5. Verify

```sh
sigil doctor              # config + permissions (FDA), does not start the daemon
sigil show config         # merged effective policy
sigil show paths          # fully expanded watch paths
sigil show risk           # AI Guard risk score per tool (queries the running daemon)
sigil show stats          # live heartbeat from the running daemon
```

`sigil show risk` is the core AI-SPM read: it scores each detected AI tool
(`claude-code`, `codex`, `gemini`, `cursor`) from its real on-disk config.
Without a running daemon, `sigil scan` produces the same per-tool scores in one
shot (and exits 0) — handy for a quick check before the daemon is set up.

---

## 6. Find this host's `host_id`

You need it to configure the sender (section 7). The agent generates a UUID on
first run and persists it in `state.db`. It's printed at startup:

```sh
# launchd: check the diagnostic log / Console for:
#   INFO sigil_agent::runtime: agent host_id resolved host_id=<uuid>
grep "agent host_id resolved" /var/log/sigil/agent.err.log
```

It also appears as the `host_id` field on every emitted event.

---

## 7. Ship events to a server (optional)

To forward events to a [`sigil-server`](install-server.md), run `sigil-sender`.
First get this host's client cert + `ca.crt` from the server operator
([install-server.md § 3](install-server.md)). Then write `sender.yaml`:

```yaml
# ~/.config/sigil/sender.yaml  (or /etc/sigil/sender.yaml as root)
server_base_url: "https://sigil.example.com:8443"
client_cert_path: "/path/to/client-hostA.crt"
client_key_path:  "/path/to/client-hostA.key"
server_ca_path:   "/path/to/ca.crt"

events_dir: "~/.local/state/sigil/events"     # MUST equal the agent's --events-dir
offset_path: "~/.local/state/sigil/sender-offset.json"
dead_letter_dir: "~/.local/state/sigil/dead-letter"

# REQUIRED — must equal the agent's host_id (section 6). A mismatch makes the
# server reject the entire batch with host_id_payload_mismatch.
host_id: "<agent host_id from section 6>"

# Control IPC — must equal the agent's control socket. As your user that is the
# auto fallback (e.g. /tmp/sigil-<uid>/control.sock), or whatever you passed to
# `sigil --control-socket`.
agent_control: "/tmp/sigil-501/control.sock"
```

```sh
sigil-sender --config ~/.config/sigil/sender.yaml start
```

Three alignment rules (each is a real failure mode found in testing):

1. **`events_dir`** = the agent's `--events-dir`, or the sender tails an empty dir.
2. **`host_id`** = the agent's `host_id`, or every batch is rejected.
3. **`agent_control`** = the agent's control socket path (matters only for
   policy push / control plane).

---

## 8. Verify the keystore (only for pushed policy)

If you use the control plane (server-pushed signed policy), the agent verifies
signatures against a keystore. Put the **public** key from the operator's
signing key (`sigil-sign keygen` produced `ed25519_pubkey_b64`) at the keystore
path (section 3):

```json
{ "pubkeys": [ {
  "id": "prod-key-1",
  "ed25519_pubkey_b64": "<PUB from signing-key.json>",
  "valid_from": "2025-01-01T00:00:00Z",
  "valid_until": "2027-01-01T00:00:00Z"
} ] }
```

Without it the agent runs fine in Phase-1 mode (local `policy.yaml`); it just
logs `keystore unavailable` and rejects any pushed policy. Plain local operation
does **not** need a keystore.

---

## 9. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `sigil doctor` reports FDA denied / few targets | No Full Disk Access | Grant FDA to the runner (§2) |
| Permission denied writing state/events as your user | System default paths need root | Pass `--state-db`/`--events-dir` to writable paths (§3) |
| Sender: server rejects all events | `host_id` ≠ agent's | Align `host_id` (§6, §7) |
| Sender tails nothing | `events_dir` ≠ agent's `--events-dir` | Match them (§7) |
| `keystore unavailable` warning | No keystore file | Expected if not using pushed policy (§8) |
| Control plane / `sigil show stats` can't connect | socket path mismatch | Align `agent_control` with `--control-socket` (§7) |

---

*Paths and behaviors here reflect `config/sender.example.yaml`,
`docs/runbook/operations.md`, and the non-root path defaults added in the agent
(`--control-socket` / `--keystore`).*
