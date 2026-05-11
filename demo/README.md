# Sigil end-to-end demo (docker-compose)

A self-contained run of the whole pipeline in containers off **one image**
(built from this repo):

```
  /watched/*  ──(file change)──▶  sigil (agent)  ──▶  JSONL spool  ──▶  sigil-sender  ──mTLS──▶  sigil-server  ──▶  per-host JSONL
                                      ▲                                                              │
                                      └────────  verified (5-check) + applied  ◀──  signed policy  ◀─┘
```

An `init` container generates a throwaway demo CA + TLS certs and a throwaway
ed25519 policy-signing key, signs `policy.demo.yaml`, and writes the config
files; then `sigil-server`, `sigil`, and `sigil-sender` start.

> **Demo build.** The image uses the **dev** profile (fast to build). Production
> release builds are `cargo build --release` — see the repo's top-level README.
> The PKI and signing key here are generated fresh and thrown away; don't reuse them.

## Run it

From this directory (`demo/`):

```sh
docker compose up --build
```

First run builds the workspace inside Docker (a few minutes), then starts four
services: `init` (runs once and exits), `sigil-server`, `sigil`, `sigil-sender`.
In another terminal:

```sh
docker compose logs -f sigil sigil-sender sigil-server
```

## What it shows

Within ~10–15 s of startup the **control plane** completes: `sigil-sender` pulls
the operator-signed policy from `sigil-server` (`GET /v1/policy`), hands it to
`sigil` over the local IPC socket, `sigil` runs the 5-check verification chain
and applies it (`PolicyReloaded`). And the **data plane** carries `sigil`'s
events the other way — over mTLS — to `sigil-server`'s per-host JSONL.

You can see both at once on the server:

```sh
docker compose exec sigil-server sh -c 'cat /var/lib/sigil-server/events/*/*.jsonl'
```

You should see a `policy_reloaded` event with `policy_version: 2` (the
operator-signed policy, pulled + verified + applied), plus heartbeats. The
per-host directory is named after the agent's `host_id` — a UUID generated on
first run (`docker compose exec sigil-server ls /var/lib/sigil-server/events`
shows it). The agent's own copy of the spool is at
`docker compose exec sigil sh -c 'cat /var/log/sigil/events-*.jsonl'`.

## Trigger a file-change event

Edit one of the watched files — `./watched/` is bind-mounted into the agent:

```sh
echo "// touched at $(date)" >> watched/mcp.json
```

`sigil` notices the change, hashes the file, writes a `file_change` event to its
spool; `sigil-sender` batches it and POSTs it to `sigil-server`. (Do it again and
the event carries both the previous and the new hash.) Allow a few seconds — the
demo runs the agent with `--poll`.

> **Why `--poll`?** The agent's default watcher is the OS-native one (inotify on
> Linux). On Docker Desktop / Rancher Desktop (and similar VM-backed engines on
> macOS/Windows) the VM doesn't deliver inotify events for changes inside
> container mounts, so the demo passes `--poll` to fall back to a polling watcher
> that `stat()`s the files instead — it works everywhere, at the cost of a few
> seconds' latency. On a native Linux host you'd drop `--poll` and get instant,
> push-based events.

## Stop / reset

```sh
docker compose down        # stop; keep the demo PKI + state in volumes
docker compose down -v     # stop and wipe everything (next `up` re-bootstraps)
```

## What's where

| file | purpose |
|---|---|
| `docker-compose.yml` | the four services + shared volumes |
| `Dockerfile` | multi-stage build (builder pinned to `bookworm` for glibc parity with the runtime); one runtime image with all four binaries |
| `init.sh` | one-shot: demo CA/certs, signing key + agent keystore, signs the policy (`policy-version 2`), writes `sender.yaml` / `server.yaml` |
| `sender-entrypoint.sh` | reads the agent's `host_id` from `state.db`, then `exec sigil-sender start` (the server requires the envelope `host_id` to match each event's) |
| `policy.demo.yaml` | the watch policy used by the agent (and the bytes that get signed) — watches `/watched/*` |
| `watched/` | bind-mounted into the agent; edit these files to trigger `file_change` events (the agent runs with `--poll` so this works on VM-backed engines too — see the note above) |
