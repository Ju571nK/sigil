# Sigil end-to-end demo (docker-compose)

A self-contained run of the whole pipeline:

```
  ./watched/*  ──(file change)──▶  sigil (agent)  ──▶  JSONL spool  ──▶  sigil-sender  ──mTLS──▶  sigil-server  ──▶  per-host JSONL
                                       ▲                                                              │
                                       └────────  verified (5-check) + applied  ◀──  signed policy  ◀─┘
```

Everything runs in containers off **one image** (built from this repo). An `init`
container generates a throwaway demo CA + TLS certs and a throwaway ed25519
policy-signing key, signs `policy.demo.yaml`, and writes the config files.

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

In another terminal, watch the logs:

```sh
docker compose logs -f sigil sigil-sender sigil-server
```

On startup you should see the **control plane** complete: `sigil-sender` pulls
the operator-signed policy from `sigil-server` (`GET /v1/policy`), hands it to
`sigil` over the local IPC socket, `sigil` runs the 5-check verification chain
and applies it — look for a `PolicyReloaded` line in `sigil`'s log and an
accepted-policy line in `sigil-server`'s.

## Trigger an event

Edit a watched file on the host (this directory is bind-mounted into the agent):

```sh
echo "// touched at $(date)" >> watched/mcp.json
```

`sigil` notices the change, hashes the file, writes a JSONL event to its spool;
`sigil-sender` batches it and POSTs it to `sigil-server` over mTLS. (Edit the
same file again and the event carries both the previous and the new hash.)

See it land on the server:

```sh
docker compose exec sigil-server sh -c 'cat /var/lib/sigil-server/events/*/*.jsonl'
```

(The per-host directory is named after the agent's `host_id` — a UUID generated
on first run. `docker compose exec sigil-server ls /var/lib/sigil-server/events`
shows it.)

## Stop / reset

```sh
docker compose down        # stop; keep the demo PKI + state in volumes
docker compose down -v     # stop and wipe everything (next `up` re-bootstraps)
```

## What's where

| file | purpose |
|---|---|
| `docker-compose.yml` | the four services + shared volumes |
| `Dockerfile` | multi-stage build; one runtime image with all four binaries |
| `init.sh` | one-shot: demo CA/certs, signing key + agent keystore, signs the policy, writes `sender.yaml` / `server.yaml` |
| `sender-entrypoint.sh` | reads the agent's `host_id` from `state.db`, then `exec sigil-sender start` (the server requires the envelope `host_id` to match each event's) |
| `policy.demo.yaml` | the watch policy used by the agent (and the bytes that get signed) — watches `/watched/*` |
| `watched/` | bind-mounted into the agent; edit these files to trigger events |
