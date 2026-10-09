# sigil-server 0.9.0 / 0.9.1 hardware verification — 2026-10-09

Hardware-verified behavior of the v0.9.0 release on a real server, plus the
follow-up fix found during the run (#237, PR #238).

## Environment

- Server: Rocky Linux 9.7, aarch64, SELinux enforcing, VM on the local network.
  An older sigil-server install (0.2.0 RPM) and an unrelated demo instance were
  left untouched; all tests ran as separate instances on loopback ports.
- Manager: sigil-manager `main` (`e5e116e`), run on macOS against the server
  through an SSH tunnel (no mock fleet).
- Release artifacts: `sigil-server-0.9.0-1.aarch64.rpm`,
  `sigil-signer-0.9.0-1.aarch64.rpm` from the v0.9.0 GitHub release.

## Results

### Release RPM

| Check | Result |
|---|---|
| `SHA256SUMS` | match |
| `rpm -qpR` | only `/bin/sh` and rpmlib entries; no glibc, no `[WEAK]` entries (#234/#235) |
| `rpm -U --test` over 0.2.0 | passes (not actually installed) |

### `/v1/meta` with a pre-0.9.0 config (fixture chain)

Config keeps the old `license.active_window_days: 14` block; events directory
holds the `legacy-chain-v1.jsonl` fixture as `license-audit.jsonl`.

- No `license` object in the response; `fleet` is
  `{"active_host_count": 0, "active_window_days": 14}` — the deprecated key is
  honored, with startup warnings.
- `audit_head` reports seq 2, hash `3f119e2f…`.
- No bearer token → 401.
- Chain file unchanged (checksum before/after).

### In-place upgrade with real data

Copy of an existing server's events directory (13-line chain, 2 hosts), new
top-level `active_window_days: 365`.

- Existing audit key reused (`sigil-audit-3b0h20`); `audit_head` seq 12.
- `fleet.active_host_count` = 2.
- `sigil-sign verify-audit --in … --pubkey … --expect-head …` →
  `AUDIT CHAIN OK (13 lines)`; a different key fails at seq 0.
- 0.9.0 `sigil-sign` has no license subcommands.
- Chain file unchanged.

### sigil-manager against the upgraded server

- `GET /api/v1/fleet/meta` passes `fleet` (2 / 365) and `audit_head` through.
- Fleet page chip: `2 active hosts · last 365 days`.
- Settings: Fleet (Active hosts 2, Active window 365 days), Audit
  (`signed head reported · seq 12 · key sigil-audit-3b0h20 (not verified)`).
- No license wording anywhere in the UI.

## Defect found: #237

`/v1/meta.audit_head` took `pubkey_id` from the chain head but `pubkey` from
the server's current key. With the fixture chain (signed by
`sigil-audit-fixt01`) and a freshly generated server key, the response paired
mismatched values. Since the chain is frozen in 0.9.0, the mismatch never
heals. An in-place upgrade (same key) was not affected.

Fix (PR #238, merged as `038b2a2`): `pubkey` is reported only when the current
key's id equals the head's `pubkey_id`; otherwise omitted. The head is also
reported when no key is loaded, and the server warns at startup on a mismatch.

### Re-verification of the fix

`main` at `038b2a2` built on the same VM (`cargo build --release -p
sigil-server`), both instances restarted on it:

| Instance | `audit_head.pubkey` | Startup log |
|---|---|---|
| Fixture chain, different key | omitted; `pubkey_id` = `sigil-audit-fixt01` | one WARN naming the head's key |
| In-place upgrade, same key | present, matches `sigil-audit-3b0h20` | no warning |

Both chain files unchanged. Server still reports version `0.9.0`; the fix
ships in the next release.

## Follow-up: v0.9.1 packaged upgrade (2026-10-10)

The two gaps left open above were closed with the v0.9.1 release RPMs.

Baseline: the installed 0.2.0 packages (`sigil`, `sigil-sender`,
`sigil-server`) with `/etc/sigil/server.yaml` (loopback port) and a systemd
drop-in for the read token. `sigil-server.service` was started on 0.2.0; it
created `audit-signing.key` and a 1-line `license-audit.jsonl` under
`/var/lib/sigil-server/events`, and accepted one event (1 active host).

`sudo rpm -Uvh` of the three 0.9.1 aarch64 RPMs with the 0.2.0 service running:

| Check | Result |
|---|---|
| `SHA256SUMS`, `rpm -qpR` | match; only `/bin/sh` and rpmlib entries |
| Upgrade | exit 0; 0.2.0 packages removed, 0.9.1 installed |
| Service | restarted automatically by the package scriptlet (new PID), active on 0.9.1; enablement unchanged |
| Operator files | `/etc/sigil/server.yaml` and the drop-in left in place |
| `/v1/meta` | `server_version` 0.9.1, no `license`, `fleet` 1 / 7 days |
| `audit_head` | seq 0, existing key `sigil-audit-xhk2i9` reused, `pubkey` present and matching (#237 fix in the packaged build) |
| Read API | no token → 401; `/v1/fleet/hosts` lists the host; host detail 200 |
| State files | chain and key checksums unchanged |
| Chain | `sigil-sign verify-audit` (0.9.1 signer, extracted from its RPM) → `AUDIT CHAIN OK (1 lines)` with the reported pubkey and head |
| SELinux (enforcing) | no AVC denials |

## Not covered

- Installing the 0.9.1 signer package itself (the binary was extracted from the
  RPM for verification only).
- A mismatched-key chain under the packaged build (covered by the source build
  above and by tests).

## Cleanup

Test instances stopped and the test directory removed; pre-existing installs
were not modified.
