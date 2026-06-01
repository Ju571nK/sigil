# Changelog

All notable changes to Sigil are recorded here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the workspace uses a
single SemVer version across all crates. Full release notes for tagged releases
also appear under [GitHub Releases](https://github.com/Ju571nK/sigil/releases).

## [Unreleased]

## [0.2.1] - 2026-06-01

### Added

- **aarch64 prebuilt binaries, `.deb`/`.rpm`, and an ed25519-signed build
  manifest** (#12, #13). Releases now ship `x86_64` **and** `aarch64` Linux
  packages, plus a `build-manifest.json` whose per-arch blake3 hashes are signed
  with the compiled-in `SIGIL_BUILD_PUBKEYS` trust anchor; `sigil doctor
  --verify-self` checks the running binary against it. `packaging/build.sh
  --target` cross-builds the OS packages.
- **`sigil-mcp --print-config [codex|claude]`** (#72). Emits a ready-to-paste MCP
  client registration block that pins the binary's **absolute** path, so
  registration works even when the client doesn't inherit your shell `PATH`.
- **SELinux policy module for the three daemons** (#69). Ships
  `packaging/selinux/sigil.{te,fc}` and loads it from the `.rpm` post-install
  (guarded — a no-op without the SELinux policy devel toolchain), confining the
  agent, sender, and server into dedicated domains
  (`sigil_agent_t`/`sigil_sender_t`/`sigil_server_t`) that coexist with the
  units' `NoNewPrivileges=yes` hardening. Verified enforcing-clean on Rocky 9.
- **`sigil-mcp` local mode — individual self-assessment, no server** (#55).
  When `SIGIL_SERVER_BASE_URL` is unset, `sigil-mcp` reads the local
  `sigil-agent` control socket instead of a fleet read API and exposes *this
  machine's* AI Guard posture as three read-only MCP tools — `my_risk`,
  `my_guard_detail`, `my_findings`. Mode is auto-detected; the control wire
  types moved to `sigil-core::control_proto` so the MCP client and the agent
  share one contract.
- **Dedicated `sigil` system group/user + `root:sigil` ownership** (#10 slice 1,
  closes #4). Declarative `sysusers.d`/`tmpfiles.d` create the `sigil`
  group/user and own `/var/lib/sigil`, `/var/log/sigil`, `/run/sigil` as
  `root:sigil 0750`. The agent and sender units run `root:sigil` (`User=root` +
  `Group=sigil`), so the control socket becomes `root:sigil 0660`. The agent
  package applies both at install (deb postinst + rpm scriptlet, guarded and
  idempotent). Foundation for de-rooting the sender/server daemons in later
  slices; the agent stays root for file-integrity monitoring.
- **`sigil-server` runs as the unprivileged `sigil` user** (#10 slice 2). The
  server unit switches from `User=root` to `User=sigil` + `Group=sigil`; systemd
  owns its `StateDirectory`/`LogsDirectory` (`/var/lib/sigil-server`,
  `/var/log/sigil-server`) as `sigil:sigil 0750`. The server package now creates
  the `sigil` user at install (sysusers.d via deb postinst + rpm scriptlet,
  idempotent), so a standalone server install resolves `User=sigil` before start.
  No code change — the server binds a non-privileged port (`:8443`) and writes
  only under its state dir. When mTLS is enabled, the operator must make
  `tls_key_path` readable by the `sigil` user.
- **`sigil-sender` runs as the unprivileged `sigil` user** (#10 slice 2). The
  sender unit switches from `User=root` to `User=sigil` (keeping `Group=sigil`)
  and writes only its own state/log dirs — `StateDirectory=sigil-sender` /
  `LogsDirectory=sigil-sender` (`/var/lib/sigil-sender`, `/var/log/sigil-sender`,
  owned `sigil:sigil 0750`). It still *reads* the agent's `root:sigil` spool and
  connects to the control socket via the `sigil` group, and no longer declares a
  `RuntimeDirectory`. `offset_path` and `dead_letter_dir` now default to the
  sender-owned dirs when omitted.

  **Breaking (operator action on upgrade):** an existing `/etc/sigil/sender.yaml`
  that sets `offset_path: /var/lib/sigil/sender-offset.json` and
  `dead_letter_dir: /var/log/sigil/dead-letter` must move them to
  `/var/lib/sigil-sender/sender-offset.json` and `/var/log/sigil-sender/dead-letter`
  (or delete both lines to take the new defaults) — the non-root sender cannot
  write the agent's `root:sigil` dirs. To preserve the read position (avoid
  re-shipping the spool), move the offset file too:
  `install -o sigil -g sigil -m700 -d /var/lib/sigil-sender && mv /var/lib/sigil/sender-offset.json /var/lib/sigil-sender/ && chown sigil:sigil /var/lib/sigil-sender/sender-offset.json`.

### Fixed

- **`query_events` multi-host filter** (#73). The MCP `query_events` tool and the
  server read API disagreed on the `host_id` filter encoding — repeated params
  tripped the server's `serde_urlencoded` deserializer ("expected a sequence",
  HTTP 400). Both sides now use one comma-separated `host_id` param.
- **`sigil-mcp` local-mode socket trust** (#57). The local upstream now verifies
  the control-socket peer is root or the current user (via
  `UnixStream::peer_cred`) before trusting its `DoctorAiGuardReport`, closing a
  local security-telemetry spoofing gap where another user could serve a
  fabricated "all-clear" posture. Returns a distinct `UntrustedPeer` error.
- **`sigil doctor` events-dir check now validates the owner, not just the group**
  (#60). `classify_events_dir_perms` previously checked only group + mode, so a
  dir owned by a non-root user with group `sigil` and mode `0750` was falsely
  reported as `root:sigil`-hardened while that owner could still mutate it. It
  now warns on a non-root owner, mirroring the control-socket classifier.
- **Standalone `sigil-sender` install no longer fails on `Group=sigil`** (#61).
  The sender unit runs `root:sigil`, but the sender package neither created the
  group nor depended on the agent package, so a sender-only install left
  `systemctl enable --now sigil-sender` failing on group credential resolution.
  The sender package now ships and applies the same idempotent
  `sysusers.d`/`tmpfiles.d` `sigil.conf` as the agent package.

### Changed

- **`sigil-mcp` defaults to single-host `sigil-check`; the fleet view is the
  operator-only `sigil-fleet`** (#80). The two auto-detected modes now register
  under distinct MCP server names: `sigil-check` (no server URL) exposes only
  *this* host's posture and is what `--print-config` emits by default, while the
  fleet-wide `sigil-fleet` (pointed at a `sigil-server` read API) is documented
  as an operator surface to run beside `sigil-server` / `sigil-manager`. No tools
  were removed — naming, default posture, and docs only.
- `sigil doctor`'s events-directory permission check is refactored around a pure
  `classify_events_dir_perms` classifier (mirrors the existing socket
  classifier) and validates `root:sigil` ownership; behavior is unchanged, the
  decision logic is now unit-tested.

## [0.2.0]

### Added

- **`sigil-mcp` — read-only fleet MCP server** (#51). Exposes a `sigil-server`'s
  GET read API as Model Context Protocol tools so an MCP client (Claude
  Desktop/Code) can read and reason over fleet posture. Shipped in `install.sh`
  and the prebuilt release archives alongside the other binaries.

_Releases at or before 0.2.0 are documented in
[GitHub Releases](https://github.com/Ju571nK/sigil/releases)._
