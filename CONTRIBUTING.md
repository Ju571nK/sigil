# Contributing

Thank you for your interest in contributing to Sigil.

## Contribution Guidelines

- Open an issue before starting large changes.
- Keep pull requests focused and easy to review.
- Include tests or documentation updates when they are relevant.
- Do not submit secrets, credentials, private keys, proprietary code, internal
  company information, confidential documents, or data you do not have the right
  to share.
- Do not submit code copied from an employer or another project unless you have
  the legal right to contribute it under the Apache License 2.0.

## Good first contributions — Linux runtime

The Linux runtime (`crates/sigil-agent/src/platform/linux.rs`) landed as a
minimal foundation in Phase 3a: it watches files (via `notify`'s inotify
backend), enumerates users from `/etc/passwd`, and computes the hardware
fingerprint. Several refinements are deliberately left open and marked
`TODO(community)` in that file — they make good standalone PRs:

- **inotify watch-count limits.** A recursive watch tree larger than
  `/proc/sys/fs/inotify/max_user_watches` causes `notify` to fail on some
  subdirectories. Today those errors are logged; a better treatment emits a
  posture event ("coverage degraded — N subtrees unwatched") and has
  `sigil doctor` warn when the sysctl looks low relative to the policy's path
  count.
- **`fda_state()` nuance.** It returns `Granted` unconditionally on Linux
  (there is no Full-Disk-Access gate). It could instead reflect whether the
  daemon runs as root / with `CAP_DAC_READ_SEARCH` vs. a limited user and
  surface that in `sigil doctor`.
- **LDAP / Active Directory users.** `list()` parses `/etc/passwd` directly.
  On directory-joined hosts, real users may only appear via `getent passwd`.
  An opt-in (config-gated) `getent` path would broaden coverage — gated
  because AD homes are often NFS-mounted and slow.
- **Init-system-agnostic service status.** `sigil doctor` does not check
  whether the agent service is running. A check that handles systemd /
  OpenRC / runit would be useful (systemd unit ships in
  `packaging/systemd/sigil.service`).
- **Packaging.** `.deb` / `.rpm` build recipes (only the systemd unit ships
  today).

Linux runtime tests run in CI on `ubuntu-22.04`, so platform-specific test
gaps in the existing agent integration suite are also fair game.

## Good first contributions — agent

- **Canonicalize policy paths.** The normalizer canonicalizes event paths
  (`dunce::canonicalize`) but compiles globs from the raw policy paths, so a
  policy path under a symlinked prefix never matches — on macOS that means
  `/var/...`, `/tmp/...`, `/etc/...` (symlinks to `/private/...`) silently fail.
  The fix is to canonicalize the literal prefix (everything before the first
  glob metacharacter) of each path when building globs / watch roots, in
  `crates/sigil-agent/src/runtime.rs` and `normalizer::compile_targets`.
- **`sigil show stats` over IPC.** It currently prints "read the next heartbeat
  from the JSONL" instead of querying the running daemon. The control protocol
  already has the `{"cmd":"stats"}` request (`crates/sigil-agent/src/control.rs`)
  and `sigil-sender` has a client (`crates/sigil-sender/src/agent_ipc.rs`) to
  model — wire `ShowWhat::Stats` in `crates/sigil-agent/src/show.rs` to connect,
  send it, and print the `StatsSnapshot`.
- **Run the agent-runtime tests on Windows CI.** The integration tests that
  boot the whole agent via `TestAgentBuilder` (`basic_events`, `critical_tier`,
  `large_file`, `shutdown`) run on macOS and Linux but are
  `#[cfg_attr(target_os = "windows", ignore)]`: on Windows, `runtime::run`
  stops right after the hardware-fingerprint step, before the control listener
  comes up. The tolerant `spawn_watcher` (a single bad watch root no longer
  kills the agent) didn't change it, so it isn't a per-root error — suspect
  `RecommendedWatcher::new` (the `ReadDirectoryChangesW` backend) or a hang in
  it. Reproduce with `SIGIL_LOG=debug cargo test -p sigil-agent --test
  basic_events` on Windows, fix, and drop the `cfg_attr`.

## License of Contributions

Unless you clearly state otherwise, any contribution intentionally submitted to
this project is provided under the Apache License 2.0.

## Maintainer Availability

This is a personal open-source project. Reviews, releases, and support are
provided on a best-effort basis. The maintainer does not guarantee acceptance of
contributions, response times, maintenance, support, or ongoing compatibility.
