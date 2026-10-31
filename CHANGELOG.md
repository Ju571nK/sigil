# Changelog

All notable changes to Lodeline are recorded here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the workspace uses a
single SemVer version across all crates. Full release notes for tagged releases
also appear under [GitHub Releases](https://github.com/Ju571nK/lodeline/releases).

## [Unreleased]

### Fixed

- lodeline-proxy no longer scans the spool's `events` table for acknowledged rows
  on each maintenance pass, so appends wait less behind it. The new partial index
  is added to existing spools on open, with no schema version change.

## [0.12.0] - 2026-10-31

### Changed

- **Breaking:** Sigil is now Lodeline. Binaries, packages, units, paths, `SIGIL_*`
  env vars and `x-sigil-*` headers all take the new name, and there is no `sigil`
  shim. Hash and signature domains, the release key id and the proxy SAN keep
  their old bytes so existing bundles, stored data and certificates still verify.
  The new `.deb` and `.rpm` packages replace the old ones and move config and state
  to the new paths. Follow [docs/migrate-from-sigil.md](docs/migrate-from-sigil.md)
  when you upgrade: it lists every step an operator must take.

### Added

- lodeline-proxy status reports now carry `spool.quarantined_bytes`, and the
  server's proxy list API returns `spool.quarantined_events` and
  `spool.quarantined_bytes` (the latter null for a proxy that has not reported
  it), so operators can watch quarantine growth. Upgrade lodeline-server first:
  its status parser rejects unknown fields, so a proxy that sends the new field
  to an older server has its status reports refused (#302). Downgrading lodeline-server after a new
  proxy has reported fails at boot until `quarantined_bytes` is removed from the
  stored proxy state, because older servers reject unknown fields.

### Fixed

- The lodeline-proxy systemd unit now sets `StateDirectoryMode=0700`. It was
  0750, which systemd reapplies on every start, and lodeline-proxy refuses a
  state directory with group or other access, so the packaged proxy could not
  start at the default path.
- lodeline-proxy now deletes a quarantined spool row once its `quarantined_at` is
  older than Q, the server-issued `event_retention_seconds` (E). This covers
  every code, `registry_conflict_original` included. Before this, quarantine
  only grew. The server keeps the matching gap for E after its `detected_at`,
  which is no later than `quarantined_at`, so local evidence lives at least as
  long as the server must keep the gap. Two known limits: proxy clock skew, and
  a gap delivered to the server more than E after the quarantine (an outage
  of at least E; R + E for `spool_expired`). Nothing is deleted
  until the proxy has applied a config that carries E. Each maintenance batch
  that deletes rows logs the count, never the content (#302).
- A wall-clock step no longer ages lodeline-proxy spool rows within a boot. An NTP
  step forward of R or more used to quarantine every unsent event at once, and a
  step of Q or more purged quarantine evidence early. A backward step delayed
  both. Each unsent event and quarantine row now has a `(boot_id, boot clock)`
  stamp, and age uses the boot clock within the boot of the stamp, restarts
  included. Across boots, or for a row with no stamp, age uses the wall clock as
  before. Timestamps on the wire stay wall clock. The stamps are in additive
  tables with the same schema version, so an older binary still opens the
  database (Refs #302).
- The lodeline-proxy systemd unit now orders itself after `time-sync.target`.
  Across a reboot spool age uses the wall clock, so a host that booted with a
  wrong RTC could misjudge the age of older rows until the first clock step. The
  target only waits when a wait service is enabled; the packaging README says
  which one to use (#302).
- On Unix, lodeline-proxy opens its spool and registry databases with
  `SQLITE_OPEN_NOFOLLOW` under the resolved state directory. This closes the
  gap between the symlink check and the open, where the file could be swapped
  for a symlink. Windows keeps the check-then-open behaviour (#302).
- The packaged `/etc/lodeline/sender.yaml.example` now tails `/var/log/lodeline`,
  where the root agent writes `events-*.jsonl`. It pointed at
  `/var/log/lodeline/events`, so a sender configured from it shipped nothing and
  logged no error. A `sender.yaml` copied from an older example needs
  `events_dir: "/var/log/lodeline"` (#328).
- The agent's spool GC now sees how far lodeline-sender has shipped. It looked
  for `<events_dir>/sender-offset.json` in a format the sender never wrote,
  while the sender writes `/var/lib/lodeline-sender/sender-offset.json`. So the
  soft floor never freed shipped segments, and at the hard ceiling the GC
  force-deleted them and raised a data-loss alarm for data already delivered.
  A sender with a non-default `offset_path` still leaves the GC without a
  sender record. Only a root agent reads it; a per-user agent's spool is not
  tailed by the packaged sender (#331).
- lodeline-sender no longer skips the same-day rotations of a segment. The agent
  writes `events-D.jsonl` and then, past 100 MiB, `events-D-001.jsonl`, but
  string order puts `-001` first, so the sender jumped from `events-D.jsonl`
  to the next day and never shipped `-001` onward. The spool GC used the same
  order to pick the live segment and to decide what was shipped. Segments are
  now ordered by date and sequence number everywhere, including
  `lodeline show events`. Rotations a sender already skipped before the upgrade
  stay unshipped. A sender that started on an existing backlog may also
  re-send or skip a few segments once after upgrading (#331).

- An agent running as root on Linux or macOS now assesses every user's AI
  agent configs, not just root's own home. Each user's readings carry a new
  optional `user` field on `ai_guard_risk_assessed` and
  `ai_guard_toggle_drift`; readings for the agent's own home and for projects
  omit it as before. lodeline-server now reports, per tool, the riskiest of a
  host's readings instead of the last one received, so one clean user or
  project no longer hides another. Readings older than 48 hours (a removed
  repo, user or rule pack) stop counting; when a config cannot be read on the
  daily heartbeat, the agent re-sends its last reading so the risk does not age
  out. A root agent used to report score 0
  for a host whose users had risky hooks. `lodeline show risk` and `lodeline doctor`
  print the user next to the scope. Codex MCP tool baselines are now kept per
  home; an existing baseline still applies to the home that wrote it. Rule
  packs still assess only the agent's own home. Windows services still assess
  only their own profile (#329).

## [0.11.0] - 2026-10-30

### Added

- A Claude Code hook script is now scanned when its interpreter follows
  `NAME=value` assignments or an `env` launcher
  (`/usr/bin/env -i bash ./check.sh`), is `bash.exe`, or carries options
  (`bash -euo pipefail ./check.sh`). These commands used to be checked only
  as inline text, so the script itself was not read (#199).

- Codex hook commands are now read the same way as Claude Code ones. A script
  run through an interpreter (`bash ./check.sh`) is scanned, and a command
  chained after a script (`./ok.sh && rm -rf ~`) is checked. Codex used to
  read a script only when the command started with its path, and then
  ignored the rest of the line.

### Changed

- Continue's `slashCommands` entries and `customCommands[].command` are no
  longer assessed, and a script named by `step` is no longer watched.
  Continue uses none of their `step`, `run` or `prompt` text: `step` is
  documented as having no effect, a slash command resolves only by name to a
  built-in, and a custom command has no `command` field. Destructive text in
  these fields used to be reported as a hook command. A custom command's
  `prompt`, which Continue sends to the model, is still scanned.
  Fleet consumers no longer see `hook_event: "slash_command"` from this
  version on (Ju571nK/sigil-manager#40).

- Codex hooks that Codex will not run are no longer assessed. A hook outside
  the system layer runs only when `~/.codex/config.toml` records a
  `trusted_hash` for it under `[hooks.state]` and does not set
  `enabled = false`. Hooks with no trust entry, or turned off, used to be
  reported as if they ran. A hook whose trusted hash is out of date is still
  reported. Hooks run with `--dangerously-bypass-hook-trust` are not seen
  (#200).

## [0.10.0] - 2026-10-28

### Added

- `sigil-server` has an optional `proxy:` config section and a
  `sigil-server proxy` operator command for the Sigil Proxy that is still in
  development. With the section set, the server registers proxies, issues
  their config, and accepts their status, events, metadata and inventory
  reports. It also serves `/v1/proxies`, `/v1/proxy-invocations` and the
  management audit log for reading. Without the section the server behaves as
  before. The `sigil-proxy` binary and packages are not part of this release.

- Claude Code hooks declared in skill (`skills/<name>/SKILL.md`) and subagent
  (`agents/**/*.md`) frontmatter are now assessed, at user and project scope,
  with the same reasons as `settings.json` hooks. A repository that ships only
  `.claude/skills/` or `.claude/agents/` is now discovered (#199).
- A hook command of the form `bash <script>` (or `sh`, `zsh`, `dash`) now has
  its script scanned, as a command starting with a script path already did.
  A command chained after a script (`./ok.sh && rm -rf ~`) is now checked
  inline as well; before, a command starting with a script path was not
  checked inline at all. The script's own arguments are not checked.
- Codex hooks in `hooks.json` are now assessed next to the `[hooks]` table of
  `config.toml`, in `~/.codex/`, in a repository's `.codex/`, and in the
  system config folder. A repository that ships only `.codex/hooks.json` is
  now discovered (#200).
- The Codex system config layer (`/etc/codex/config.toml`, or
  `%ProgramData%\OpenAI\Codex\config.toml` on Windows) is now read under the
  user config, as Codex layers them: `~/.codex/config.toml` overrides its
  scalar settings, `mcp_servers` tables merge, and the hooks of both layers
  are assessed (#200).

### Fixed

- The declared minimum supported Rust version is now 1.88 (was 1.78). The
  committed lockfile already required 1.88: edition-2024 dependencies (for
  example `rmcp` and `idna_adapter`) fail on 1.78, and `darling` 0.23 needs
  1.88. A new CI job checks the workspace with the declared toolchain so the
  value stays accurate (#240).
- The `sigil`, `sigil-sender` and `sigil-server` `.deb` packages can now be
  installed on the same host. They all shipped
  `/usr/lib/sysusers.d/sigil.conf`, so dpkg refused the second one;
  `sigil-sender` and `sigil-server` now install the same content as
  `sigil-sender.conf` / `sigil-server.conf` (also in `tmpfiles.d` for
  `sigil-sender`). The `.rpm` packages use the same names. CI now installs all
  packages together (#252).

## [0.9.1] - 2026-10-10

### Fixed

- `GET /v1/meta.audit_head` no longer pairs the chain head's `pubkey_id` with
  the server's current audit key when the two differ (for example after the
  key was regenerated or the chain was moved between installs). `pubkey` is now
  reported only when the current key signed the head; otherwise it is omitted,
  and `pubkey_id` names the key to verify with. The head is also reported when
  no audit key is loaded. The server logs a warning at startup when the head's
  key is not the one it holds (#237).

## [0.9.0] - 2026-10-09

### Added

- Define the targeted deployment v2 core manifest contract, domain-separated
  signature verification, paired artifact validation, and replay/migration
  checks with a shared golden fixture (#230, first stage). Runtime activation,
  server distribution, and signer CLI integration are not enabled yet.
- Add a FULL-synchronous transactional deployment store and agent preparation
  coordinator (#230, second stage). Commit manifest, both artifacts, and replay
  state together; reverify on recovery and compile one coherent policy/rubric/
  evaluator generation before publication. This remains an internal API, not
  daemon activation or an `applied` acknowledgement.

### Changed

- `GET /v1/meta` reports the active host count and its rolling window under
  `fleet` (`{"active_host_count": <u32>, "active_window_days": <u32>}`). The
  window is configured with the new top-level `active_window_days` key in
  server config (default 7).

### Deprecated

- The `license:` block in server config. `license.active_window_days` is still
  honored when top-level `active_window_days` is absent; `license.path` is
  ignored. Both log a warning at startup; configs that contain the block keep
  loading.

### Removed

- The license verification module (`sigil_core::license`), the server's boot
  license load, and the `license` object in `GET /v1/meta`; active host count
  and window are now reported under `fleet`.
- The `sigil-sign license` subcommand.
- `sigil-server` no longer appends records to `license-audit.jsonl`. An
  existing chain is left untouched: its head is still read at startup and
  exposed as `/v1/meta.audit_head`, the record format is frozen, and
  `sigil-sign verify-audit` still verifies it.

### Fixed

- Native (glibc) `.rpm` builds use rpm's `find-requires` for dependency
  generation. With Rust 1.99+ binaries, cargo-generate-rpm's builtin fallback
  wrote weak glibc version references as unsatisfiable requirements such as
  `libc.so.6(GLIBC_2.18)[WEAK](64bit)`, so `rpm -i` failed on Rocky 9.
  `packaging/build.sh` now stops with an error when `find-requires` is missing
  for a dynamic build. Release packages are static musl builds and were not
  affected (#234).

## [0.8.3] - 2026-09-13

### Fixed

- Drain the agent pipeline on Unix SIGINT/SIGTERM and Windows Ctrl-C. Release
  retained channel senders, stop IPC acceptance, drain accepted requests for up
  to five seconds, and remove Unix socket files. Supervise failures concurrently
  and report a nonzero exit on storage errors or a 30-second shutdown timeout
  instead of waiting indefinitely (#225).
- Resolve wildcard directory ancestors into concrete watch roots and rediscover
  matches every five seconds with native and polling backends. Catch up newly
  discovered or replaced directories without recursively watching broad parent
  trees, and preserve shared-root ownership across policy reloads (#223).

## [0.8.2] - 2026-09-12

### Fixed

- Retry absent or replaced filesystem watch roots every five seconds without
  recursively watching parent directories. Replay current files after successful
  subscription, cancel recovery when targets are removed, and retain failed
  registrations for retry with both native and polling backends (#219).

## [0.8.1] - 2026-09-12

### Fixed

- Include all 30 binaries from the five Linux, macOS, and Windows release
  archives in the signed build manifest. Preserve canonical binary names for
  Windows `.exe` files so `sigil doctor --verify-self` can find them (#221).
- Block signed release publication unless native runners for all five targets
  verify their downloaded agent and reject a tampered manifest. Add regression
  tests for incomplete archives, duplicate entries, and unsafe archive members.

## [0.8.0] - 2026-09-12

### Added

- Report-only AI Guard controls across scan, daemon, IPC, event history, and
  fleet detail (#207). Controls preserve absent versus empty reporting and
  never reduce risk scores or suppress findings.
- Allowlisted Claude managed-file and Codex requirements-file observations
  with exact source paths (#199, #200). `configured` controls describe local
  files only, not effective cloud/MDM policy or verified runtime enforcement.
- Persistent, per-server MCP metadata baselines beside state.db (#201).
  Detect changed surfaces, new tools, schema expansion, and advisory read-only
  hint contradictions; scan server-info text and v3/v4 cache fields. Repeated
  changes retain distinct evidence hashes. One-shot scan remains stateless.
- Claude auto-mode/default-rule, non-command hook, loop-prompt, and Codex
  standing-approval detection from the earlier #199/#200 increment (#206).
- Antigravity enforcement adapter limited to the hardware-verified contract
  (#208), with compatibility re-probe evidence (#202). Existing unsupported
  modes remain gated.

### Fixed

- Preserve inherited Claude permission rules when merging local settings
  instead of losing broad allows behind an unrelated override (#216).
- Scan all MCP cache variants so an older clean snapshot cannot hide poisoned
  metadata; enforce the schema text cap for a single oversized string (#217).
- Add default watcher coverage for MCP caches and local managed policies,
  and resolve canonical parser paths on macOS (#218).
- Detect broad Antigravity permission allows (#209).

### Upgrade Notes

- Upgrade sigil-server before agents: new MCP reason variants require an
  updated consumer. Manager rendering of controls remains a companion change.
- MCP baselines are first-observed references, not user approvals. Review
  metadata before deliberately resetting a reference. Keep the baseline
  directory protected with the agent's state files.
- #199/#200 remain open for other configuration scopes and effective-policy
  verification. Missing watch directories created after startup may require
  restart; the heartbeat fallback remains in place (#219).

## [0.7.2] - 2026-07-26

### Security

- **Bash deny rules are matched against the command a shell would actually run**
  (#198). Rules previously ran the operator's regex at the raw command string,
  but the shell rewrites that string before `execve`, so any re-spelling that
  survives the rewrite defeated the rule — `r''m -rf /`, `rm${IFS}-rf${IFS}/`,
  `X=rm; $X -rf /`, `sudo rm -rf /`, `sh -c 'rm -rf /'`. (This is the class
  Adversa AI published as GuardFall, which bypassed plaintext denylists in 10 of
  11 OSS coding agents.) On a blocking path a bypassable matcher is worse than no
  rule, because it reads as coverage that is not there.

  A rule written as `rm -rf /` now also denies quote and escape re-spellings,
  `$IFS` word splitting, variables assigned earlier in the line, ANSI-C quoting
  (`$'\x72\x6d'`), wrapper commands (`sudo`, `env`, `nice`, `timeout 5`,
  `xargs`), `-c` string payloads (`sh -c`, `bash -lc`, `su -c`), commands fed to
  a shell on stdin (`bash <<< '…'`, `sh <<EOF … EOF`), mid-command redirections
  (`rm >/dev/null -rf /`), compound-statement context, and trailing comments.
  Normalized segments are matched **in addition to** the raw string, so existing
  rule packs keep firing unchanged; a rule that fires only after rewriting says
  so in the deny reason.

  Normalization refuses to guess in the other direction, since an invented
  command means denying legitimate work: `r$(printf x)m -rf /` is not `rm`
  (the shell runs `rxm`), a `cat <<EOF` body stays data while a `bash <<EOF`
  body is commands, `su rm` switches to a user, and `timeout rm -rf /` never
  ran anything.

### Added

- **Static MCP tool-metadata poisoning detection** (#148). The Codex tool cache
  (`~/.codex/cache/codex_apps_tools/*.json`) holds tool descriptions and input
  schemas that the model reads but the user never sees — the payload surface for
  the poisoning technique Microsoft warned about on 2026-06-30. Three new
  findings: `mcp_tool_instruction_override` (imperative directives aimed at the
  agent inside tool metadata), `mcp_tool_hidden_text` (zero-width, bidi,
  control, or homoglyph characters), and `mcp_tool_name_shadow` (two servers
  offering the same tool name). Bounded and defensive against hostile input.
- **New deny-rule shape `bash_indirection`** (#198). Constructs whose effect
  cannot be known without running them — `$(...)`, backticks, process
  substitution, `eval`, unmodeled parameter expansions, pipelines feeding a
  shell — are reported rather than guessed at, so an operator can deny on the
  shape instead of enumerating spellings. Values: `command_substitution`,
  `eval`, `pipe_to_shell`, `unresolved_command_variable`, `unparsable`.
  Exceeding a size or segment bound always reports `unparsable`, so a text
  rule's silence is never mistaken for safety.
- **`sigil-server` binds enrollment to issuer certs and can require a
  cert↔host_id match** (#194). `enroll_issuer_fingerprints` lists the blake3
  fingerprints of client certs permitted to call `POST /v1/enroll`; a caller not
  on the list is denied before its token is consumed, so a leaked token is
  useless without the issuer cert. The opt-in `events_require_cert_host_match`
  requires a `POST /v1/events` client cert whose CN or SAN DNS entry matches the
  envelope's `host_id`, blocking an enrolled host from impersonating another.
  Both rest on new per-connection TLS peer-certificate identity; enrollment
  audit records now carry the caller fingerprint.

### Documentation

- `config/server.example.yaml` documents the enrollment (#184), peer-cert
  (#194), and artifact-serving (#182) keys, with a test that keeps the example
  in step with the config schema (#196).
- `docs/install-personal.md` explains how bash deny rules are matched, what a
  plain rule now covers, and what it deliberately does not (#198).

## [0.7.1] - 2026-07-02

### Added

- **Autonomous / unattended Claude Code config is flagged** (#191). Loop/goal-style
  features run repeated work unattended; if the agent runs without guardrails the
  blast radius grows, so the readable signals are now measured:
  `permissions.defaultMode` of `auto` / `bypassPermissions` / `acceptEdits` in
  `~/.claude/settings.json` surfaces as `auto_approval_enabled` (flowing into
  scan, #147 toggle-drift, and remediation hints), and each
  `~/.claude/scheduled-tasks/<name>/SKILL.md` — the readable, persistent
  equivalent of a loop — emits a new `unattended_scheduled_task` finding.
  Session-only state (an active `/loop`, `/goal` conditions, cloud `/schedule`
  routines) leaves no on-disk trace and is documented as out of scope.
- **`sigil scan` remediation hints** (#188 follow-up). Every finding now carries a
  one-line advisory "how to reduce it": the human output gains a `How to reduce`
  section after the table (distinct finding kinds, highest-impact first) and
  `--json` adds a `hint` field per reason. Advisory only — Sigil measures, it
  does not block or auto-edit.
- **Personal install offers a read-only Claude Code allowlist** (#188). Driving
  sigil from inside an AI agent caused a per-command permission-prompt storm.
  The personal `install.sh` / `install.ps1` now offer (opt-in, terminal consent
  only, never silent) to add `Bash(sigil:*)` to `~/.claude/settings.json`
  permissions.allow with an explicit deny of `sigil run` and `sigil-hook`, so
  the daemon and hook-enforce are never silently granted to the agent.

## [0.7.0] - 2026-06-28

### Added

- **Dangerous-toggle drift detection** (#147). When a coding agent's config
  silently flips a self-escalation toggle on — auto-approve, sandbox-off,
  broad-allow, or project-MCP-autorun — the daemon emits a one-time
  `AiGuardToggleDrift` security event (the CVE-2025-53773 `chat.tools.autoApprove`
  class). Fires only on the OFF→ON transition vs the previous hashed snapshot
  (baseline-safe across restarts; re-arms on off→on→off→on); classified as a
  fleet alert. Works over reason kinds, so rule-pack-emitted toggles are covered.
- **`sigil-server` enrollment endpoint (B-mint)** (#184). `POST /v1/enroll` signs
  a host CSR into a per-host mTLS client cert using an operator-provided
  intermediate CA (root stays offline), gated by a single-use, TTL, per-host
  token (`sigil-server enroll-token`). Fixed client-cert profile + post-sign
  inspection, allowlist auto-add, signed enrollment audit; enrollment refuses to
  run without mTLS + a restrictive allowlist. Lets a PMS bootstrap host identity
  without hand-running openssl per host. Hardware-verified on Rocky 9 aarch64.
- **`sigil-server` signed-artifact serving** (#182). `GET /v1/artifacts[/<file>]`
  serves the release binaries (tarballs/zips, `.deb`/`.rpm`, `SHA256SUMS`,
  build-manifest) read-only from an operator-populated `artifacts_dir`, so an
  air-gapped fleet/PMS can pull from the server instead of GitHub. Bearer-gated,
  path-traversal-hardened; `install.sh`/`install.ps1` gained `SIGIL_BASE_URL` +
  `SIGIL_BASE_TOKEN` to fetch from it.
## [0.6.2] - 2026-06-21

### Added

- **`sigil scan` — one-shot, daemon-free posture score** (#174). The fastest
  personal read: it reads each installed agent's user-global config once
  (`~/.claude`, `~/.codex`, `~/.cursor`, …) plus the current directory if it is a
  project, scores them with the default rubric, and prints a headline (worst-scope
  bucket + score) and a per-tool table — no daemon, no `state.db`, no policy.
  `--json` emits the full report; the command always exits 0 (a read-out, not a
  gate). Closes the gap behind the one-line installers ("install → score").
- **One-line installer for all three OSes** (#172, #171). New `install.ps1` is the
  Windows counterpart to `install.sh` (`irm …/install.ps1 | iex`): arch-detected
  (x64 / ARM64), checksum-verified, installs the personal profile to
  `%LOCALAPPDATA%\Programs\sigil` and adds it to PATH. `install.sh` now resolves
  Linux **aarch64** (the musl tarball it had been wrongly rejecting), so the
  one-liner works on Graviton/Ampere and RHEL/Rocky 9 aarch64. Script installs
  avoid code-signing friction (Gatekeeper/SmartScreen) by design.
### Fixed

- **`sigil doctor` no longer warns about a control socket on a non-root install**
  (#178). The check hardcoded `/var/run/sigil/control.sock` and expected it
  root-owned, so a non-root personal user got a spurious `Permission denied`
  warning (and a non-zero exit) about a socket the non-root daemon never binds.
  Doctor now resolves the same XDG/tmp fallback path the daemon uses and expects
  ownership by the invoking user.
- **`install.sh` suggests how to install a missing tool** (#179). On a minimal
  RHEL-family / container host without `tar` (or `curl`), the bare "missing
  required tool" message now appends the host package manager's one-liner
  (`sudo dnf install -y tar`, `sudo apt-get install -y …`, etc.).
- **macOS install guide corrected** (#176). It claimed `install.sh` installs all
  six binaries; the personal default is three. Added a 30-second personal
  quickstart and framed the rest as the operator deployment.

## [0.6.0] - 2026-06-16

### Added

- **OpenClaw / Hermes integration glue for `assess`** (#151). `sigil-mcp
  --print-config` now emits ready-to-paste blocks for `hermes` (a `config.yaml`
  `mcp_servers:` entry) and `openclaw` (a `~/.openclaw/openclaw.json` `mcpServers`
  entry), alongside the existing `codex`/`claude`. New `examples/integrations/`
  carries a drop-in OpenClaw `SKILL.md` (pre-flights commands via `sigil assess`)
  and a Hermes `config.yaml` snippet, plus a README describing the reusable
  pre-flight contract (assess → decision → allow/warn/deny).
- **`assess` — a callable pre-flight risk check** (#149). A new primitive scores a
  *proposed* shell command or a single MCP server definition against this host's
  loaded policy (the same rubric + rule-pack deny rules the agent enforces), and
  returns a risk band, score, reasons, any deny-rule match, and a decision
  (allow / warn / deny). Where the existing read surfaces report standing posture
  ("what is my risk right now?"), `assess` answers "is *this action* risky / would
  Sigil block it?" before it runs. Exposed two ways:
  - **`sigil assess` CLI** — `--command "<cmd>"` (or `--mcp-config <file>` /
    `--mcp-stdin --mcp-name <name>`), evaluated against the on-disk policy
    (no daemon required). Prints a one-line JSON verdict and maps the decision to
    exit codes (allow/warn → 0, deny → 2, usage/policy-load error → 1; `--fail-on-warn`
    makes warn → 2) so it can gate a shell pre-flight.
  - **`assess` MCP tool** (local surface) — evaluates against the running agent's
    *live* loaded policy via the existing control IPC. Read-only; executes nothing.
  Malformed or oversize input fails closed (error, never an allow verdict).

### Fixed

- **The local `rule-packs.yaml` watcher re-arms when the config dir is recreated
  at runtime** (#135). The dedicated hot-reload watcher previously gave up
  permanently if its config directory was absent at start, and a by-inode watch
  went silent if the directory was deleted and re-created while the agent ran. It
  now watches the grandparent directory (always present — `~/.config`, `/etc`,
  `$HOME`) and re-arms the parent-directory watch whenever the config dir
  (re)appears, so local rule-pack edits keep hot-reloading across a dir recreate.
- **A transient empty `rule-packs.yaml` read retains the active bundle instead of
  clearing it** (#135). A non-atomic `cp` truncates the destination to zero bytes
  before writing; that empty window was treated as "file removed" and momentarily
  dropped the local rule packs (and their enforcement) until the next reload. A
  zero-byte / whitespace-only read is now retained as last-good. To deliberately
  clear the bundle, remove the file (honored as before) or write a valid empty
  document; only a real removal clears.

## [0.5.1] - 2026-06-12

### Fixed

- **The agent `.deb` is published in releases again** (#138). The agent package
  is named `sigil`, so cargo-deb emits `sigil_<ver>-1_<arch>.deb` (underscore) —
  and the release job's `sigil-*` (hyphen) artifact globs silently skipped it
  in the checksums, the provenance attestation, and the release upload, while
  every other artifact matched. Affected v0.4.0 and v0.5.0 (the agent `.rpm`
  shipped throughout). The globs are now `sigil*`; this release carries the
  agent `.deb` for both x86_64 and aarch64, restoring `apt install` of the
  agent (personal profile: `sigil` + `sigil-mcp` + `sigil-hook`) on
  Debian/Ubuntu.

## [0.5.0] - 2026-06-11

### Added

- **Personal / Fleet install profiles** (#134). Sigil now installs as one of two
  profiles from a single release. `install.sh` takes `SIGIL_PROFILE=personal|fleet`
  (default `personal`): **personal** installs `sigil` + `sigil-mcp` + `sigil-hook`
  for local self-assessment with no server; **fleet** adds `sigil-sender`,
  `sigil-server`, and `sigil-sign` for the signed server-push path. The `sigil`
  `.deb`/`.rpm` package now bundles `sigil-mcp` and `sigil-hook` (so installing the
  `sigil` package is the personal profile). See
  [docs/install-personal.md](docs/install-personal.md).
- **Local rule-pack hot-reload** (#134). A dedicated filesystem watcher on
  `rule-packs.yaml` (beside `policy.yaml`) hot-reloads locally-distributed rule
  packs — e.g. pulled from a git repository — without a server, honoring `--poll`.
  Corrupt edits retain the last-good bundle (a broken `git pull` will not drop your
  active packs); a deliberately removed file clears the bundle layer. The local
  reload path validates deny-rule IDs and compiles regexes with keep-previous
  semantics, matching the signed-bundle path minus the signature. Local rule packs
  are unsigned — their trust boundary is the git repository they come from, and
  they carry `hook_deny_rules` enforcement authority, so use only trusted sources.

### Changed

- **`install.sh` default now installs three binaries, not six** (#134). A plain
  `curl … | sh` installs the `personal` set (`sigil`, `sigil-mcp`, `sigil-hook`).
  Existing users who need the server components must install with
  `SIGIL_PROFILE=fleet`. Personal is Unix-first (`sigil-mcp` local mode and
  `sigil-hook` enforce are Unix-only; Windows has partial support via the tarball).

### Fixed

- **Empty / whitespace AI-tool config is treated as clean, not a parse error**
  (#131). A zero-byte or whitespace-only tool config file (e.g. an empty
  `~/.gemini/config/mcp_config.json`) no longer drops that tool from assessment
  with an EOF parse error — closing a silent coverage hole found via two-machine
  dogfooding. Shared `read_json_optional` helper across the JSON config parsers.

### CI

- **Build-provenance attestation is non-blocking** (#130). A transient Sigstore
  Rekor outage during the release attestation step no longer blocks publishing
  already-built, already-signed artifacts; re-run the job to (re-)attach
  attestations. The enforced trust root remains the ed25519 build-manifest
  signature.

## [0.4.0] - 2026-06-10

### Added

- **`sigil-hook` Stage 2 — in-domain enforcement (block)** (#100). The same
  `PreToolUse` hook that observed tool calls in Stage 1 can now also *decide* and
  **deny** a disallowed call at the agent tool boundary. Delivered per-agent: a
  generalized `deny_output` trait with **Claude Code** (#106), **Codex** (#111),
  **Cursor** (#119), and **Grok Build (xAI)** (#118) adapters. Each agent's deny
  contract is honored exactly (Cursor `permission`, Grok `decision`), including
  Cursor's explicit-allow seam so `--on-failure closed` is genuinely fail-closed.
  Enforcement stays advisory-at-root and open-source/in-tree, never claiming
  tamper-resistant runtime command security.
- **Tamper-evidence — hook config-drift detection** (#109, #120). A new
  `sigil-hook verify` compares the live agent settings against a per-agent
  recorded baseline (`hook-registration-<agent>.json`) and reports drift:
  missing hook, repointed binary, narrowed matcher, or a flipped fail-mode
  (`DriftKind::FailModeDrift`). Format-aware verify with per-agent baselines so
  enforce and tamper-evidence stay symmetric.
- **Hook-activity silence detection** (#107). First-class detection of a hook
  that has gone quiet (absence/silence), closing the gap where a disabled or
  bypassed hook would otherwise look identical to an idle one.
- **Signed distribution of hook deny rules** (#115). Hook deny policy now rides
  the existing signed-bundle pipeline, so enforce rules are distributed with the
  same provenance guarantees as rule packs.
- **AI Guard — MCP stdio launcher attack-shape scoring** (#127). A new
  `McpServerSuspiciousLauncher` reason scores a stdio MCP launcher that is a
  shell with an inline-exec flag (`bash -c`, including POSIX bundled forms like
  `-lc`) or that resolves into a transient/writable path (`/tmp`, `/dev/shm`,
  `/run/user`, Windows `Temp`, `~/.cache`, …) — lifting the attacker-injected
  launcher shape (the 2026 zero-click MCP incident class) above the benign
  stdio baseline. Two independently operator-tunable rubric keys.

### Changed

- **Uniform local stdio MCP command detection across all parsers** (#125, #126).
  Every per-agent parser now routes its per-server MCP definition through one
  shared `emit_one_server`, closing the divergence where Codex and Claude Code
  never read a local `command` at all and others only partially scored it.
- **`show risk --tool` accepts every known tool** (#121, #124). The flag is
  driven from a single source of truth, so Antigravity, Claude Desktop, and
  Continue are accepted alongside the others (no more `exit 2` on a valid tool),
  with a legacy `claude_code` alias preserved.

### Fixed

- **FS-watch e2e tests hardened against parallel-load flake** (#108). Watcher
  tests that dropped a single startup-window write now use continuous writers or
  retry loops, and the control-IPC connect budget is configurable — eliminating
  a class of load-dependent failures rather than a single flake.

### Security

- Stopped tracking a local `.codex/` Codex CLI config that had leaked a test
  bearer token and an internal server address into the public repo; the token
  was rotated.

### Internal

- Measurement pilot quantifying the hardcoded-parser → rule-pack migration
  (#102): a 26-case Antigravity parity harness proving the migration is
  net-negative today (DSL is type-blind and cannot express the destructive
  inline-command scan), with no runtime change. Documents the decision to keep
  the imperative parser kernel.

## [0.3.0] - 2026-06-04

### Added

- **`sigil-hook` — runtime observe at the agent tool boundary** (#64). A new
  in-tree crate that AI coding agents invoke as a `PreToolUse` hook to *observe*
  each command at the moment it is about to run, complementing the static config
  scanning of the AI Guard. Stage 1 is measurement-only (no blocking) and runs
  as a separate process over IPC, keeping the hook surface decoupled from the
  agent binary. Ships adapters and install/uninstall for **Claude Code, Codex,
  Cursor, and Antigravity** (#83, #85, #88, #89) — Antigravity installs through
  its native `agy plugin` bundle (#91). Architecture is documented in the README
  (#84).
- **Antigravity AI Guard support** (#86, #87). A static parser for Antigravity's
  global config plus a per-repo parser wired into `workspace_discovery`, with a
  new `antigravity_workspaces` policy field — so Antigravity is scored like the
  other built-in tools, per-repo included.
- **Rule-pack `scope = Project { path }` + per-repo discovery** (#92, 3b.7.2).
  Operator-defined rule packs can now target per-repo scopes and hook into the
  existing `workspace_discovery`, getting per-repo instances like the built-ins.
  Events carry a `rule_pack_id` (forward-compatible) and the agent keys parser
  state by `(tool, scope, pack_id)`.
- **Generic `AiTool::Other` for operator rule packs** (#95, 3b.7.5). In-house and
  third-party AI tools can be scored without a code change, via the `Other` tool
  variant plus a `tool_label` carried on the pack and emitted on events
  (UserGlobal scope).
- **Server-side signed rule-pack distribution** (#96, 3b.7.4). `sigil-server`
  serves a signed rule-pack-set bundle over `GET /v1/rule-packs`, versioned
  independently from policy; the agent fetches, verifies the signed envelope,
  and merges in three layers (defaults < policy < bundle). Operators push packs
  centrally instead of editing each host.
- **DSL Tier 2 — conditional rule blocks** (#101, 3b.7.1). A rule-pack rule may
  carry `when` gate conditions (`selector` + `matcher` + optional `negate`,
  ANDed) that must all hold for it to emit — giving operator packs compound
  detection the flat Tier-1 grammar could not express. Gated behind
  `pack_version: 2`; an empty `when` is byte-identical to prior behavior.

### Fixed

- **Antigravity approval key is `toolPermission`** (#90), corrected against
  on-hardware behavior so the static parser reads the right setting.
- **`AntigravityProjectParser` now reconciles on hot-reload** (#94, fixes #93) —
  a per-repo Antigravity parser added by a policy reload is assessed without
  waiting for the next file change.
- **`sigil doctor --state-db` override and optional sender mTLS** (#99, fixes
  #97/#98). `doctor` accepts a state-db path override, and the sender's mTLS
  client identity is now optional (the three cert paths may be omitted to run
  against a plain-HTTP dev server) — both surfaced by two-machine E2E testing.

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
