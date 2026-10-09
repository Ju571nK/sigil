# Sigil roadmap

The full phase-by-phase log. The [README](README.md#roadmap) carries a short
"what's shipped" summary; this file is the authoritative record, including the
merge SHA for each shipped phase.

## Status

- **0.1.x — alpha.** The event schema and CLI surface can break between minor
  releases until 0.2. `schema_version` in every event lets downstream
  consumers detect this.
- **Platforms.** macOS, Windows, and Linux at runtime. The Linux runtime
  landed as a minimal foundation (Phase 3a) and is exercised in CI; some
  refinements are marked `TODO(community)` in `platform/linux.rs` — see
  [CONTRIBUTING.md](CONTRIBUTING.md).
- **Schema.** Version `1`.

## Shipped

- **Phase 1 — shipped.** Filesystem watcher, JSONL sink, host metadata, state
  database, debounce / rate-limit, JSONL retention GC.
- **Phase 2 — shipped.** Split-process IPC via the durable spool, signed
  policy envelopes, a sender that ships JSONL over mTLS, an operator signing
  CLI, and an OSS reference server. Transport spec was locked on 2026-05-10.
- **Phase 3a — shipped.** Linux runtime (inotify watcher, `/etc/passwd` user
  enumeration, hardware fingerprint). Minimal foundation; refinements open
  for community contribution.
- **Phase 3b.1 — shipped.** AI Agent Risk Index foundation: scoring rubric
  for **Claude Code + Codex** hooks, permissions, sandbox boundaries, and
  MCP servers. Emits `ai_guard_risk_assessed` evidence variants alongside
  the underlying `file_change` events; `sigil show risk` operator CLI.
- **Phase 3b.3 — shipped 053bbe3.** Dynamic hook-script watch:
  external (non-convention-dir) hook scripts referenced by claude_code /
  codex / continue_dev configs are now read + scanned for destructive
  patterns (256 KB cap, binary detection, follow symlinks via dunce).
  Synthetic in-memory WatchTargets make fsnotify fire on script changes
  between policy reloads; reconcile_ext_scripts diffs the registry on
  reload. Wire-additive — no new AiGuardReason variants. Also closes a
  pre-existing gap where codex convention-dir scripts were never read.
- **Phase 3b.3.1 — shipped f5a80bd.** Recursive source/include hook script scan:
  walks `source X` / `. X` directives inside hook scripts (depth 5, file-count
  32, cycle-safe) so destructive patterns hidden in sourced helpers are caught.
  Adds `source_chain: Vec<PathBuf>` to `DestructiveInHookScript` events for
  forensic visibility into the source-follow path that led to each match.
- **Phase 3b.4 — shipped.** Server-side fleet aggregation on
  `sigil-server`: bearer-gated read API (9 endpoints — `/v1/healthz`,
  `/v1/meta`, `/v1/policy/meta`, `/v1/fleet/hosts` + detail, `/v1/fleet/risk`,
  `/v1/fleet/compliance`, `/v1/events` + lookup). In-memory per-host
  index rebuilt from JSONL on boot, updated inline on each `POST /v1/events`.
- **Phase 3b.5 — shipped d00b958.** `sigil doctor` gains an AI Guard
  diagnostic section showing active parsers, per-repo discoveries (3b.6.x),
  loaded rule packs (3b.7), ext-script watch (3b.3), latest risk per
  (tool, scope), and the effective rubric table. Operator can tune rubric
  weights via signed envelope (`rubric_overrides: HashMap<String, f32>`).
  Unknown keys warn + ignore. Bucket thresholds (1/4/7) and repeat
  surcharge (+25%) stay hardcoded. Wire-additive — no new variants.
- **Phase 3b.6 — shipped.** Application-form coverage: Claude Desktop
  (Anthropic.app) + Continue.dev (VSCode/JetBrains 확장) parsers.
  Reuses Phase 3b.1 rubric — MCP server entries, slashCommands /
  customCommands inline destructive patterns, external script
  references. Emits `ai_guard_risk_assessed` with new
  `scope.kind = "application"`.
- **Phase 3b.6.1 — shipped.** Continue.dev per-repo config auto-discovery.
  Operator lists workspace roots in the signed policy envelope
  (`continue_workspaces: [path, ...]`); agent walks each root 1-level
  deep, spawns a `ContinueDevProjectParser` for every direct subdir
  that contains `.continue/config.json`, and emits
  `ai_guard_risk_assessed` events with `scope = project{path: <repo>}`.
  Hot-reload via the existing signed policy reload path.
- **Phase 3b.6.2 — shipped.** Per-repo auto-discovery extended to
  Claude Code (`<repo>/.claude/settings*.json` + `.claude/hooks/`)
  and Codex (`<repo>/.codex/config.toml`). Same operator UX as
  3b.6.1 — `claude_code_workspaces: [path, ...]` and
  `codex_workspaces: [path, ...]` in the signed policy envelope.
  Discovery logic generalized into a shared
  `workspace_discovery::discover_per_repo` helper.
- **Phase 3b.7 — shipped.** Declarative rule pack architecture (MVP).
  New `rule_packs:` field in the signed policy envelope lets operators
  declare scan rules without recompiling sigil-agent. Tier 1 DSL: file
  path + JSON/TOML selector + matcher → `AiGuardReason` emit. OSS
  defaults shipped for **Gemini CLI** (`~/.gemini/settings.json`) and
  **Cursor** (`~/.cursor/mcp.json`) — replaces the originally-planned
  hardcoded Phase 3b.2.
- **Fleet size reporting + audit-chain verification.** `GET /v1/meta` reports
  `fleet.active_host_count` and `fleet.active_window_days` (top-level
  `active_window_days` in server config, default 7). The earlier license
  verification module and its `/v1/meta.license` block were removed; `license:`
  in server config is deprecated (its window value is still honored). Existing
  signed, hash-chained `license-audit.jsonl` chains are no longer appended to but
  remain verifiable: the record format is frozen, the head is still exposed at
  `/v1/meta.audit_head`, and `sigil-sign verify-audit` checks them.
- **Phase 3b.8 — shipped 3d8a227.** Hardcoded Gemini CLI + Cursor guard-surface
  parsers: per-repo scope, destructive scanning, full Gemini surface coverage.
  Retired the declarative default packs shipped in 3b.7; new shared `mcp_scan`
  helper lowercases URL schemes before comparison.
- **Phase 3c (slice 1) — shipped 30ac7d4.** Build self-verification: vendor-signed
  `BuildManifest` (`sigil-core::manifest`, ed25519 over RFC 8785 canonical bytes,
  compiled-in `SIGIL_BUILD_PUBKEYS` trust anchor), `sigil-sign manifest` signer, and
  `sigil doctor --verify-self` (hashes the running binary with blake3, checks it
  against the manifest). Mirrors the policy signing pattern; mechanism ships with the anchor
  empty until the build-signing key ceremony.

## Planned

- **Sigil Proxy — P0 research/contracts/fixtures in progress; production proxy not implemented.** Optional, independently deployed MCP observation/control service in this workspace, managed through sigil-server and the existing sigil-manager UI. See the [specification and implementation plan](docs/specs/sigil-proxy/README.md). Compatibility/contracts precede the observation MVP; enforcement and human approvals follow separate gates.

- **Phase 3c (remaining) — planned.** CI manifest generation + build-signing key
  ceremony (populate `SIGIL_BUILD_PUBKEYS`), bit-identical reproducibility audit;
  additional posture signals.
