# ANDEDA — Phase 1 Design Specification

**Status:** Brainstormed, awaiting user review before plan-writing.
**Date:** 2026-05-08
**Authors:** Brainstorming session (user + Claude + Codex consult)

---

## Naming

**ANDEDA** — pronounced *an-DEH-da*.

Official expansion (used in all external documentation, marketing, UI):

> **A**I-**N**ative **D**etection **E**ngine for **D**evice **A**ssurance

Internal lore (footnote only, not promoted): the name also evokes the Korean word *안된다*
("not allowed") and the Latin gerundive pattern (*agenda*, *addenda*, *corrigenda* —
"things to be done / added / corrected"; ANDEDA = "things to be watched"). One meaning
gets the marketing weight; the others are kept as a wink for those who notice.

---

## Architectural Assumption — "Ride-Along"

> ANDEDA assumes the host machine is already managed by:
>
> - **MDM** (Jamf, Intune, Kandji) — for daemon installation, configuration push, binary
>   updates, OS-level permission grants (TCC/FDA, ProgramData ACLs).
> - **EDR** (CrowdStrike, SentinelOne, Defender for Endpoint) — for process protection,
>   anti-tamper, kill prevention, file integrity for the agent's own binary.
> - **SIEM** (Splunk, Datadog, Elastic, Sentinel) — as the *only* downstream consumer of
>   ANDEDA events.
>
> ANDEDA does not attempt to replicate any of the above. It is a thin posture-management
> tenant inside this stack. Operators who do not have all three should deploy ANDEDA only
> in observability-trusted environments (e.g., dev sandboxes), not as a security control.

This single assumption justifies every "why we don't do X" decision below.

---

## Goals (Phase 1)

1. Detect installation or modification of unsanctioned LLM clients on managed endpoints
   (shadow AI).
2. Detect tampering or supply-chain modifications to MCP server configuration files
   (`~/.claude.json`, `claude_desktop_config.json`, `.cursor/`, etc.).
3. Emit posture events to the local filesystem in a stable, SIEM-ingestible format.
4. Run on macOS and Windows as a system daemon under the host's existing service manager.

## Operating Model

- The daemon runs as **`root`** on macOS (`LaunchDaemon`, not `LaunchAgent`) and as
  **`LocalSystem`** on Windows (`Windows Service`).
- It is **detection-only**. It emits events; it never blocks, kills, quarantines, or
  rolls back. Enforcement, if needed, comes from the EDR running alongside.
- It supports **all human users on a multi-user endpoint** by enumerating users at
  startup and applying user-scoped path templates (`~`, `$HOME`, `%USERPROFILE%`) per
  user (Section 1.5). Service accounts and admin-only profiles are excluded.
- Daemon-default file paths (Section 6.2) assume `root` / `LocalSystem` write
  permission. Operators are responsible for validating ACLs do not conflict.

## Non-Goals (Phase 1)

- DLP / network traffic inspection — Phase 2.
- Process tracking / agent action audit — Phase 3.
- Linux support — build-only in CI; runtime work begins Phase 2+.
- Tamper resistance, anti-kill, code-sign verification of self, log-chain HMAC, ACL
  enforcement — delegated to EDR (ride-along).
- File-content shipping or semantic config diff. Events carry hashes only.
- Bundled auto-updater, self-watchdog, or phone-home telemetry.
- Web UI, dashboard, Prometheus `/metrics`, OpenTelemetry export. SIEM does
  visualization.
- Cross-platform unified packaging — packaging is a separate workstream that consumes
  Phase 1 binaries.

---

## 1. System Architecture

### 1.1 Crate layout (Cargo workspace)

```
anti_i/                                  # repo root
├── Cargo.toml                           # [workspace] members
├── crates/
│   ├── andeda-core/                     # pure library, OS/tokio-independent
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs                   # pub re-exports
│   │       ├── event.rs                 # Event, Severity, SourceKind, Subject,
│   │       │                            # Evidence, FileChangeKind, EvidenceQuality
│   │       ├── policy.rs                # Policy, WatchTarget, Tier, parse, merge,
│   │       │                            # path expansion, glob compilation
│   │       ├── hashing.rs               # streaming blake3 over a Read
│   │       ├── debounce.rs              # per-path Debouncer with kind-specific windows
│   │       ├── state.rs                 # HashCache backed by SQLite (rusqlite)
│   │       ├── stats.rs                 # atomic counters + p50/p99 histograms
│   │       └── sink/
│   │           ├── mod.rs               # EventSink trait
│   │           └── jsonl.rs             # rotating JSONL writer
│   └── andeda-agent/                    # binary: tokio runtime + system integration
│       ├── Cargo.toml
│       └── src/
│           ├── main.rs                  # tokio runtime, clap CLI, signal handling
│           ├── runtime.rs               # task spawning + channel wiring + supervisor
│           ├── watcher.rs               # notify → tokio mpsc adapter
│           ├── doctor.rs                # `andeda doctor` subcommand
│           ├── show.rs                  # `andeda show ...` subcommands
│           ├── control.rs               # UDS / Named Pipe control IPC
│           └── platform/
│               ├── mod.rs
│               ├── macos.rs             # FDA self-check, machine_id resolution
│               └── windows.rs           # AppData expansion, MachineGuid
├── config/
│   └── policy.example.yaml
└── docs/
    └── superpowers/
        ├── specs/
        └── plans/
```

**Boundary rule:** `andeda-core` MUST NOT depend on `notify`, `tokio`, or any OS-specific
crate. Every test in `andeda-core` runs in milliseconds without touching the filesystem
or spawning threads (except where `tempfile::TempDir` is used inside an integration-style
unit test, e.g., for `JsonlSink` and `HashCache`).

### 1.2 Pipeline (single tokio runtime)

```
notify backend (OS thread)
    │  raw fs events
    ▼
[watcher task, per watch root]    ← matches WatchTarget by path; drops non-matches
    │  FsEventRaw    bounded mpsc capacity 1024
    ▼
[normalizer task]                 ← canonicalize path (dunce), assign target_id,
    │                               tag tier, glob-filter under recursive roots,
    │                               rename pairing (Section 3.4), per-target token-
    │                               bucket rate-limit (Section 1.8)
    │  NormalizedEvent  bounded mpsc capacity 512
    ▼
[debouncer task]                  ← per-path, kind-specific window (Section 3.4);
    │                               critical tier window forced to 0 ms;
    │                               held events flushed when window expires
    │  DebouncedEvent  bounded mpsc capacity 512
    ▼
[hasher pool]                     ← tokio::task::spawn_blocking workers
    │                               (configurable, default 4); skip files > 10 MB
    │                               (emit Incomplete)
    │  Event (with hashes)  bounded mpsc capacity 512
    ▼
[state store task]                ← reads/writes HashCache (SQLite); fills
    │                               before_hash; for critical tier, schedules
    │                               100 ms recheck;
    │                               commit ordering: JSONL line first, DB next
    │  Event (canonical)   bounded mpsc capacity 256
    ▼
[sink task — JsonlSink]           ← serialize, write line, flush; periodic fsync;
                                    lazy rotation check on every write (date or
                                    100 MB threshold)
```

Channels are **bounded mpsc**. Overflow behavior: senders **block** (backpressure).
No events are dropped at the channel boundary. To surface backpressure
visibly: every 10 s, a `ChannelStall` event reports any per-channel cumulative
sender-block time that exceeded 5 s within the window. Operators reading the
SIEM see this as "the daemon is keeping up but the pipeline is under pressure",
not as silent loss.

The hasher pool uses `tokio::task::spawn_blocking` (or a dedicated `rayon` pool — final
choice deferred to the implementing engineer per benchmark; either is acceptable). **The
core tokio runtime threads must never run blocking IO** (file open, hash compute).

### 1.3 Process supervision

- All long-lived tasks spawn from a root supervisor that retains every `JoinHandle`.
- A task panic propagates to the supervisor, which:
  1. Captures panic payload.
  2. Signals shutdown to siblings.
  3. Enqueues a final `AgentDying` event into the sink.
  4. Waits for sink drain + fsync (bounded by 5 s timeout).
  5. Calls `std::process::exit(101)`.
- The host service manager (launchd / Windows Service) restarts the process. ANDEDA does
  not implement its own watchdog (ride-along).
- `[profile.release] panic = "unwind"` so the supervisor can catch panics. Do NOT use
  `panic = "abort"`.

### 1.4 Hash baseline persistence and commit ordering

Hashes are stored in a SQLite database (`state.db`) at the platform-defined path.
SQLite is opened with:

- `PRAGMA journal_mode = WAL` — concurrent readers do not block the single writer.
- `PRAGMA synchronous = NORMAL` — durable enough for our model (we accept ≤ 1 s of
  cache loss on hard crash, same as the JSONL fsync window).
- `PRAGMA temp_store = MEMORY`, `PRAGMA mmap_size = 0` (predictable resident-set).

On daemon start:

1. Open `state.db` (create on first run).
2. **Tiered warmup**:
   - `tier: critical` targets — synchronous walk + hash on startup. Blocks `Heartbeat`
     emission until complete. Bounded by typical small-file count expected for the
     critical tier (config files, not application bundles).
   - `tier: standard` targets — lazy. The first event for an unseen path computes its
     hash on-demand and stores baseline.
3. After warmup, every change event reads the prior hash from `state.db`, fills
   `before_hash`, computes new hash, fills `after_hash`, then proceeds in the order
   below.

#### Commit order — Event-first

Per change, the sink writes the JSONL line **before** the state.db update commits:

```
1. Compute new hash.
2. Write Event line to JSONL (already buffered; flushed inside the same task tick).
3. Commit new hash to state.db.
```

If the host crashes between steps 2 and 3, the next start re-observes the file with
its current hash. The previous baseline (the one that was about to be replaced) is
re-used as `before_hash`, and `after_hash` will equal the current hash. If those are
the same as a previously emitted event, **the same logical change appears twice in
JSONL** — but with a different `event_id` (UUIDv7).

SIEM rules MUST therefore dedup on the tuple `(host_id, target_id, after_hash,
floor(ts to 1 minute))`, not on `event_id`. A recommended template is included in
Section 4.7.

The reverse order ("DB first, then JSONL") is **explicitly rejected**: a crash between
DB commit and JSONL write would silently drop the security signal. We prefer "loud
duplicate" over "silent loss".

#### File size cap

Files larger than **10 MB** are not hashed. The Event is still emitted with
`evidence_quality: incomplete`, `before_hash`/`after_hash` `None`, and `size_after`
populated. Rationale: Phase 1 watch targets are config files (KB scale); a 10+ MB
file appearing under a watch path is itself anomalous (e.g., binary disguised as
config) and worth surfacing without the IO cost of hashing it.

### 1.5 Multi-user enumeration and per-user path expansion

The daemon runs as `root` / `LocalSystem`, but most watch paths are user-scoped
(`~/.claude.json`, `%APPDATA%\Cursor\...`). Path expansion is therefore per-user.

#### Enumeration

- **macOS**: read `/Users/*` directories. Skip entries whose name starts with `_`
  (system service accounts), the `Shared` entry, the `Guest` account when no shell,
  and any directory whose `mode & 0o001 == 0` and whose owner UID < 500. Cross-check
  against `dscl . -list /Users` to filter purely-virtual accounts.
- **Windows**: enumerate `C:\Users\*` directories. Skip `Default`, `Default User`,
  `Public`, `All Users`. Cross-check against `NetUserEnum` to filter
  service/system-only profiles.

The result is `Vec<UserContext { uid_or_sid, home: PathBuf, name: String }>`. This
runs once at startup and once on SIGHUP. New users that log in mid-flight are picked
up only at next reload (SIGHUP from MDM script after user provisioning is the
recommended flow).

#### Per-user path templating

A `WatchTarget` whose `paths` contain `~`, `$HOME`, or `%USERPROFILE%` is
**multiplied** across the enumerated users at policy load time:

```yaml
- id: claude-desktop-config-macos
  paths: ["~/Library/Application Support/Claude/claude_desktop_config.json"]
```

Becomes, on a machine with users `alice` and `bob`:

- effective path 1: `/Users/alice/Library/Application Support/Claude/claude_desktop_config.json`
- effective path 2: `/Users/bob/Library/Application Support/Claude/claude_desktop_config.json`

Both are watched independently. Events carry `target_id` (same for both) and
`subject.path` (the resolved per-user path). SIEM rules can group by `target_id`
or filter by user via path prefix.

#### Per-user TCC / FDA on macOS

Full Disk Access is granted **per agent process**, not per target user. A daemon
running as `root` with FDA can read all users' `~/Library/Application Support/`
without per-user grants. If FDA is missing, every per-user expansion of a target
that requires it emits its own `PermissionMissing` event. A single MDM
Configuration Profile pushing `com.apple.TCC.configuration-profile-policy` to grant
`SystemPolicyAllFiles` to the ANDEDA bundle id resolves all of them at once.

### 1.6 macOS and Windows traps (handled in `andeda-agent::platform`)

**macOS:**
- FSEvents coalesces events. Per-path debounce windows (Section 3.4) absorb this.
- Some paths under `~/Library/Application Support/` require Full Disk Access (TCC).
  On daemon start, `platform::macos::check_fda()` runs a probe **against a known,
  always-present, FDA-protected system path**: `/Library/Application
  Support/com.apple.TCC/TCC.db`. The probe is a `metadata()` call (does not read
  contents). The error is then mapped explicitly by errno:
  - `EACCES` or `EPERM` → FDA is **not** granted.
  - `ENOENT` → unexpected (file is part of macOS); log a `tracing::warn!` and
    treat as "FDA status unknown, assume granted" to avoid false negatives.
  - Success → FDA is granted.
  This avoids the ambiguity of probing a target file that may not exist (where
  `ENOENT` would otherwise be confused with `EACCES`). If `EACCES`/`EPERM` is
  returned, emit `PermissionMissing` once per *affected target* (not once
  globally), then continue with reduced coverage. **Do not refuse to start.**
  Re-probe runs on every SIGHUP (policy reload); if FDA was granted in the
  interim, the missing-permission flag is cleared. We do **not** emit a
  follow-up "now granted" event — the operator sees absence of the warning on
  the next heartbeat (whose `events_by_kind` no longer contains
  `permission_missing`).
- `host_id` source: `IOPlatformUUID` via `IOKit` (or `system_profiler` shell-out as fallback).

**Windows:**
- `ReadDirectoryChangesW` has buffer-overflow risk under heavy churn; we configure
  `notify` with a 64 KB buffer (default 8 KB). Under sustained churn beyond what 64 KB
  absorbs, `notify` returns a backend-overflow signal — we emit `WatcherDegraded
  { from: "read_directory_changes_w", to: "polling", reason: "buffer overflow" }`
  and switch the affected watch root to `PollWatcher`. Polling has higher latency
  (~5 s default poll interval) and may miss transient changes between polls; this
  is documented as the operating expectation when degraded.
- Do **not** follow junctions, symlinks, or reparse points. `notify` config:
  `with_follow_symlinks(false)`. Path canonicalization uses `dunce::canonicalize`.
  The recursive directory walker (when `recursive: true`) honors the same rule.
- `%APPDATA%` (roaming) and `%LOCALAPPDATA%` differ; default targets use whichever is
  correct per known LLM client. WOW64 path redirection: targets that need `Program Files`
  use `%PROGRAMFILES%`; ANDEDA itself runs as 64-bit so WOW64 redirection does not apply
  to it.
- `host_id` source: `MachineGuid` from `HKLM\SOFTWARE\Microsoft\Cryptography`.

### 1.7 Heartbeat (visibility signal — NOT self-defense)

- Emitted every 60 s as `Evidence::Heartbeat`.
- Marked **explicitly in spec** as a *visibility signal*, not a defense mechanism.
  An attacker who disables the daemon also disables heartbeats; the SIEM rule
  "alert if no heartbeat in 90 s" gives the security team *the signal that something
  is wrong*, but the daemon does not attempt to prevent its own takedown.
- Final heartbeat emitted on graceful shutdown with `is_final: true`.

### 1.8 Per-target rate limiting (DoS containment)

A malicious or pathological process can flood a watch path with thousands of file
events per second (e.g., a script that creates and deletes a config file in a tight
loop). Without protection this saturates the hasher pool, fills mpsc buffers,
overruns notify's OS-level queue, and risks SQLite bloat.

ANDEDA applies a **per-target token bucket** in the normalizer task:

- Bucket size: 200 tokens. Refill rate: 100 tokens/sec.
- Each event consumes 1 token. When the bucket is empty, the event is **dropped
  (consciously, not silently)** for that target.
- A counter accumulates the dropped count per target.
- Every 10 s, if any drops occurred for a given target, a `RateLimitExceeded` event
  is emitted summarizing `target_id`, `count_dropped_in_window`, and the path
  prefix common to the dropped events. After emission the counter resets.
- The bucket also resets to full on policy reload (SIGHUP).
- Token-bucket parameters are **not** user-configurable in Phase 1. They live in
  `andeda-core::ratelimit::DEFAULT_BUCKET`. If real-world tuning is needed, expose
  a YAML field in Phase 1.5.

Why drop instead of block: if a single noisy target blocks the normalizer task
indefinitely, **other** targets stop being observed. Conscious drop preserves
observability of the rest of the watchlist while the offending target is loud.
The drop is surfaced as a security-relevant event so SIEM operators see "this
host's `~/.cursor/` was hit by 12,000 events in 10 s" and can investigate.

---

## 2. Policy & Configuration

### 2.1 Two-layer model

```
EFFECTIVE POLICY  =  BUILT-IN DEFAULTS  ⊕  USER OVERRIDE
                     (bundled in binary  (optional file at
                      via include_str!)   /etc/andeda/policy.yaml or
                                          %ProgramData%\Andeda\policy.yaml)
```

- Defaults compiled into the binary as YAML text using `include_str!()`. Parsed once at
  startup.
- The override file is optional; absence is fine.
- The merged result is held as `Arc<Policy>` for the lifetime of the daemon.
- Reload trigger: SIGHUP (Unix) or Windows Service custom control code 128. Reload
  re-parses both layers and atomically swaps the `Arc`. A failed reload (parse error,
  duplicate id) keeps the previous policy active and emits a `tracing::error!` to the
  diagnostic log; no event is emitted (this is operator-facing, not security-facing).

### 2.2 `WatchTarget` schema (YAML version 1)

```yaml
version: 1
host_id_strategy: machine_id     # machine_id | hostname | uuid | static:"<value>"

targets:
  - id: claude-desktop-config-macos
    description: Claude Desktop config and MCP server definitions
    tier: critical               # critical | standard
    platform: macos              # macos | windows | any
    paths:
      - "~/Library/Application Support/Claude/claude_desktop_config.json"
      - "~/.claude.json"
    recursive: false
    follow_symlinks: false
```

- `id` is the primary key. Duplicate ids across the merged policy is a startup error.
- `tier` has exactly two values: `critical` and `standard`. More tiers are YAGNI for
  Phase 1.
- Each entry in `paths` may be either a **file path** (with optional glob) or a
  **directory path**. If the resolved entry is a directory, behavior depends on
  `recursive`: `false` watches only direct file changes within that directory (the
  directory's children, one level deep); `true` watches the entire subtree.
- `recursive: true` uses `notify`'s **native recursive watch** mode
  (`RecursiveMode::Recursive`). On macOS this maps to FSEvents (recursive by
  design). On Windows it maps to `ReadDirectoryChangesW` with `bWatchSubtree =
  TRUE`. We do **not** walk the subtree at startup to attach per-subdirectory
  watches — the OS APIs already cover the subtree. Glob filtering against the
  `paths` patterns happens **on each event after delivery** (in the normalizer
  task); events whose absolute path does not match any active glob are dropped
  silently.
- Symlinks, junctions, and reparse points encountered inside a recursive watch
  are not followed. `notify` config: `with_follow_symlinks(false)`. The flag
  `follow_symlinks` in YAML is reserved at `false` in Phase 1 — set it explicitly
  for documentation; setting it to `true` is a startup error.
- Path tokens supported: `~`, `$HOME`, `$VAR`, `%VAR%`, `%USERPROFILE%`. The
  `%VAR%` form supports parenthesized variable names too (e.g.,
  `%ProgramFiles(x86)%`, which exists on 64-bit Windows for 32-bit applications
  installed under `Program Files (x86)`). Variables are matched non-greedily —
  expansion of `%PROGRAMFILES%\foo` and `%ProgramFiles(x86)%\foo` are
  unambiguous because the parens are part of the token. Implementation lives in
  `andeda-core::policy::expand` using `std::env` directly for system variables,
  plus the multi-user enumeration in Section 1.5 for user variables. `~` and
  `%USERPROFILE%` are user-scoped — they expand once per enumerated user,
  producing one effective path per user.
- Glob syntax: `*`, `?`, `[abc]` only, via `globset`. `**` is **explicitly unsupported**
  in Phase 1; directory recursion is expressed via `recursive: true`.
- **No exclude/negated patterns** in Phase 1. The policy is include-only. Adding a
  noisy directory and trying to subtract it is an anti-pattern; instead, scope `paths`
  precisely. Negated patterns are a Phase 1.5 candidate.
- `platform` filtering happens at policy load: targets whose platform does not match
  the current OS are silently dropped. This allows shipping a single YAML across both
  OSes. **However**, a target with `platform: any` whose path contains an OS-specific
  variable (`%APPDATA%` on macOS, `$HOME/Library/...` on Windows) and resolves to an
  empty/unresolvable path emits a `tracing::warn!` to the diag log at startup and is
  excluded from the active watchlist for that OS. This catches policy authors using
  `any` accidentally on a path that only makes sense on one OS.

### 2.3 Override merge semantics

```yaml
version: 1

overrides:
  - id: shadow-ai-binaries-macos
    disabled: true
  - id: claude-desktop-config-macos
    tier: standard

targets:
  - id: internal-mcp-policy
    description: Corporate MCP allowlist file
    tier: critical
    platform: any
    paths: ["~/.config/our-corp/mcp-allowlist.json"]
```

Algorithm (deterministic, in order):

1. Load defaults → list of `WatchTarget`.
2. Apply each `overrides[]` entry: locate target by id, set `disabled` and/or modify
   `tier`. Override referencing an unknown id → error (fail-fast).
3. Append each `targets[]` entry. id collision with any existing (default or
   previously-appended) id → error.
4. Filter out targets where `disabled == true`.
5. Filter out targets where `platform` does not match current OS.
6. Result: `Arc<Policy>` with the surviving targets.

### 2.4 Configuration Non-Goals (Phase 1)

- Policy file signing or sealing — EDR ACL enforcement is the trust boundary.
- Partial reload semantics — reload is all-or-nothing.
- Conditional expressions in YAML (e.g., `if user.role == "dev"`) — flat list only.
- Drop-in directory of policy fragments — Phase 1.5.
- HTTPS-fetched remote policy — Phase 2+.

---

## 3. Event Schema and Output Format

### 3.1 Generalized `Event` (Phase 1, designed for Phase 2/3 extension)

```rust
// andeda-core/src/event.rs (sketch — final field order is normative for serialization)

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Event {
    pub schema_version: u32,             // = 1 in Phase 1
    pub event_id: Uuid,                  // UUIDv7
    pub ts: OffsetDateTime,              // RFC3339, UTC, millisecond precision
    pub host_id: String,
    pub agent_version: &'static str,     // env!("CARGO_PKG_VERSION")
    pub severity: Severity,              // Info | Warn (Phase 1: no Critical/Error)
    pub source: SourceKind,              // FileSystem | Agent (Phase 1)
    pub subject: Subject,                // technical identifier of the observed thing
    pub evidence: Evidence,              // the observation itself (variant)
    pub target_id: Option<String>,       // matched WatchTarget.id, when applicable
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SourceKind {
    FileSystem,
    Agent,
    // Network,    // Phase 2
    // Process,    // Phase 3
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Subject {
    Path { value: PathBuf },
    #[serde(rename = "self")]
    Self_,
    // Endpoint { host: String, port: u16 },   // Phase 2
    // Process { pid: u32, exe: PathBuf },     // Phase 3
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Evidence {
    FileChange {
        change_kind: FileChangeKind,
        before_hash: Option<String>,     // hex blake3, None when no baseline yet
                                         // or file > 10 MB
        after_hash: Option<String>,      // None when Removed or file > 10 MB
        recheck_hash: Option<String>,    // critical tier only: re-hash after 100 ms
        rename_from: Option<PathBuf>,    // present iff change_kind = Renamed; the
                                         // pre-rename path. subject.path holds the
                                         // post-rename (destination) path.
        size_after: Option<u64>,
        evidence_quality: EvidenceQuality,
    },
    Heartbeat {
        uptime_s: u64,
        is_final: bool,
        channel_stall_events_total: u64,    // count of ChannelStall emitted since start
        events_emitted_total: u64,
        events_by_kind: BTreeMap<String, u64>,
        hash_p50_ms: u32,
        hash_p99_ms: u32,
        watcher_backend: String,
        state_db_size_bytes: u64,
        last_log_rotation_ts: Option<OffsetDateTime>,
    },
    PermissionMissing {
        resource: String,                // e.g., "FullDiskAccess"
        platform_hint: String,           // human-readable remedy
    },
    ChannelStall {
        channel: String,                       // e.g., "norm_to_hasher"
        blocked_seconds_in_window: f32,        // cumulative sender-block time, last 10 s
        block_events_in_window: u64,           // number of distinct block episodes
        first_block_ts: OffsetDateTime,
    },
    WatcherDegraded {
        from: String,                    // e.g., "fsevents"
        to: String,                      // e.g., "polling"
        reason: String,
    },
    AgentDying {
        reason: AgentDyingReason,        // Panic | UnrecoverableSinkError | Signal
        detail: String,
        task: Option<String>,
    },
    RateLimitExceeded {
        target_id: String,               // the watch target whose rate exceeded the bucket
        count_dropped_in_window: u64,    // events consciously dropped in the last 10 s
        common_path_prefix: PathBuf,     // longest shared prefix of dropped events
    },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
pub enum FileChangeKind { Created, Modified, Removed, Renamed }

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceQuality {
    Definitive,    // single event, clean debounce window
    BestEffort,    // multiple events coalesced inside the debounce window
    Delayed,       // event spent > 1 s in any queue before reaching the sink
    Incomplete,    // observation could not be fully captured (e.g., file removed before hash)
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
pub enum Severity { Info, Warn }
```

#### Severity assignment

| Evidence variant     | Severity |
|----------------------|----------|
| `FileChange`         | `Warn`   |
| `Heartbeat`          | `Info`   |
| `PermissionMissing`  | `Warn`   |
| `ChannelStall`       | `Warn`   |
| `WatcherDegraded`    | `Warn`   |
| `AgentDying`         | `Warn`   |
| `RateLimitExceeded`  | `Warn`   |

Phase 1 emits no `Info` events other than `Heartbeat`. Severity classification is
deliberately coarse — SIEM rules do the per-customer fine-tuning.

### 3.2 Limitations of metadata-only evidence (TOCTOU)

Phase 1 events carry path + hashes. They do **not** carry file contents. The
fundamental limitation here is the classic **Time-of-Check-to-Time-of-Use
(TOCTOU) race**: the file-system change reaches us via `notify`, but the malicious
bytes that triggered it may already be gone by the time the hasher pool opens the
file.

- `before_hash` may itself be the hash of a malicious prior write. The pair tells
  "the file changed and here is how the bytes differ", not "this is the canonical
  baseline".
- An attacker who rapidly overwrites a file with a malicious payload and then reverts
  before the hash is computed produces a `FileChange` event with both hashes equal to
  pre/post legitimate state. Detection coverage is partial.
- Mitigation for `tier: critical`: skip debounce (window 0 ms), emit immediately, and
  re-hash 100 ms later. Both hashes ride along in `recheck_hash`. If they differ,
  forensic analyst sees a transient state existed.
- The TOCTOU race is fundamentally **unsolvable at the file-system-watcher layer
  alone**. The complete remedies require:
  - **Phase 2** (network proxy on outbound LLM API traffic) — catches the *intent*
    of the attacker even when the on-disk artifact is reverted, because the
    malicious payload was already transmitted to the LLM provider.
  - **Phase 3** (per-process action audit via EndpointSecurity on macOS, ETW on
    Windows) — observes the open/write/read syscalls on the path, independent of
    file-system-event delivery timing.
- Phase 1 explicitly accepts the TOCTOU limitation. The security team must factor
  this into their threat-model coverage and not treat ANDEDA-Phase-1 as a complete
  detection of supply-chain compromise on its own. This is restated in the
  recommended SIEM-rule preamble (Section 4.7).

### 3.3 JSONL output format

One JSON object per line, terminated by `\n`. No pretty-printing. UTF-8.

Example output (one line per record; wrapped for readability only):

```jsonl
{"schema_version":1,"event_id":"01910f5a-1234-7890-abcd-ef0123456789","ts":"2026-05-08T14:23:45.123Z","host_id":"5A7C3E91-...","agent_version":"0.1.0","severity":"warn","source":{"kind":"file_system"},"subject":{"kind":"path","value":"/Users/alice/.claude.json"},"evidence":{"kind":"file_change","change_kind":"modified","before_hash":"a1b2c3...","after_hash":"d4e5f6...","recheck_hash":"d4e5f6...","rename_from":null,"size_after":1843,"evidence_quality":"definitive"},"target_id":"claude-desktop-config-macos"}
```

Implementation:
- `serde_json::to_writer(&mut buf, &event)` then `buf.write_all(b"\n")`.
- Field order is the struct definition order. Field order is part of the contract.
- **`#[serde(flatten)]` is forbidden anywhere in the event tree.** A flattened struct
  cannot guarantee field ordering or schema-version migration cleanliness. Event
  composition uses explicit nested structs only.
- **Path serialization is platform-native.** `PathBuf` serializes as a string with the
  separator the host uses (`/` on macOS, `\` on Windows). SIEM rules that need to
  match cross-platform should normalize on the SIEM side. Rationale: an operator
  reading the JSONL on a Windows machine should see Windows-style paths that match
  what their other tools (Event Viewer, Sysinternals) display.
- BufWriter wraps the file with an 8 KB buffer.

#### `schema_version` bump policy

- `schema_version` is a `u32`, currently `1`.
- It bumps when **any** of: a field is removed, a field is renamed, a field's
  semantics change, an enum variant is renamed, a `tag` discriminator value changes,
  field ordering changes.
- **Adding** a new optional field, or adding a new enum variant, does **NOT** bump
  the version. Consumers must tolerate unknown fields/variants (forward compatibility).
- Snapshot tests in `andeda-core` (Section 5.5) lock the on-the-wire shape. A change
  to any snapshot is a deliberate signal that a version bump may be needed; PR
  reviewers must check.

### 3.4 Per-path debounce policy

Per-path queue, `kind`-specific window:

| `FileChangeKind` | Window     | Rationale                                          |
|------------------|------------|----------------------------------------------------|
| `Removed`        | 0 ms       | Final state; no further coalescing benefit         |
| `Created`        | 50 ms      | Atomic-create patterns (write-then-rename)         |
| `Modified`       | 100 ms     | Editors often emit 2–5 events per save             |
| `Renamed`        | 50 ms      | Pair with corresponding move target                |

For `tier: critical`, all windows are forced to 0 ms regardless of kind, and a
recheck-hash is scheduled at +100 ms. The recheck behavior per `FileChangeKind`:

- `Created`, `Modified`, `Renamed` — re-read file at +100 ms; if hash differs from
  `after_hash`, populate `recheck_hash`. If unchanged, `recheck_hash == after_hash`.
- `Removed` — schedule a +100 ms existence probe. If the path now exists,
  `recheck_hash` holds the new file's hash (transient delete + recreate detected),
  the original `Removed` event is still emitted, **plus** a separate `Created` event
  for the recreate. Both are linked in SIEM by `(host_id, target_id, ts)`.

#### Renamed pairing

`notify` typically reports a rename as a pair: a `From` event followed by a `To`
event (often within the same poll cycle, sometimes split). The normalizer task
holds the `From` half in a small per-watcher map for up to **200 ms**:

- If the matching `To` arrives within 200 ms and lands on a path that matches the
  same target, emit a single `FileChange { change_kind: Renamed, rename_from: Some(from), subject.path: to, ... }`.
- If the matching `To` arrives but lands **outside** the watchlist (the file moved
  away from a watched location), emit `FileChange { change_kind: Removed, rename_from: Some(from), subject.path: from, ... }`.
- If 200 ms elapses with no match, emit `FileChange { change_kind: Removed, subject.path: from, ... }`.
- A `To`-only event arriving with no matching `From` (the file moved **into** the
  watchlist from outside) is treated as `change_kind: Created`. The `rename_from`
  field is `None` because we have no prior path knowledge.

`evidence_quality` field reflects the result:
- `Definitive` — single event, clean window.
- `BestEffort` — multiple events coalesced inside the window.
- `Delayed` — event spent > 1 s in any queue before reaching the sink.
- `Incomplete` — observation could not be fully captured (e.g., file removed
  before hash computed); `after_hash` will be `None`.

### 3.5 File rotation

```
/var/log/andeda/events-2026-05-08.jsonl              # current writer
/var/log/andeda/events-2026-05-08-001.jsonl          # rotated at 100 MB
/var/log/andeda/events-2026-05-08-002.jsonl
/var/log/andeda/events-2026-05-07.jsonl              # yesterday
```

Triggers (evaluated **lazily on every write attempt**, not by a wall-clock timer):

1. **UTC date has rolled over** since the current file was opened → fsync + close
   current, open new dated file. Lazy evaluation handles laptop sleep correctly: a
   machine that sleeps through midnight rotates on the first event after wake-up,
   regardless of how many days of sleep elapsed.
2. **Current file size ≥ 100 MB** → fsync + close, open same-date sequence file.
3. **Graceful shutdown** → fsync + close, no rename.

Why lazy: a wall-clock timer firing at UTC midnight is missed entirely if the
host is asleep at that moment. The lazy approach has zero idle cost and is robust
against sleep, hibernation, clock changes, and CPU starvation.

Durability:
- Per-event `flush()` (memory → OS page cache).
- Background fsync every 1 s (OS page cache → disk).
- Immediate fsync on rotation and shutdown.
- Acceptable loss window on hard crash: ≤ 1 s of events. Per-event `fsync` is
  rejected — SSD wear and throughput are unacceptable.

### 3.6 Filesystem permissions

ANDEDA creates its directories at `0750` if missing. If they exist, ANDEDA does
**not** modify their mode (MDM-set ACLs are respected). Recommended permissions
for MDM to enforce on **every** ANDEDA-owned path — not just events. The
state-database and policy file are part of the trust boundary: a non-privileged
write to `state.db` could let an attacker rewrite baseline hashes so a subsequent
malicious config edit produces matching `before_hash`/`after_hash` and blends in
as a benign change.

| Path | macOS (recommended) | Windows (recommended) |
|------|---------------------|------------------------|
| Binary (`andeda`) | `root:wheel 0755` | SYSTEM + Administrators (RX) |
| Policy file (`policy.yaml`) | `root:wheel 0640` | SYSTEM + Administrators (RW); other users (R only) |
| State directory (`state.db`) | `root:wheel 0700` (file `0600`) | SYSTEM only (RW); no Administrators read |
| Event directory | `root:wheel 0750` (files `0640`) | SYSTEM + Administrators (RW) |
| Diag log (if enabled) | `root:wheel 0640` | SYSTEM + Administrators (RW) |
| Control IPC | `root:wheel 0600` (UDS) | Administrators + SYSTEM ACL on pipe |

**`state.db` is intentionally tighter than the event log**: even other Administrator-
group accounts should not read or write it, because the trust boundary for the
posture-management service is `LocalSystem` / `root` only. The event log is set to
allow read by trusted Administrator-group members so SIEM-forwarder service
accounts can ingest it without elevation.

ANDEDA does **not** enforce these ACLs itself (ride-along). The expected control is
an MDM-pushed `chmod`/`chown` script (macOS) or `icacls`/Group Policy (Windows). The
`andeda doctor` subcommand surfaces a `[WARN]` line if it detects mode drift on
any of the paths above; this is a posture signal, not enforcement.

### 3.8 SIEM forwarder integration

ANDEDA's JSONL output directory is intentionally compatible with file-based SIEM
forwarders. Reference snippets (full versions in `docs/runbook/siem-rules.md`):

**Splunk Universal Forwarder (`inputs.conf`):**
```
[monitor:///var/log/andeda/events-*.jsonl]
sourcetype = andeda:event:json
disabled   = false
```

**Datadog Agent (`conf.d/andeda.d/conf.yaml`):**
```yaml
logs:
  - type: file
    path: /var/log/andeda/events-*.jsonl
    service: andeda
    source: andeda
```

The wildcard `events-*.jsonl` covers both the active file and rotated sequence
files. Forwarders following filesystem rotation (i.e., the `*.jsonl` pattern, not a
single fixed name) ingest rotated files automatically. Forwarders configured to
follow only a fixed path will miss events after the first rotation.

**Latency expectation**: ANDEDA flushes per event (memory) and fsyncs every 1 s
(disk). The SIEM forwarder's tail-poll interval typically dominates end-to-end
latency (Splunk UF default ~250 ms; Datadog Agent ~1 s). End-to-end p99 to SIEM
indexer is normally 5–15 s; this is well within standard "near-real-time" SLAs.
Sub-second alerting is not a Phase 1 design point.

### 3.9 Output Non-Goals (Phase 1)

- gzip compression of rotated files — Phase 1.5.
- Batched event transmission — Phase 1.5.
- At-rest payload encryption — disk encryption / EDR is the trust boundary.
- Direct push to SIEM (HTTPS / syslog / OTLP) — Phase 2 product decision.
- Auto-GC of old `.jsonl` files — `logrotate` or the SIEM forwarder owns this.

---

## 4. Error Handling and Observability

### 4.1 Two channels — never mixed

| Channel    | Audience      | Format        | Path                                   |
|------------|---------------|---------------|----------------------------------------|
| Events     | SIEM (security) | JSONL       | `/var/log/andeda/events-*.jsonl`       |
| Diag log   | Operator (debug) | text via `tracing` | stderr; optionally `/var/log/andeda/diag.log` |

Operator information (notify backend chosen, policy reload notice, internal warnings,
panic backtrace) goes only to the diag channel. Security-relevant signals go only to
the events channel. The two are wired through entirely separate code paths.

`tracing` + `tracing-subscriber` for diag. Level via `ANDEDA_LOG` env var
(`tracing_subscriber::EnvFilter`); default `info`.

### 4.2 Error categories and behavior

| Category | Examples | Behavior | Event |
|----------|----------|----------|-------|
| Config error (startup) | malformed YAML, duplicate id, unknown platform | stderr error, exit 2 | none (sink not yet open) |
| Permission denied (runtime) | macOS TCC FDA, EACCES on path | exclude affected target, continue | `PermissionMissing` (once per target) |
| Watcher backend degraded | FSEvents init fail → PollWatcher fallback | switch automatically | `WatcherDegraded` (once) |
| Hash compute error | file removed between event and hash | emit with `after_hash: None` | `FileChange` `evidence_quality: incomplete` |
| Sink write error | disk full, EIO | exponential backoff retry 3× (100 ms, 500 ms, 2 s); persistent failure → panic | success on retry / `AgentDying` if exhausted |
| Channel overflow | bounded mpsc full | sender blocks (backpressure); no events lost; cumulative block ≥ 5 s in 10 s window triggers reporting | `ChannelStall` (10 s aggregation) |
| Task panic | code bug | supervisor catches via `JoinHandle`, emits `AgentDying`, fsync, exit 101 | `AgentDying` |
| SIGTERM / Ctrl-C | normal shutdown | drain in pipeline order, final fsync, exit 0 | `Heartbeat` with `is_final: true` |

### 4.3 CLI subcommands (`clap` derive API)

```
andeda run                         # daemon mode (service entrypoint)
andeda doctor                      # startup diagnostics; no daemon launched
andeda show config                 # print merged effective policy
andeda show paths                  # print expanded watch paths after env + glob
andeda show stats                  # query running daemon via control IPC
andeda version
```

`andeda doctor` exit codes: `0` OK, `1` warning, `2` error.

Sample `doctor` output:

```
ANDEDA doctor 0.1.0
─────────────────────────────────────────────
[OK]   policy: /etc/andeda/policy.yaml (overrides: 2, custom targets: 1)
[OK]   effective targets: 7 (critical: 4, standard: 3)
[OK]   host_id: 5A7C3E91-... (strategy: machine_id)
[WARN] permission: Full Disk Access NOT granted
       affected target: claude-desktop-config-macos
       remedy: System Settings → Privacy & Security → Full Disk Access
[OK]   state.db: /var/lib/andeda/state.db (12 KB, 8 baseline hashes)
[OK]   sink: /var/log/andeda/events-2026-05-08.jsonl (writable, mode 0640)
[OK]   notify backend: fsevents
─────────────────────────────────────────────
1 warning. Daemon will start with reduced coverage.
```

### 4.4 Control IPC

- macOS / Linux: Unix Domain Socket at `/var/run/andeda/control.sock`, mode `0600`,
  owned by root.
- Windows: Named Pipe `\\.\pipe\andeda-control`, ACL restricted to `Administrators`
  and `SYSTEM`.

Protocol: newline-delimited JSON request/response, one command per connection.
Phase 1 supports exactly one command:

```
→ {"cmd": "stats"}
← {"ok": true, "stats": { ...same payload as Heartbeat... }}
```

Future commands (`reload`, `flush`) are reserved but not implemented in Phase 1.

### 4.5 Stats payload

Held as `Arc<RwLock<Stats>>` in `andeda-core::stats`. Each pipeline task contributes
via atomic counters. p50/p99 hash latencies use `hdrhistogram` over a 5-minute sliding
window (decision: keep `hdrhistogram` despite the dependency cost — accurate
percentiles are the primary value of this telemetry; simple mean/max would obscure
hash-pool tail behavior).

The Heartbeat payload is the canonical externally-visible shape (Section 3.1).

### 4.7 Recommended SIEM rule templates (operator-facing, non-normative)

These are starter rules to ship in `docs/runbook/siem-rules.md`. ANDEDA itself does
not enforce them — they live in the customer's SIEM.

**Heartbeat absence (host went silent or daemon died):**
```
trigger: events.source.kind == "agent"
         AND events.evidence.kind == "heartbeat"
         absent for 90 s by host_id
severity: medium
action: page on-call security
```

**Idempotent dedup (Section 1.4 documented duplicate cause):**
```
key:    (host_id, target_id, evidence.after_hash, floor(ts to 60s))
keep:   first event, drop subsequent
```
This dedup applies before any alerting rule, so a documented Event-first commit
crash duplicate doesn't generate two pages.

**Critical-tier integrity recheck mismatch:**
```
trigger: events.evidence.kind == "file_change"
         AND events.evidence.recheck_hash IS NOT NULL
         AND events.evidence.recheck_hash != events.evidence.after_hash
severity: high
note:   transient state existed between change and recheck — file changed twice
        within 100 ms; possible attempted obfuscation
```

**Channel stall warning:**
```
trigger: count(events.evidence.kind == "channel_stall") > 3 in 5 min by host_id
severity: low
action: pipeline saturation; consider raising channel capacity in policy
```

### 4.8 Observability Non-Goals (Phase 1)

- Prometheus `/metrics` HTTP endpoint.
- Bundled web UI / dashboard.
- OpenTelemetry tracing or metrics export.
- Log indexing / search inside ANDEDA — SIEM ingests JSONL.
- Crash dump auto-collection — OS / EDR domain.
- Auto-update / self-upgrade — MDM domain.

---

## 5. Testing Strategy

### 5.1 Test pyramid for this project

```
                 Manual Runbook (~5 scenarios)        ← TCC/FDA, MDM deploy, real SIEM, EDR coexistence
                Integration tests (~15 cases)         ← real fs, real notify, real sink; CI: macOS + Windows
              Snapshot tests (~10 fixtures)           ← jsonl serialization stability, doctor output stability
            Property tests (~6 properties)            ← policy merge invariants, debounce invariants
          Unit tests (~80 in andeda-core)             ← every pure-logic function; runs in < 1 s; OS-independent
```

Principle: cover the surface where "if this breaks, a security event is missed".
Coverage percentage targets are not chased, except for two modules called out below.

### 5.2 Unit tests (`andeda-core`)

| Module | Representative cases |
|--------|----------------------|
| `policy::parse` | valid YAML; unknown key; version mismatch; duplicate id; non-current platform silently dropped; empty targets is error |
| `policy::merge` | defaults alone; `disabled: true`; `tier` override; custom target appended; id collision is error |
| `policy::expand` | `~` → `$HOME`; `%APPDATA%` → env var; missing var is error; `**` is error; absolute path passes through |
| `event::serialize` | round-trip for every `Evidence` variant; `kind` discriminator correct; field order stable (enforced by snapshot) |
| `hashing` | empty file → blake3 empty hash; 1 MB file exact value; streaming caps allocation < 64 KB |
| `debounce` | same-path burst coalesces; `Removed` is immediate; per-kind window timing exact under `tokio::time::pause`; concurrent paths are independent |
| `sink::JsonlSink` | single write; rotation at 100 MB; rotation at UTC midnight; shutdown fsync; new file mode 0640 |
| `state::HashCache` | put/get; persistence across reopen; 50 000 entries lookup p99 < 1 ms |
| `host_id` | strategy enum parsing (`machine_id`, `hostname`, `uuid`, `static:"..."`); `Static` returns literal value; fallback ordering when supplied resolver returns `None`. OS-specific resolution (`IOKit`, registry) is NOT tested here — see integration tests |

`cargo test -p andeda-core` runs in < 1 s on developer machine.

### 5.3 Property tests (`proptest`)

```rust
proptest! {
    #[test]
    fn merge_is_idempotent(defaults in arb_targets(), overrides in arb_overrides()) { ... }

    #[test]
    fn debounce_never_drops_removed(events in arb_event_burst()) { ... }

    #[test]
    fn jsonl_lines_independently_parseable(events in arb_events(1..50)) { ... }

    #[test]
    fn policy_id_uniqueness_holds(p in arb_policy_with_potential_duplicates()) { ... }

    #[test]
    fn warmup_then_change_yields_correct_before_hash(...) { ... }

    #[test]
    fn critical_tier_always_emits_recheck(...) { ... }
}
```

Six properties total. The discipline is to pin invariants that genuinely must hold —
not to use property testing as a substitute for unit cases.

#### Named arbitraries (input domain definitions)

Each `arb_*` strategy below has a single canonical definition in
`andeda-core/tests/proptest_arbs.rs`. Listed for reviewers:

- `arb_targets()` — `Vec<WatchTarget>`, length 0..20. ids are unique within the vec
  by construction.
- `arb_overrides()` — `Vec<Override>`, length 0..10. ids may or may not exist in the
  paired `arb_targets()` value (some are intentionally orphan to exercise the
  fail-fast path).
- `arb_event_burst()` — `Vec<RawFsEvent>`, length 1..100, randomized `change_kind`
  distribution biased toward `Modified` (matches real workloads). Per-event timing
  jitter 0..50 ms.
- `arb_events(n)` — `Vec<Event>` of length `n`, with realistic field shapes
  (UUIDv7 ts-monotonic, distinct paths, plausible hashes).
- `arb_policy_with_potential_duplicates()` — `Policy` constructed by combining
  `arb_targets` with a 30% probability of injecting an id collision somewhere in
  the merge chain.

### 5.4 Integration tests (`andeda-agent/tests/`)

Real filesystem (in `tempfile::TempDir`), real `notify`, real tokio runtime.

| Test | Action | Assertion |
|------|--------|-----------|
| `it_emits_modified_event` | watch tempdir, write file | one `file_change.modified` line |
| `it_warmup_sets_baseline` | pre-existing file → daemon start → modify | `before_hash` matches warmup hash |
| `it_survives_restart_with_baseline` | daemon start → stop → restart → modify | `before_hash` after restart matches prior `after_hash` |
| `it_critical_tier_emits_recheck` | critical target, single change + a 100 ms-later change | `recheck_hash` is set and matches second hash |
| `it_emits_channel_stall_on_overflow` | block channel, force burst, release | `channel_stall` event appears with non-zero `blocked_seconds_in_window` |
| `it_handles_rapid_create_delete` | 100 create/delete cycles per second | no crash; final state correct |
| `it_doctor_succeeds_on_valid_config` | `andeda doctor` (subprocess) | exit 0; stdout contains `[OK]` |
| `it_doctor_warns_on_missing_target_path` | policy referencing non-existent path | exit 1; `[WARN]` present |
| `it_graceful_shutdown_drains_queue` | 1000 events in flight, SIGTERM | all 1000 in JSONL; final heartbeat with `is_final: true` |
| `it_multi_user_path_expansion` | tempdir with `/Users/alice/` and `/Users/bob/` mock home dirs; policy with `~/...` template | watcher attaches to both expanded paths; events from each carry distinct `subject.path` and same `target_id` |
| `it_renamed_pair_within_window` | watch dir, atomic rename `tmp` → `target.json` within 200 ms | single `change_kind: renamed` event with `rename_from = "tmp"`, `subject.path = "target.json"` |
| `it_renamed_from_outside_watchlist` | move file from outside watch root **into** watch root | `change_kind: created`, `rename_from: null` |
| `it_event_first_commit_survives_crash` | force panic between JSONL write and DB commit; restart | next event for same path has `before_hash` matching the un-committed prior baseline (i.e., the JSONL line was written, the new baseline was lost) |
| `it_large_file_emits_incomplete` | 11 MB file appearing under watchlist | event emitted with `before_hash: null`, `after_hash: null`, `evidence_quality: incomplete`, `size_after: 11534336` |
| `it_rate_limit_drops_excess` | flood a target with 1000 events/sec for 15 s | `RateLimitExceeded` event(s) appear; total `count_dropped_in_window` > 0; other targets continue to emit normally |
| `it_lazy_rotation_after_simulated_sleep` | open file with date X, monkeypatch clock to X+2, write event | rotation triggered on the first post-sleep write; new file `events-X+2.jsonl` opened |
| `it_fda_probe_distinguishes_eacces_from_enoent` | mock probe call returning each errno | `check_fda()` returns `Granted`, `Denied`, `Unknown` per the matrix in Section 1.6 |

OS-specific tests live in `#[cfg(target_os = "...")]` modules (`macos_tests`,
`windows_tests`).

A `TestAgent` builder is exposed from `andeda-agent` to drive these tests through the
real `run()` entrypoint with paths redirected to tempdirs.

### 5.5 Snapshot tests (`insta`)

- One snapshot per `Evidence` variant of its serialized JSONL line, with stable
  fixtures.
- `andeda doctor` output snapshot, with `ts` and `host_id` masked.
- Format changes require `cargo insta accept` + a spec version bump. Snapshot diffs in
  PRs surface SIEM-rule impact explicitly.

### 5.6 Manual test runbook (`docs/runbook/manual-tests.md`)

Pre-release sign-off scenarios:

1. **macOS Full Disk Access flow** — first run emits `PermissionMissing`; grant FDA
   in System Settings; SIGHUP without restart; coverage restored.
2. **Windows Service registration** — `sc create` / `sc start`, validate Event Viewer
   start log, `sc stop` and confirm graceful drain.
3. **Real SIEM ingest** — point Splunk Universal Forwarder (or Datadog Agent) at the
   JSONL directory; confirm events arrive in SIEM; confirm rotated files are also
   ingested without gaps.
4. **EDR coexistence** — run alongside CrowdStrike (or Defender for Endpoint); confirm
   ANDEDA is not flagged or blocked.
5. **MDM dry-run** — deploy via Jamf or Intune; `andeda doctor` returns only `[OK]`
   or identifiable `[WARN]` lines on a freshly-imaged endpoint.

### 5.7 CI matrix

GitHub Actions:

```yaml
matrix:
  os: [macos-14, windows-2022]
  toolchain: [stable]
```

Per OS:
1. `cargo fmt --check`
2. `cargo clippy --all-targets -- -D warnings`
3. `cargo test -p andeda-core`
4. `cargo test -p andeda-agent --test '*'`
5. `cargo build --release`

A separate Linux job runs `cargo build --target x86_64-unknown-linux-gnu` for
build-only verification. No tests run on Linux in Phase 1.

### 5.8 Coverage policy

- `andeda-core::policy` and `andeda-core::event` — line coverage ≥ 90% via
  `cargo-llvm-cov`. These two modules are where a missed line directly equates to a
  missed security event.
- Other modules — coverage falls out of the test surfaces above and is not measured
  against a target.

### 5.9 Testing Non-Goals (Phase 1)

- E2E with a real SIEM in CI — manual runbook is sufficient for Phase 1 frequency.
- Fuzzing (`cargo-fuzz`) — Phase 1.5 / Phase 2 (revisit when network proxy is added).
- Chaos / load testing — Phase 2 introduces network, which is when this matters.
- Mutation testing (`cargo-mutants`) — diagnostic only, not a CI gate.

---

## 6. Packaging Contract

Phase 1 produces `cargo build --release` binaries. Packaging into installable artifacts
is a separate workstream that consumes these binaries. The contract below defines what
that workstream may rely on.

### 6.1 Distribution artifacts

- **macOS**: `andeda-<version>-aarch64-apple-darwin.pkg` (Apple-signed + notarized).
  The `.pkg` carries a `lipo`-merged universal binary (x86_64 + aarch64). Install
  scripts register the LaunchDaemon plist.
- **Windows**: `andeda-<version>-x86_64-pc-windows-msvc.msi` (Authenticode-signed).
  Install registers a Windows Service.
- **Linux**: a static `.tar.gz` for build verification. `.deb` / `.rpm` are out of
  Phase 1 scope.

### 6.2 Predictable paths (MDM scripts may rely on these)

| Item                | macOS                                      | Windows                                   |
|---------------------|--------------------------------------------|-------------------------------------------|
| Binary              | `/usr/local/bin/andeda`                    | `%PROGRAMFILES%\Andeda\andeda.exe`        |
| Policy file         | `/etc/andeda/policy.yaml`                  | `%ProgramData%\Andeda\policy.yaml`        |
| Event directory     | `/var/log/andeda/`                         | `%ProgramData%\Andeda\events\`            |
| `state.db`          | `/var/lib/andeda/state.db`                 | `%ProgramData%\Andeda\state.db`           |
| Service identifier  | `com.andeda.agent` (LaunchDaemon label)    | `Andeda` (Windows Service name)           |
| Control IPC         | `/var/run/andeda/control.sock`             | `\\.\pipe\andeda-control`                 |

CLI flags may override these paths. MDM-driven deployments rely on the defaults.

### 6.3 Idempotency and exit codes

These flags belong to the **packaging installer** (the `.pkg` install scripts and the
`.msi` custom actions), **not** the `andeda` daemon binary's `clap` CLI. The daemon
binary itself only exposes the subcommands listed in Section 4.3 (`run`, `doctor`,
`show`, `version`).

- Reinstall of the same version → installer no-op, exit 0.
- Downgrade attempt → installer exit 65 (`downgrade-not-permitted`). Forced
  downgrade requires the installer's `--force-downgrade` argument (passed by the
  MDM script invoking the installer).
- Pre-existing user-modified `policy.yaml` → installer leaves it intact; new
  defaults are written to `policy.yaml.new`. `andeda doctor` (the daemon binary)
  surfaces a `[NOTE] new defaults available at policy.yaml.new`.
- Uninstall preserves `state.db`, `events/`, and `policy.yaml` (audit trail).
  Removes only the binary and service registration. Forced wipe requires the
  installer's `--purge` argument.

### 6.4 Auto-update — explicitly disabled

- No bundled auto-updater.
- No phone-home / version check / telemetry.
- All updates flow through MDM (Jamf Pro Patch Management, Intune App Assignment).

---

## Appendix A — Decisions deferred to later phases

| Decision | Phase | Rationale |
|----------|-------|-----------|
| Network proxy for outbound LLM API traffic (DLP) | 2 | Requires CA cert distribution; orthogonal to Phase 1 |
| Process tracking and agent action audit | 3 | Requires per-OS APIs (EndpointSecurity, ETW); largest scope |
| Linux runtime support + eBPF monitor | 2+ | No critical Phase 1 customer; non-trivial OS work |
| Direct SIEM push (HTTPS / syslog / OTLP) | 2 | Operator can use existing SIEM forwarders for Phase 1 |
| Drop-in policy directory (`/etc/andeda/policy.d/`) | 1.5 | Single override file is sufficient until it isn't |
| HMAC log chain / log-record signing | 1.5 | Adds value only when ANDEDA is the trust root, which it isn't (ride-along) |
| gzip rotation, batched transmission | 1.5 | SIEM forwarders handle this when they need to |
| Self-watch of agent's own files / heartbeat-as-defense | never | Out of scope by SPM positioning; EDR territory |

---

## Appendix B — Open implementation choices

These are decisions intentionally left to the implementing engineer; either listed
option is acceptable per spec:

- Hasher pool implementation: `tokio::task::spawn_blocking` (default) vs. dedicated
  `rayon::ThreadPool`. Pick whichever benchmarks better on the target workload.
- `notify`'s `RecommendedWatcher` vs. explicit backend selection. Default to
  `RecommendedWatcher`; switch to explicit only if a measured pathology emerges.
- Time-quantized batching for SQLite writes in `state::HashCache` vs. write-per-event.
  Either acceptable as long as a daemon panic does not lose more than 1 s of cache
  writes.

---

*End of Phase 1 design specification.*
