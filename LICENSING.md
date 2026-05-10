# ANDEDA Licensing & Module-Split Policy

This document describes which parts of ANDEDA are open source under
[Apache License 2.0](LICENSE), and which parts are reserved for
binary-only / commercial distribution. It is the canonical reference
when adding new modules or rule packs.

The intent is to keep the **detection mechanism** open and auditable
while protecting **detection content** (rule knowledge, enterprise
integrations) as the project's commercial value.

---

## Open source (Apache 2.0)

These modules are public and accept community contributions:

| Crate / module                                    | Role                                             |
| ------------------------------------------------- | ------------------------------------------------ |
| `crates/andeda-core`                              | Event schema, policy types, signing primitives   |
| `crates/andeda-agent`                             | Daemon runtime, file watcher, IPC, GC, heartbeat |
| `crates/andeda-spool`                             | Generic JSONL spool (producer/consumer/GC)       |
| `crates/andeda-rules-basic`                       | Baseline detection ruleset (macOS + Windows)     |
| `crates/andeda-core/src/sink/jsonl.rs`            | JSONL output sink                                |
| `crates/andeda-core/src/policy/verify.rs`         | Signed-policy verification chain                 |
| `crates/andeda-core/src/policy/canonical.rs`      | RFC 8785 canonical JSON for signature input      |
| `crates/andeda-core/src/policy/atomic_writer.rs`  | Crash-safe policy.yaml + state.db commit         |
| `crates/andeda-agent/src/policy_apply.rs`         | apply_policy IPC handler                         |
| `crates/andeda-agent/src/normalizer.rs`           | Default event normalizer/classifier              |
| `crates/andeda-agent/src/cli.rs`                  | CLI surface                                      |
| All Phase 1+ tests                                | Integration + property tests                     |

**Why these stay open**: trust in a security daemon depends on operators
being able to audit *how* events are captured, *how* policies are
verified, and *how* data is persisted. Mechanism transparency builds
that trust. Open contributors also accelerate platform support and
edge-case fixes.

## Binary-only / commercial (private)

These deliverables are **not** part of the public repository and ship as
either signed policy bundles, separate private crates, or hosted
services. The choice depends on integration depth.

| Deliverable                  | Form                            | Notes                                          |
| ---------------------------- | ------------------------------- | ---------------------------------------------- |
| Extended detection rule pack | `andeda-rules-pro` (private)    | Shadow AI, MCP/IDE configs, SaaS agents, etc.  |
| Enterprise rule packs        | Signed policy bundle (Phase 2)  | Verified via `andeda-core::policy::verify`     |
| `andeda-sender`              | Binary release (Plan B)         | Signs + ships envelopes to fleet               |
| Hosted policy service        | Cloud service                   | Enterprise rule distribution + telemetry       |
| SIEM / EDR connectors        | Separate private crates         | One per upstream (Splunk/Sentinel/CrowdStrike) |

**Why these are closed**: detection knowledge is the product's commercial
moat. Closed *content* combined with open *mechanism* is the standard
split for security tooling (cf. Falco/Sysdig, Snort/Talos, Suricata/Pro
ETPro).

---

## Decision rule for new modules

When adding a new file or crate, ask:

1. **Does it implement a verification, transport, or storage mechanism?**
   → Open source. Auditability matters more than competitive advantage.

2. **Does it encode detection knowledge (rule strings, paths, regexes,
   ML models, threat-intel)?**
   → Closed if it represents non-trivial research or customer value;
   open otherwise (e.g. trivial single-target watch rules belong in
   `andeda-rules-basic`).

3. **Does it integrate with an enterprise upstream (SIEM, IdP, ticketing)?**
   → Closed (separate private crate or service).

When in doubt, open it. Closing later is reversible; opening leaked
content is not.

---

## How signed policy packs replace the old "monolithic binary" approach

Plan A (already merged) shipped:

- `SignedEnvelope` + RFC 8785 canonical JSON ([signed_envelope.rs](crates/andeda-core/src/policy/signed_envelope.rs), [canonical.rs](crates/andeda-core/src/policy/canonical.rs))
- 5-check `verify_envelope` chain ([verify.rs](crates/andeda-core/src/policy/verify.rs))
- Pubkey keystore loader ([pubkeys.rs](crates/andeda-core/src/policy/pubkeys.rs))
- `apply_policy` IPC handler ([policy_apply.rs](crates/andeda-agent/src/policy_apply.rs))
- Atomic disk + state.db commit ([atomic_writer.rs](crates/andeda-core/src/policy/atomic_writer.rs))

Together these form a **signed policy bundle pipeline**: a private
`andeda-rules-pro` build can ship as a signed YAML that the OSS agent
applies via the same code path operators audit. No `.dylib`/`.dll`
plugin loading, no Rust ABI boundary, no commercial-only code paths in
the daemon binary itself.

This is the recommended distribution form for closed rule packs.

---

## Repository layout commitments

- The `main` branch is and remains Apache 2.0.
- Closed content lives in **separate repositories** (e.g.
  `andeda-rules-pro`), never as `.gitignored` files in this tree.
- `andeda-rules-basic` is the boundary marker: anything more specialized
  than its baseline targets is a candidate for the closed track.

---

## Building with the `pro` feature

The OSS daemon links the commercial rule pack only when the `pro` Cargo
feature is enabled. Without the feature, `andeda-rules-pro` is not a
dependency at all — the OSS build does not require the private crate to
be present.

**Local development**: check out the private repo as a sibling of this
one, then build with `--features pro`:

```
parent/
├── anti_i/                  # this repo (Apache 2.0)
└── anti_i-rules-pro/        # private repo (commercial)

cd anti_i
cargo build --workspace --features pro
cargo test  --workspace --features pro
```

The path resolution is `../../../anti_i-rules-pro/crates/andeda-rules-pro`
from `crates/andeda-core/Cargo.toml`. Once the private repo is published,
this path dependency can be swapped for a `git = "ssh://..."` URL with no
other changes.

**Merge semantics**: `andeda-core::policy::defaults()` first parses the
baseline ruleset, then (when `pro` is enabled) merges the extended pack
on top. Target IDs from the pro pack override baseline IDs of the same
name; new IDs are appended. The merged document is sorted by ID for
deterministic output.
