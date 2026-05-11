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
| `crates/sigil-core`                              | Event schema, policy types, signing primitives   |
| `crates/sigil-agent`                             | Daemon runtime, file watcher, IPC, GC, heartbeat |
| `crates/sigil-spool`                             | Generic JSONL spool (producer/consumer/GC)       |
| `crates/sigil-rules-basic`                       | Baseline detection ruleset (macOS + Windows)     |
| `crates/sigil-core/src/sink/jsonl.rs`            | JSONL output sink                                |
| `crates/sigil-core/src/policy/verify.rs`         | Signed-policy verification chain                 |
| `crates/sigil-core/src/policy/canonical.rs`      | RFC 8785 canonical JSON for signature input      |
| `crates/sigil-core/src/policy/atomic_writer.rs`  | Crash-safe policy.yaml + state.db commit         |
| `crates/sigil-agent/src/policy_apply.rs`         | apply_policy IPC handler                         |
| `crates/sigil-agent/src/normalizer.rs`           | Default event normalizer/classifier              |
| `crates/sigil-agent/src/cli.rs`                  | CLI surface                                      |
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
| Enterprise rule packs        | Signed policy bundle (Phase 2)  | Verified via `sigil-core::policy::verify`     |
| `sigil-sender`              | Binary release (Plan B)         | Signs + ships envelopes to fleet               |
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
   `sigil-rules-basic`).

3. **Does it integrate with an enterprise upstream (SIEM, IdP, ticketing)?**
   → Closed (separate private crate or service).

When in doubt, open it. Closing later is reversible; opening leaked
content is not.

---

## How signed policy packs replace the old "monolithic binary" approach

Plan A (already merged) shipped:

- `SignedEnvelope` + RFC 8785 canonical JSON ([signed_envelope.rs](crates/sigil-core/src/policy/signed_envelope.rs), [canonical.rs](crates/sigil-core/src/policy/canonical.rs))
- 5-check `verify_envelope` chain ([verify.rs](crates/sigil-core/src/policy/verify.rs))
- Pubkey keystore loader ([pubkeys.rs](crates/sigil-core/src/policy/pubkeys.rs))
- `apply_policy` IPC handler ([policy_apply.rs](crates/sigil-agent/src/policy_apply.rs))
- Atomic disk + state.db commit ([atomic_writer.rs](crates/sigil-core/src/policy/atomic_writer.rs))

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
- `sigil-rules-basic` is the boundary marker: anything more specialized
  than its baseline targets is a candidate for the closed track.

---

## Distributing the pro rule pack — signed bundles, not build linking

The OSS daemon does **not** link `andeda-rules-pro` at build time. We
considered a Cargo `pro` feature gated behind a private git dep, but
Cargo records every conditional dep in `Cargo.lock` and tries to fetch
on every build, which (a) breaks OSS CI on forks/PRs without SSH access
to the private repo and (b) leaks the private URL into a public lock
file. The cleaner architecture — already enabled by Plan A — is to ship
extended rule packs as **signed policy bundles**.

**The pipeline (already shipped in Plan A)**:
1. `andeda-rules-pro` (private repo) holds the YAML rule sources.
2. A signing tool (Plan B `sigil-sender` companion) wraps a YAML
   payload in a [`SignedEnvelope`](crates/sigil-core/src/policy/signed_envelope.rs)
   using a private ed25519 key.
3. `sigil-sender` (Plan B) ships the envelope to fleet hosts over the
   Phase 2 transport (mTLS + apply_policy IPC).
4. The OSS agent verifies via [`verify_envelope`](crates/sigil-core/src/policy/verify.rs)
   (5-check chain), commits via [`atomic_write`](crates/sigil-core/src/policy/atomic_writer.rs),
   and emits `PolicyReloaded` — all paths operators can audit.

**Why this is better than build-time linking**:
- OSS binary stays trivially reproducible — one artifact, no secret deps.
- Rule pack iteration doesn't require an agent rebuild — push a signed
  YAML and the live fleet picks it up.
- Customer-specific rule packs are possible without a per-customer build.
- Aligns with the open-mechanism / closed-content split this document
  describes — the signing key is the only secret the daemon needs to
  trust.

**Status**: `andeda-rules-pro` repo holds the rule YAML sources today
([github.com/Ju571nK/anti_i-rules-pro](https://github.com/Ju571nK/anti_i-rules-pro)).
The signer + sender pieces land in Plan B; until then the YAML is only
consumed via the signed-bundle test fixtures used by `verify.rs`.
