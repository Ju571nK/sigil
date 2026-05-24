# Sigil Licensing & Module-Split Policy

This document describes which parts of Sigil are open source under
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
| Extended detection rule pack | `sigil-rules-pro` (private)    | Shadow AI, MCP/IDE configs, SaaS agents, etc.  |
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
`sigil-rules-pro` build can ship as a signed YAML that the OSS agent
applies via the same code path operators audit. No `.dylib`/`.dll`
plugin loading, no Rust ABI boundary, no commercial-only code paths in
the daemon binary itself.

This is the recommended distribution form for closed rule packs.

---

## Repository layout commitments

- The `main` branch is and remains Apache 2.0.
- Closed content lives in **separate repositories** (e.g.
  `sigil-rules-pro`), never as `.gitignored` files in this tree.
- `sigil-rules-basic` is the boundary marker: anything more specialized
  than its baseline targets is a candidate for the closed track.

---

## Distributing the pro rule pack — signed bundles, not build linking

The OSS daemon does **not** link `sigil-rules-pro` at build time. We
considered a Cargo `pro` feature gated behind a private git dep, but
Cargo records every conditional dep in `Cargo.lock` and tries to fetch
on every build, which (a) breaks OSS CI on forks/PRs without SSH access
to the private repo and (b) leaks the private URL into a public lock
file. The cleaner architecture — already enabled by Plan A — is to ship
extended rule packs as **signed policy bundles**.

**The pipeline (already shipped in Plan A)**:
1. `sigil-rules-pro` (private repo) holds the YAML rule sources.
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

**Status**: `sigil-rules-pro` repo holds the rule YAML sources today
([github.com/Ju571nK/sigil-rules-pro](https://github.com/Ju571nK/sigil-rules-pro)).
The signer + sender pieces land in Plan B; until then the YAML is only
consumed via the signed-bundle test fixtures used by `verify.rs`.

---

## Issuing licenses (vendor key ceremony)

Commercial licenses are vendor-signed and verified by the OSS agent against the
compiled-in `SIGIL_LICENSE_PUBKEYS` trust anchor. The signing tool is OSS
(`sigil-sign license`); only the vendor private key is secret.

1. **Generate the vendor keypair** (once, in a secure environment):

   ```
   sigil-sign keygen --id sigil-license-2026 --out vendor-license.key
   ```

   The `--id` becomes the `signing_pubkey_id` stamped on every license you issue.

2. **Secure the private key.** Store `vendor-license.key` in a password manager,
   encrypted volume, or HSM. NEVER commit it; never leave it in a repo working
   tree. Anyone with this file can forge licenses.

3. **Publish the public key.** Copy the printed `ed25519_pubkey_b64` into
   `SIGIL_LICENSE_PUBKEYS` in `crates/sigil-core/src/license/mod.rs`:

   ```
   pub const SIGIL_LICENSE_PUBKEYS: &[(&str, &str)] = &[
       ("sigil-license-2026", "ed25519:<ed25519_pubkey_b64>"),
   ];
   ```

   Cut a release so deployed servers trust licenses signed by this key.

4. **Issue a license:**

   ```
   sigil-sign license \
     --key vendor-license.key \
     --customer-id ACME \
     --max-hosts 1000 \
     --valid-days 365 \
     --out acme.license.json
   ```

5. **Deliver** `acme.license.json` to the customer; they point their
   `sigil-server` config's `license.path` at it.

**Rotation:** `SIGIL_LICENSE_PUBKEYS` holds multiple entries. To rotate,
generate a new keypair with a new `--id`, add its pubkey alongside the old one,
and sign new licenses with the new key. Old licenses keep verifying until you
remove the old pubkey in a later release.

---

## Audit log tamper-evidence (and its limits)

`sigil-server` writes a signed, hash-chained `license-audit.jsonl`: each line is
an ed25519-signed record whose `prev_hash` links to the previous line. The
verification logic lives in OSS `sigil-core::audit`; anyone can check a chain
with `sigil-sign verify-audit <file> --pubkey ed25519:<b64>`.

**What it proves.** Any edit, reordering, deletion, or truncation of the log
breaks a hash or a signature and is detected by the verifier. This fully covers
third-party tampering and accidental corruption.

**What it does NOT prove.** The signing key is auto-generated on the server's
own host, so a determined operator who controls that host can re-sign a forged
chain. The operator is bound only for history *before an externally-observed
head*: the signed head is exposed at `GET /v1/meta` (`audit_head`), and any
external party (a vendor audit, monitoring, sigil-manager) that records a head
pins the operator to that history. Capture heads off-box to anchor the chain.

This is corroborating evidence, not an automatic legal proof of usage.
Automatic push-anchoring and public timestamping are future work.

## Build self-verification (and its limits)

`sigil doctor --verify-self` hashes the running binary with blake3 and checks it
against a vendor-signed build manifest (`sigil-sign manifest`), verified with the
compiled-in `SIGIL_BUILD_PUBKEYS` trust anchor. The verification logic lives in OSS
`sigil-core::manifest`.

**What it catches.** Accidental corruption, in-place/partial tampering, version and
architecture drift, and naive swaps that didn't re-sign — provided the embedded
trust anchor and verifier are intact.

**What it does NOT prove.** The trust anchor is compiled into the binary, so an
attacker who fully replaces the binary can also replace `SIGIL_BUILD_PUBKEYS` and the
verifier itself. Pair this with the externally-anchored, harder-to-forge
`gh attestation verify` (Sigstore-backed build provenance) for defense in depth.

This slice ships the mechanism; `SIGIL_BUILD_PUBKEYS` is empty until a signed release
populates it (the build-signing key ceremony, mirroring the license vendor key).
