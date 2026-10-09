# T-01 partial evidence and recovery checkpoint

2026-09-27. Status: **incomplete; no product compatibility approval**.
The researcher attempts `ctx_3e7856e537a5` and `ctx_64bc0eeaa75a` both ended in
an observed unrecoverable app-server session failure before delivering their final report.
The coordinator stopped those exact failed executions and recovered the source facts below.
This is not a replacement for the missing independent research/probe report.

## Coordinator-confirmed local facts

Inspected local registry `rmcp-0.16.0` under
`~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/`:

- `Cargo.toml:13` declares edition 2024; no `rust-version` declaration was found.
- `src/model.rs:153–157` declares 2025-06-18 and 2025-03-26 constants, but sets
  `LATEST` to 2025-03-26 with a comment deferring full 2025-06-18 compliance/testing.
- HTTP client/server feature names exist in the crate; this workspace declares only
  server + transport-io features. Merely existing feature names do not verify behavior.
- Workspace declares Rust minimum 1.78. Local `rustc --version` is
  `rustc 1.95.0 (59807616e 2026-04-14)`. No minimum-version build was run.
- Earlier local CLI discovery found codex-cli 0.156.1. No actual Codex-to-fixture HTTP
  session was observed by the coordinator.

## Evidence reported but not accepted as a reproducible result

The researcher reported a temporary SDK probe that accepted an unknown version string
and lost an unknown tool-call field on typed serialization. Its final commands/artifact
report did not arrive before session failure. Preserve this as a follow-up hypothesis;
do not label it a completed reproducible compatibility test.

The [initial official-document survey](sigil-proxy-compatibility-2026-09-27.md)
remains the source for documented revision differences. Local SDK source, an arbitrary
version string, and protocol documentation must not be collapsed into a runtime-support claim.

## Resume work

1. Reproduce and retain a minimal SDK round-trip probe with source/output and dependency lock.
2. Decide explicit SDK/raw relay boundary and verify its build toolchain.
3. Align the selected supported revision with the existing 2025-11-25 fixture, or extend
   the fixture with explicitly versioned behavior. Do not silently rename its revision.
4. Run an actual client against an isolated temporary fixture, recording HTTP auth,
   lifecycle and cancellation behavior without modifying normal client configuration.
5. Complete the product-specific configuration/permission/hook/unattended/OS matrix.

D-01 and client-specific D-02 remain open. No Cargo dependency, MSRV, client config,
or existing enforcement gate was changed by this task.
