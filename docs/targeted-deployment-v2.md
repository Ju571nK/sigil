# Targeted Deployment v2 Contract

Date: 2026-09-23. Tracks #230; consumed by #229 (server) and #231 (signer).

## Status and Boundary

The core wire verifier and the next storage/preparation stage are implemented:
`sigil_core::policy::deployment`, `deployment_store`, and
`sigil_agent::deployment`. This is not yet a deployed protocol.
The agent does not advertise v2 capability, accept v2 IPC, activate a deployment,
or send deployment acknowledgements yet. Server export/import and signer CLI
integration remain pending. Existing fleet-wide envelopes are unchanged.

This work changes Sigil's control-plane contract, not any generative AI product
adapter, permission mode, or hook. No product compatibility gate is relaxed.

## Wire and Signature

`SignedDeploymentManifest` has exactly `manifest` and `signature`. The manifest
requires all of these fields; unknown fields and duplicate JSON keys are errors:

| Field | Meaning |
| --- | --- |
| `schema_version` | Integer `2`; no implicit legacy fallback |
| `deployment_id` | Non-nil, lowercase hyphenated UUID |
| `target_host_id` | Exact independently enrolled identity |
| `sequence` | Integer 1 through 9007199254740991, per host |
| `policy`, `rule_packs` | Exactly one descriptor for each required artifact |
| `issued_at`, `valid_until` | UTC Unix seconds, valid on `[issued_at, valid_until)` |
| `signing_pubkey_id` | Trusted keystore ID, also covered by the signature |

Each descriptor has `kind` (`policy` or `rule_packs`, matching its slot),
`blake3` (64 lowercase hex characters), and `size_bytes`. Hash the exact UTF-8
YAML bytes without newline normalization. Both artifacts are required, nonempty,
and at most 4 MiB each. An empty logical pack is a valid version-1 YAML document,
not an omitted or zero-byte artifact. The signed JSON response is at most 16 KiB.
Transport readers must enforce these limits while streaming, before allocation;
`from_json` also bounds input before deserializing. Do not first parse into
`serde_json::Value`, which loses duplicate-key evidence.

Host/key IDs are nonempty UTF-8 strings up to 256 bytes, without control
characters or leading/trailing whitespace. They are not case-folded, trimmed,
Unicode-normalized, or interpreted as filesystem paths. Timestamps are integer
seconds from 0 through 253402300799 with `issued_at < valid_until`.

Ed25519 signs `b"sigil.targeted-deployment.v2\0"` followed by the existing
`to_canonical_bytes(manifest)` representation. This restricted schema has no
floats, numeric values outside the exact JSON integer range, optional fields,
or unordered arrays. Use `DeploymentManifest::signing_bytes()` everywhere;
do not introduce a signer-specific serializer. The signature is standard padded
base64 of 64 bytes. Verification uses Ed25519 strict verification and a unique,
currently active trusted key ID. No algorithm negotiation is supported.

The manifest digest is BLAKE3 of those same domain-prefixed signing bytes.
It identifies the complete deployment intent, not the transport formatting or
signature. BLAKE3 reuses the repository's existing hashing dependency; this v2
contract does not reinterpret legacy ETags.

The public test vector is
`crates/sigil-core/tests/fixtures/targeted-deployment-v2.json`. It pins exact
signing bytes, public key, signature, manifest digest, and artifact bytes. Its
test seed is public and MUST NOT be used for production keys.

## Verification and Replay

1. Validate the schema and bounded fields, resolve a unique active trusted key,
   and verify the signature with the v2 domain.
2. Match the target against the caller's enrolled identity, not a request query,
   hostname lookup, or identity proposed in the downloaded policy.
3. Reject future-issued or expired manifests, including expired retries.
4. Compare against trusted durable `ReplayState`. First v2 sequence must exceed
   **both** legacy policy and rule-pack watermarks. Later sequences must increase;
   equal sequence is a retry only for the exact same manifest digest. A rollback
   to earlier contents requires a newly signed, higher sequence.
5. Check both artifact lengths and digests, UTF-8, and the existing core policy
   parser. Return both documents only if both pass. `VerifiedManifest` means
   authenticated, not prepared, committed, active, or acknowledged.

The core wire verifier alone does not compile agent regexes/rubrics, validate
the final merged policy, or persist replay state. The storage and coordinator
modules below implement those next steps. None enforces enrollment or protects
against deletion of all trusted local state; provisioning must handle that.
Do not reset absent/corrupt enrolled state to zero. A host identity change must
reject the old manifest/checkpoint and require explicit trusted re-enrollment.
Identity derivation cannot be changed by applying a targeted policy.

## Durable Storage and Preparation

The storage implementation uses a dedicated SQLite store rather than staging
directories and a pointer file. One FULL-synchronous WAL transaction contains
the complete signed manifest, both bounded artifact BLOBs, enrolled host ID,
sequence/digest checkpoint, and targeted-mode marker. This avoids a filesystem
rename followed by a separately committed watermark. macOS `fullfsync` is also
requested. Provisioning uses an exclusive, owner-only file on Unix; deployment
directory permissions and Windows ACLs remain the installer's responsibility.

`DeploymentStore::initialize` is explicit provisioning, refuses an existing
path, and imports both trusted legacy watermarks. `open_existing` never creates
a missing store or resets malformed state. Before integration, legacy writers
must be stopped under the same migration lock while those watermarks are copied;
the new store does **not** yet block existing `policy.yaml` writers by itself.

Commit holds an immediate transaction while checking identity/replay, both
artifacts, and the caller's semantic preparation. It rechecks key/manifest
validity after compilation. Exact retries still validate and compile both
artifacts. Newer commits serialize across connections; a late lower sequence
cannot replace a newer generation. Recovery reverifies signatures, contents,
expiry, and compilation; failure does not fall back to legacy files.

`DeploymentCoordinator` serializes commit and publishes one `Arc` containing
the manifest/digest, effective policy, rubric, deny evaluator, and rule-pack
templates. Preparation uses the existing three-layer merge, rejects changed
identity strategy, invalid globs/selectors/regexes, incompatible or duplicate
packs/rules, and non-finite/negative/unknown rubric overrides. It validates input
packs before merging so an overriding pack cannot hide a malformed input.
Foreign-platform packs are not instantiated, matching existing runtime filtering.

Failed verification/preparation retains the last-good generation. Ambiguous
storage errors require reopening/recovery before serving snapshots. Expired
generations cannot be returned as healthy snapshots. These are **committed
snapshots**, not daemon activation or fleet `applied` acknowledgements; project
templates still need discovery/binding and watchers still need activation.

Process-kill tests exercise the actual transaction immediately before and after
commit. They verify complete old/new generations, not power-loss durability on
every filesystem. Windows/Linux execution and production daemon integration
remain unverified locally.

## Remaining Activation Contract

Before advertising capability or sending `applied`, #230 must implement:

- Serialized prepare/commit across legacy and v2 writers; recheck trusted state
  and expiry at commit. Never persist a verifier result as an apply success.
- Bind the prepared generation into daemon boot/reload and preserve the existing
  platform/user path expansion and workspace discovery. Add server/compiler
  golden tests of final rules once #229 is implemented.
- A coherent live runtime generation for evaluator, rubric, watchers, and reporting.
  Preserve last-good on failure; expiry must not be reported as healthy.
- A persisted v2-mode latch preventing later legacy refresh/reload writes from
  partially replacing the generation. Reinstallation must retain the trusted
  checkpoint or require enrollment recovery; a local file alone is not a defense
  against an administrator deleting all trusted state.
- Additive capability/protocol and desired/observed reporting: deployment ID,
  sequence, manifest/artifact digests, observation time, and stage-specific
  errors. Older reports mean unknown; connectivity is separate from apply state.
- Daemon-level crash/retry, concurrent legacy refresh, migration, identity change,
  and A/B-host server-to-signer-to-agent tests. #229/#231 integration is required before
  closing #230 as end-to-end supported.

Run targeted tests:

```sh
cargo test -p sigil-core --test deployment_contract
cargo test -p sigil-core policy::deployment_store
cargo test -p sigil-agent --test deployment_generation
```
