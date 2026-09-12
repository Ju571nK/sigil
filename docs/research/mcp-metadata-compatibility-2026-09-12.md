# MCP Metadata Baseline Compatibility

Date: 2026-09-12. Scope: #201. Local codex-cli: 0.147.0.

## Acquisition Evidence

The [official Codex MCP documentation](https://learn.chatgpt.com/docs/extend/mcp)
describes server instructions and configurable approval modes. A server's
read-only annotation is not an implementation audit. Sigil reports suspicious
execution/write parameters as an advisory contradiction, not a proven approval
bypass. A path/URL parameter alone is compatible with legitimate read-only tools
and does not trigger that heuristic.

Local structure inspection (keys/types only, no credentials or tool text copied)
found `codex_apps_tools` schema 4 with nested `tool`, `namespace_description`,
`plugin_display_names`, `inputSchema`, and `annotations`. The server-info cache
was schema 1 with `server_info.name/title/version/description`; this machine had
no `instructions` field. Fixtures cover optional root/nested instructions,
description/title, v3/v4 tool names, `callable_name`, legacy connector descriptions,
and hidden text in plugin display names. These are parser tests, not vendor
runtime enforcement tests. No hook adapter, unattended mode, or approval gate
was enabled or relaxed.

Cursor's parser already reads `~/.cursor/mcp.json` and `.cursor/mcp.json`.
No replacement with the obsolete `projects/*/mcps` path is needed.

## Baseline Contract

The daemon stores one immutable JSON baseline per server under
`state.mcp-baselines/`, beside its configured `state.db`. A custom `--state-db`
changes that directory too. Filenames hash the server identity; each file binds
to the canonical HOME and contains metadata hashes and schema-property paths,
not raw descriptions, schema values, or prompts. Temporary-file creation and
no-clobber persistence prevent partial writes and replacement by another initial
writer. Baselines need the same filesystem protection as state.db.

Each server's first complete observation establishes a trust-on-first-observation
reference, **not user approval**. Later servers get separate references. Changed
descriptions/schemas/annotations produce surface drift; new tools on a baselined
server produce new-tool findings; new sensitive parameters or removed required
constraints produce expansion findings. Current hashes in evidence ensure a
second edit to an already-drifted tool emits another assessment. Existing #147
toggle events report transitions; steady findings remain in the assessment.

Nothing automatically approves an updated tool. Stop the daemon, inspect the
cached metadata and event history, and archive the relevant baseline file only
after review to intentionally establish a new reference on restart. There is no
automatic reset command. Losing the state directory loses this history.

One-shot `sigil scan` stays read-only and stateless: it runs static checks but
does not create, read, or modify daemon baselines. Cache corruption/size limits
fail daemon assessment without rebasing; scan retains its defensive best-effort
behavior. Empty/missing caches do not establish a baseline. Cache observations
do not identify a running session's active tools or prove code execution.

## Bounds And Delivery

Scan every distinct snapshot variant so a clean filename cannot hide a poisoned
collision (#217). Deduplicate findings before the severity cap. Limit files,
bytes, tool entries, schema depth, and text length. Existing first-party heuristic
exemptions do not exempt hidden text, contradictions, or drift.

Built-in watch targets now cover tool/server caches and local policy sources
(#218). Operators overriding target paths must include these paths themselves.
Targets absent at daemon startup may still require restart after directory
creation (#219); heartbeat remains the fallback. Canonicalize parser watch prefixes
so macOS `/etc` and symlinked HOME paths match normalized events.

Deploy the updated server before agents: new reason enum variants require a
consumer that recognizes them. Controls remain additive and report-only.
