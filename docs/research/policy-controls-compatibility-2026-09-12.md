# Policy Controls Compatibility Check

Checked 2026-09-12. Local binaries: Claude Code 2.1.267; codex-cli 0.147.0.
Version commands and local cache structure were inspected. No live approval,
organization-policy, Windows, Linux, or sandbox enforcement experiment was run.

## Claude Code (#199)

Official [settings precedence](https://code.claude.com/docs/en/settings) combines
permission lists. Sigil's shallow overlay erased inherited lists; #216 tracks
the regression and its tests. Local approvals now use the repository/main
checkout root with platform and ownership exceptions. Nested skill discovery
and full worktree-local resolution remain separate #199 work.

[Managed settings](https://code.claude.com/docs/en/managed-settings) use a system
directory: `/Library/Application Support/ClaudeCode`, `/etc/claude-code`, or
`C:\Program Files\ClaudeCode`. File policy combines `managed-settings.json`
with non-hidden `managed-settings.d/*.json` in filename order. Remote policy,
MDM, parent-host settings, and source-composition options prevent treating that
file set as the effective session policy.

The [settings reference](https://code.claude.com/docs/en/settings-reference)
was retrieved as Markdown because the HTML exceeded the documentation fetch
limit. Scalar mappings cover disable-auto/bypass, managed-only rules/hooks/MCP,
sideload/skill-shell restrictions, strict-plugin boolean, and sandbox restrictions.
Wrong types and inactive sandbox subsettings are not reported. The array form
of strict-plugin customization is deliberately not mapped in this increment.
Hook enforcement and existing compatibility gates are unchanged.

## Observation Boundary

Controls use `PRODUCT.configured.KEY` IDs and retain their actual file path.
These are local-source observations, **not active or effective controls**.
Resolve overrides inside the inspected file set before emitting. CLI output
explicitly says enforcement is unverified. Neither controls nor their removal
change risk scores, suppress reasons, or enable blocking. Do not summarize a
host as hardened from these records. Cloud/MDM precedence verification and
manager presentation remain follow-ups; #199/#200 must stay open for those
and their other outstanding scopes.

Malformed, unreadable, oversized, or excessive policy inputs fail assessment;
they cannot publish an empty successful snapshot. Values are allowlisted and
do not copy credentials, environment objects, script commands, or custom data.
