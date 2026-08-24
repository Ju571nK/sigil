# Generative AI Compatibility Baseline

Date: 2026-08-16
Scope: Sigil hook adapters and AI Guard parsers

This document is the compatibility gate for the current open issue set. An
official document proves only the documented contract. A behavior marked
"hardware required" must be measured on the named product and version before
an enforcement default or parser assumption changes.

## Local Verification Inventory

| Product | Local version | Verification status |
| --- | --- | --- |
| Claude Code | 2.1.221 | Available |
| Claude Desktop | 1.28929.0 | Available |
| Codex CLI | 0.147.0 | Available |
| Cursor Agent / Desktop | 2026.05.07 / 3.7.12 | Available, behind current docs |
| Antigravity CLI / Desktop | 1.1.7 / 2.0.6 | Available; contracts must stay separate |
| Grok Build | 0.2.32 | Available, far behind 0.2.112 |
| Gemini CLI | Not installed | Official-source review only |
| Continue CLI | Not installed | Official-source review only |

## Product Findings

### Claude Code

Current documentation confirms permission modes `default`, `plan`,
`acceptEdits`, `auto`, `dontAsk`, and `bypassPermissions`. Hooks now include
command, prompt, agent, HTTP, and MCP-tool handlers and may originate from user,
project, local, managed, plugin, skill, or agent configuration. `PermissionRequest`
hooks can approve prompts, while scheduled local, desktop, and cloud work adds
unattended execution surfaces.

The current parser covers the main permission modes, `autoMode`, HTTP/MCP hooks,
`loop.md`, and scheduled tasks after PR #206. It still needs recursive skill and
agent frontmatter enumeration and managed-control reporting. Treat #199 as a
remaining-scope issue; #191 Phase 1 is already implemented.

Sources: [permissions](https://code.claude.com/docs/en/permissions),
[hooks](https://code.claude.com/docs/en/hooks),
[scheduled tasks](https://code.claude.com/docs/en/scheduled-tasks)

### Codex

Codex 0.147.0 loads user, profile, project, and managed configuration layers.
`approval_policy` accepts a scalar or granular table. Current approval surfaces
also include `approvals_reviewer = "auto_review"`, app/MCP
`default_tools_approval_mode`, `.rules` files, lifecycle hooks, and
`requirements.toml`. Project config is trust-gated, but hooks, MCP servers, and
approval policy remain allowed project keys.

PR #206 added scalar/table tolerance, standing allow-rule detection, hooks, and
the project config path. The parser does not yet compute the effective layer
stack, assess profiles and managed requirements, or inspect per-app/per-MCP
approval reviewers and modes. These are the remaining #200 requirements.

Sources: [configuration reference](https://learn.chatgpt.com/docs/config-file/config-reference),
[hooks](https://learn.chatgpt.com/docs/hooks)

### Cursor

Hooks load with Enterprise > Team > Project > User precedence. Project hooks
run in trusted local workspaces and command hooks run in cloud agents; user hooks
do not exist in cloud VMs. Cloud agents omit MCP hooks and prompt-based hooks.
Local hooks support command and prompt handlers, `failClosed`, broad lifecycle
events, and explicit `allow | deny | ask` decisions.

Sigil installs and verifies only the user hook file and AI Guard currently scans
only MCP config. #203 should add project and enterprise hook inventory, prompt
hook findings, and explicit cloud-coverage documentation. Team hooks are remote
state and must be reported as a visibility limit.

Sources: [hooks](https://cursor.com/docs/hooks),
[changelog](https://cursor.com/changelog)

### Antigravity

The CLI permissions engine now documents `permissions.deny`, `ask`, and `allow`
with Deny > Ask > Allow precedence. Global settings live at
`~/.gemini/antigravity-cli/settings.json`; current documentation says project
permissions are merged. `toolPermission` documents four modes including
`strict`.

The local CLI 1.1.7 hook contract was hardware-verified as nested `toolCall`
input and `{"allow_tool":false}` output in #202/#208. Current documentation,
covering CLI and Antigravity 2.0, instead specifies
`decision = allow | deny | ask | force_ask | deny_unless_prior_grant`. Do not
replace the 1.1.7 adapter from documentation alone. Re-probe CLI and Desktop
separately and version the contract if both shapes are real.

#209 is confirmed as a genuine parser gap. It should parse all three permission
lists, not only broad `allow`, so precedence prevents false positives.

Sources: [permissions](https://antigravity.google/docs/cli/permissions),
[hooks](https://antigravity.google/docs/hooks),
[CLI reference](https://antigravity.google/docs/cli-reference),
[changelog](https://antigravity.google/changelog)

### Grok Build

The local 0.2.32 build is substantially behind official 0.2.112. Since 0.2.32,
Grok added project and host hook sources, hooks in `config.toml`, default-enabled
workflows, scheduled/background tasks, auto-mode classifier changes, global
cross-vendor rule discovery, configurable goal mode, and live MCP updates.

Do not implement #203 against 0.2.32 behavior. Upgrade or use a disposable copy
of current Grok, then verify hook trust, JSON/TOML precedence, deny/failure
semantics, Claude-compatible hook discovery, and project MCP loading.

Source: [Grok Build changelog](https://x.ai/build/changelog)

### Gemini CLI

Gemini CLI now has system-default, user, project, system-override, environment,
and CLI layers. It supports `BeforeTool` and other model/agent lifecycle hooks,
approval modes `default`, `auto_edit`, `yolo`, and `plan`, persistent allowed
tools, and tool-level sandbox expansion.

The current parser reads only user/project settings, `tools.sandbox`,
`tools.allowed`, `general.defaultApprovalMode == auto_edit`, MCP, and three
custom commands. It misses `yolo`, hooks, system layers, policy paths,
`hooksConfig.enabled`, and `security.toolSandboxing`. Create a dedicated issue
before modifying this parser.

Sources: [configuration](https://github.com/google-gemini/gemini-cli/blob/main/docs/reference/configuration.md),
[hooks](https://github.com/google-gemini/gemini-cli/blob/main/docs/hooks/reference.md),
[sandboxing](https://geminicli.com/docs/cli/sandbox/)

### Continue

Continue shipped a final 2.0.0 and its repository is now read-only. The current
CLI uses `config.yaml`, persistent `~/.continue/permissions.yaml`, and absolute
mode overrides: `--auto` allows all tools and `--readonly` applies plan policy.
Headless mode excludes ask-only tools unless explicitly allowed.

Sigil still reads legacy `config.json`, `mcpServers`, and slash/custom commands.
It does not assess the active YAML config or persistent permissions. Create a
bounded final-version migration issue; do not design for speculative future
Continue releases.

Sources: [project status](https://docs.continue.dev/),
[tool permissions](https://docs.continue.dev/cli/tool-permissions),
[CLI guide](https://docs.continue.dev/guides/cli)

### Claude Desktop

Claude Desktop still supports local `claude_desktop_config.json`, but desktop
extensions (`.mcpb`) and remote account connectors are now separate acquisition
paths. Enterprise policies can disable local MCP and extension execution, and
extension secrets may be stored in OS secure storage rather than plaintext JSON.

The current parser sees only legacy local MCP JSON. Add extension inventory,
remote-state visibility limits, and enterprise hardening signals after #207
defines how positive controls are represented.

Sources: [desktop extensions](https://support.claude.com/en/articles/10949351-getting-started-with-local-mcp-servers-on-claude-desktop),
[enterprise configuration](https://support.claude.com/en/articles/12622667-enterprise-configuration-for-claude-desktop)

### MCP Protocol

The 2026-07-28 specification introduces a stateless core, first-class
extensions, task and app extensions, authorization hardening, cache metadata,
and full JSON Schema 2020-12 for tool schemas. Tool annotations remain
untrusted hints; clients must not rely on `readOnlyHint` as an enforcement fact.

#201 remains valid. Baseline and drift logic must handle composed schemas and
bounded references, and the `readOnlyHint` contradiction should be reported as
a server claim mismatch rather than proof of behavior.

Sources: [2026-07-28 release](https://blog.modelcontextprotocol.io/posts/2026-07-28-release-candidate/),
[tool annotations](https://blog.modelcontextprotocol.io/posts/2026-03-16-tool-annotations/)

## Issue Gates and Order

| Order | Issue | Gate before implementation |
| --- | --- | --- |
| 1 | #202 | Re-probe current Antigravity CLI and Desktop hook output separately. |
| 2 | #209 | Confirm effective permission-list merge and implement precedence-aware parsing. |
| 3 | #207 | Define positive controls without offsetting unrelated risk scores. |
| 4 | #199 / #200 | Implement only remaining scope after PR #206; include newly found approval surfaces. |
| 5 | #203 | Test current Cursor and Grok versions; document cloud and remote-state limits. |
| 6 | #201 | Design schema-aware metadata baseline against MCP 2026-07-28. |
| 7 | #100 | Resume the epic only after adapter contracts and failure modes are versioned. |

Create separate follow-ups for Gemini CLI, Continue 2.0, and Claude Desktop
extensions rather than silently expanding unrelated issues. Every implementation
PR must cite the product version and evidence level used for its contract.
