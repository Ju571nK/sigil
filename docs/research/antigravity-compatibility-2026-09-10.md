# Antigravity Compatibility Probe

Date: 2026-09-10

Platform: macOS arm64
Issue: #202

This report separates official documentation from behavior observed on the
local machine. It does not extend macOS results to Linux or Windows.

## Version Inventory

The installed CLI started at `1.1.7` and updated itself to `1.2.0` after the
first headless invocation. All results below were captured on `1.2.0` unless
explicitly stated otherwise. The installed Antigravity app is `2.0.6`; it was
not exercised because current official documentation targets Antigravity 2.0
`2.12.2`. Current Desktop behavior therefore remains a hardware gate.

Official documentation reviewed on 2026-09-10 identifies CLI `1.2.0`,
Antigravity 2.0 `2.12.2`, and Antigravity for IDEs `2.5.5`.

## Hook Results

| Probe | Observed result |
| --- | --- |
| `~/.gemini/config/hooks.json` | `PreToolUse` fired |
| `<workspace>/.agents/hooks.json` | `PreToolUse` fired |
| `~/.gemini/antigravity-cli/hooks.json` | Did not fire |
| `{"allow_tool":false,"deny_reason":"..."}` | Blocked the command |
| `{"decision":"deny","reason":"..."}` | Blocked the command |

The CLI emitted nested `toolCall.name` and `toolCall.args`, plus
`conversationId`, `modelName`, `stepIdx`, `workspacePaths`, `transcriptPath`,
and `artifactDirectoryPath`. `run_command` arguments remained PascalCase,
including `CommandLine` and `Cwd`.

The official hook contract documents `decision` values `allow`, `deny`, `ask`,
`force_ask`, and `deny_unless_prior_grant`. CLI `1.2.0` accepts that contract
and the legacy `allow_tool` deny form measured on CLI `1.1.7` for #208. Sigil
should retain `allow_tool` output for backward compatibility until its minimum
supported CLI version changes. Empty stdout and non-zero hook exit behavior
were not re-probed on `1.2.0`; the existing fail-open claim remains a `1.1.7`
measurement.

## Permission Results

Only `~/.gemini/antigravity-cli/settings.json` affected the headless permission
engine. Identical `permissions.allow` entries in `.agents/settings.json` and
`.antigravity/settings.json` had no effect.

| Configuration | Observed result |
| --- | --- |
| allow `command(touch)` | Command ran |
| allow `command(touch)` + ask `command(*)` | Auto-denied in headless mode |
| allow `command(touch)` + deny `command(*)` | Denied with matching-rule message |
| `toolPermission: always-proceed` | Command ran |
| `toolPermission: request-review` or `strict` | Auto-denied in headless mode |
| `toolPermission: proceed-in-sandbox` without `--sandbox` | Auto-denied |
| Unknown `toolPermission` value | Behaved like review and auto-denied |

These results confirm `Deny > Ask > Allow` precedence for the tested command.
They unblock #209 for the global permission lists. Project permission parsing
must not be added without a newly verified settings source.

## Reproduction

The probe scripts create a disposable workspace and marker file. They back up
and restore any global file they touch.

```sh
HOOK_SOURCE=global-config DENY_STYLE=decision docs/research/probes/probe-antigravity-hook.sh
HOOK_SOURCE=workspace-agents DENY_STYLE=decision docs/research/probes/probe-antigravity-hook.sh
SETTINGS_SOURCE=global-cli RULE_SET=deny-over-allow docs/research/probes/probe-antigravity-permissions.sh
```

Sources: [hooks](https://antigravity.google/docs/hooks),
[permissions](https://antigravity.google/docs/cli/permissions), and
[settings](https://antigravity.google/docs/cli/settings).
