# Personal Install — Local Self-Assessment with Sigil

The **personal profile** installs everything you need to monitor your own machine's AI agent posture and enforce local deny rules, with no server required.

---

## What you get

| Component | Role |
|-----------|------|
| `sigil` (agent daemon) | Watches AI agent config files, scores risk, evaluates rules |
| `sigil-mcp` (local mode) | Exposes `my_risk` / `my_guard_detail` MCP tools to an AI client |
| `sigil-hook` | PreToolUse hook — observe tool calls and optionally enforce deny rules |
| `sigil-rules-basic` (built-in) | Built-in parsers that assess AI-tool config files and produce risk scores / posture — active with no config needed. **No built-in `hook_deny_rules`**: enforcement (sigil-hook blocking) requires you to supply a `rule-packs.yaml`. |

Rule evaluation is **daemon-centric**: all rules run inside the `sigil` daemon. `sigil-mcp` and `sigil-hook` are thin clients of the daemon's Unix sockets and do nothing without it.

---

## Install

### Script (macOS / Linux)

```sh
curl --proto '=https' --tlsv1.2 -fsSL https://raw.githubusercontent.com/Ju571nK/sigil/main/install.sh | sh
```

`personal` is the default profile, so no environment variable is required. You can be explicit:

```sh
SIGIL_PROFILE=personal curl --proto '=https' --tlsv1.2 -fsSL https://raw.githubusercontent.com/Ju571nK/sigil/main/install.sh | sh
```

### Linux package (.rpm / .deb)

The `sigil` package bundles `sigil-mcp` and `sigil-hook` — installing it gives you the full personal set:

```sh
# RHEL / Rocky / Fedora. `sigil-[0-9]…` selects only the agent package: the
# fleet packages (sigil-sender / sigil-server / sigil-signer) have a letter
# after `sigil-`, so they are excluded. Arch-pinned so a second downloaded
# architecture isn't pulled in.
sudo dnf install ./sigil-[0-9]*.$(uname -m).rpm

# Debian / Ubuntu. The agent .deb is `sigil_<ver>…` (underscore), which already
# excludes the `sigil-…` fleet packages; arch-pinned likewise.
sudo apt install ./sigil_*_$(dpkg --print-architecture).deb
```

These globs select only the agent package even if you downloaded the whole
release into one directory. For the packaged install you do **not** need to
create the config directory by hand — see below.

### Create the config directory

The rule-pack watcher monitors the config directory; it must exist before or at install time.

For a user-session install:

```sh
mkdir -p ~/.config/sigil
```

For a packaged install the directory is `/etc/sigil` (created by the package).

### Agent permission prompts (optional, opt-in)

If you drive sigil from inside an AI coding agent (Claude Code), the agent
improvises `sigil` commands with varying flags, so each distinct command string
is a fresh approval and "don't ask again" never sticks — a first-run prompt
storm. The **personal** `install.sh` / `install.ps1` therefore *offers* (opt-in,
only when a terminal is present) to add a read-only allowlist to
`~/.claude/settings.json`:

```json
{ "permissions": {
    "allow": ["Bash(sigil:*)"],
    "deny": ["Bash(sigil run:*)", "Bash(sigil-hook:*)"]
} }
```

The broad `Bash(sigil:*)` allow stops the storm; the explicit **deny** keeps the
privileged `sigil run` (daemon) and `sigil-hook` (enforce) from being silently
granted to the agent — Claude Code evaluates deny before allow. Decline and the
installer just prints the snippet; it never edits silently, and the fleet profile
never offers it. (A posture tool editing agent config must be opt-in, read-only,
and transparent.)

---

## Run the daemon

**Packaged install (systemd):**

```sh
sudo systemctl enable --now sigil
```

**User session (no systemd):**

```sh
sigil run
```

The daemon must be running for `sigil-mcp` and `sigil-hook` to function. Both are clients of the daemon's Unix sockets — they have no independent capability without it.

---

## Local rule packs via git

The agent has a dedicated watcher on `rule-packs.yaml` in the config directory. Editing or replacing that file hot-reloads the local rule packs without restarting the daemon or touching a server.

**Initial setup:**

```sh
git clone <your-rules-repo> ~/sigil-rules
cp ~/sigil-rules/rule-packs.yaml ~/.config/sigil/rule-packs.yaml
```

The agent detects the new file and loads the packs immediately.

**Updating:**

```sh
git -C ~/sigil-rules pull
cp ~/sigil-rules/rule-packs.yaml ~/.config/sigil/rule-packs.yaml
```

For larger packs, prefer an atomic rename so the agent never sees a partially-written file:

```sh
cp ~/sigil-rules/rule-packs.yaml ~/.config/sigil/.rule-packs.yaml.tmp && \
  mv ~/.config/sigil/.rule-packs.yaml.tmp ~/.config/sigil/rule-packs.yaml
```

**Prefer plain `cp` over symlinks.** The watcher monitors the config directory; replacing the file in place is reliably detected. An in-place edit of a symlink target in another directory may not be picked up.

**Fault tolerance:** If you save a corrupt `rule-packs.yaml`, the agent retains the last known-good bundle (your active packs stay loaded). A momentarily empty read — the zero-byte window a non-atomic `cp` opens mid-write — is likewise retained, so a write race never drops your active packs. Only an actual removal (`rm`) clears the bundle layer; to deliberately empty it without removing the file, write a valid empty document (it parses to a bundle with no packs). If the config directory itself is deleted and re-created while the agent runs, the watcher re-arms and resumes hot-reloading.

For the packaged install, the config directory is `/etc/sigil`:

```sh
# simple
cp ~/sigil-rules/rule-packs.yaml /etc/sigil/rule-packs.yaml
# atomic (recommended for larger packs)
cp ~/sigil-rules/rule-packs.yaml /etc/sigil/.rule-packs.yaml.tmp && \
  mv /etc/sigil/.rule-packs.yaml.tmp /etc/sigil/rule-packs.yaml
```

---

## Using it

### Check posture

```sh
sigil show risk
```

Queries the running daemon and prints the current AI Guard risk assessment for each detected tool. Add `--tool claude-code` (or `codex`, etc.) to filter to one tool.

### MCP client integration

`sigil-mcp` in local mode (auto-detected when no server URL is configured) registers as **`sigil-check`** and exposes three read-only tools to an AI client such as Claude Desktop or Claude Code:

- `my_risk` — per-tool risk band and score
- `my_guard_detail` — rubric breakdown and reasons
- `my_findings` — full finding list

Point your MCP client at `sigil-mcp` with no server URL to use local mode. See [`crates/sigil-mcp/README.md`](../crates/sigil-mcp/README.md) for registration details.

### Hook enforcement (PreToolUse)

`sigil-hook --enforce` asks the daemon to allow or deny a tool call against the `hook_deny_rules` in the loaded rule packs. Register it as a `PreToolUse` hook in your agent's settings.

Example for Claude Code (`.claude/settings.json`):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "sigil-hook claude-code --enforce --on-failure open"
          }
        ]
      }
    ]
  }
}
```

**`--on-failure` defaults to `open` (fail-open):** if the daemon socket is absent or the verdict times out, the hook allows the command and does not block. To opt into fail-closed behavior (block when the daemon is unreachable):

```sh
sigil-hook claude-code --enforce --on-failure closed
```

Choose fail-closed only when you are confident the daemon will always be running; an unexpected daemon outage will block all matched tool calls.

#### How bash deny rules are matched

A `bash` deny rule is tested against the raw command *and* against the command as the shell would actually run it. Writing the obvious rule is enough:

```yaml
hook_deny_rules:
  - id: no-rm-rf-root
    match:
      kind: bash
      command: { kind: regex, pattern: "^rm\\s+-rf\\s+/$" }
```

That one rule denies all of these:

| Spelling | Why the raw text differs |
| --- | --- |
| `r''m -rf /`, `\rm -rf /`, `"rm" -rf /` | quote and escape removal |
| `rm${IFS}-rf${IFS}/` | `$IFS` word splitting |
| `X=rm; $X -rf /` | variable assigned earlier in the line |
| `$'\x72\x6d' -rf /` | ANSI-C quoting (`$'…'`) |
| `sudo rm -rf /`, `env rm -rf /`, `timeout 5 rm -rf /`, `xargs -0 rm -rf /` | wrapper commands |
| `sh -c 'rm -rf /'`, `bash -lc 'rm -rf /'`, `su -c 'rm -rf /'` | command passed as a `-c` string |
| `bash <<< 'rm -rf /'`, `sh <<EOF … EOF` | commands fed to a shell on stdin |
| `rm >/dev/null -rf /` | redirection placed mid-command |
| `cd /tmp && rm -rf /`, `for i in 1; do rm -rf /; done` | list, pipeline, and compound-statement context |
| `rm -rf / # cleanup` | trailing comment |

A wrapped or nested command contributes both its literal form and its unwrapped form, so `sudo rm -rf /` matches a rule written either way. When a rule fires only after rewriting, the deny reason says so: `matched deny rule no-rm-rf-root (normalized command)`.

Normalization also refuses to invent commands, so these are **not** denied by the rule above: `r$(printf x)m -rf /` (the shell runs `rxm`), `echo ok # ; rm -rf /` (commented out), `cat <<EOF … EOF` whose body contains the text (data for `cat`, unlike the `bash <<EOF` row above), `su rm` (switches to a user named `rm`), and `timeout rm -rf /` (an error — `timeout` needs a duration, so nothing ran).

Some constructs cannot be resolved without running them — `$(...)`, backticks, process substitution `<(...)`, `eval`, parameter expansions like `${X:-rm}`, and pipelines that feed a shell (`curl … | sh`, `base64 -d | sh`). Sigil does not guess what those expand to. Match them by shape instead:

```yaml
  - id: no-opaque-commands
    match:
      kind: bash_indirection
      indirection: { kind: exists }
```

`indirection` matches one of `command_substitution`, `eval`, `pipe_to_shell`, `unresolved_command_variable`, or `unparsable`. Use `{ kind: equals, value: pipe_to_shell }` to target a single class. These rules are strict: they block a legitimate `$(git rev-parse HEAD)` too, so they suit a locked-down profile rather than a developer laptop.

`unparsable` deserves its own rule if you care about coverage. It fires when quoting never closes, or when the command is past the parser's size or segment bound — cases where a text rule's silence means "not checked", not "safe".

**Limits worth knowing.** Normalization models POSIX sh/bash quoting and expansion, not the whole language: arithmetic expansion, brace expansion, globbing, aliases, and shell functions are not interpreted, and Windows/PowerShell quoting is not covered. Those leave a rule exactly where a plain text match already stood — gaps to close, not regressions. As always, a command whose text the hook never sees (no preview) fails open.

The four ways rules manifest at runtime:

1. The daemon auto-assesses AI agent config files on change → posture events in the event log.
2. `sigil show risk` queries the daemon and prints the current score.
3. `sigil-mcp` local mode exposes `my_risk` / `my_guard_detail` to an AI client.
4. `sigil-hook --enforce` (PreToolUse) asks the daemon to allow or deny a command against `hook_deny_rules`.

---

## Trust model

**Local `rule-packs.yaml` is unsigned.** Its trust boundary is the git repository you clone it from.

This matters for security: `hook_deny_rules` inside a rule pack carry **enforcement authority** — in enforce mode, a matching rule blocks tool execution in your AI coding agent. This is not passive self-assessment data. A malicious or compromised rule pack could deny legitimate tool calls or be crafted to allow harmful ones.

**Only use rule packs from a git repository you trust.** Signed commits are recommended so you can verify that the YAML you are applying is what the author intended. Inspect the `hook_deny_rules` section before deploying any pack.

For comparison, the fleet path (signed bundles) uses `verify_envelope` to cryptographically verify every rule pack before the agent applies it, with the signing key as the trust anchor. The local git path has no equivalent cryptographic gate — the git repo's own access controls and commit signing are the trust boundary.

A future optional community-pubkey gate for local packs is out of scope for this release.

---

## Platform

The personal profile is **Unix-first**. `sigil-mcp` local mode and `sigil-hook` enforce are Unix-only; on non-Unix platforms these fall back to a stub / no-verdict path. Windows gets partial support via tarball install and fsnotify-based watching; full parity with the Unix personal profile is out of scope for this release.

For the fleet profile (central server, signed rule-pack push, `sigil-sender`, `sigil-server`, `sigil-sign`), install with `SIGIL_PROFILE=fleet`.
