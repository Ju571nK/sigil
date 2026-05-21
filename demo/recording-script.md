# README demo — recording script

The README's **See it** section needs a short clip (≤ ~25 s) of Sigil scoring a
dangerous AI-agent config in real time. This is the single highest-leverage
asset for a 30-second repo scan, so the goal is one tight money shot, not a
feature tour.

## The money shot

A clean per-repo Claude Code config (`acme-api/.claude/settings.json`,
read-only permissions, no hooks → score 0 / low) gains a `PreToolUse` hook with
a `.*` matcher that runs `rm -rf $HOME` in the host shell — and Sigil re-emits
`ai_guard_risk_assessed` for that repo with `score: 7.5, bucket: critical` and
the reasons `destructive_in_inline_command` (4.0) + `no_sandbox` (2.0) +
`broad_matcher` (1.5). The viewer sees the config change and the score land
back to back.

Everything runs in a throwaway sandbox under `/tmp`, so it never touches your
real `~/.claude`:

- A local policy points `claude_code_workspaces` at the sandbox workspace, so
  the agent discovers + watches `acme-api/.claude/settings.json` and the
  per-repo parser (`scope = project`) re-assesses on every edit. The parser
  keys off the repo path, not `$HOME`.
- The agent still runs with `HOME` redirected into the sandbox, so the *global*
  parser reads an empty home and no real `~/.claude` risk leaks into the clip.
- No `sudo`: the control socket lives at the hardcoded
  `/var/run/sigil/control.sock`, which a non-root user can't bind — non-fatal,
  and the demo reads events straight from the JSONL spool.

> The dangerous hook uses `rm -rf $HOME` specifically because Sigil's baseline
> destructive matcher keys on concrete targets (`rm -rf /`, `rm -rf ~`,
> `rm -rf $HOME`); `rm -rf "$SOME_VAR"` would only score `no_sandbox` +
> `broad_matcher` (3.5 / medium).

## Prereqs

```sh
cargo build --release          # produces target/release/sigil
jq --version                   # used to pretty-print the raw assessment
```

## Verify it live first (no recording)

From the repo root:

```sh
demo/aiguard-demo.sh demo
```

You should see the benign config, then `sigil show events --pretty` listing a
critical `ai_guard_risk_assessed` line, then the raw `score / bucket / reasons`
via `jq`. If nothing shows, give it another second (the demo uses `--poll`;
drop it with `POLL='' demo/aiguard-demo.sh demo` on a native FS for instant
events).

## Record a GIF (recommended — deterministic)

[vhs](https://github.com/charmbracelet/vhs) replays a script into a GIF, so the
result is reproducible and re-runnable when the output changes.

```sh
brew install vhs               # or: go install github.com/charmbracelet/vhs@latest
vhs demo/aiguard-demo.tape     # writes demo/aiguard-demo.gif
```

Then wire it into the README **See it** section:

```md
![Sigil scores a dangerous AI-agent config in real time](demo/aiguard-demo.gif)
```

Tweak `FontSize` / `Width` / `Height` / `Theme` / `Sleep` timings in
`demo/aiguard-demo.tape` to taste before committing the GIF.

## Record with asciinema (alternative — copy-paste friendly)

```sh
asciinema rec sigil-aiguard.cast
demo/aiguard-demo.sh demo
exit
```

Upload with `asciinema upload sigil-aiguard.cast` and embed the player badge, or
convert to GIF with [agg](https://github.com/asciinema/agg):
`agg sigil-aiguard.cast demo/aiguard-demo.gif`.

## Files

| file | purpose |
|---|---|
| `aiguard-demo.sh` | the sandboxed scenario — `demo` (all-in-one) or phase subcommands `up` / `attack` / `show` / `down` |
| `aiguard-demo.tape` | vhs script that drives the phases into `aiguard-demo.gif` |
