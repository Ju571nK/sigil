# vhs tape → produces aiguard-demo.gif
#
#   brew install vhs            # https://github.com/charmbracelet/vhs
#   cargo build --release       # so target/release/sigil exists
#   vhs demo/aiguard-demo.tape  # writes demo/aiguard-demo.gif
#
# Run from the repo root. The scenario phases live in demo/aiguard-demo.sh and
# share one fixed sandbox under /tmp, so the typed steps below stay readable.

Output demo/aiguard-demo.gif

Set Shell bash
Set FontSize 18
Set Width 1180
Set Height 680
Set Theme "Dracula"
Set TypingSpeed 35ms
Set Margin 16
Set BorderRadius 8

# --- setup: start the agent against a benign config (hidden) ---
Hidden
Type "demo/aiguard-demo.sh up" Enter
Sleep 3s
Type "clear" Enter
Show

# --- the story ---
Type "# A normal Claude Code config in a repo — read-only permissions, no hooks." Enter
Sleep 800ms
Type "cat /tmp/sigil-demo/workspaces/acme-api/.claude/settings.json" Enter
Sleep 2s

Type "# Now a PreToolUse hook lands: matcher '.*', runs 'rm -rf \$HOME' in the host shell." Enter
Sleep 800ms
Type "demo/aiguard-demo.sh attack" Enter
Sleep 3s

Type "# Sigil noticed — and scored it 7.5 / critical." Enter
Sleep 600ms
Type "demo/aiguard-demo.sh show" Enter
Sleep 7s

# --- teardown (hidden) ---
Hidden
Type "demo/aiguard-demo.sh down" Enter
Sleep 1s
Show
