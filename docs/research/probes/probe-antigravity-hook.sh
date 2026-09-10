#!/bin/sh
set -eu

# Hardware probe for #202. It temporarily installs one global PreToolUse hook,
# runs an isolated headless command, and restores the user's file byte-for-byte.
AGY_BIN=${AGY_BIN:-agy}
DENY_STYLE=${DENY_STYLE:-allow_tool}
HOOK_SOURCE=${HOOK_SOURCE:-global-config}
PROBE_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/sigil-agy-hook.XXXXXX")
BACKUP=${PROBE_ROOT}/hooks.json.backup
HAD_HOOKS=0

case "$HOOK_SOURCE" in
  global-config)
    HOOKS_FILE=${HOME}/.gemini/config/hooks.json
    HOOK_SCHEMA=nested
    ;;
  global-cli)
    HOOKS_FILE=${HOME}/.gemini/antigravity-cli/hooks.json
    HOOK_SCHEMA=named
    ;;
  workspace-agents)
    HOOKS_FILE=${PROBE_ROOT}/.agents/hooks.json
    HOOK_SCHEMA=named
    ;;
  *)
    printf 'unsupported HOOK_SOURCE: %s\n' "$HOOK_SOURCE" >&2
    exit 2
    ;;
esac

cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  if [ "$HAD_HOOKS" -eq 1 ]; then
    cp -p "$BACKUP" "$HOOKS_FILE"
  else
    rm -f "$HOOKS_FILE"
  fi
  rm -rf "$PROBE_ROOT"
  exit "$status"
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$(dirname "$HOOKS_FILE")"
if [ -f "$HOOKS_FILE" ]; then
  cp -p "$HOOKS_FILE" "$BACKUP"
  HAD_HOOKS=1
fi

HOOK=${PROBE_ROOT}/deny-hook.sh
LOG=${PROBE_ROOT}/payload.jsonl
MARKER=${PROBE_ROOT}/command-ran

case "$DENY_STYLE" in
  allow_tool)
    DENY_JSON='{"allow_tool":false,"deny_reason":"SIGIL_PROBE_ALLOW_TOOL_FALSE"}'
    ;;
  decision)
    DENY_JSON='{"decision":"deny","reason":"SIGIL_PROBE_DECISION_DENY"}'
    ;;
  *)
    printf 'unsupported DENY_STYLE: %s\n' "$DENY_STYLE" >&2
    exit 2
    ;;
esac

sed \
  -e "s|@LOG@|$LOG|g" \
  -e "s|@DENY_JSON@|$DENY_JSON|g" \
  >"$HOOK" <<'EOF'
#!/bin/sh
payload=$(cat)
printf '%s\n' "$payload" >> "@LOG@"
printf '%s\n' '@DENY_JSON@'
EOF
chmod 700 "$HOOK"

HOOK_ESCAPED=$(printf '%s' "$HOOK" | sed 's/\\/\\\\/g; s/"/\\"/g')
if [ "$HOOK_SCHEMA" = nested ]; then
  printf '%s\n' "{\"hooks\":{\"PreToolUse\":[{\"matcher\":\"run_command\",\"hooks\":[{\"type\":\"command\",\"command\":\"$HOOK_ESCAPED\",\"timeout\":10}]}]}}" >"$HOOKS_FILE"
else
  printf '%s\n' "{\"sigil-probe\":{\"PreToolUse\":[{\"matcher\":\"run_command\",\"hooks\":[{\"type\":\"command\",\"command\":\"$HOOK_ESCAPED\",\"timeout\":10}]}]}}" >"$HOOKS_FILE"
fi

VERSION=$($AGY_BIN --version)
set +e
OUTPUT=$(cd "$PROBE_ROOT" && $AGY_BIN --new-project -p \
  "Use run_command to execute exactly: touch $MARKER . Do not simulate it and do not use another tool." \
  --print-timeout 90s 2>&1)
STATUS=$?
set -e

printf 'version=%s\n' "$VERSION"
printf 'deny_style=%s\n' "$DENY_STYLE"
printf 'hook_source=%s\n' "$HOOK_SOURCE"
printf 'agy_exit=%s\n' "$STATUS"
if [ -s "$LOG" ]; then
  printf 'hook_fired=yes\n'
  printf 'payload=' && head -n 1 "$LOG"
else
  printf 'hook_fired=no\n'
fi
if [ -e "$MARKER" ]; then
  printf 'command_ran=yes\n'
else
  printf 'command_ran=no\n'
fi
printf '%s\n' 'agy_output_begin'
printf '%s\n' "$OUTPUT"
printf '%s\n' 'agy_output_end'
