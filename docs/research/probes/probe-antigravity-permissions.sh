#!/bin/sh
set -eu

# Hardware probe for #202/#209. It verifies which settings path controls
# headless command permissions and restores any user-global file exactly.
AGY_BIN=${AGY_BIN:-agy}
SETTINGS_SOURCE=${SETTINGS_SOURCE:-global-cli}
RULE_SET=${RULE_SET:-allow}
PROBE_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/sigil-agy-permissions.XXXXXX")
BACKUP=${PROBE_ROOT}/settings.json.backup
HAD_SETTINGS=0

case "$SETTINGS_SOURCE" in
  global-cli)
    SETTINGS_FILE=${HOME}/.gemini/antigravity-cli/settings.json
    ;;
  workspace-agents)
    SETTINGS_FILE=${PROBE_ROOT}/.agents/settings.json
    ;;
  workspace-antigravity)
    SETTINGS_FILE=${PROBE_ROOT}/.antigravity/settings.json
    ;;
  *)
    printf 'unsupported SETTINGS_SOURCE: %s\n' "$SETTINGS_SOURCE" >&2
    exit 2
    ;;
esac

case "$RULE_SET" in
  allow)
    SETTINGS_JSON='{"permissions":{"allow":["command(touch)"]}}'
    ;;
  ask-over-allow)
    SETTINGS_JSON='{"permissions":{"allow":["command(touch)"],"ask":["command(*)"]}}'
    ;;
  deny-over-allow)
    SETTINGS_JSON='{"permissions":{"allow":["command(touch)"],"deny":["command(*)"]}}'
    ;;
  tool-request-review)
    SETTINGS_JSON='{"toolPermission":"request-review"}'
    ;;
  tool-proceed-in-sandbox)
    SETTINGS_JSON='{"toolPermission":"proceed-in-sandbox"}'
    ;;
  tool-strict)
    SETTINGS_JSON='{"toolPermission":"strict"}'
    ;;
  tool-always-proceed)
    SETTINGS_JSON='{"toolPermission":"always-proceed"}'
    ;;
  tool-unknown)
    SETTINGS_JSON='{"toolPermission":"sigil-unknown-probe"}'
    ;;
  *)
    printf 'unsupported RULE_SET: %s\n' "$RULE_SET" >&2
    exit 2
    ;;
esac

cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  if [ "$HAD_SETTINGS" -eq 1 ]; then
    cp -p "$BACKUP" "$SETTINGS_FILE"
  elif [ "$SETTINGS_SOURCE" = global-cli ]; then
    rm -f "$SETTINGS_FILE"
  fi
  rm -rf "$PROBE_ROOT"
  exit "$status"
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$(dirname "$SETTINGS_FILE")"
if [ -f "$SETTINGS_FILE" ]; then
  cp -p "$SETTINGS_FILE" "$BACKUP"
  HAD_SETTINGS=1
fi
printf '%s\n' "$SETTINGS_JSON" >"$SETTINGS_FILE"

MARKER=${PROBE_ROOT}/command-ran
VERSION=$($AGY_BIN --version)
set +e
OUTPUT=$(cd "$PROBE_ROOT" && $AGY_BIN --new-project -p \
  "Use run_command to execute exactly: touch $MARKER . Do not simulate it and do not use another tool." \
  --print-timeout 90s 2>&1)
STATUS=$?
set -e

printf 'version=%s\n' "$VERSION"
printf 'settings_source=%s\n' "$SETTINGS_SOURCE"
printf 'rule_set=%s\n' "$RULE_SET"
printf 'agy_exit=%s\n' "$STATUS"
if [ -e "$MARKER" ]; then
  printf 'command_ran=yes\n'
else
  printf 'command_ran=no\n'
fi
printf '%s\n' 'agy_output_begin'
printf '%s\n' "$OUTPUT"
printf '%s\n' 'agy_output_end'
