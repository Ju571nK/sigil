#!/bin/sh
# `sigil-sender` stamps every event envelope with $SIGIL_HOST_ID, and
# `sigil-server` rejects events whose own `host_id` field doesn't match the
# envelope (events_route.rs: `host_id_payload_mismatch`). On a co-located host
# the sender must therefore use the agent's host_id — which the agent persists
# (a fresh UUID on first run) into state.db. Wait for it, then start.
set -eu
DB=/var/lib/sigil/state.db
echo "sender: waiting for the agent to publish its host_id ($DB)..."
while :; do
  if [ -f "$DB" ]; then
    HID=$(sqlite3 "$DB" "SELECT host_id FROM host_meta WHERE id = 1;" 2>/dev/null || true)
    if [ -n "${HID:-}" ]; then
      break
    fi
  fi
  sleep 1
done
export SIGIL_HOST_ID="$HID"
echo "sender: using host_id=$SIGIL_HOST_ID"
exec sigil-sender start --config /etc/sigil/sender.yaml
