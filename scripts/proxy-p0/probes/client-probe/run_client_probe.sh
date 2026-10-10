#!/bin/sh
# T-01 real-client probe (2026-10-10). Usage, from repo root:
#   sh scripts/proxy-p0/probes/client-probe/run_client_probe.sh claude [--out DIR]
#   sh scripts/proxy-p0/probes/client-probe/run_client_probe.sh codex  [--out DIR]
# Outputs go to DIR, which defaults to a new mktemp directory outside the repository; an
# existing <client>-wire.jsonl in DIR is never overwritten or deleted (the run refuses).
# Each run = ONE client invocation against a fresh loopback capture fixture.
# - The client MCP config lives in a mktemp dir (mode 0700) and is deleted afterwards.
# - The bearer is a random per-run synthetic token for the loopback fixture only.
# - No user client configuration is written: claude uses --strict-mcp-config,
#   --restricted (ignores user/project/local settings files) and
#   --no-session-persistence; codex uses a temporary CODEX_HOME with no credentials.
# - Wire log redacts bearer values and session ids. Client stdout is reduced to
#   non-identifying fields before being stored.
set -eu
CLIENT="$1"
OUT=""
if [ "${2:-}" = "--out" ]; then OUT="${3:?--out needs a directory}"; fi
[ -n "$OUT" ] || OUT=$(mktemp -d -t t01-client)
mkdir -p "$OUT"
WIRE="$OUT/$CLIENT-wire.jsonl"
if [ -e "$WIRE" ]; then echo "refusing: $WIRE exists (choose another --out)" >&2; exit 2; fi
TMP=$(mktemp -d)
chmod 700 "$TMP"
python3 -B scripts/proxy-p0/probes/capture/capture_fixture.py --log "$WIRE" \
  --bearer-file "$TMP/token" --slow-seconds 30 > "$TMP/fixture.out" 2>&1 &
FX=$!
trap 'kill $FX 2>/dev/null || true; rm -rf "$TMP"' EXIT INT TERM
sleep 1
EP=$(python3 -c 'import json,sys; print(json.loads(open(sys.argv[1]).readline())["endpoint"])' "$TMP/fixture.out")
TOKEN=$(cat "$TMP/token")
PROMPT='Call the MCP tool json_ok from the server named probe exactly once, then call the tool slow_ok from the same server exactly once. Do not retry any call. Report each tool output or error verbatim in one line each.'

snapshot() { # hashes only; never prints contents
  for f in "$HOME/.claude.json" "$HOME/.claude/settings.json" "$HOME/.codex/config.toml"; do
    if [ -f "$f" ]; then printf '%s %s\n' "$(shasum -a 256 "$f" | cut -c1-16)" "${f#$HOME/}"; else echo "absent ${f#$HOME/}"; fi
  done
  python3 -c 'import json,os,hashlib;p=os.path.expanduser("~/.claude.json");d=json.load(open(p)) if os.path.exists(p) else {};print(hashlib.sha256(json.dumps({"top":d.get("mcpServers"),"projects":{k:v.get("mcpServers") for k,v in d.get("projects",{}).items()}},sort_keys=True).encode()).hexdigest()[:16],"claude.json mcpServers subset")'
}
snapshot > "$OUT/$CLIENT-config-before.txt"

START=$(date +%s)
set +e
case "$CLIENT" in
claude)
  printf '{"mcpServers":{"probe":{"type":"http","url":"%s","headers":{"Authorization":"Bearer %s"}}}}' \
    "$EP" "$TOKEN" > "$TMP/mcp.json"
  chmod 600 "$TMP/mcp.json"
  claude --version > "$OUT/claude-version.txt" 2>&1
  (cd "$TMP" && MCP_TOOL_TIMEOUT=5000 timeout 180 claude -p "$PROMPT" --model haiku \
     --strict-mcp-config --mcp-config "$TMP/mcp.json" --restricted \
     --no-session-persistence --output-format json \
     --allowedTools "mcp__probe__json_ok,mcp__probe__slow_ok" \
     > "$TMP/stdout.json" 2> "$TMP/stderr.txt")
  RC=$?
  python3 -c 'import json,sys
try: d=json.load(open(sys.argv[1]))
except Exception as e: d={"unparsed":str(e)}
keep={k:d.get(k) for k in ("type","subtype","is_error","num_turns","result","duration_ms")}
json.dump(keep,open(sys.argv[2],"w"),indent=2)' "$TMP/stdout.json" "$OUT/claude-result.json"
  ;;
codex)
  export CODEX_HOME="$TMP/codex-home"
  mkdir -p "$CODEX_HOME"
  printf '[mcp_servers.probe]\nurl = "%s"\nbearer_token_env_var = "T01_PROBE_TOKEN"\n' "$EP" > "$CODEX_HOME/config.toml"
  codex --version > "$OUT/codex-version.txt" 2>&1
  (cd "$TMP" && T01_PROBE_TOKEN="$TOKEN" timeout 120 codex exec --skip-git-repo-check "$PROMPT" \
     > "$TMP/stdout.txt" 2> "$TMP/stderr.txt" < /dev/null)
  RC=$?
  # Keep only a short, token-free tail of codex output.
  { echo "exit=$RC"; tail -n 15 "$TMP/stderr.txt"; tail -n 15 "$TMP/stdout.txt"; } \
    | sed "s/$TOKEN/<redacted>/g" > "$OUT/codex-result.txt"
  ;;
*) echo "unknown client" >&2; exit 2 ;;
esac
set -e
echo "exit=$RC elapsed_s=$(( $(date +%s) - START ))" > "$OUT/$CLIENT-exit.txt"
sed "s/$TOKEN/<redacted>/g" "$TMP/stderr.txt" | tail -n 20 > "$OUT/$CLIENT-stderr-tail.txt"
sleep 2
python3 -c 'import json,urllib.request,sys
ep=sys.argv[1].replace("/mcp","/_fixture/counters")
print(urllib.request.urlopen(urllib.request.Request(ep,headers={"Authorization":"Bearer "+sys.argv[2]})).read().decode())' "$EP" "$TOKEN" \
  > "$OUT/$CLIENT-counters.json" 2>/dev/null || true
snapshot > "$OUT/$CLIENT-config-after.txt"
kill $FX 2>/dev/null || true
wait $FX 2>/dev/null || true
# Scrub every output file, including the capture (wire) log: synthetic bearer, Claude tool-use
# ids, and vendor request / cf-ray ids (including the PoP suffix).
for f in "$OUT"/*; do
  [ -f "$f" ] || continue
  sed -i.bak -E "s/$TOKEN/<redacted>/g; s/toolu_[A-Za-z0-9]+/toolu_<redacted>/g; s/cf-ray: [A-Za-z0-9-]+/cf-ray: <redacted>/g; s/request id: [A-Za-z0-9_-]+/request id: <redacted>/g" "$f"
  rm -f "$f.bak"
done
# Leak check over all outputs (wire/capture logs included) and the fixture's stdout.
if grep -rqE "$TOKEN|toolu_[A-Za-z0-9]{6,}|req_[A-Za-z0-9]{10,}|cf-ray: [A-Za-z0-9]" "$OUT" "$TMP/fixture.out"; then
  echo "LEAK: token or vendor id in $OUT" >&2; exit 3
fi
echo "done: $CLIENT rc=$RC out=$OUT"
