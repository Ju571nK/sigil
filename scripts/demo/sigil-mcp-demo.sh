#!/usr/bin/env bash
# Live sigil-mcp demo: drive the read-only MCP server against a Sigil fleet and
# pretty-print the results. Used to record docs/sigil-mcp-demo.gif (via vhs).
# Authentic — every number below is a real tool response, not mocked.
set -euo pipefail

# Local convenience: a gitignored demo/.env supplies SIGIL_SERVER_BASE_URL +
# SIGIL_SERVER_READ_TOKEN so they stay out of committed source and recordings.
[ -f demo/.env ] && { set -a; . demo/.env; set +a; }
# Point at your sigil-server read API (direct :8443, or a bearer-only proxy).
export SIGIL_SERVER_BASE_URL="${SIGIL_SERVER_BASE_URL:?set SIGIL_SERVER_BASE_URL=http://your-sigil-server:PORT}"
export SIGIL_SERVER_READ_TOKEN="${SIGIL_SERVER_READ_TOKEN:?set SIGIL_SERVER_READ_TOKEN}"
BIN="${SIGIL_MCP_BIN:-target/release/sigil-mcp}"
HOST="${SIGIL_DEMO_HOST:-4376ef7a-4fac-4644-b4cf-128fc471f783}"  # real id for the query; sanitize.py scrubs it on display

P=$'\033[38;5;141m'; C=$'\033[38;5;80m'; D=$'\033[2m'; B=$'\033[1m'; R=$'\033[0m'

printf '\n  %s%ssigil-mcp%s  —  query a live Sigil fleet over MCP\n' "$B" "$P" "$R"
printf '  %sserver %s · read-only · 9 tools%s\n\n' "$D" "$SIGIL_SERVER_BASE_URL" "$R"
sleep 0.7
printf '  %s→%s  initialize · tools/list · fleet_risk · get_host   %s(querying live fleet…)%s\n' "$C" "$R" "$D" "$R"

OUT=$( ( printf '%s\n' \
'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"demo","version":"0"}}}' \
'{"jsonrpc":"2.0","method":"notifications/initialized"}' \
'{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
'{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"fleet_risk","arguments":{}}}' \
"{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/call\",\"params\":{\"name\":\"get_host\",\"arguments\":{\"host_id\":\"$HOST\"}}}" ; sleep 2.5 ) \
| "$BIN" 2>/dev/null )

SIGIL_OUT="$OUT" python3 - <<'PY'
import os, json, time, sys

R="\033[0m"; B="\033[1m"; D="\033[2m"
P="\033[38;5;141m"; C="\033[38;5;80m"; GREY="\033[38;5;245m"
BAND={"critical":"\033[38;5;203m","high":"\033[38;5;208m","medium":"\033[38;5;221m","low":"\033[38;5;71m"}

def band(b):
    col=BAND.get(b, R); txt=b.upper() if b in ("high","critical","medium") else b
    return f"{col}{txt:<7}{R}"

def out(s=""): print(s, flush=True)

resp={}
for line in os.environ["SIGIL_OUT"].splitlines():
    line=line.strip()
    if not line: continue
    try: o=json.loads(line)
    except Exception: continue
    if "id" in o: resp[o["id"]]=o

# tools/list
tools=[t["name"] for t in resp.get(2,{}).get("result",{}).get("tools",[])]
out(f"  {C}✓{R}  connected · {len(tools)} tools: {GREY}{', '.join(tools[:5])}…{R}")
time.sleep(0.7)

# fleet_risk (id 3)
row=json.loads(resp[3]["result"]["content"][0]["text"])["rows"][0]
out(); out(f"  {B}{P}fleet_risk{R}")
out(f"    {GREY}{'HOST':<8} {'BAND':<7} {'SCORE':<6} {'24h ALERTS':<11} TOP TOOL{R}")
out(f"    {row['hostname']:<8} {band(row['bucket'])} {row['score']:<6} {str(row['open_alert_count_24h']):<11} {C}{row['top_tool']}{R}")
time.sleep(1.0)

# get_host (id 4)
host=json.loads(resp[4]["result"]["content"][0]["text"])
by_tool=host["current_risk"]["by_tool"]
out(); out(f"  {B}{P}get_host(ju571n){R}  ·  AI Guard risk by tool")
for tool,e in sorted(by_tool.items(), key=lambda kv:-kv[1]["score"]):
    out(f"    {tool:<16} {band(e['bucket'])} {e['score']:>5.2f}")
    time.sleep(0.18)
time.sleep(0.7)

# why high — reasons for the top tool
aig=host.get("ai_guard",{}).get("by_tool",{}).get(row["top_tool"],{})
reasons=aig.get("reasons",[])
if reasons:
    out(); out(f"  {B}{P}why {row['top_tool']} is HIGH{R}  ·  {len(reasons)} reasons")
    for rsn in reasons[:5]:
        kind=rsn.get("kind","?")
        extra=rsn.get("matcher") or rsn.get("executor") or rsn.get("hook_event") or ""
        extra=f"  {D}{extra}{R}" if extra else ""
        out(f"    {C}•{R} {kind}{extra}")
        time.sleep(0.18)
time.sleep(0.6)
out(); out(f"  {D}Sigil measures, doesn't block — sigil-mcp · {len(tools)} read-only tools{R}")
out()
PY
