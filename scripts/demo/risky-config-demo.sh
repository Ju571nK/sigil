#!/usr/bin/env bash
# Live demo: sigil-mcp queries a host whose Claude Code + Codex configs were
# deliberately set up risky. Every reason below is real ai_guard parser output.
set -euo pipefail

# Point at your sigil-server read API (direct :8443, or a bearer-only proxy).
export SIGIL_SERVER_BASE_URL="${SIGIL_SERVER_BASE_URL:?set SIGIL_SERVER_BASE_URL=http://your-sigil-server:PORT}"
export SIGIL_SERVER_READ_TOKEN="${SIGIL_SERVER_READ_TOKEN:?set SIGIL_SERVER_READ_TOKEN}"
BIN="${SIGIL_MCP_BIN:-target/release/sigil-mcp}"
HOST="4376ef7a-4fac-4644-b4cf-128fc471f783"

P=$'\033[38;5;141m'; C=$'\033[38;5;80m'; D=$'\033[2m'; B=$'\033[1m'; R=$'\033[0m'

printf '\n  %s%ssigil-mcp%s  —  risky Claude Code + Codex configs, flagged live\n' "$B" "$P" "$R"
printf '  %shost dev-mbp-01 · every reason is real ai_guard parser output%s\n\n' "$D" "$R"
sleep 0.7
printf '  %s→%s  fleet_risk · get_host   %s(querying live fleet…)%s\n' "$C" "$R" "$D" "$R"

OUT=$( ( printf '%s\n' \
'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"demo","version":"0"}}}' \
'{"jsonrpc":"2.0","method":"notifications/initialized"}' \
'{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"fleet_risk","arguments":{}}}' \
"{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/call\",\"params\":{\"name\":\"get_host\",\"arguments\":{\"host_id\":\"$HOST\"}}}" ; sleep 2.5 ) \
| "$BIN" 2>/dev/null )

SIGIL_OUT="$OUT" python3 - <<'PY'
import os, json, time
R="\033[0m"; B="\033[1m"; D="\033[2m"; P="\033[38;5;141m"; C="\033[38;5;80m"; GREY="\033[38;5;245m"
BAND={"critical":"\033[38;5;203m","high":"\033[38;5;208m","medium":"\033[38;5;221m","low":"\033[38;5;71m"}
def band(b): return f"{BAND.get(b,R)}{(b.upper() if b in ('high','critical','medium') else b):<8}{R}"
def out(s=""): print(s, flush=True)

resp={}
for line in os.environ["SIGIL_OUT"].splitlines():
    line=line.strip()
    if not line: continue
    try: o=json.loads(line)
    except Exception: continue
    if "id" in o: resp[o["id"]]=o

rows=json.loads(resp[3]["result"]["content"][0]["text"])["rows"]
row=next(r for r in rows if r["hostname"]=="dev-mbp-01")
out(); out(f"  {B}{P}fleet_risk{R}")
out(f"    {GREY}{'HOST':<12} {'BAND':<8} {'SCORE':<6} TOP TOOL{R}")
out(f"    {row['hostname']:<12} {band(row['bucket'])} {row['score']:<6} {C}{row['top_tool']}{R}")
time.sleep(1.0)

host=json.loads(resp[4]["result"]["content"][0]["text"])
by=host["current_risk"]["by_tool"]; aig=host.get("ai_guard",{}).get("by_tool",{})
def show(tool, title, cfg):
    e=by[tool]
    out(); out(f"  {B}{P}{title}{R}   {band(e['bucket'])} {e['score']}   {D}{cfg}{R}")
    seen=[]
    for r in aig.get(tool,{}).get("reasons",[]):
        k=r.get("kind"); extra=r.get("matcher") or r.get("executor") or ""
        tag=f"{k} {D}{extra}{R}" if extra else k
        out(f"    {BAND['critical']}•{R} {tag}"); seen.append(k); time.sleep(0.16)
show("claude_code", "Claude Code", ".claude/settings.json")
time.sleep(0.6)
show("codex", "Codex", ".codex/config.toml")
time.sleep(0.6)
out(); out(f"  {D}Sigil measures, doesn't block — these configs would let an AI agent run unsandboxed.{R}")
out()
PY
