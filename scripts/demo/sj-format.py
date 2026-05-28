#!/usr/bin/env python3
# Pretty-print `claude -p --output-format stream-json` events live: show
# sigil-fleet tool calls as they happen, then the final answer. Reads NDJSON
# on stdin, prints with flush so the terminal (and a vhs recording) reveals
# activity in real time — no dead air while Claude works.
import sys, json

R="\033[0m"; B="\033[1m"; D="\033[2m"
P="\033[38;5;141m"; C="\033[38;5;80m"; G="\033[38;5;71m"

def out(s=""): print(s, flush=True)

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        e = json.loads(line)
    except Exception:
        continue
    t = e.get("type")
    if t == "system" and e.get("subtype") == "init":
        n = sum(1 for x in e.get("tools", []) if "sigil-fleet" in str(x))
        out(f"  {C}✓{R} sigil-fleet 接続  {D}(MCP・読み取り専用・{n} tools){R}")
    elif t == "assistant":
        for c in e.get("message", {}).get("content", []):
            if c.get("type") == "tool_use":
                name = c.get("name", "")
                if name.startswith("mcp__sigil-fleet__"):
                    tool = name.replace("mcp__sigil-fleet__", "")
                    inp = c.get("input", {}) or {}
                    arg = ""
                    if "host_id" in inp:
                        arg = str(inp["host_id"])[:13] + "…"
                    out(f"  {P}🔧 {tool}({arg}){R}")
    elif t == "result" and e.get("subtype") == "success":
        out()
        out(e.get("result", "") or "")
