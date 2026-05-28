#!/usr/bin/env bash
# Real claude -p turn over sigil-fleet, stream-json → live formatted output.
set -e
printf '\n  \033[38;5;141m\033[1mClaude\033[0m に fleet のリスクを聞く  \033[2m(sigil-fleet MCP)\033[0m\n\n'
claude -p 'sigil-fleet を使って、フリートで最もリスクの高いホストを1つ特定してください。Claude Code と Codex が危険な理由をそれぞれ2〜3点に絞って挙げ、最優先の対策を3つ挙げてください。Markdown記号(#,*,**等)は使わずプレーンテキストで、前置きや結語なしに簡潔に。日本語で。' \
  --output-format stream-json --verbose \
  --allowedTools "mcp__sigil-fleet__fleet_risk" "mcp__sigil-fleet__get_host" "mcp__sigil-fleet__list_hosts" \
  2>/dev/null | python3 scripts/demo/sj-format.py
