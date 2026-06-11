#!/bin/sh
set -eu
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; cd "$ROOT"
if ! command -v rpm >/dev/null 2>&1 || ! command -v cargo-generate-rpm >/dev/null 2>&1; then
  echo "SKIP: rpm/cargo-generate-rpm not available (run on Linux CI)"; exit 0
fi
packaging/build.sh agent rpm
RPM=$(find target/generate-rpm -maxdepth 1 -name 'sigil-*.rpm' 2>/dev/null | head -1)
[ -n "$RPM" ] || { echo "FAIL: no sigil rpm produced"; exit 1; }
LIST=$(rpm -qlp "$RPM" 2>/dev/null)
echo "$LIST" | grep -q '/usr/bin/sigil-mcp'  || { echo "FAIL: rpm missing sigil-mcp"; exit 1; }
echo "$LIST" | grep -q '/usr/bin/sigil-hook' || { echo "FAIL: rpm missing sigil-hook"; exit 1; }
echo "ok: sigil rpm bundles mcp+hook"
