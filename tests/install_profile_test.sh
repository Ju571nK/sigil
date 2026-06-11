#!/bin/sh
# install.sh의 프로파일→BINARIES 매핑을 dry-run으로 검증 (#134).
set -eu
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SH="$ROOT/install.sh"

run() { SIGIL_PROFILE="$1" SIGIL_PROFILE_DRYRUN=1 sh "$SH" 2>/dev/null; }

fail=0
assert_eq() { # $1=desc $2=expected $3=actual
  if [ "$2" != "$3" ]; then printf 'FAIL: %s\n  want: %s\n  got:  %s\n' "$1" "$2" "$3"; fail=1
  else printf 'ok: %s\n' "$1"; fi
}

assert_eq "personal subset" "sigil sigil-mcp sigil-hook" "$(run personal)"
assert_eq "fleet superset" "sigil sigil-mcp sigil-hook sigil-sender sigil-server sigil-sign" "$(run fleet)"
assert_eq "default is personal" "sigil sigil-mcp sigil-hook" "$(SIGIL_PROFILE_DRYRUN=1 sh "$SH" 2>/dev/null)"

if SIGIL_PROFILE=bogus SIGIL_PROFILE_DRYRUN=1 sh "$SH" >/dev/null 2>&1; then
  echo "FAIL: bogus profile should exit non-zero"; fail=1
else echo "ok: bogus profile rejected"; fi

exit $fail
