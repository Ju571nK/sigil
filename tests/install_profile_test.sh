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

# platform -> release target mapping (#171: aarch64 Linux must resolve, not err).
tgt() { SIGIL_UNAME_S="$1" SIGIL_UNAME_M="$2" SIGIL_TARGET_DRYRUN=1 sh "$SH" 2>/dev/null; }
assert_eq "linux x86_64 target"  "x86_64-unknown-linux-musl"  "$(tgt Linux x86_64)"
assert_eq "linux aarch64 target" "aarch64-unknown-linux-musl" "$(tgt Linux aarch64)"
assert_eq "linux arm64 target"   "aarch64-unknown-linux-musl" "$(tgt Linux arm64)"
assert_eq "macos arm64 target"   "aarch64-apple-darwin"       "$(tgt Darwin arm64)"

if tgt Darwin x86_64 >/dev/null 2>&1; then
  echo "FAIL: intel mac should exit non-zero"; fail=1
else echo "ok: intel mac rejected"; fi

exit $fail
