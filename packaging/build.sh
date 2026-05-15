#!/usr/bin/env sh
# Build Sigil OS packages.
#
# Prerequisites (one-time):
#   cargo install cargo-deb cargo-generate-rpm
#
# Usage:
#   packaging/build.sh                          # all packages, both formats
#   packaging/build.sh deb                      # all packages, .deb only
#   packaging/build.sh rpm                      # all packages, .rpm only
#   packaging/build.sh agent                    # sigil-agent, both formats
#   packaging/build.sh sender rpm               # sigil-sender, .rpm only
#   packaging/build.sh signer deb               # sigil-signer, .deb only
#
# Args (any order, both optional):
#   <what>:   agent|sender|server|signer|all   (default: all)
#   <format>: deb|rpm|all                      (default: all)
#
# Outputs:
#   target/debian/<pkg>_<version>_<arch>.deb
#   target/generate-rpm/<pkg>-<version>-1.<arch>.rpm
#
# The packagers are invoked from each crate's directory because the asset
# paths in the per-crate [package.metadata.deb] / [package.metadata.generate-rpm]
# blocks are written relative to that directory.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

WHAT=all
FORMAT=all
for arg in "$@"; do
    case "$arg" in
        agent|sender|server|signer|all) WHAT="$arg" ;;
        deb|rpm) FORMAT="$arg" ;;
        *)
            echo "unknown arg: $arg" >&2
            echo "usage: packaging/build.sh [agent|sender|server|signer|all] [deb|rpm]" >&2
            exit 2
            ;;
    esac
done

case "$WHAT" in
    all)    CRATES="sigil-agent sigil-sender sigil-server sigil-signer" ;;
    agent)  CRATES="sigil-agent" ;;
    sender) CRATES="sigil-sender" ;;
    server) CRATES="sigil-server" ;;
    signer) CRATES="sigil-signer" ;;
esac

# Single release build for everything we'll package.
echo ">> building release binaries for: $CRATES"
BUILD_ARGS=""
for c in $CRATES; do
    BUILD_ARGS="$BUILD_ARGS -p $c"
done
# shellcheck disable=SC2086
cargo build --release $BUILD_ARGS --manifest-path "$ROOT/Cargo.toml"

mkdir -p "$ROOT/target/generate-rpm"

for c in $CRATES; do
    cd "$ROOT/crates/$c"
    case "$FORMAT" in
        deb|all)
            echo ">> cargo deb ($c)"
            cargo deb --no-build
            ;;
    esac
    case "$FORMAT" in
        rpm|all)
            echo ">> cargo generate-rpm ($c)"
            cargo generate-rpm --output "$ROOT/target/generate-rpm/"
            ;;
    esac
done

echo
echo ">> built:"
ls -l "$ROOT"/target/debian/*.deb 2>/dev/null || true
ls -l "$ROOT"/target/generate-rpm/*.rpm 2>/dev/null || true
