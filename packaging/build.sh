#!/usr/bin/env sh
# Build the Sigil agent .deb and .rpm packages.
#
# Prerequisites (one-time):
#   cargo install cargo-deb cargo-generate-rpm
#
# Usage:
#   packaging/build.sh            # build both .deb and .rpm
#   packaging/build.sh deb        # only .deb
#   packaging/build.sh rpm        # only .rpm
#
# Outputs:
#   target/debian/sigil_<version>_<arch>.deb
#   target/generate-rpm/sigil-<version>-1.<arch>.rpm
#
# The packagers are run from crates/sigil-agent/ because the asset paths in
# its Cargo.toml ([package.metadata.deb] / [package.metadata.generate-rpm])
# are written relative to that directory.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
WHAT=${1:-all}

echo ">> building release binary (sigil)"
cargo build --release -p sigil-agent --manifest-path "$ROOT/Cargo.toml"

cd "$ROOT/crates/sigil-agent"

case "$WHAT" in
  deb|all)
    echo ">> cargo deb"
    cargo deb --no-build
    ;;
esac
case "$WHAT" in
  rpm|all)
    echo ">> cargo generate-rpm"
    mkdir -p "$ROOT/target/generate-rpm"
    cargo generate-rpm --output "$ROOT/target/generate-rpm/"
    ;;
esac

echo
echo ">> built:"
ls -l "$ROOT"/target/debian/*.deb 2>/dev/null || true
ls -l "$ROOT"/target/generate-rpm/*.rpm 2>/dev/null || true
