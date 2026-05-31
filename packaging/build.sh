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
#   packaging/build.sh agent rpm --target aarch64-unknown-linux-gnu
#                                               # cross-build an ARM64 .rpm (#12)
#
# Args (any order):
#   <what>:   agent|sender|server|signer|all      (default: all)
#   <format>: deb|rpm|all                         (default: all)
#   --target <triple>:  Rust target triple        (default: host arch)
#                       e.g. aarch64-unknown-linux-gnu,
#                       aarch64-unknown-linux-musl, armv7-unknown-linux-gnueabihf.
#                       Requires the target installed (`rustup target add <triple>`)
#                       and, for cross-compiles, an appropriate linker/toolchain.
#
# Outputs (host build):
#   target/debian/<pkg>_<version>_<arch>.deb
#   target/generate-rpm/<pkg>-<version>-1.<arch>.rpm
# Outputs (--target <triple>):
#   target/<triple>/debian/<pkg>_<version>_<arch>.deb
#   target/generate-rpm/<pkg>-<version>-1.<arch>.rpm
#
# The packagers are invoked from each crate's directory because the asset paths
# in the per-crate [package.metadata.deb] / [package.metadata.generate-rpm]
# blocks are written relative to that directory (`../../target/release/...`).
# Neither cargo-deb nor cargo-generate-rpm rewrites a `../../target/release`
# asset path for a cross target, so for --target we cross-build into
# `target/<triple>/release`, stage the binary into `target/release` (where the
# asset paths point), and stamp the package architecture explicitly: cargo-deb
# via `--target`, cargo-generate-rpm via `--arch`.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

WHAT=all
FORMAT=all
TARGET=""
# Parse args. --target takes the following arg (or --target=<triple>).
while [ $# -gt 0 ]; do
    arg="$1"
    case "$arg" in
        agent|sender|server|signer|all) WHAT="$arg" ;;
        deb|rpm) FORMAT="$arg" ;;
        --target)
            shift
            TARGET="${1:-}"
            [ -n "$TARGET" ] || { echo "--target needs a triple" >&2; exit 2; }
            ;;
        --target=*) TARGET="${arg#--target=}" ;;
        *)
            echo "unknown arg: $arg" >&2
            echo "usage: packaging/build.sh [agent|sender|server|signer|all] [deb|rpm] [--target <triple>]" >&2
            exit 2
            ;;
    esac
    shift
done

case "$WHAT" in
    all)    CRATES="sigil-agent sigil-sender sigil-server sigil-signer" ;;
    agent)  CRATES="sigil-agent" ;;
    sender) CRATES="sigil-sender" ;;
    server) CRATES="sigil-server" ;;
    signer) CRATES="sigil-signer" ;;
esac

# crate -> binary name (the agent ships `sigil`, the signer ships `sigil-sign`).
bin_for() {
    case "$1" in
        sigil-agent)  echo sigil ;;
        sigil-sender) echo sigil-sender ;;
        sigil-server) echo sigil-server ;;
        sigil-signer) echo sigil-sign ;;
    esac
}

# cargo build gets --target directly; the packagers need an explicit arch.
TARGET_ARG=""
RPM_ARCH=""
if [ -n "$TARGET" ]; then
    TARGET_ARG="--target $TARGET"
    case "$TARGET" in
        aarch64*) RPM_ARCH=aarch64 ;;
        armv7*)   RPM_ARCH=armv7hl ;;
        x86_64*)  RPM_ARCH=x86_64 ;;
        *) echo "warning: no rpm arch mapping for $TARGET; .rpm arch may be wrong" >&2 ;;
    esac
fi

# Single release build for everything we'll package.
echo ">> building release binaries for: $CRATES${TARGET:+ (target: $TARGET)}"
BUILD_ARGS=""
for c in $CRATES; do
    BUILD_ARGS="$BUILD_ARGS -p $c"
done
# shellcheck disable=SC2086
cargo build --release $BUILD_ARGS $TARGET_ARG --manifest-path "$ROOT/Cargo.toml"

# For a cross target, stage each binary into target/release so the crate asset
# paths (`../../target/release/<bin>`) resolve to the cross-built binary.
if [ -n "$TARGET" ]; then
    mkdir -p "$ROOT/target/release"
    for c in $CRATES; do
        b=$(bin_for "$c")
        cp -f "$ROOT/target/$TARGET/release/$b" "$ROOT/target/release/$b"
    done
fi

mkdir -p "$ROOT/target/generate-rpm"

for c in $CRATES; do
    cd "$ROOT/crates/$c"
    case "$FORMAT" in
        deb|all)
            echo ">> cargo deb ($c)${TARGET:+ [$TARGET]}"
            # --target stamps the Debian arch; the staged binary is read from
            # the unrewritten ../../target/release path.
            # shellcheck disable=SC2086
            cargo deb --no-build $TARGET_ARG
            ;;
    esac
    case "$FORMAT" in
        rpm|all)
            echo ">> cargo generate-rpm ($c)${TARGET:+ [$TARGET]}"
            RPM_ARCH_ARG=""
            [ -n "$RPM_ARCH" ] && RPM_ARCH_ARG="--arch $RPM_ARCH"
            # shellcheck disable=SC2086
            cargo generate-rpm $RPM_ARCH_ARG --output "$ROOT/target/generate-rpm/"
            ;;
    esac
done

echo
echo ">> built:"
# Host build writes target/debian; --target writes target/<triple>/debian.
ls -l "$ROOT"/target/debian/*.deb 2>/dev/null || true
[ -n "$TARGET" ] && ls -l "$ROOT/target/$TARGET"/debian/*.deb 2>/dev/null || true
ls -l "$ROOT"/target/generate-rpm/*.rpm 2>/dev/null || true
