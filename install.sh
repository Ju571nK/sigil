#!/bin/sh
# Sigil installer (macOS / Linux). Downloads the prebuilt binaries from the
# latest GitHub release, verifies their SHA-256 checksum, and installs them.
#
#   curl --proto '=https' --tlsv1.2 -fsSL https://raw.githubusercontent.com/Ju571nK/sigil/main/install.sh | sh
#
# Environment overrides:
#   SIGIL_VERSION       pin a release tag (default: latest), e.g. v0.1.0
#   SIGIL_INSTALL_DIR   install directory (default: $HOME/.local/bin)
#   SIGIL_PROFILE       personal (default) | fleet
#                       personal = sigil + sigil-mcp + sigil-hook (local self-assessment)
#                       fleet    = + sigil-sender + sigil-server + sigil-sign
#
# Provenance: every release archive also carries a GitHub build-provenance
# attestation. To verify it (optional, needs the gh CLI):
#   gh attestation verify <archive> --repo Ju571nK/sigil
set -eu

REPO="Ju571nK/sigil"
INSTALL_DIR="${SIGIL_INSTALL_DIR:-$HOME/.local/bin}"

say() { printf 'sigil-install: %s\n' "$1" >&2; }
err() { printf 'sigil-install: error: %s\n' "$1" >&2; exit 1; }

PROFILE="${SIGIL_PROFILE:-personal}"
case "$PROFILE" in
  personal) BINARIES="sigil sigil-mcp sigil-hook" ;;
  fleet)    BINARIES="sigil sigil-mcp sigil-hook sigil-sender sigil-server sigil-sign" ;;
  *) err "unknown SIGIL_PROFILE '$PROFILE' (expected: personal | fleet)" ;;
esac

# dry-run hook: print the resolved binary set and exit before any network I/O.
# Used by tests/install_profile_test.sh to verify profile->binaries mapping.
if [ "${SIGIL_PROFILE_DRYRUN:-}" = "1" ]; then
  printf '%s\n' "$BINARIES"
  exit 0
fi

# --- tooling ---------------------------------------------------------------
command -v uname >/dev/null 2>&1 || err "missing required tool: uname"
command -v tar   >/dev/null 2>&1 || err "missing required tool: tar"
command -v mktemp >/dev/null 2>&1 || err "missing required tool: mktemp"

if command -v curl >/dev/null 2>&1; then
  dl() { curl --proto '=https' --tlsv1.2 -fsSL "$1"; }
elif command -v wget >/dev/null 2>&1; then
  dl() { wget -qO- "$1"; }
else
  err "need curl or wget"
fi

if command -v sha256sum >/dev/null 2>&1; then
  sha_check() { sha256sum -c "$1"; }
elif command -v shasum >/dev/null 2>&1; then
  sha_check() { shasum -a 256 -c "$1"; }
else
  err "need sha256sum or shasum to verify the download"
fi

# --- detect platform -------------------------------------------------------
os="$(uname -s)"
arch="$(uname -m)"
case "$os/$arch" in
  Linux/x86_64 | Linux/amd64)
    target="x86_64-unknown-linux-musl" ;;
  Darwin/arm64 | Darwin/aarch64)
    target="aarch64-apple-darwin" ;;
  Darwin/x86_64)
    err "Intel Macs aren't supported — build from source: https://github.com/$REPO#build-from-source" ;;
  Linux/aarch64 | Linux/arm64)
    err "no prebuilt Linux aarch64 binary yet — build from source or open an issue" ;;
  *)
    err "unsupported platform '$os/$arch' — see https://github.com/$REPO#installation" ;;
esac

# --- resolve version -------------------------------------------------------
ver="${SIGIL_VERSION:-}"
if [ -z "$ver" ]; then
  ver="$(dl "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null \
          | grep -m1 '"tag_name"' | cut -d'"' -f4 || true)"
  [ -n "$ver" ] || err "could not resolve the latest release (set SIGIL_VERSION to pin one)"
fi
verN="${ver#v}"
asset="sigil-${verN}-${target}.tar.gz"
base="https://github.com/$REPO/releases/download/$ver"

# --- download + verify -----------------------------------------------------
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

say "downloading $asset ($ver)"
dl "$base/$asset"    > "$tmp/$asset"      || err "download failed: $base/$asset"
dl "$base/SHA256SUMS" > "$tmp/SHA256SUMS" || err "download failed: $base/SHA256SUMS"

say "verifying checksum"
grep " $asset\$" "$tmp/SHA256SUMS" > "$tmp/expected.sha256" 2>/dev/null \
  || grep "  *$asset\$" "$tmp/SHA256SUMS" > "$tmp/expected.sha256" \
  || err "no checksum entry for $asset in SHA256SUMS"
( cd "$tmp" && sha_check expected.sha256 >/dev/null 2>&1 ) \
  || err "checksum verification FAILED for $asset — refusing to install"

# --- install ---------------------------------------------------------------
tar -xzf "$tmp/$asset" -C "$tmp"
mkdir -p "$INSTALL_DIR"
for b in $BINARIES; do
  src="$tmp/sigil-${verN}-${target}/$b"
  [ -f "$src" ] || err "archive is missing expected binary: $b"
  cp "$src" "$INSTALL_DIR/$b"
  chmod 0755 "$INSTALL_DIR/$b"
done

say "installed into $INSTALL_DIR: $BINARIES"
say "profile: $PROFILE — start the agent with 'sigil run' (sigil-mcp/sigil-hook need the running daemon)"
case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *) say "note: add $INSTALL_DIR to your PATH to run 'sigil' directly" ;;
esac
say "next: sigil doctor"
