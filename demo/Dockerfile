# Sigil docker-compose demo image. ONE image, run in four roles
# (init / sigil-server / sigil / sigil-sender) with different commands.
#
# DEMO build: uses the dev profile (fast to build, fat binaries). Production
# release builds are `cargo build --release` — see the repo README.
#
# Build context is the REPO ROOT (docker-compose.yml sets `context: ..`), so
# the COPY paths below are repo-root-relative.

# ---- builder ----
# Pinned to the bookworm variant so the binaries link against the same glibc
# (2.36) the runtime stage has — a bare `rust:slim` tracks the newest Debian and
# would emit GLIBC_2.38+ symbol refs that `debian:bookworm-slim` can't satisfy.
FROM rust:slim-bookworm AS builder
WORKDIR /src
# Copy only what cargo needs (keeps this layer cacheable; no host target/ or .git).
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --workspace --locked

# ---- runtime ----
FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates openssl jq sqlite3 \
 && rm -rf /var/lib/apt/lists/*
COPY --from=builder \
     /src/target/debug/sigil \
     /src/target/debug/sigil-sender \
     /src/target/debug/sigil-server \
     /src/target/debug/sigil-sign \
     /usr/local/bin/
COPY demo/init.sh demo/sender-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/init.sh /usr/local/bin/sender-entrypoint.sh
EXPOSE 8443
