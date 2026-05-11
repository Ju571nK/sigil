# Sigil docker-compose demo image. ONE image, run in four roles
# (init / sigil-server / sigil / sigil-sender) with different commands.
#
# DEMO build: uses the dev profile (fast to build, fat binaries). Production
# release builds are `cargo build --release` — see the repo README.
#
# Build context is the REPO ROOT (docker-compose.yml sets `context: ..`), so
# the COPY paths below are repo-root-relative.

# ---- builder ----
FROM rust:slim AS builder
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
