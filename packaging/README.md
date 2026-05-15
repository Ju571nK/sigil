# OS packages

Sigil ships four `.deb` / `.rpm` packages — one per binary crate. They install
the binary, optional systemd unit, and example config to standard FHS paths.

## What's in each package

| Package | Binary | Systemd unit | Example config |
| --- | --- | --- | --- |
| `sigil` | `/usr/bin/sigil` | `sigil.service` | `/etc/sigil/policy.yaml.example` |
| `sigil-sender` | `/usr/bin/sigil-sender` | `sigil-sender.service` | `/etc/sigil/sender.yaml.example` |
| `sigil-server` | `/usr/bin/sigil-server` | `sigil-server.service` | `/etc/sigil/server.yaml.example` |
| `sigil-signer` | `/usr/bin/sigil-sign` | — | — |

All systemd units are installed **disabled**. Nothing starts on install — the
operator decides.

## Building

Pure-Rust packagers, so this runs on macOS or Linux:

```sh
cargo install cargo-deb cargo-generate-rpm     # one-time
packaging/build.sh                              # build all 4 packages, both formats
packaging/build.sh sender                       # only sigil-sender, both formats
packaging/build.sh signer rpm                   # only sigil-signer .rpm
packaging/build.sh deb                          # all 4 packages, .deb only
```

Args (any order, both optional):

| Arg | Values | Default |
| --- | --- | --- |
| `<what>` | `agent`, `sender`, `server`, `signer`, `all` | `all` |
| `<format>` | `deb`, `rpm` | both formats |

**Build a release package on Linux** (or cross-compile) — the packagers just
bundle whatever is at `target/release/<bin>`, so a package built on macOS
contains a macOS binary. CI builds and install-tests all 4 `.rpm`s on the
`rocky9` job (`rpm -qpl`, `rpm -i`, `<bin> --help`, `rpm -e`); the `.deb`s
are not built in CI.

The metadata lives in `[package.metadata.deb]` / `[package.metadata.generate-rpm]`
in each crate's `Cargo.toml`; the deb maintainer-script skeletons are in
[`packaging/debian/`](debian/) (agent), [`packaging/debian-sender/`](debian-sender/),
and [`packaging/debian-server/`](debian-server/). `sigil-signer` has no skeleton
dir — operator CLI, no systemd integration.

## Installing

The filenames embed the version and host arch — adjust to match what
`packaging/build.sh` printed (e.g. `sigil-sender-0.1.0-1.x86_64.rpm`,
`sigil-sender_0.1.0-1_amd64.deb`):

```sh
# RHEL / Rocky / Fedora
sudo dnf install ./target/generate-rpm/sigil-sender-*.rpm

# Debian / Ubuntu
sudo apt install ./target/debian/sigil-sender_*.deb
```

Then for any of the three daemons, drop a config in place and start it. Agent first (defaults work without a config), then sender / server which need TLS materials:

```sh
# agent
sudo cp /etc/sigil/policy.yaml.example /etc/sigil/policy.yaml   # optional — defaults apply if absent
sudo systemctl enable --now sigil
journalctl -u sigil -f

# sender
sudo cp /etc/sigil/sender.yaml.example /etc/sigil/sender.yaml
sudo $EDITOR /etc/sigil/sender.yaml
sudo systemctl enable --now sigil-sender
journalctl -u sigil-sender -f

# server
sudo cp /etc/sigil/server.yaml.example /etc/sigil/server.yaml
sudo $EDITOR /etc/sigil/server.yaml
sudo systemctl enable --now sigil-server
journalctl -u sigil-server -f
```

`sigil-signer` is a one-shot operator CLI — no service to start:

```sh
# Keypair goes wherever you want — the signer package doesn't create /etc/sigil/.
sigil-sign keygen --id ops-2026 --out ./signing-key.json
sigil-sign sign \
    --in policy.yaml --key ./signing-key.json \
    --policy-version 1 --valid-until 2026-06-15T00:00:00Z \
    --out signed-policy.json
sigil-sign verify \
    --keystore /etc/sigil/policy-signing-pubkeys.pem \
    --in signed-policy.json
```

## Uninstalling

```sh
sudo dnf remove sigil-sender         # or: sudo apt remove sigil-sender
sudo dnf remove sigil-server         # etc.
sudo dnf remove sigil-signer
sudo dnf remove sigil
```

Daemon package scripts stop & disable the unit on removal. State under
`/var/lib/sigil` (agent, sender) and `/var/lib/sigil-server` (server, events
also land here) plus logs under `/var/log/sigil` (agent events) are left in
place — remove them by hand if you want a clean slate.
