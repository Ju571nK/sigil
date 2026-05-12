# OS packages

The Sigil **agent** (the `sigil` binary + its systemd unit) ships as a `.deb`
and a `.rpm`. The sender / signer / server are not packaged yet.

## What's in the package

| Path | Source |
| --- | --- |
| `/usr/bin/sigil` | the release binary |
| `/usr/lib/systemd/system/sigil.service` | [`packaging/systemd/sigil.service`](systemd/sigil.service) |
| `/etc/sigil/policy.yaml.example` | [`config/policy.example.yaml`](../config/policy.example.yaml) |
| `/usr/share/doc/sigil/README.md`, `LICENSE` | repo docs |

The systemd unit is installed **disabled**. Nothing starts on install — the
operator decides.

## Building

Pure-Rust packagers, so this runs on macOS or Linux:

```sh
cargo install cargo-deb cargo-generate-rpm   # one-time
packaging/build.sh                            # → target/debian/*.deb, target/generate-rpm/*.rpm
```

`packaging/build.sh deb` / `packaging/build.sh rpm` build just one.

**Build a release package on Linux** (or cross-compile) — the packagers just
bundle whatever is at `target/release/sigil`, so a package built on macOS
contains a macOS binary. CI builds and install-tests the `.rpm` on the
`rocky9` job (`rpm -qpl`, `rpm -i`, `sigil version`, `rpm -e`); the `.deb`
is not built in CI.

The metadata lives in `[package.metadata.deb]` / `[package.metadata.generate-rpm]`
in [`crates/sigil-agent/Cargo.toml`](../crates/sigil-agent/Cargo.toml); the deb
maintainer-script skeletons are in [`packaging/debian/`](debian/).

## Installing

The filenames embed the version and host arch — adjust to match what
`packaging/build.sh` printed (e.g. `sigil-0.1.0-1.x86_64.rpm`,
`sigil_0.1.0-1_amd64.deb`):

```sh
# RHEL / Rocky / Fedora
sudo dnf install ./target/generate-rpm/sigil-*.rpm

# Debian / Ubuntu
sudo apt install ./target/debian/sigil_*.deb
```

Then, optionally, drop a policy in place and start it:

```sh
sudo cp /etc/sigil/policy.yaml.example /etc/sigil/policy.yaml
sudo $EDITOR /etc/sigil/policy.yaml          # or skip — built-in defaults apply if absent
sudo systemctl enable --now sigil
sigil doctor                                  # check coverage / privileges
journalctl -u sigil -f                        # watch it run
```

Events land in `/var/log/sigil/events-*.jsonl` — point your SIEM agent there.

## Uninstalling

```sh
sudo dnf remove sigil     # or: sudo apt remove sigil
```

The package scripts stop & disable the unit on removal. State under
`/var/lib/sigil` and logs under `/var/log/sigil` are left in place — remove
them by hand if you want a clean slate.
