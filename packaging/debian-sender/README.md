# Debian maintainer-script skeletons (sigil-sender)

Referenced by `maintainer-scripts` in `[package.metadata.deb]`
(`crates/sigil-sender/Cargo.toml`). cargo-deb substitutes the `#DEBHELPER#`
token in each with the systemd integration snippet derived from
`[package.metadata.deb.systemd-units]` (daemon-reload on install; stop +
state-cleanup on remove/purge; **no** enable/start). cargo-deb won't emit any
systemd maintainer scripts unless this directory is configured, so the
skeletons exist for that side effect even though they're otherwise empty.

Keep the literal string `#DEBHELPER#` out of comments in these files —
cargo-deb does a plain substring replace and will mangle the comment.
