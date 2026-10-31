# Migrate from Sigil to Lodeline

Sigil is now Lodeline. This guide lists every step an operator takes to upgrade an
existing install. It names the old paths on purpose.

There is no `sigil` shim and no `SIGIL_*` fallback. The old name collided with
another tool's command, and removing that collision is the point of the rename.
Each section below ends with what happens if you do nothing.

## Summary

| Area | Old | New |
|---|---|---|
| Binaries | `sigil`, `sigil-hook`, `sigil-mcp`, `sigil-sender`, `sigil-server`, `sigil-sign`, `sigil-proxy` | `lodeline`, `lodeline-hook`, `lodeline-mcp`, `lodeline-sender`, `lodeline-server`, `lodeline-sign`, `lodeline-proxy` |
| Packages | `sigil`, `sigil-sender`, `sigil-server`, `sigil-proxy` | `lodeline`, `lodeline-sender`, `lodeline-server`, `lodeline-proxy` |
| Env vars | `SIGIL_*` | `LODELINE_*` |
| Units | `sigil*.service` | `lodeline*.service` |
| MCP servers | `sigil-check`, `sigil-fleet` | `lodeline-check`, `lodeline-fleet` |
| HTTP headers | `x-sigil-*` | `x-lodeline-*` |
| Manager cookies | `sigil_session`, `sigil_oidc_binding` | `lodeline_session`, `lodeline_oidc_binding` |

## 1. Binaries and packages

**Linux packages.** Install the new `.deb` or `.rpm` for each Sigil package on the
host. They replace the old ones.

No release publishes a `lodeline-proxy` package yet, so there is nothing to
download for it. On a host with `sigil-proxy`, build the package first and name it
in the same `apt-get` or `dnf` run as the others. If you leave it out, `sigil-proxy`
holds back the `/etc/sigil` move, and `lodeline-sender` stays down because
`/etc/lodeline/sender.yaml` does not exist yet.

Check out the release tag, for example `git checkout v0.12.0`. Install `cargo-deb`,
or `cargo-generate-rpm` and the `rpm-build` system package, then build:

```sh
packaging/build.sh proxy deb    # target/debian/lodeline-proxy_*.deb
packaging/build.sh proxy rpm    # target/generate-rpm/lodeline-proxy-*.rpm
```

As a precaution, build on the distribution you will install on, or pass
`--target x86_64-unknown-linux-musl`, which writes the `.deb` to
`target/x86_64-unknown-linux-musl/debian/`. The `.deb` depends on `libc6` with no
version, so a package built against a newer glibc could install and then fail at
start.

- `.deb`: each `lodeline*` package declares Conflicts and Replaces for the
  matching `sigil*` package below version 0.12.
- `.rpm`: each `lodeline*` package declares Obsoletes for the matching `sigil*`
  package below version 0.12.
- `lodeline-sender`, `lodeline-server`, `lodeline-signer` and `lodeline-proxy` also
  Provide their old names. `lodeline` does not Provide `sigil`.

The bound protects the Sigil ebook editor, which Debian, Ubuntu and Fedora package
as `sigil` at version 1.x or later. Installing Lodeline leaves that editor alone.
On Debian ports and end-of-life Ubuntu releases the editor is still at 0.9.x and
counts as old. No Lodeline package ships for those.

Upgrade every Sigil package on the host in the same run. The shared `/etc/sigil`
and `/var/log/sigil` directories move only after `dpkg-query` or `rpm -q` shows no
`sigil`, `sigil-sender`, `sigil-server` or `sigil-proxy` package below version
0.12, because a running old sender still reads them. A partial upgrade leaves them
in place and prints a notice that names the packages. Its `Upgrade those packages
to finish` also covers removing one: an upgrade finishes the move by itself, but a
removal runs no Lodeline script, so rerun `migrate-from-sigil` afterwards. Another
program named `sigil` in `/usr/bin`, such as NOMARJ/sigil, does not hold them back.

Removing `sigil-proxy` without installing `lodeline-proxy` leaves
`/var/lib/sigil-proxy` behind, and nothing tells you. Every Lodeline package ships
the same script under its own directory, so move the state with the one installed:

```sh
/usr/libexec/lodeline/migrate-from-sigil proxy         # lodeline
/usr/libexec/lodeline-sender/migrate-from-sigil proxy  # lodeline-sender
/usr/libexec/lodeline-server/migrate-from-sigil proxy  # lodeline-server
```

**Debian and Ubuntu.** First check what the `sigil` package on the host is:

```sh
dpkg-query -W -f='${Version}\n' sigil
```

If it prints a 0.x version, it is old Sigil. Name it with a trailing `-` so apt
removes it. Name one `.deb` for each old package, because a `./lodeline*.deb` glob
also installs packages the host did not have:

```sh
sudo apt-get install ./lodeline_*.deb ./lodeline-sender_*.deb sigil-
```

If it prints 1.x or later, or the package is not installed, leave `sigil-` off. The
`-` has no version bound, so it would remove a real editor, and on a host whose
repository has no `sigil` package apt can refuse the name:

```sh
sudo apt-get install ./lodeline-sender_*.deb ./lodeline-server_*.deb
```

Without `sigil-` on a 0.x host, a release whose repository carries the Sigil ebook
editor satisfies `Conflicts: sigil (<< 0.12)` by upgrading `sigil` to the editor
instead of removing it. Every test of this did so: 281 packages, a 174 MB download
and 768 MB of disk. Your data is not harmed, and the `sigil` package stays installed
as the editor. No version bound that keeps the editor installable prevents this. A
host that wants the editor can install it afterwards with `apt-get install sigil`.

apt removes the old packages, unpacks all the new ones, then configures them one
at a time in an order it picks. dpkg keeps a removed package's conffiles, so
`dpkg -l` lists each removed package as `rc` and `/etc/sigil` still holds its
`*.example` files. An `rc` entry does not hold the move back, and the script
leaves those files alone (section 2). If you left `sigil-` off and apt upgraded the
editor, `sigil` shows as `ii` at 1.x, not `rc`, and the editor is not an old
package.

If a package stops at a conffile prompt, or `apt-get` with no terminal exits 100
with `dpkg: error processing package`, an old example is already at the new path,
for example from an earlier test build or a copy made by hand. Finish with:

```sh
apt-get -f install -o Dpkg::Options::=--force-confold
```

This keeps the file that is there and leaves the packaged example beside it as
`<name>.dpkg-dist`. The stopped packages then configure, and their scripts move
what is left.

On a host with no package database, the script cannot tell what `/usr/bin/sigil`
is. It keeps the shared directories and prints the command that moves them.

**Script installs and Windows `.zip`.** Run the new installer. It writes the new
binary names and does not remove the old ones. Delete the old `sigil*` binaries
by hand, including `%LOCALAPPDATA%\Programs\sigil` on Windows. The installer's
`SIGIL_INSTALL_DIR` is now `LODELINE_INSTALL_DIR`, with the same defaults under
the new name.

**If you do nothing.** Old script-installed binaries keep running as they were,
and nothing updates them. Old packages stay until you replace them.

## 2. Config, state and log paths

The package post-install script runs `migrate-from-sigil` for you. It moves what
it can to the new path, and it never overwrites or deletes data.

| Old | New | Moved by package |
|---|---|---|
| `/etc/sigil` | `/etc/lodeline` | any, once no old package is left |
| `/etc/sigil-server` | `/etc/lodeline-server` | `lodeline-server` |
| `/var/log/sigil` | `/var/log/lodeline` | any, once no old package is left |
| `/var/lib/sigil` | `/var/lib/lodeline` | `lodeline` |
| `/var/lib/sigil-sender`, `/var/log/sigil-sender` | `/var/lib/lodeline-sender`, `/var/log/lodeline-sender` | `lodeline-sender` |
| `/var/lib/sigil-server`, `/var/log/sigil-server` | `/var/lib/lodeline-server`, `/var/log/lodeline-server` | `lodeline-server` |
| `/var/lib/sigil-proxy`, `/var/log/sigil-proxy` | `/var/lib/lodeline-proxy`, `/var/log/lodeline-proxy` | `lodeline-proxy` |

Rules for each directory:

- The new path is absent or empty: the old directory is renamed onto it. If it
  holds packaged examples, it is copied there without them.
- The new path has entries: each old entry that is not there yet moves in. An
  entry already at the new path is never overwritten. It stays at the old path
  and the script lists it.
- Packaged `*.example` files never move, at any depth, including under
  `/etc/sigil/proxy/`. The new packages own those names, and a changed file there
  stops dpkg at a conffile prompt. A subdirectory that holds one is copied without
  it, keeping its owner and mode. The old examples stay at the old path and the
  script reports them as safe to remove, so a non-empty `/etc/sigil` afterwards is
  not a failure. Delete them, or run `dpkg --purge` on the `rc` packages. If
  `sigil` is `ii` because apt upgraded it to the editor, it is not `rc` and a purge
  would remove the editor. `/etc/sigil` can then stay after you purge the others.
  Delete the old `*.example` files by hand.
- The script says `moved` only when everything moved. Otherwise it says
  `kept in <dir>:` and names what is left.
- Across filesystems, for example when the new directory is its own mount, each
  entry is copied to `<name>.lodeline-migrate-tmp` in the new directory, renamed,
  and only then removed from the old one. A killed run never leaves a partial file
  under the real name, and a rerun removes its temporary file and copies again. If
  a run dies between the rename and the removal, the file is at both paths and is
  reported as kept, and the notice names every file still at the old path,
  including a sidecar such as `state.db-wal`. Check each pair with `cmp`, delete
  the old copy, and rerun.

**SQLite databases.** A database moves together with its `-wal`, `-shm` and
`-journal` files. If a database is at both paths, the script stops for that
database, moves none of its files and reports it. Do not merge those files.
Likewise, if the database is at the new path and its `-wal` is still at the old
one, the script leaves the `-wal` where it is, because pairing a WAL with the wrong
database corrupts it. The script moves a database last, so it never leaves this
state itself: something else put that database there. For each case:

1. Keep the service stopped, and back up both directories with `cp -a`.
2. Only where the database came from can prove the pair. Move the `-wal` next to
   it only if you moved that database out of the old path yourself, with every
   service stopped, and nothing has opened it since. `PRAGMA integrity_check` does
   not settle this: a WAL from another database can pass it and silently replace
   pages. It can only rule a pair out, so try the pair on a copy first:

   ```sh
   mkdir /root/wal-check
   cp /var/lib/lodeline/state.db /var/lib/sigil/state.db-wal /root/wal-check/
   sqlite3 /root/wal-check/state.db 'PRAGMA integrity_check;'
   sqlite3 /root/wal-check/state.db '.tables'
   ```

   If it prints `ok` and the tables you expect, move the `-wal` next to the database
   and delete the old `-shm`. SQLite rebuilds it. Keep the backup from step 1 until
   the service has run. In every other case, leave the `-wal` alone and go to step 3.
3. If the service ran and made a fresh database, decide which one to keep. To keep
   the old one, delete the new database and its sidecars, then rerun the script.

**Symlinked directories.** If an old state or log directory is a symlink, the
script moves nothing and prints the link target. Lodeline would otherwise start
on an empty directory, and the agent would make a fresh `state.db` and a new
`host_id`. Rename the link before you start the service, then rerun the script
to repair ownership. The link target is never changed.

```sh
mkdir -p /var/lib/lodeline && rm -f /var/lib/lodeline/*.example && rmdir /var/lib/lodeline && find /var/lib/sigil/ -name '*.example' ! -type d -exec rm -f {} + && mv /var/lib/sigil /var/lib/lodeline
```

This works whether the new directory is missing, empty or holds only packaged
`*.example` files. If it holds anything else, `rmdir` fails and nothing moves. The
old examples are deleted just before the `mv`, so none arrives at the new path.

Files owned by the `sigil` user and group, or by `sigil-proxy`, move to the
matching `lodeline` account. Every run repairs this across all the new
directories, as soon as the new account exists. The old accounts stay on the host.
Accounts from LDAP or sssd count. When only one account of a pair resolves, the
script skips the repair for that pair and prints a note. Fix the lookup, then rerun.

If the post-install run was staged or interrupted, finish it by hand. Pick the
component that matches the package:

```sh
/usr/libexec/lodeline/migrate-from-sigil agent
/usr/libexec/lodeline-sender/migrate-from-sigil sender
/usr/libexec/lodeline-server/migrate-from-sigil server
/usr/libexec/lodeline-proxy/migrate-from-sigil proxy
```

The script is safe to run again.

**Config contents.** The script does not edit files. A config that names an old
absolute path keeps pointing at the old path. Every run lists each such file
under `/etc`, including while `/etc/sigil` waits. Edit them before you start the
service. In `sender.yaml` that means:

| Key | New default |
|---|---|
| `client_cert_path` | `/etc/lodeline/client.crt` |
| `client_key_path` | `/etc/lodeline/client.key` |
| `server_ca_path` | `/etc/lodeline/server-ca.pem` |
| `events_dir` | `/var/log/lodeline` |
| `offset_path` | `/var/lib/lodeline-sender/sender-offset.json` |
| `agent_control` | `/var/run/lodeline/control.sock` |
| `dead_letter_dir` | `/var/log/lodeline-sender/dead-letter` |

In `proxy.yaml`, certificates and keys default to the subdirectory `/etc/sigil/proxy/`,
which is now `/etc/lodeline/proxy/`:

| Key | New default |
|---|---|
| `state_dir` | `/var/lib/lodeline-proxy` |
| `tls_cert_file` | `/etc/lodeline/proxy/listener.crt` |
| `tls_key_file` | `/etc/lodeline/proxy/listener.key` |
| `client_cert_file` | `/etc/lodeline/proxy/client.crt` |
| `client_key_file` | `/etc/lodeline/proxy/client.key` |
| `ca_file` | `/etc/lodeline/proxy/ca.pem` |
| `credentials.<ref>.secret_file`, for upstream secrets | `/etc/lodeline/proxy/example-upstream.secret` |

In `server.yaml`, edit these keys if you set them:

| Key | New path |
|---|---|
| `events_out_dir` | `/var/lib/lodeline-server/events` |
| `policy_bundle_path` | `/var/lib/lodeline-server/signed-policy.json` |
| `tls_cert_path` | `/etc/lodeline/server.crt` |
| `tls_key_path` | `/etc/lodeline/server.key` |
| `client_ca_path` | `/etc/lodeline/client-ca.pem` |

Other path keys, such as `host_allowlist_path` and the `enroll_*` paths, need the
same edit when they name an old directory.

**Per-user paths.** No package owns these, so move them yourself:

| Platform | Old | New |
|---|---|---|
| Linux, macOS | `~/.config/sigil` | `~/.config/lodeline` |
| Linux, macOS | `~/.local/state/sigil` | `~/.local/state/lodeline` |
| Windows | `%LOCALAPPDATA%\Sigil` | `%LOCALAPPDATA%\Lodeline` |
| Windows | `%ProgramData%\Sigil` | `%ProgramData%\Lodeline` |

The control socket moves from `/var/run/sigil/control.sock` to
`/var/run/lodeline/control.sock`, and the Windows named pipe from
`\\.\pipe\sigil-control` to `\\.\pipe\lodeline-control`. Both are created at
start, so there is nothing to move.

**If you do nothing.** On a Linux package upgrade the script handles the system
paths, and only the config edits and per-user paths above remain. On macOS,
Windows and script installs nothing moves. The new binaries start with built-in
defaults, with no policy, keys or history, while your old files sit unused.

## 3. Environment variables

Rename every `SIGIL_*` variable to `LODELINE_*`. Only the prefix changes. Update
shell profiles, unit drop-ins, CI variables and container definitions.

| Variable | Used by |
|---|---|
| `LODELINE_PROFILE`, `LODELINE_VERSION`, `LODELINE_INSTALL_DIR` | installers |
| `LODELINE_BASE_URL`, `LODELINE_BASE_TOKEN` | installers, fetching from a server instead of GitHub |
| `LODELINE_AGENT_CONTROL_SOCKET` | agent and CLI |
| `LODELINE_HOOK_SOCKET`, `LODELINE_HOOK_DECIDE_SOCKET` | `lodeline-hook` |
| `LODELINE_HOST_ID` | agent host identity |
| `LODELINE_LOG` | log filter |
| `LODELINE_SERVER_BASE_URL`, `LODELINE_SERVER_READ_TOKEN` | `lodeline-mcp` fleet mode |
| `LODELINE_CA_CERT`, `LODELINE_CLIENT_CERT`, `LODELINE_CLIENT_KEY` | `lodeline-mcp` direct mTLS |
| `LODELINE_BUILD_PUBKEYS`, `LODELINE_BUILD_TARGET` | release builds |

Other `LODELINE_*` names are test and demo switches. List every name the code
reads with `git grep -hoE 'LODELINE_[A-Z0-9_]+' | sort -u`.

One name stays. The GitHub Actions secret that signs releases is still
`SIGIL_BUILD_SIGNING_KEY`. A repository rename keeps its secrets, so there is
nothing to do, and a renamed secret would silently ship unsigned releases.

**If you do nothing.** The old variables are ignored. A fleet-mode `lodeline-mcp`
starts without its server URL and token and falls back to local mode. A sender or
server that took a secret from `SIGIL_*` starts without it.

## 4. systemd units

The new packages ship `lodeline.service`, `lodeline-sender.service`,
`lodeline-server.service` and `lodeline-proxy.service`. They use the matching
`lodeline` user and group, sysusers entries and tmpfiles rules.

Packages never enable or start a service, and the old unit's enabled state does
not carry over. Services stay stopped after the upgrade, by design, and the
post-install output names the `systemctl enable --now` command for its package.
Finish the config edits in section 2 first, then enable what you ran before:

```sh
systemctl daemon-reload
systemctl enable --now lodeline            # agent
systemctl enable --now lodeline-sender
systemctl enable --now lodeline-server
systemctl enable --now lodeline-proxy
```

`lodeline-proxy` requires its state directory to be mode 0700, and the packaged
unit sets `StateDirectoryMode=0700`. If you use a custom `state_dir` or a drop-in,
keep that directory at 0700 and owned by `lodeline-proxy`, or the proxy refuses to
start.

Move any unit drop-ins from `/etc/systemd/system/sigil*.service.d/` to
`/etc/systemd/system/lodeline*.service.d/`. On SELinux hosts the policy module is
now `lodeline`, with domains such as `lodeline_agent_t`.

**macOS and Windows.** No package installs a service there, so you wrote it by
hand and you replace it by hand. On macOS, unload the `com.sigil.agent` LaunchDaemon
and remove `/Library/LaunchDaemons/com.sigil.agent.plist`. Then create
`com.lodeline.agent.plist` that runs `lodeline`, as in
[the macOS guide](install-macos-agent.md), and load it. On Windows, remove any
service named `Sigil` and any scheduled task that runs `sigil.exe`, then register
the new binary under the name `Lodeline`.

**If you do nothing.** The old package is gone and its unit with it. No Lodeline
service runs until you enable it, so the host stops reporting posture and
stops receiving policy.

## 5. Hooks

Old hook entries run `sigil-hook`, which an upgrade removes. Re-register them
with the new binary for each agent, repeating any flags you used before:

```sh
lodeline-hook install --agent claude-code --write
lodeline-hook install --agent codex --enforce --write
```

`lodeline-hook install` finds its own old `sigil-hook` entries in the agent's
settings, replaces them, and leaves every other hook alone. It is safe to run
again. `lodeline-hook uninstall` removes both old and new entries. For Grok it
also retires the old `~/.grok/hooks/sigil-hook.json` file.

Install is observe-only unless you pass `--enforce`. An enforcing hook comes back
as observe-only if you leave the flag off, so repeat it.

If the installer added its read-only allowlist to `~/.claude/settings.json`, that
file still holds `Bash(sigil:*)` in `permissions.allow` and `Bash(sigil run:*)`
and `Bash(sigil-hook:*)` in `permissions.deny`. Add the `lodeline` equivalents and
remove the old rules. The installer prints the snippet again when you rerun it.

The legacy Antigravity plugin is the exception. `lodeline-hook install --agent
antigravity --force` registers a plugin named `lodeline-hook` and leaves any old
plugin named `sigil-hook` in place. Remove it with `agy plugin uninstall
sigil-hook`.

**If you do nothing.** Each old entry points at a missing command. The agent
reports a hook error or skips the hook, depending on the agent. Observation
and any enforcement stop until you re-register. The scanner still recognises old
`sigil-hook` entries as Lodeline's own, so a half-upgraded host does not flag
itself.

## 6. MCP client config

`lodeline-mcp` registers under new server names. Update each MCP client, such as
Claude Desktop, Claude Code, Codex or Cursor:

| Old | New |
|---|---|
| server `sigil-check` | server `lodeline-check` |
| server `sigil-fleet` | server `lodeline-fleet` |
| command `sigil-mcp` | command `lodeline-mcp` |

Tool names (`my_risk`, `my_guard_detail`, `my_findings`) do not change. Prompts
and saved allow-lists in the client that name `sigil-check` need the same edit.

**If you do nothing.** The client tries to launch `sigil-mcp`, which no longer
exists, and the server shows as failed. The scanner treats the old entry as
Lodeline's own, so it adds no finding for it.

## 7. HTTP headers

The management API reads `x-lodeline-requested-by` instead of
`x-sigil-requested-by`. Update every client and reverse proxy that sets it,
including the CLI. An old `sigil-server proxy` command against a new server still
succeeds, but its `requested_by` is dropped without an error.

The proxy treats `x-lodeline-*` request headers as its own auth headers and never
forwards them upstream. It strips `x-sigil-*` the same way, so an old client's
`x-sigil-auth` value does not reach an upstream. The proxy does not accept that
header. The strip is a security filter, not a compatibility path.

**If you do nothing.** Management calls lose the requester name in the audit
trail, silently. Clients that send `x-sigil-auth` get no auth from it.

## 8. Fleet certificates and signed policy

Certificates keep working. You do not reissue them. The proxy certificate SAN is
still `<proxy_id>.proxy.sigil.invalid`, and the server only accepts that suffix.

Signed policy, deployments, audit chains, registry fingerprints and release
manifests verify as before. Their hash and signature domains and the release key
id (`sigil-build-2026b`) did not change.

Check three things on each fleet host after the move:

- The sender's config points at the new certificate paths under `/etc/lodeline`.
- The server's `tls_cert_path`, `tls_key_path` and `client_ca_path`, and the
  manager's CA path, resolve under the new directories.
- `lodeline-sign verify` still passes on your current policy bundle.

**If you do nothing.** The certificates are fine. A sender that still names
`/etc/sigil/...` fails to find them once the directory has moved.

## 9. The manager

`lodeline-manager` renames its env vars, cookies and repository.

| Old | New |
|---|---|
| `SIGIL_SERVER_BASE_URL` | `LODELINE_SERVER_BASE_URL` |
| `SIGIL_SERVER_READ_TOKEN` | `LODELINE_SERVER_READ_TOKEN` |
| `SIGIL_SERVER_CA_PATH` | `LODELINE_SERVER_CA_PATH` |
| `SIGIL_SERVER_CLIENT_CERT_PATH` | `LODELINE_SERVER_CLIENT_CERT_PATH` |
| `SIGIL_SERVER_CLIENT_KEY_PATH` | `LODELINE_SERVER_CLIENT_KEY_PATH` |
| `SIGIL_INSECURE_COOKIE` | `LODELINE_INSECURE_COOKIE` |
| cookie `sigil_session` | cookie `lodeline_session` |
| cookie `sigil_oidc_binding` | cookie `lodeline_oidc_binding` |
| `/etc/sigil-manager/` | `/etc/lodeline-manager/` |

The read token on the server side is `LODELINE_SERVER_READ_TOKEN` too. Set the
same value in both places.

**If you do nothing.** The manager cannot find its server URL or token and
stops at startup with a config error about the missing variables, unless
`MOCK_FLEET=1`. After you set the new variables, every
user signs in once more because the old session cookie is not read. An OIDC
sign-in that began before the upgrade fails once and works on retry.

## What stays the same

Hash and signature domains, the release key id and the proxy SAN suffix keep
their old bytes or names on purpose, because changing them would break
verification of existing bundles and stored data.

The site moved to `lodeline.dev`. `sigilworks.net` redirects there.

Everything else keeps its meaning: the policy format, the event schema, the
exit codes and the "measures, does not block by default" behaviour.

## Check the result

```sh
lodeline --version
lodeline scan
lodeline doctor
systemctl status lodeline lodeline-sender lodeline-server lodeline-proxy
```

`Unit lodeline-server.service could not be found` is harmless on a host that does
not run the server. Name only the units you installed.

`lodeline scan` should print a `Lodeline scan` summary. If it reports no policy or
no history on a host that had both, the move in section 2 did not run. Run
`migrate-from-sigil` again and read what it prints.
