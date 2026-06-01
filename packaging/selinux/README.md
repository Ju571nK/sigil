# Sigil SELinux policy (#69)

Confines the three de-rooted sigil daemons (#10) into dedicated SELinux domains
on RHEL-family systems (Rocky/RHEL/Fedora) instead of leaving them in
`unconfined_service_t`:

| daemon | domain | binary type |
|--------|--------|-------------|
| `sigil` (agent) | `sigil_agent_t` | `sigil_agent_exec_t` |
| `sigil-sender`  | `sigil_sender_t` | `sigil_sender_exec_t` |
| `sigil-server`  | `sigil_server_t` | `sigil_server_exec_t` |

State/log/runtime get dedicated file types (`sigil_var_lib_t`, `sigil_var_log_t`,
`sigil_conf_t`, `sigil_*_var_lib_t`, …). The agent can read any file (it does
file-integrity monitoring by design) but is otherwise tightly confined; the
sender/server only touch their own state, the agent's spool/socket, and the
network they need.

## Why `init_nnp_daemon_domain`

The units keep systemd's `NoNewPrivileges=yes` plus sandboxing
(`ProtectSystem=strict`, `ProtectKernelModules=yes`, …). Under `NoNewPrivileges`
the kernel blocks the exec-time SELinux domain transition unless the policy
grants `process2:nnp_transition` — otherwise it falls back to a *bounded*
transition and is denied. `init_nnp_daemon_domain(...)` grants exactly that, so
the daemons get **both** the systemd hardening **and** SELinux confinement with
no unit drop-in.

## Build + install (Rocky/RHEL 9)

```sh
sudo dnf install -y selinux-policy-devel   # provides the devel Makefile
make -f /usr/share/selinux/devel/Makefile sigil.pp
sudo semodule -i sigil.pp
sudo restorecon -Rv /usr/bin/sigil* /var/lib/sigil* /var/log/sigil* /etc/sigil
sudo systemctl restart sigil sigil-server sigil-sender   # whichever are installed
```

Verify confinement + zero denials:

```sh
ps -eZ | grep sigil          # → sigil_agent_t / sigil_sender_t / sigil_server_t
sudo ausearch -m avc -ts recent | grep sigil   # → nothing
```

Remove: `sudo semodule -r sigil`.

Verified enforcing-clean on Rocky Linux 9.7 (aarch64) with all three daemons
running (0 AVC denials, even with `dontaudit` disabled).

> The `.deb` path is unaffected — Debian/Ubuntu use AppArmor, not SELinux. An
> AppArmor profile would be a sibling follow-up.
