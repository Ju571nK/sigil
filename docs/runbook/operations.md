# Operations notes

## Default paths

| Item             | macOS                              | Windows                              |
|------------------|------------------------------------|--------------------------------------|
| Binary           | /usr/local/bin/sigil              | %PROGRAMFILES%\Sigil\sigil.exe     |
| Policy           | /etc/sigil/policy.yaml            | %ProgramData%\Sigil\policy.yaml     |
| Events           | /var/log/sigil/                   | %ProgramData%\Sigil\events\         |
| State            | /var/lib/sigil/state.db           | %ProgramData%\Sigil\state.db        |
| Service id       | com.sigil.agent (launchd label)   | Sigil (Windows Service name)        |
| Control IPC      | /var/run/sigil/control.sock       | \\.\pipe\sigil-control              |

## Signal handling

- Unix `SIGINT` / `SIGTERM`, Windows Ctrl-C: stop event producers and new IPC
  connections, drain queued pipeline events, durably flush JSONL, and exit 0.
- Accepted IPC requests have up to five seconds to finish. Stalled requests
  are cancelled and cause a nonzero exit; Unix socket files are removed.
- The overall graceful drain has a 30-second deadline. Timeout or sink failure
  returns nonzero, not a successful flush. Runtime teardown gets one additional
  second for blocking workers.
- A pipeline panic triggers cancellation immediately and a best-effort
  `AgentDying` event before sink closure; exit 101 unless draining times out.
- Use `sigil reload` for policy reload. `SIGHUP` is not a reload interface.

## Watch-root recovery

- Missing or replaced roots are retried every five seconds. Nonrecursive
  patterns such as `/Applications/*.app/Contents/Info.plist` resolve only
  matching directory components; discovery does not recursively watch all of
  `/Applications`. Symlink directories below a wildcard are not followed.
- After registration, current files are replayed through normal filtering and
  hashing. This recovers current state, not historical changes that occurred
  and disappeared while the root was unavailable. Native and polling backends
  share this behavior; policy reload removes obsolete subscriptions.

## Logs

- JSONL events: as configured above. SIEM consumes.
- Diag log: `tracing` to stderr (captured by launchd / Windows Event Log).
  Configure level via `SIGIL_LOG=debug,sigil_core=info`.
