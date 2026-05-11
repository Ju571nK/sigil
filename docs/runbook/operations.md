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

- `SIGTERM` / Ctrl-C → graceful drain → exit 0
- `SIGHUP` → policy reload (re-parse, swap `Arc<Policy>`, re-probe FDA)
- panic in any pipeline task → emit AgentDying → fsync → exit 101

## Logs

- JSONL events: as configured above. SIEM consumes.
- Diag log: `tracing` to stderr (captured by launchd / Windows Event Log).
  Configure level via `SIGIL_LOG=debug,sigil_core=info`.
