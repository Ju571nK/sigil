# Operations notes

## Default paths

| Item             | macOS                              | Windows                              |
|------------------|------------------------------------|--------------------------------------|
| Binary           | /usr/local/bin/andeda              | %PROGRAMFILES%\Andeda\andeda.exe     |
| Policy           | /etc/andeda/policy.yaml            | %ProgramData%\Andeda\policy.yaml     |
| Events           | /var/log/andeda/                   | %ProgramData%\Andeda\events\         |
| State            | /var/lib/andeda/state.db           | %ProgramData%\Andeda\state.db        |
| Service id       | com.andeda.agent (launchd label)   | Andeda (Windows Service name)        |
| Control IPC      | /var/run/andeda/control.sock       | \\.\pipe\andeda-control              |

## Signal handling

- `SIGTERM` / Ctrl-C → graceful drain → exit 0
- `SIGHUP` → policy reload (re-parse, swap `Arc<Policy>`, re-probe FDA)
- panic in any pipeline task → emit AgentDying → fsync → exit 101

## Logs

- JSONL events: as configured above. SIEM consumes.
- Diag log: `tracing` to stderr (captured by launchd / Windows Event Log).
  Configure level via `ANDEDA_LOG=debug,andeda_core=info`.
