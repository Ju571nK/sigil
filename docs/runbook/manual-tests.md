# Manual pre-release test runbook

Five scenarios that automation cannot cover.

## 1. macOS Full Disk Access flow

1. Install ANDEDA without granting FDA. Run `andeda doctor` — expect `[WARN]
   Full Disk Access: NOT granted`.
2. Run the daemon. Confirm a `permission_missing` event appears in
   `/var/log/andeda/events-*.jsonl`.
3. Open System Settings → Privacy & Security → Full Disk Access. Add
   `/usr/local/bin/andeda`.
4. Send SIGHUP: `sudo launchctl kickstart -k system/com.andeda.agent`.
5. Confirm next heartbeat's `events_by_kind` no longer contains
   `permission_missing`.

## 2. Windows Service registration

1. `sc create Andeda binPath= "C:\Program Files\Andeda\andeda.exe run" start= auto`
2. `sc start Andeda` — confirm Event Viewer shows successful start.
3. Modify a watched config file; confirm event in `%ProgramData%\Andeda\events`.
4. `sc stop Andeda` — confirm graceful shutdown (final heartbeat with
   `is_final: true` in the events file).

## 3. Real SIEM ingest

1. Configure Splunk Universal Forwarder per `siem-rules.md`.
2. Run ANDEDA, generate events via test changes.
3. Search Splunk: `index=main sourcetype=andeda:event:json`.
4. Force a rotation (write 100 MB or wait for midnight UTC). Confirm rotated
   files are picked up without gaps.

## 4. EDR coexistence

1. Install ANDEDA on a workstation running CrowdStrike Falcon (or Defender ATP).
2. Confirm ANDEDA daemon process is not flagged or blocked.
3. Confirm both agents continue running for 24 hours.

## 5. MDM dry-run

1. Use Jamf Pro (macOS) or Intune (Windows) to deploy the signed installer
   package.
2. After deployment, run `andeda doctor` on the target machine.
3. Expect exit code 0 or 1 with only known `[WARN]` lines (e.g., FDA
   pending grant).
