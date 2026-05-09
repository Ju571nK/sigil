# Recommended SIEM rules for ANDEDA

ANDEDA itself does not enforce these rules — they live in the customer's SIEM.

## Splunk inputs.conf

```
[monitor:///var/log/andeda/events-*.jsonl]
sourcetype = andeda:event:json
disabled   = false
```

## Datadog Agent

```yaml
logs:
  - type: file
    path: /var/log/andeda/events-*.jsonl
    service: andeda
    source: andeda
```

## Heartbeat absence (host went silent)

```
trigger:  evidence.kind == "heartbeat" absent for 90s by host_id
severity: medium
action:   page on-call security
```

## Idempotent dedup (spec 1.4)

```
key:    (host_id, target_id, evidence.after_hash, floor(ts to 60s))
keep:   first; drop subsequent
```

## Critical-tier integrity recheck mismatch

```
trigger:  evidence.kind == "file_change"
          AND evidence.recheck_hash IS NOT NULL
          AND evidence.recheck_hash != evidence.after_hash
severity: high
note:     transient state existed between change and recheck
```

## Channel stall warning

```
trigger:  count(evidence.kind == "channel_stall") > 3 in 5min by host_id
severity: low
```

## Rate-limit exceeded

```
trigger:  evidence.kind == "rate_limit_exceeded" by host_id
severity: medium
note:     a process is generating events faster than 100/sec for one target
```
