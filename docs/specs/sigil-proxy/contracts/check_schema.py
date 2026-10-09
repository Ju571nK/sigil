"""Contract/fixture checks only; no producer, ingestion, registry or ledger implementation.

Requires jsonschema==4.26.0. Related: R1-R3, PX-006/009/010/011/012/015,
AC-01/03/05/06/07. Provenance and durable ingestion need integration tests later.
"""
import copy
import itertools
import json
from pathlib import Path
from uuid import UUID

from jsonschema import Draft202012Validator, FormatChecker

root = Path(__file__).resolve().parent
schema = json.loads((root / "proxy-event.schema.json").read_text())
example = json.loads((root / "invocation-started.example.json").read_text())
Draft202012Validator.check_schema(schema)
v = Draft202012Validator(schema, format_checker=FormatChecker())
ids = itertools.count(100)


def variant(base):
    event = copy.deepcopy(base)
    event["event_id"] = str(UUID(int=next(ids)))
    return event


cancel = variant(example)
cancel.update(event_type="invocation.cancel_requested", sequence=2)
cancel["payload"] = {"invocation_id": example["payload"]["invocation_id"]}
completion = variant(example)
completion.update(event_type="invocation.completed", sequence=3)
completion["payload"] = {
    "invocation_id": example["payload"]["invocation_id"],
    "outcome": "success", "delivery_state": "sent",
    "duration_ms": 1200, "response_bytes": 32,
}
positive = [("tool start", example), ("cancel observation", cancel),
            ("success after cancellation", completion)]
negative = []


def reject_field(label, base, path, value):
    event = variant(base)
    target = event
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    negative.append((label, event))


# Closed objects, identity representation and envelope validation.
for label, base, path, value in [
    ("raw arguments", example, ("payload", "arguments"), {"token": "canary"}),
    ("unknown schema", example, ("schema_version",), 2),
    ("human self claim", example, ("payload", "actor", "actor_kind"), "human"),
    ("bad event UUID", example, ("event_id",), "invalid"),
    ("zero sequence", example, ("sequence",), 0),
    ("raw error", completion, ("payload", "raw_error"), "canary"),
    ("raw result", completion, ("payload", "result"), "canary"),
    ("unknown event", example, ("event_type",), "unknown"),
    ("raw tool name", example, ("payload", "tool_name"), "canary-secret"),
    ("tool object raw name", example, ("payload", "tool", "name"), "canary-secret"),
    ("raw metadata ref", example, ("payload", "tool", "metadata_ref"), "canary-secret"),
    ("cancel as terminal outcome", completion, ("payload", "outcome"), "cancel_requested"),
    ("cancel raw reason", cancel, ("payload", "reason"), "canary-secret"),
    ("cancel outcome", cancel, ("payload", "outcome"), "success"),
]:
    reject_field(label, base, path, value)
for field in ("actor", "tool"):
    event = variant(example)
    del event["payload"][field]
    negative.append((f"missing {field}", event))

# Explicit unavailable representation is bounded and restricted to pre-dispatch
# rejection by the semantic contract; schema alone cannot enforce cross-event facts.
rejected_starts = []
for reason in ("malformed", "unresolved"):
    event = variant(example)
    event["payload"]["tool"] = {"status": "unavailable", "reason": reason}
    positive.append((f"rejected call {reason}", event))
    rejected_starts.append(event)
    reject_field(f"unavailable plus reference {reason}", event,
                 ("payload", "tool", "metadata_ref"), example["payload"]["tool"]["metadata_ref"])
    reject_field(f"raw unavailable reason {reason}", event,
                 ("payload", "tool", "reason"), "canary-secret")

# Canary values are rejected even on malformed/rejected-call starts.
for source in [example, *rejected_starts]:
    for field in ("method", "protocol_version"):
        for value in ("canary-secret", "", None, {"secret": "canary"}):
            reject_field(f"{source['payload']['tool']['status']} unsafe {field}: {value!r}",
                         source, ("payload", field), value)
    reject_field("rejected/raw tool-name path", source,
                 ("payload", "tool_name"), "canary-secret")

# Every audit constant has a positive fixture; unknown is a literal safe value,
# not a passthrough string. Enum membership does not prove negotiated provenance.
start_schema = schema["allOf"][0]["then"]["properties"]["payload"]
for method in start_schema["properties"]["method"]["enum"]:
    event = variant(example)
    event["payload"]["method"] = method
    if method != "tools/call":
        event["payload"].pop("tool")
        reject_field(f"tool on {method}", event, ("payload", "tool"), example["payload"]["tool"])
    positive.append((f"method {method}", event))
for version in start_schema["properties"]["protocol_version"]["enum"]:
    event = variant(example)
    event["payload"]["protocol_version"] = version
    positive.append((f"version {version}", event))
reject_field("empty tool", example, ("payload", "tool"), {})
reject_field("identified without reference", example, ("payload", "tool"), {"status": "identified"})
reject_field("unavailable without reason", example, ("payload", "tool"), {"status": "unavailable"})

# All currently permitted outcome/delivery combinations; cancellation is absent
# from terminal outcomes and may precede success, error, or unknown completion.
complete_schema = schema["allOf"][1]["then"]["properties"]["payload"]
for outcome in complete_schema["properties"]["outcome"]["enum"]:
    for delivery in ("not_sent", "sent", "unknown"):
        event = variant(completion)
        event["payload"].update(outcome=outcome, delivery_state=delivery)
        allowed = (delivery == "sent" if outcome in ("success", "tool_error")
                   else delivery == "not_sent" if outcome == "denied" else True)
        (positive if allowed else negative).append((f"{outcome}/{delivery}", event))

for label, event in positive:
    errors = list(v.iter_errors(event))
    assert not errors, f"positive case {label} failed: {errors}"
for label, event in negative:
    assert list(v.iter_errors(event)), f"negative case {label} was accepted"

# Fixture integrity, not ledger behavior: distinct observations retain one
# invocation ID but have different event IDs/sequences, including cancellation.
lifecycle = [example, cancel, completion]
assert len({event["event_id"] for event in lifecycle}) == len(lifecycle)
assert [event["sequence"] for event in lifecycle] == [1, 2, 3]
assert len({event["payload"]["invocation_id"] for event in lifecycle}) == 1
assert len({event["proxy_id"] for event in lifecycle}) == 1
assert len({event["event_id"] for _, event in positive}) == len(positive)
retransmission = copy.deepcopy(completion)
assert retransmission == completion  # Same observation: keep ID and payload.
conflicting_reuse = copy.deepcopy(completion)
conflicting_reuse["payload"]["duration_ms"] += 1
v.validate(conflicting_reuse)  # Cross-record conflict is NOT a schema violation.
assert conflicting_reuse["event_id"] == completion["event_id"]
assert conflicting_reuse != completion  # Future ledger must reject, not ACK.
print(f"PASS: schema, {len(positive)} positive cases, {len(negative)} rejected cases; "
      "lifecycle IDs, unchanged retransmission and conflicting-reuse fixture assertions")
print("NOT TESTED: producer normalization/provenance, metadata authorization, ingestion/ledger, "
      "durability, protocol support or hardware compatibility")
