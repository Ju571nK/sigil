"""Contract/fixture checks only; no producer, ingestion, registry or ledger implementation.

Install the exact pins in requirements-check.txt in an isolated venv. The script
exits 2 if date-time/uuid format checking is unavailable (N1) or if run under
python -O (T-02-fix-3 m1). Related: R1-R3,
N1-N4/N7-N9, PX-003/006/007/008/010/011/015, AC-03/04/05/06. Provenance, durable
ingestion and the registry need integration tests later.
"""
import copy
import hashlib
import hmac
import itertools
import json
import sys
from importlib import metadata
from pathlib import Path
from uuid import UUID

from jsonschema import Draft202012Validator, FormatChecker, validators


def fatal(message):
    print(f"FATAL: {message}", file=sys.stderr)
    sys.exit(2)


# --- m1: assertions are the checks; refuse to run when Python strips them. -----
if sys.flags.optimize:
    fatal("python -O/-OO disables assert-based checks; run without -O")

# --- N1 preflight: refuse to run without real format checking. -------------
format_checker = FormatChecker()
for fmt in ("date-time", "uuid"):
    if fmt not in format_checker.checkers:
        fatal(f"format checker '{fmt}' unavailable; install requirements-check.txt "
              "(rfc3339-validator is required for date-time)")
for fmt, bad in (("date-time", "canary-secret"), ("date-time", "2026-13-01T00:00:00Z"),
                 ("uuid", "canary-secret")):
    if format_checker.conforms(bad, fmt):
        fatal(f"format checker '{fmt}' accepted {bad!r}; format checking is not effective")
versions = {name: metadata.version(name) for name in ("jsonschema", "rfc3339-validator")}

root = Path(__file__).resolve().parent
schema_text = (root / "proxy-event.schema.json").read_text()
example_text = (root / "invocation-started.example.json").read_text()
schema = json.loads(schema_text)
example = json.loads(example_text)
Draft202012Validator.check_schema(schema)

# --- N7: strict integers. JSON Schema "integer" accepts 1.0; the contract does not.
standard = Draft202012Validator(schema, format_checker=format_checker)
strict_types = Draft202012Validator.TYPE_CHECKER.redefine(
    "integer", lambda _checker, value: isinstance(value, int) and not isinstance(value, bool))
StrictValidator = validators.extend(Draft202012Validator, type_checker=strict_types)
v = StrictValidator(schema, format_checker=format_checker)
ids = itertools.count(100)
INT64_MAX = 2**63 - 1


def variant(base):
    event = copy.deepcopy(base)
    event["event_id"] = str(UUID(int=next(ids)))
    return event


def set_path(event, path, value):
    target = event
    for key in path[:-1]:
        target = target[key]
    if value is DELETE:
        del target[path[-1]]
    else:
        target[path[-1]] = value


DELETE = object()
invocation_id = example["payload"]["invocation_id"]
cancel = variant(example)
cancel.update(event_type="invocation.cancel_requested", sequence=2)
cancel["payload"] = {"invocation_id": invocation_id}
completion = variant(example)
completion.update(event_type="invocation.completed", sequence=3)
completion["payload"] = {
    "invocation_id": invocation_id,
    "outcome": "success", "delivery_state": "sent",
    "duration_ms": 1200, "response_bytes": 32,
}
positive = [("tool start", example), ("cancel observation", cancel),
            ("success after cancellation", completion)]
negative = []


def accept(label, base, path, value):
    event = variant(base)
    set_path(event, path, value)
    positive.append((label, event))
    return event


def reject(label, base, path, value):
    event = variant(base)
    set_path(event, path, value)
    negative.append((label, event))
    return event


# Closed objects, identity representation and envelope validation (R1-R3 baseline).
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
    ("missing actor", example, ("payload", "actor"), DELETE),
    ("missing tool", example, ("payload", "tool"), DELETE),
]:
    reject(label, base, path, value)

# N1: occurred_at is a validated UTC timestamp, never free text. The calendar
# cases pass the shape pattern and are rejected only by the format checker.
for bad in ("canary-secret", "not-a-date", "", "2026-09-27T08:00:00Z\n",
            "2026-09-27T08:00:00+00:00", "2026-09-27t08:00:00z", "2026-09-27 08:00:00Z",
            "2026-09-27T08:00:00.1234567890Z", "2026-13-01T00:00:00Z",
            "2026-02-30T00:00:00Z", 1727424000):
    reject(f"occurred_at {bad!r}", example, ("occurred_at",), bad)
no_format = StrictValidator(schema)  # proves the calendar cases depend on format checking
for bad in ("2026-13-01T00:00:00Z", "2026-02-30T00:00:00Z"):
    probe = dict(example, occurred_at=bad)
    assert no_format.is_valid(probe) and not v.is_valid(probe), bad
# m2: no leap second on the wire; producers clamp to :59.999999999 or use a smeared clock.
reject("occurred_at leap second", example, ("occurred_at",), "2026-12-31T23:59:60Z")
accept("occurred_at clamped leap second", example, ("occurred_at",),
       "2026-12-31T23:59:59.999999999Z")
# M1: epoch_id is a required, closed UUID.
for label, value in (("missing", DELETE), ("raw", "canary-secret"), ("empty", ""),
                     ("uppercase", "3F1C9A52-6B0E-4D2A-9C1E-7A5B2D8E4F10"),
                     ("integer", 1), ("newline", "3f1c9a52-6b0e-4d2a-9c1e-7a5b2d8e4f10\n")):
    reject(f"epoch_id {label}", example, ("epoch_id",), value)
accept("other epoch_id", example, ("epoch_id",), "9b2e4c71-0d3a-4f6b-8e5c-1a7d9f3b2c64")
for good in ("2026-09-27T08:00:00.5Z", "2026-09-27T08:00:00.123456789Z"):
    accept(f"occurred_at {good}", example, ("occurred_at",), good)
for field_path in (("event_id",), ("payload", "invocation_id"),
                   ("payload", "tool", "metadata_ref")):
    reject(f"uppercase {field_path[-1]}", example, field_path,
           "0C635E55-7E09-8E3D-978F-4B88870428F1")
    reject(f"trailing newline {field_path[-1]}", example, field_path,
           "0c635e55-7e09-8e3d-978f-4b88870428f1\n")
for field_path in (("proxy_id",), ("payload", "upstream_id"), ("payload", "actor", "actor_id")):
    reject(f"trailing newline {field_path[-1]}", example, field_path, "proxy-demo\n")

# N3: actor fields are server-side mapping results; client-asserted values are
# not representable and there is no unauthenticated actor.
for label, path, value in [
    ("missing evidence_source", ("payload", "actor", "evidence_source"), DELETE),
    ("client-asserted evidence", ("payload", "actor", "evidence_source"), "client_asserted"),
    ("raw evidence", ("payload", "actor", "evidence_source"), "canary-secret"),
    ("authentication none", ("payload", "actor", "authentication_method"), "none"),
    ("authentication unknown", ("payload", "actor", "authentication_method"), "unknown"),
    ("authentication unauthenticated", ("payload", "actor", "authentication_method"),
     "unauthenticated"),
    ("missing authentication", ("payload", "actor", "authentication_method"), DELETE),
    ("human flag", ("payload", "actor", "human"), True),
    ("client tool-use id in actor", ("payload", "actor", "client_tool_use_id"), "toolu_canary"),
    ("_meta in payload", ("payload", "_meta"), {"claudecode/toolUseId": "toolu_canary"}),
    ("clientInfo in actor", ("payload", "actor", "client_info"), {"name": "canary"}),
    ("raw owner", ("payload", "actor", "credential_owner_id"), "canary secret"),
]:
    reject(label, example, path, value)
accept("owner recorded", example, ("payload", "actor", "credential_owner_id"), "team-ops")
accept("kind unknown", example, ("payload", "actor", "actor_kind"), "unknown")
accept("mtls", example, ("payload", "actor", "authentication_method"), "mtls")

# N9: three tool states. metadata_unavailable is forwarded; unavailable/malformed
# is pre-dispatch rejection. `unresolved` is withdrawn.
example_ref = example["payload"]["tool"]["metadata_ref"]
for reason in ("not_in_inventory", "no_complete_inventory", "ambiguous_in_inventory",
               "registry_conflict"):
    tool = {"status": "metadata_unavailable", "reason": reason}
    event = accept(f"metadata_unavailable {reason}", example, ("payload", "tool"), tool)
    reject(f"metadata_unavailable plus reference {reason}", event,
           ("payload", "tool", "metadata_ref"), example_ref)
malformed = accept("rejected call malformed", example, ("payload", "tool"),
                   {"status": "unavailable", "reason": "malformed"})
for label, tool in [
    ("withdrawn unresolved", {"status": "unavailable", "reason": "unresolved"}),
    ("unavailable plus reference", {"status": "unavailable", "reason": "malformed",
                                    "metadata_ref": example_ref}),
    ("raw unavailable reason", {"status": "unavailable", "reason": "canary-secret"}),
    ("raw metadata_unavailable reason", {"status": "metadata_unavailable",
                                         "reason": "canary-secret"}),
    ("metadata_unavailable without reason", {"status": "metadata_unavailable"}),
    ("cross-status reason", {"status": "unavailable", "reason": "not_in_inventory"}),
    ("cross-status reason 2", {"status": "metadata_unavailable", "reason": "malformed"}),
    ("metadata_unavailable raw name", {"status": "metadata_unavailable",
                                       "reason": "not_in_inventory", "name": "canary"}),
    ("random v4 reference", {"status": "identified",
                             "metadata_ref": "0c635e55-7e09-4e3d-978f-4b88870428f1"}),
    ("empty tool", {}),
    ("identified without reference", {"status": "identified"}),
    ("unavailable without reason", {"status": "unavailable"}),
]:
    reject(label, example, ("payload", "tool"), tool)

# Canary values are rejected on every tool state.
unavailable_start = positive[[label for label, _ in positive].index(
    "metadata_unavailable not_in_inventory")][1]
for source in (example, unavailable_start, malformed):
    status = source["payload"]["tool"]["status"]
    for field in ("method", "protocol_version"):
        for value in ("canary-secret", "", None, {"secret": "canary"}, "2026-07-28",
                      "2025-06-18", "tasks/get"):
            reject(f"{status} unsafe {field}: {value!r}", source, ("payload", field), value)
    reject(f"{status} raw tool-name path", source, ("payload", "tool_name"), "canary-secret")

# Every audit constant has a positive fixture. N8: initialize is always unknown.
start_schema = schema["allOf"][0]["then"]["properties"]["payload"]
for method in start_schema["properties"]["method"]["enum"]:
    event = variant(example)
    event["payload"]["method"] = method
    if method != "tools/call":
        event["payload"].pop("tool")
        reject(f"tool on {method}", event, ("payload", "tool"), example["payload"]["tool"])
    if method == "initialize":
        reject("initialize with negotiated version", event,
               ("payload", "protocol_version"), "2025-11-25")
        event["payload"]["protocol_version"] = "unknown"
    positive.append((f"method {method}", event))
for version in start_schema["properties"]["protocol_version"]["enum"]:
    accept(f"version {version}", example, ("payload", "protocol_version"), version)

# Outcome/delivery/reason matrix (N4). Cancellation is never a terminal outcome.
complete_schema = schema["allOf"][1]["then"]["properties"]["payload"]
outcomes = complete_schema["properties"]["outcome"]["enum"]
deliveries = ("not_sent", "sent", "unknown")
for outcome, delivery, reason in itertools.product(
        outcomes, deliveries, (None, "task_augmentation_unsupported",
                               "upstream_capability_unsupported", "upstream_version_unsupported",
                               "upstream_initialize_unreadable", "modern_request_unsupported",
                               "cancel_no_response", "cancelled_before_dispatch")):
    event = variant(completion)
    event["payload"].update(outcome=outcome, delivery_state=delivery)
    if reason:
        event["payload"]["reason"] = reason
    if reason == "task_augmentation_unsupported":
        allowed = outcome == "protocol_error" and delivery != "unknown"
    elif reason in ("upstream_capability_unsupported", "upstream_version_unsupported",
                    "upstream_initialize_unreadable"):
        allowed = outcome == "protocol_error" and delivery == "sent"
    elif reason == "modern_request_unsupported":
        allowed = outcome == "protocol_error" and delivery == "not_sent"
    elif reason == "cancel_no_response":
        allowed = outcome == "unknown" and delivery != "not_sent"
    elif reason == "cancelled_before_dispatch":
        allowed = outcome == "unknown" and delivery == "not_sent"
    else:
        allowed = (delivery == "sent" if outcome in ("success", "tool_error")
                   else delivery == "not_sent" if outcome == "denied" else True)
    (positive if allowed else negative).append((f"{outcome}/{delivery}/{reason}", event))
# Correction 4 (B1): an intercepted modern request is a start with method and
# protocol_version both unknown and a protocol_error/not_sent completion.
b1_start = variant(example)
b1_start["payload"].update(method="unknown", protocol_version="unknown")
del b1_start["payload"]["tool"]
positive.append(("B1 intercepted modern request start", b1_start))
b1_done = variant(completion)
b1_done["payload"].update(outcome="protocol_error", delivery_state="not_sent",
                          reason="modern_request_unsupported")
positive.append(("B1 intercepted modern request completion", b1_done))
reject("B1 raw modern method", b1_start, ("payload", "method"), "server/discover")
reject("B1 raw modern version", b1_start, ("payload", "protocol_version"), "2026-07-28")
reject("B1 reason as sent", b1_done, ("payload", "delivery_state"), "sent")
reject("B1 raw protocolVersion _meta", b1_start, ("payload", "_meta"),
       {"io.modelcontextprotocol/protocolVersion": "2026-07-28"})
# N10: a task-augmented tools/call is forwarded and audited by its normal outcome
# (the start carries no task marker); tasks/* is refused before dispatch.
task_call_done = variant(completion)
task_call_done["payload"].update(outcome="tool_error", delivery_state="sent")
positive.append(("N10 forwarded task-augmented call, normal outcome", task_call_done))
reject("N10 raw task field on start", example, ("payload", "task"), {"ttl": 60000})
tasks_method_start = copy.deepcopy(b1_start)
tasks_method_start["event_id"] = str(UUID(int=next(ids)))
positive.append(("N10 tasks/* start audited as unknown", tasks_method_start))
tasks_refused = variant(completion)
tasks_refused["payload"].update(outcome="protocol_error", delivery_state="not_sent",
                                reason="task_augmentation_unsupported")
positive.append(("N10 tasks/* refusal", tasks_refused))
# Corrections 2/3: route-level refusal on an upstream initialize answer.
init_start = variant(example)
init_start["payload"].update(method="initialize", protocol_version="unknown")
del init_start["payload"]["tool"]
positive.append(("initialize start for upstream refusal", init_start))
for bad in ("canary-secret", "cancel_requested", "timeout", "", None, "registry_conflict",
            "upstream_unsupported", "2026-07-28"):
    reject(f"completion reason {bad!r}", completion, ("payload", "reason"), bad)

# N7: bounded integers.
for path in (("sequence",), ("payload", "route_revision")):
    accept(f"{path[-1]} int64 max", example, path, INT64_MAX)
    reject(f"{path[-1]} int64 max+1", example, path, INT64_MAX + 1)
    reject(f"{path[-1]} 2^70", example, path, 2**70)
    reject(f"{path[-1]} float 1.0", example, path, 1.0)
    reject(f"{path[-1]} bool", example, path, True)
for field in ("duration_ms", "response_bytes"):
    accept(f"{field} int64 max", completion, ("payload", field), INT64_MAX)
    reject(f"{field} int64 max+1", completion, ("payload", field), INT64_MAX + 1)
    reject(f"{field} negative", completion, ("payload", field), -1)
    reject(f"{field} float 1.0", completion, ("payload", field), 1.0)

for label, event in positive:
    errors = list(v.iter_errors(event))
    assert not errors, f"positive case {label} failed: {[e.message for e in errors]}"
for label, event in negative:
    assert list(v.iter_errors(event)), f"negative case {label} was accepted"

# N7 at the JSON token level: 1.0 and 1e0 parse as floats and are rejected by the
# strict layer, although a standard validator accepts 1.0 as an integer.
token_cases = 0
for token in ("1.0", "1e0", "1E0", "1.00"):
    text = example_text.replace('"sequence": 1,', f'"sequence": {token},', 1)
    assert text != example_text
    parsed = json.loads(text)
    assert list(v.iter_errors(parsed)), f"JSON token {token} accepted as integer"
    token_cases += 1
float_event = variant(example)
float_event["sequence"] = 1.0
assert standard.is_valid(float_event), "expected the standard validator to accept 1.0"

# --- Lifecycle fixture integrity (R3) ------------------------------------------
lifecycle = [example, cancel, completion]
assert len({event["event_id"] for event in lifecycle}) == len(lifecycle)
assert [event["sequence"] for event in lifecycle] == [1, 2, 3]
assert len({event["payload"]["invocation_id"] for event in lifecycle}) == 1
assert len({event["proxy_id"] for event in lifecycle}) == 1
assert len({event["event_id"] for _, event in positive}) == len(positive)


# --- N2: reference model of the dedup rule (fixture, not ledger behaviour). ------
def canonical(event):
    """Full submitted event (every envelope field and the payload)."""
    return json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class LedgerModel:
    """Dedup key (proxy_id, event_id); sequence key (proxy_id, epoch_id, sequence)."""

    def __init__(self):
        self.by_event, self.by_sequence, self.epochs, self.gaps = {}, {}, {}, []
        self.registered_refs = set()

    def classify(self, event, pending=None):
        assert v.is_valid(event), "only schema-valid events reach dedup"
        pending = pending or {}
        key = (event["proxy_id"], event["event_id"])
        seq_key = (event["proxy_id"], event["epoch_id"], event["sequence"])
        stored = pending.get(key, self.by_event.get(key))
        if stored is not None:
            return "duplicate" if stored == canonical(event) else "conflict"
        if seq_key in self.by_sequence or seq_key in pending:
            return "sequence_conflict"
        ref = event["payload"].get("tool", {}).get("metadata_ref")
        if ref is not None and ref not in self.registered_refs:
            return "metadata_ref_pending"
        return "accepted"

    def commit(self, event):
        proxy, epoch = event["proxy_id"], event["epoch_id"]
        known = self.epochs.setdefault(proxy, [])
        if epoch not in known:
            if known:  # a new epoch after an earlier one is an explicit audit gap
                self.gaps.append({"proxy_id": proxy, "kind": "producer_epoch_change",
                                  "previous_epoch_id": known[-1], "epoch_id": epoch})
            known.append(epoch)
        self.by_event[(proxy, event["event_id"])] = canonical(event)
        self.by_sequence[(proxy, epoch, event["sequence"])] = event["event_id"]

    def ingest(self, event):
        result = self.classify(event)
        if result == "accepted":
            self.commit(event)
        return result

    def submit_batch(self, batch):
        """All-or-nothing POST /v1/proxy-events model (M2a). Items name index, event_id
        and a fixed code; 424 also lists pending refs. No field value is echoed."""
        invalid = [{"index": i, "code": "schema_invalid"}
                   for i, event in enumerate(batch) if not v.is_valid(event)]
        if invalid:  # event_id is not trusted before validation: index only
            return 422, {"error": {"code": "invalid_events", "message": "Invalid events",
                                   "items": invalid}}
        staged, results = {}, []
        for event in batch:
            result = self.classify(event, staged)
            results.append(result)
            if result == "accepted":
                staged[(event["proxy_id"], event["event_id"])] = canonical(event)
                staged[(event["proxy_id"], event["epoch_id"], event["sequence"])] = True
        items = lambda codes: [{"index": i, "event_id": e["event_id"], "code": r}
                               for i, (e, r) in enumerate(zip(batch, results)) if r in codes]
        conflicts = items({"conflict", "sequence_conflict"})
        if conflicts:
            return 409, {"error": {"code": "event_conflict", "message": "Conflicting events",
                                   "items": conflicts}}
        pending = items({"metadata_ref_pending"})
        if pending:
            refs = sorted({batch[item["index"]]["payload"]["tool"]["metadata_ref"]
                           for item in pending})
            return 424, {"error": {"code": "metadata_ref_pending",
                                   "message": "Metadata references pending",
                                   "items": pending, "pending_metadata_refs": refs}}
        for event, result in zip(batch, results):
            if result == "accepted":
                self.commit(event)
        return 200, {
            "accepted_event_ids": [e["event_id"] for e, r in zip(batch, results)
                                   if r == "accepted"],
            "duplicate_event_ids": [e["event_id"] for e, r in zip(batch, results)
                                    if r == "duplicate"]}


ledger = LedgerModel()
ledger.registered_refs.add(example["payload"]["tool"]["metadata_ref"])
for event in lifecycle:
    assert ledger.ingest(event) == "accepted"
dedup_cases = {"unchanged retransmission": (copy.deepcopy(completion), "duplicate")}
for label, path, value in [
    ("sequence only", ("sequence",), 4),
    ("occurred_at only", ("occurred_at",), "2026-09-27T08:00:01Z"),
    ("occurred_at same instant, different text", ("occurred_at",), "2026-09-27T08:00:00.0Z"),
    ("payload duration only", ("payload", "duration_ms"), 1201),
    ("payload outcome only", ("payload", "outcome"), "tool_error"),
]:
    mutated = copy.deepcopy(completion)
    set_path(mutated, path, value)
    dedup_cases[f"conflict: {label}"] = (mutated, "conflict")
same_sequence = variant(completion)  # new event_id, already-used sequence 3
dedup_cases["same sequence, same epoch, new event_id"] = (same_sequence, "sequence_conflict")
other_epoch = "9b2e4c71-0d3a-4f6b-8e5c-1a7d9f3b2c64"
moved = copy.deepcopy(completion)
moved["epoch_id"] = other_epoch
dedup_cases["conflict: same event_id, other epoch"] = (moved, "conflict")
restart = variant(cancel)  # state loss: sequence restarts at 1 in a new epoch
restart.update(epoch_id=other_epoch, sequence=1)
dedup_cases["same sequence, new epoch (restart)"] = (restart, "accepted")
restart_dup_seq = variant(restart)
dedup_cases["new epoch reused sequence"] = (restart_dup_seq, "sequence_conflict")
for label, (event, expected) in dedup_cases.items():
    got = ledger.ingest(event)
    assert got == expected, f"dedup {label}: {got} != {expected}"
assert ledger.gaps == [{"proxy_id": "proxy-demo", "kind": "producer_epoch_change",
                        "previous_epoch_id": example["epoch_id"], "epoch_id": other_epoch}]

# M2a: batch errors name the offending items precisely and never echo field values.
CANARY = "canary-secret"
unregistered_ref = "5cd96a8c-723a-80e8-bfd1-a9f880bf8f00"
pending_start = variant(example)
pending_start.update(sequence=10)
pending_start["payload"]["tool"]["metadata_ref"] = unregistered_ref
fresh = variant(cancel)
fresh.update(sequence=11)
batch_cases = []
status, body = ledger.submit_batch([fresh, copy.deepcopy(moved), pending_start])
batch_cases.append(("409 names conflict", status == 409 and body["error"]["items"] == [
    {"index": 1, "event_id": moved["event_id"], "code": "conflict"}]))
status, body = ledger.submit_batch([fresh, pending_start])
batch_cases.append(("424 names pending", status == 424 and body["error"]["items"] == [
    {"index": 1, "event_id": pending_start["event_id"], "code": "metadata_ref_pending"}]
    and body["error"]["pending_metadata_refs"] == [unregistered_ref]))
poisoned = variant(example)
poisoned["payload"]["tool_name"] = CANARY
status, body = ledger.submit_batch([fresh, poisoned])
batch_cases.append(("422 index only", status == 422 and body["error"]["items"] == [
    {"index": 1, "code": "schema_invalid"}] and CANARY not in json.dumps(body)))
status, body = ledger.submit_batch([fresh, copy.deepcopy(completion)])
batch_cases.append(("200 accepted+duplicate", status == 200
                    and body == {"accepted_event_ids": [fresh["event_id"]],
                                 "duplicate_event_ids": [completion["event_id"]]}))
for label, ok in batch_cases:
    assert ok, f"batch model {label}"


# M2b: registry entry equality over immutable fields only; producer action on 409.
REGISTRY_IMMUTABLE = ("proxy_id", "metadata_ref", "upstream_id", "credential_scope_id",
                      "protocol_version", "observation_source", "canon", "key_id",
                      "fingerprint")  # content is bound through the keyed fingerprint


def registry_ingest(store, entry):
    key = (entry["proxy_id"], entry["metadata_ref"])
    immutable = {name: entry[name] for name in REGISTRY_IMMUTABLE}
    if key not in store:
        store[key] = immutable
        return "registered"
    return "duplicate" if store[key] == immutable else "conflict"


entry = {"proxy_id": "proxy-demo", "metadata_ref": unregistered_ref, "upstream_id": "fixture",
         "credential_scope_id": "scope-1", "protocol_version": "2025-11-25",
         "observation_source": "proxy_live", "canon": "sigil-tooldef-fp-v1", "key_id": "kid-3c8e1f0a9b7d42e6a1c5f804",
         "fingerprint": "00" * 32, "observed_at": "2026-10-10T00:00:00Z"}
registry = {}
registry_cases = [
    ("first upload", registry_ingest(registry, entry), "registered"),
    ("volatile observed_at only", registry_ingest(
        registry, dict(entry, observed_at="2026-10-10T01:00:00Z")), "duplicate"),
    ("immutable fingerprint differs", registry_ingest(
        registry, dict(entry, fingerprint="11" * 32)), "conflict"),
]
for label, got, expected in registry_cases:
    assert got == expected, f"registry {label}: {got} != {expected}"
# Producer action on registry 409: the never-accepted dependent start is rewritten
# (tool only) to metadata_unavailable/registry_conflict and stops waiting on 424.
rewritten = copy.deepcopy(pending_start)
rewritten["payload"]["tool"] = {"status": "metadata_unavailable", "reason": "registry_conflict"}
assert v.is_valid(rewritten)
status, body = ledger.submit_batch([rewritten])
assert status == 200 and body["accepted_event_ids"] == [rewritten["event_id"]]
registry_cases.append(("dependent event unblocked", status, 200))

# N11: central integrity-gap report carries identifiers only; (iii) local hash check.
def entry_hash(e):
    return hashlib.sha256(canonical({k: e[k] for k in REGISTRY_IMMUTABLE}).encode()).hexdigest()


def gap_report(entry_, event_ids):
    return {"kind": "registry_conflict", "metadata_ref": entry_["metadata_ref"],
            "key_id": entry_["key_id"], "event_ids": sorted(event_ids)}


uploaded_hash = entry_hash(entry)
tampered = dict(entry, fingerprint="22" * 32)
report = gap_report(entry, [pending_start["event_id"]])
integrity_cases = [
    ("hash matches upload", entry_hash(dict(entry, observed_at="2026-10-11T00:00:00Z"))
     == uploaded_hash),
    ("tampered entry detected", entry_hash(tampered) != uploaded_hash),
    ("gap report has identifiers only", set(report) == {"kind", "metadata_ref", "key_id",
                                                       "event_ids"}
     and entry["fingerprint"] not in json.dumps(report)),
]


# N13: requestId matching is exact JSON value equality (type and value).
def same_request_id(a, b):
    return type(a) is type(b) and a == b


for label, a, b, expected in [("string vs number", "4", 4, False), ("int vs float", 4, 4.0, False),
                              ("bool vs int", True, 1, False), ("same int", 4, 4, True),
                              ("same string", "4", "4", True)]:
    integrity_cases.append((f"requestId {label}", same_request_id(a, b) is expected))


# M1 gap: any unrecoverable part of local state (epoch, K, spool) starts a new epoch.
def startup_needs_new_epoch(state):
    return not all(state.get(part) for part in ("epoch_id", "key", "spool"))


for label, state, expected in [
    ("all present", {"epoch_id": 1, "key": 1, "spool": 1}, False),
    ("K absent, spool present", {"epoch_id": 1, "key": None, "spool": 1}, True),
    ("epoch absent", {"epoch_id": None, "key": 1, "spool": 1}, True),
    ("spool absent", {"epoch_id": 1, "key": 1, "spool": None}, True),
]:
    integrity_cases.append((f"startup {label}", startup_needs_new_epoch(state) is expected))
for label, ok in integrity_cases:
    assert ok, f"model case {label}"

# event_type cannot change with an identical payload and stay schema-valid.
retyped = copy.deepcopy(completion)
retyped["event_type"] = "invocation.started"
assert not v.is_valid(retyped)


# --- N9: reference model of proxy-local metadata_ref derivation. ----------------
def jcs_subset(value):
    """RFC 8785 for fixtures with ASCII keys and integer/str/bool/null/obj/array only."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def fingerprint(key, tool_definition):
    return hmac.new(key, b"sigil-tooldef-fp-v1\x00" + jcs_subset(tool_definition),
                    hashlib.sha256).hexdigest()


def metadata_ref(key, key_id, scope, tool_definition):
    material = dict(scope, canon="sigil-tooldef-fp-v1", key_id=key_id,
                    fingerprint=fingerprint(key, tool_definition))
    digest = bytearray(hmac.new(key, b"sigil-metadata-ref-v1\x00" + jcs_subset(material),
                                hashlib.sha256).digest()[:16])
    digest[6] = (digest[6] & 0x0F) | 0x80  # RFC 9562 version 8
    digest[8] = (digest[8] & 0x3F) | 0x80  # RFC 9562 variant
    return str(UUID(bytes=bytes(digest)))


def key_id_for(key):
    """Derived from K, so a fresh random K always gets a fresh, never-reused key_id."""
    return "kid-" + hashlib.sha256(b"sigil-key-id-v1\x00" + key).hexdigest()[:24]


TEST_KEY = b"fixture-only-key-not-a-secret-00"  # never a real proxy key
OTHER_KEY = b"fixture-only-key-not-a-secret-01"
KID = key_id_for(TEST_KEY)
assert KID != key_id_for(OTHER_KEY)
scope = {"proxy_id": "proxy-demo", "upstream_id": "fixture", "credential_scope_id": "scope-1",
         "protocol_version": "2025-11-25", "observation_source": "proxy_live"}
tool_def = {"name": "json_ok", "description": "fixture tool",
            "inputSchema": {"type": "object", "properties": {}}}
ref = metadata_ref(TEST_KEY, KID, scope, tool_def)
assert ref == example_ref, f"example metadata_ref must be the fixture derivation {ref}"
assert UUID(ref).version == 8
assert ref == metadata_ref(TEST_KEY, KID, dict(scope), copy.deepcopy(tool_def))  # deterministic
assert "json_ok" not in ref and "route_revision" not in scope  # route edits do not re-mint
changed = dict(tool_def, description="changed")
derivation_cases = [
    ("definition change", metadata_ref(TEST_KEY, KID, scope, changed)),
    ("other key", metadata_ref(OTHER_KEY, key_id_for(OTHER_KEY), scope, tool_def)),
    ("other credential scope", metadata_ref(TEST_KEY, KID,
                                            dict(scope, credential_scope_id="scope-2"), tool_def)),
    ("other proxy", metadata_ref(TEST_KEY, KID, dict(scope, proxy_id="proxy-b"), tool_def)),
]
for label, other in derivation_cases:
    assert other != ref, f"derivation {label} did not change the reference"
    assert v.is_valid(dict(example, payload=dict(example["payload"], tool={
        "status": "identified", "metadata_ref": other})))
print(f"PASS: schema, {len(positive)} positive cases, {len(negative)} rejected cases, "
      f"{token_cases} JSON-token integer rejections, {len(dedup_cases)} dedup-model cases, "
      f"{len(batch_cases)} batch-error-model cases, {len(registry_cases)} registry-model cases, "
      f"{len(integrity_cases)} integrity/requestId/startup-model cases, "
      f"{len(derivation_cases) + 1} ref-derivation-model cases "
      f"(jsonschema {versions['jsonschema']}, rfc3339-validator {versions['rfc3339-validator']}, "
      "date-time and uuid format checking active)")
print("NOT TESTED: producer normalization/provenance, registry sync/authorization, "
      "ingestion/ledger, durability, protocol support or hardware compatibility")
