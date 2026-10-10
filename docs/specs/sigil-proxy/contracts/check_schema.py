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

_legacy_pass_line = (f"PASS: schema, {len(positive)} positive cases, {len(negative)} rejected cases, "
      f"{token_cases} JSON-token integer rejections, {len(dedup_cases)} dedup-model cases, "
      f"{len(batch_cases)} batch-error-model cases, {len(registry_cases)} registry-model cases, "
      f"{len(integrity_cases)} integrity/requestId/startup-model cases, "
      f"{len(derivation_cases) + 1} ref-derivation-model cases "
      f"(jsonschema {versions['jsonschema']}, rfc3339-validator {versions['rfc3339-validator']}, "
      "date-time and uuid format checking active)")


# =============================================================================
# W2 (D-03 / D-05 remaining contracts): registry entry, inventory report and
# status report schemas, plus fixture models for retention, projection,
# cross-event validation, cursors, inventory/marker and counters.
# Contract fixtures only; ledger-and-query.md and registry.md are the prose.
# =============================================================================
import base64

registry_schema = json.loads((root / "registry-entry.schema.json").read_text())
status_schema = json.loads((root / "proxy-status.schema.json").read_text())
Draft202012Validator.check_schema(registry_schema)
Draft202012Validator.check_schema(status_schema)


def def_validator(schema_, name):
    wrapper = {"$schema": schema_["$schema"], "$defs": schema_["$defs"],
               "$ref": f"#/$defs/{name}"}
    return StrictValidator(wrapper, format_checker=format_checker)


reg_root = StrictValidator(registry_schema, format_checker=format_checker)
reg_view = def_validator(registry_schema, "entry_view")
reg_upload = def_validator(registry_schema, "upload_request")
reg_response = def_validator(registry_schema, "upload_response")
reg_report = def_validator(registry_schema, "inventory_report")
stat = StrictValidator(status_schema, format_checker=format_checker)
stat_resp = def_validator(status_schema, "status_response")

# The schema's immutable field set is the registry equality set of the M2b model above.
assert tuple(registry_schema["x-immutable-fields"]) == REGISTRY_IMMUTABLE
assert set(registry_schema["required"]) == set(REGISTRY_IMMUTABLE) | {"observed_at", "definition"}
assert set(registry_schema["x-volatile-fields"]) == {"observed_at", "definition"}

w_pos, w_neg = [], []   # (label, validator, document)
W_IDS = itertools.count(5000)


def new_uuid():
    return str(UUID(int=next(W_IDS)))


def v8_ref(n):
    return f"00000000-0000-8000-8000-{n:012x}"


def make_entry(tool, key=TEST_KEY, scope_=None, **over):
    scope_ = scope_ or scope
    kid = key_id_for(key)
    out = {"proxy_id": scope_["proxy_id"],
           "metadata_ref": metadata_ref(key, kid, scope_, tool),
           "upstream_id": scope_["upstream_id"],
           "credential_scope_id": scope_["credential_scope_id"],
           "protocol_version": scope_["protocol_version"],
           "observation_source": scope_["observation_source"],
           "canon": "sigil-tooldef-fp-v1", "key_id": kid,
           "fingerprint": fingerprint(key, tool),
           "observed_at": "2026-10-10T00:00:00Z", "definition": tool}
    out.update(over)
    return out


def w_mut(base, path, value):
    doc = copy.deepcopy(base)
    set_path(doc, path, value)
    return doc


TOOL_A = {"name": "json_ok", "description": "fixture tool", "inputSchema": {"type": "object"}}
TOOL_A2 = dict(TOOL_A, description="changed")
TOOL_B = {"name": "json_two", "description": "second", "inputSchema": {"type": "object"}}
TOOL_C = {"name": "json_three", "description": "third", "inputSchema": {"type": "object"}}
ent_a, ent_a2 = make_entry(TOOL_A), make_entry(TOOL_A2)
ent_b, ent_c = make_entry(TOOL_B), make_entry(TOOL_C)
REF = {k: e["metadata_ref"] for k, e in
       dict(a=ent_a, a2=ent_a2, b=ent_b, c=ent_c).items()}

# --- registry entry (root), view, upload request/response -------------------------
w_pos.append(("entry", reg_root, ent_a))
w_pos.append(("second entry", reg_root, ent_b))
w_pos.append(("upload request", reg_upload, {"schema_version": 1, "proxy_id": "proxy-demo",
                                             "entries": [ent_a, ent_b]}))
w_pos.append(("upload response", reg_response, {"registered_metadata_refs": [REF["a"]],
                                                "duplicate_metadata_refs": [REF["b"]]}))
view = {k: ent_a[k] for k in REGISTRY_IMMUTABLE if k != "fingerprint"}
view.update(registered_at="2026-10-10T00:00:01Z", content_state="present")
w_pos.append(("entry view", reg_view, view))
w_pos.append(("entry view deleted content", reg_view, dict(view, content_state="deleted")))
for field in REGISTRY_IMMUTABLE:
    w_neg.append((f"entry missing {field}", reg_root, w_mut(ent_a, (field,), DELETE)))
for label, path, value in [
    ("raw tool_name", ("tool_name",), "canary-secret"),
    ("name field", ("name",), "canary-secret"),
    ("route_revision in entry", ("route_revision",), 3),
    ("secret key field", ("key",), "canary-secret"),
    ("uppercase ref", ("metadata_ref",), REF["a"].upper()),
    ("v4 ref", ("metadata_ref",), "0c635e55-7e09-4e3d-978f-4b88870428f1"),
    ("ref newline", ("metadata_ref",), REF["a"] + "\n"),
    ("raw ref", ("metadata_ref",), "canary-secret"),
    ("key_id raw", ("key_id",), "canary-secret"),
    ("key_id short", ("key_id",), "kid-" + "0" * 23),
    ("key_id newline", ("key_id",), KID + "\n"),
    ("fingerprint uppercase", ("fingerprint",), "AB" * 32),
    ("fingerprint short", ("fingerprint",), "ab" * 31),
    ("fingerprint newline", ("fingerprint",), "ab" * 32 + "\n"),
    ("fingerprint raw", ("fingerprint",), "canary-secret"),
    ("observation_source daemon cache", ("observation_source",), "daemon_cache"),
    ("canon v2 until contract update", ("canon",), "sigil-tooldef-fp-v2"),
    ("protocol 2025-06-18", ("protocol_version",), "2025-06-18"),
    ("protocol unknown", ("protocol_version",), "unknown"),
    ("empty definition", ("definition",), {}),
    ("definition string", ("definition",), "canary-secret"),
    ("missing definition", ("definition",), DELETE),
    ("missing observed_at", ("observed_at",), DELETE),
    ("observed_at calendar", ("observed_at",), "2026-02-30T00:00:00Z"),
    ("proxy_id newline", ("proxy_id",), "proxy-demo\n"),
]:
    w_neg.append((f"entry {label}", reg_root, w_mut(ent_a, path, value)))
upload = {"schema_version": 1, "proxy_id": "proxy-demo", "entries": [ent_a]}
for label, doc in [
    ("101 entries", dict(upload, entries=[ent_a] * 101)),
    ("no entries", dict(upload, entries=[])),
    ("schema_version 2", dict(upload, schema_version=2)),
    ("missing proxy_id", {k: v_ for k, v_ in upload.items() if k != "proxy_id"}),
    ("extra field", dict(upload, key_material="canary-secret")),
    ("entry with route_revision", dict(upload, entries=[dict(ent_a, route_revision=1)])),
]:
    w_neg.append((f"upload request {label}", reg_upload, doc))
w_pos.append(("upload request 100 entries", reg_upload, dict(upload, entries=[ent_a] * 100)))
for label, doc in [
    ("non-v8 ref", {"registered_metadata_refs": ["0c635e55-7e09-4e3d-978f-4b88870428f1"],
                    "duplicate_metadata_refs": []}),
    ("missing duplicates", {"registered_metadata_refs": []}),
    ("echoes fingerprint", {"registered_metadata_refs": [], "duplicate_metadata_refs": [],
                            "fingerprint": ent_a["fingerprint"]}),
]:
    w_neg.append((f"upload response {label}", reg_response, doc))
for label, doc in [
    ("view with definition", dict(view, definition=TOOL_A)),
    ("view bad content_state", dict(view, content_state="redacted")),
    ("view missing registered_at", {k: v_ for k, v_ in view.items() if k != "registered_at"}),
    ("view with tool name", dict(view, name="json_ok")),
    ("view with keyed fingerprint (F3)", dict(view, fingerprint=ent_a["fingerprint"])),
]:
    w_neg.append((f"entry {label}", reg_view, doc))

# --- inventory report ---------------------------------------------------------------
INV = [new_uuid() for _ in range(8)]
SCOPE_DOC = {k: scope[k] for k in ("upstream_id", "credential_scope_id", "protocol_version",
                                    "observation_source")}


def report(**over):
    base = {"schema_version": 1, "report_id": new_uuid(), "proxy_id": "proxy-demo",
            "epoch_id": example["epoch_id"], "observed_at": "2026-10-10T01:00:00Z",
            "scope": dict(SCOPE_DOC), "canon": "sigil-tooldef-fp-v1", "key_id": KID,
            "completeness": "complete", "pages_observed": 2,
            "inventory_id": INV[0], "members": [REF["a"], REF["b"]],
            "comparison": {"kind": "initial_baseline"}}
    base.update(over)
    return base


def incomplete(**over):
    doc = report(completeness="incomplete", incomplete_reason="page_error", pages_observed=1)
    for field in ("inventory_id", "members", "comparison"):
        del doc[field]
    doc.update(over)
    return doc


rep_initial = report()
rep_compared = report(inventory_id=INV[1], members=[REF["a2"], REF["c"]], comparison={
    "kind": "compared", "previous_inventory_id": INV[0],
    "changes": [{"change": "changed", "metadata_ref": REF["a2"], "previous_metadata_ref": REF["a"]},
                {"change": "removed", "metadata_ref": REF["b"]},
                {"change": "added", "metadata_ref": REF["c"]}]})
rep_nodrift = report(inventory_id=INV[2], comparison={
    "kind": "compared", "previous_inventory_id": INV[0], "changes": []})
rep_rebase = report(inventory_id=INV[3], key_id="kid-" + "ab" * 12, members=[v8_ref(1), v8_ref(2)],
                    comparison={"kind": "rebaseline", "previous_inventory_id": INV[0],
                                "reason": "key_rotation",
                                "links": [{"from_metadata_ref": REF["a"],
                                           "to_metadata_ref": v8_ref(1),
                                           "definition_comparison": "identical"}]})
rep_incomplete = incomplete()
for label, doc in [("initial baseline", rep_initial), ("compared with changes", rep_compared),
                   ("compared no change", rep_nodrift), ("rebaseline with links", rep_rebase),
                   ("incomplete", rep_incomplete),
                   ("empty complete listing", report(members=[]))]:
    w_pos.append((f"inventory {label}", reg_report, doc))
for reason in ("page_limit_exceeded", "tool_limit_exceeded", "size_limit_exceeded", "page_error",
               "cursor_invalid", "access_denied", "session_ended", "canonicalization_failed",
               "ambiguous_name"):
    w_pos.append((f"inventory incomplete {reason}", reg_report, incomplete(incomplete_reason=reason)))


def del_field(doc, field):
    out = copy.deepcopy(doc)
    del out[field]
    return out


for label, doc in [
    ("incomplete with changes-bearing comparison", dict(rep_incomplete, comparison=rep_compared["comparison"])),
    ("incomplete with members", dict(rep_incomplete, members=[REF["a"]])),
    ("incomplete with inventory_id", dict(rep_incomplete, inventory_id=INV[4])),
    ("incomplete without reason", del_field(rep_incomplete, "incomplete_reason")),
    ("incomplete raw reason", dict(rep_incomplete, incomplete_reason="canary-secret")),
    ("complete without comparison", del_field(rep_initial, "comparison")),
    ("complete without members", del_field(rep_initial, "members")),
    ("complete without inventory_id", del_field(rep_initial, "inventory_id")),
    ("complete with incomplete_reason", dict(rep_initial, incomplete_reason="page_error")),
    ("rebaseline with changes", dict(rep_rebase, comparison=dict(
        rep_rebase["comparison"], changes=rep_compared["comparison"]["changes"]))),
    ("compared with links", dict(rep_compared, comparison=dict(
        rep_compared["comparison"], links=rep_rebase["comparison"]["links"]))),
    ("compared without changes", dict(rep_compared, comparison={
        "kind": "compared", "previous_inventory_id": INV[0]})),
    ("initial with previous", dict(rep_initial, comparison={
        "kind": "initial_baseline", "previous_inventory_id": INV[0]})),
    ("unknown comparison kind", dict(rep_initial, comparison={"kind": "approved"})),
    ("rebaseline unknown reason", dict(rep_rebase, comparison=dict(
        rep_rebase["comparison"], reason="state_loss"))),
    ("changed without previous", dict(rep_compared, comparison=dict(
        rep_compared["comparison"], changes=[{"change": "changed", "metadata_ref": REF["a2"]}]))),
    ("added with previous", dict(rep_compared, comparison=dict(
        rep_compared["comparison"], changes=[{"change": "added", "metadata_ref": REF["c"],
                                              "previous_metadata_ref": REF["a"]}]))),
    ("unknown change", dict(rep_compared, comparison=dict(
        rep_compared["comparison"], changes=[{"change": "renamed", "metadata_ref": REF["c"]}]))),
    ("raw name in members", dict(rep_initial, members=["json_ok"])),
    ("duplicate members", dict(rep_initial, members=[REF["a"], REF["a"]])),
    ("10001 members", dict(rep_initial, members=[v8_ref(i) for i in range(10001)])),
    ("route_revision in scope", dict(rep_initial, scope=dict(SCOPE_DOC, route_revision=1))),
    ("scope daemon cache", dict(rep_initial, scope=dict(SCOPE_DOC, observation_source="daemon_cache"))),
    ("canon v2", dict(rep_initial, canon="sigil-tooldef-fp-v2")),
    ("negative pages", dict(rep_initial, pages_observed=-1)),
    ("float pages", dict(rep_initial, pages_observed=1.0)),
    ("tool names list", dict(rep_initial, tools=["json_ok"])),
    ("link comparison raw", dict(rep_rebase, comparison=dict(rep_rebase["comparison"], links=[
        {"from_metadata_ref": REF["a"], "to_metadata_ref": v8_ref(1),
         "definition_comparison": "canary-secret"}]))),
    ("link with key", dict(rep_rebase, comparison=dict(rep_rebase["comparison"], links=[
        {"from_metadata_ref": REF["a"], "to_metadata_ref": v8_ref(1),
         "definition_comparison": "identical", "key": "canary-secret"}]))),
]:
    w_neg.append((f"inventory {label}", reg_report, doc))
assert len(report(members=[v8_ref(i) for i in range(10000)])["members"]) == 10000
w_pos.append(("inventory 10000 members", reg_report,
              report(members=[v8_ref(i) for i in range(10000)])))

# K never appears in anything the registry/rotation contract transmits.
wire_docs = json.dumps([ent_a, rep_rebase, upload])
assert TEST_KEY.decode() not in wire_docs and TEST_KEY.hex() not in wire_docs
assert all(metadata_ref(OTHER_KEY, key_id_for(OTHER_KEY), scope, t) != REF[k]
           for k, t in (("a", TOOL_A), ("b", TOOL_B), ("c", TOOL_C))), "rotation re-mints refs"

# --- status report -------------------------------------------------------------------
def status(**over):
    base = {
        "schema_version": 1, "report_id": new_uuid(), "proxy_id": "proxy-demo",
        "epoch_id": example["epoch_id"], "status_sequence": 7,
        "last_assigned_sequence": 12, "sent_at": "2026-10-10T02:00:00Z",
        "config": {"state": "valid", "applied_revision": 4, "observed_desired_revision": 5,
                   "expires_at": "2026-10-11T02:00:00Z", "last_update_error": "fetch_failed",
                   "config_hash": hashlib.sha256(b"fixture-config").hexdigest(),
                   "max_offline_retry_age_seconds": 30 * 86400,
                   "event_retention_seconds": 90 * 86400},
        "spool": {"state": "ok", "depth_events": 12, "unsent_events": 3, "bytes": 4096,
                  "capacity_bytes": 1073741824, "oldest_unsent_age_seconds": 40,
                  "quarantined_events": 0},
        "registry": {"pending_entries": 0, "sync_stalled": False},
        "central": {"last_ingest_ack_at": "2026-10-10T01:59:30Z", "consecutive_failures": 0},
        "routes": [{"upstream_id": "fixture", "state": "supported"},
                   {"upstream_id": "tasks-upstream", "state": "unsupported",
                    "reason": "upstream_capability_unsupported"}],
        "counters": {"auth_failures": [{"upstream_id": "fixture", "reason": "credential_invalid",
                                        "count": 3},
                                       {"upstream_id": None, "reason": "credential_missing",
                                        "count": 1}],
                     "unmatched_cancels": [{"upstream_id": "fixture", "reason": "window_expired",
                                            "count": 2}]},
        "gaps": [],
    }
    base.update(over)
    return base


GAPS = {
    "registry_conflict": {"gap_id": None, "kind": "registry_conflict",
                          "detected_at": "2026-10-10T02:00:00Z", "metadata_ref": REF["a"],
                          "key_id": KID, "event_ids": [new_uuid()], "affected_event_count": 1,
                          "detected_by": "central_409"},
    "event_quarantined": {"gap_id": None, "kind": "event_quarantined",
                          "detected_at": "2026-10-10T02:00:00Z", "event_ids": [new_uuid()],
                          "code": "conflict"},
    "local_record_failed": {"gap_id": None, "kind": "local_record_failed",
                            "detected_at": "2026-10-10T02:00:00Z", "count": 1,
                            "invocation_ids": [new_uuid()]},
    "spool_expired": {"gap_id": None, "kind": "spool_expired",
                      "detected_at": "2026-10-10T02:00:00Z", "epoch_id": example["epoch_id"],
                      "from_sequence": 3, "to_sequence": 9, "count": 7},
    "unrecorded_calls": {"gap_id": None, "kind": "unrecorded_calls",
                         "detected_at": "2026-10-10T02:00:00Z", "count": 4,
                         "from_at": "2026-10-10T01:00:00Z", "to_at": "2026-10-10T01:05:00Z"},
    "central_outage": {"gap_id": None, "kind": "central_outage",
                       "detected_at": "2026-10-10T02:00:00Z",
                       "started_at": "2026-10-10T01:00:00Z", "ended_at": None},
}
for kind, gap in GAPS.items():
    gap["gap_id"] = new_uuid()
    w_pos.append((f"status gap {kind}", stat, status(gaps=[gap])))
w_pos.append(("status all gaps", stat, status(gaps=list(GAPS.values()))))
w_pos.append(("status minimal config none", stat, status(config={
    "state": "none", "applied_revision": None, "observed_desired_revision": None,
    "expires_at": None})))
w_pos.append(("status", stat, status()))
HASH = hashlib.sha256(b"fixture-config").hexdigest()
for state_ in ("none", "valid", "expired", "disabled"):
    cfg_ = dict(status()["config"], state=state_, config_hash=HASH)
    w_pos.append((f"status config state {state_}", stat, status(config=cfg_)))
for err_ in ("stale_revision", "validation_failed", "fetch_failed", "apply_failed",
             "config_hash_mismatch"):
    w_pos.append((f"status config error {err_}", stat, status(config=dict(
        status()["config"], last_update_error=err_))))
for state_ in ("none", "expired"):
    cfg_ = {k: x for k, x in status()["config"].items() if k != "config_hash"}
    cfg_["state"] = state_
    w_pos.append((f"status config {state_} without config_hash", stat, status(config=cfg_)))
for state_ in ("valid", "disabled"):
    cfg_ = {k: x for k, x in status()["config"].items() if k != "config_hash"}
    cfg_["state"] = state_
    w_neg.append((f"status config {state_} without config_hash", stat, status(config=cfg_)))
for label_, cfg_ in [
    ("state raw", dict(status()["config"], state="canary-secret")),
    ("state suspended", dict(status()["config"], state="suspended")),
    ("error raw", dict(status()["config"], last_update_error="canary-secret")),
    ("error revision_regression", dict(status()["config"], last_update_error="revision_regression")),
    ("hash uppercase", dict(status()["config"], config_hash=HASH.upper())),
    ("hash short", dict(status()["config"], config_hash=HASH[:63])),
    ("hash newline", dict(status()["config"], config_hash=HASH + "\n")),
    ("hash raw", dict(status()["config"], config_hash="canary-secret")),
    ("hash integer", dict(status()["config"], config_hash=1)),
]:
    w_neg.append((f"status config {label_}", stat, status(config=cfg_)))
w_pos.append(("status response", stat_resp, {"state_applied": False,
                                             "acknowledged_gap_ids": [new_uuid()],
                                             "duplicate_gap_ids": []}))
w_neg.append(("status response extra field", stat_resp, {
    "state_applied": True, "acknowledged_gap_ids": [], "duplicate_gap_ids": [], "gaps": []}))
w_neg.append(("status response raw id", stat_resp, {
    "state_applied": True, "acknowledged_gap_ids": ["canary-secret"], "duplicate_gap_ids": []}))
w_pos.append(("status epoch change report", stat, status(
    epoch_id="9b2e4c71-0d3a-4f6b-8e5c-1a7d9f3b2c64", status_sequence=1)))
spool_ok = status()["spool"]
for label, doc in [
    ("raw name in gap", status(gaps=[dict(GAPS["registry_conflict"], name="json_ok")])),
    ("gap carries fingerprint", status(gaps=[dict(GAPS["registry_conflict"],
                                                  fingerprint=ent_a["fingerprint"])])),
    ("registry gap without ids", status(gaps=[dict(GAPS["registry_conflict"], event_ids=[])])),
    ("registry gap 101 event_ids (F14)", status(gaps=[dict(
        GAPS["registry_conflict"], event_ids=[new_uuid() for _ in range(101)],
        affected_event_count=101)])),
    ("registry gap without affected count (F14)",
     status(gaps=[del_field(GAPS["registry_conflict"], "affected_event_count")])),
    ("registry gap zero affected count",
     status(gaps=[dict(GAPS["registry_conflict"], affected_event_count=0)])),
    ("missing last_assigned_sequence (F13)", del_field(status(), "last_assigned_sequence")),
    ("negative last_assigned_sequence", status(last_assigned_sequence=-1)),
    ("valid config without echoed R/E (F4)", status(config={
        "state": "valid", "applied_revision": 4, "observed_desired_revision": 5,
        "expires_at": "2026-10-11T02:00:00Z"})),
    ("echoed R below bound", status(config=dict(status()["config"], max_offline_retry_age_seconds=0))),
    ("echoed R above 90 days", status(config=dict(
        status()["config"], max_offline_retry_age_seconds=91 * 86400))),
    ("echoed E float", status(config=dict(status()["config"], event_retention_seconds=1.0))),
    ("registry gap bad detector", status(gaps=[dict(GAPS["registry_conflict"],
                                                    detected_by="canary-secret")])),
    ("quarantine unknown code", status(gaps=[dict(GAPS["event_quarantined"],
                                                  code="canary-secret")])),
    ("quarantine with payload", status(gaps=[dict(GAPS["event_quarantined"],
                                                  payload={"arguments": "canary"})])),
    ("unknown gap kind", status(gaps=[dict(GAPS["central_outage"], kind="canary")])),
    ("gap without gap_id", status(gaps=[del_field(GAPS["central_outage"], "gap_id")])),
    ("101 gaps", status(gaps=[GAPS["central_outage"]] * 101)),
    ("local_record_failed zero count", status(gaps=[dict(GAPS["local_record_failed"], count=0)])),
    ("spool_expired without epoch", status(gaps=[del_field(GAPS["spool_expired"], "epoch_id")])),
    ("counter unknown reason", status(counters={"auth_failures": [
        {"upstream_id": "fixture", "reason": "canary-secret", "count": 1}],
        "unmatched_cancels": []})),
    ("counter reason on wrong list", status(counters={"auth_failures": [
        {"upstream_id": "fixture", "reason": "window_expired", "count": 1}],
        "unmatched_cancels": []})),
    ("counter with actor", status(counters={"auth_failures": [
        {"upstream_id": "fixture", "reason": "credential_invalid", "count": 1,
         "actor_id": "agent-1"}], "unmatched_cancels": []})),
    ("counter with source address", status(counters={"auth_failures": [
        {"upstream_id": "fixture", "reason": "credential_invalid", "count": 1,
         "source_address": "203.0.113.5"}], "unmatched_cancels": []})),
    ("counter negative", status(counters={"auth_failures": [
        {"upstream_id": "fixture", "reason": "credential_invalid", "count": -1}],
        "unmatched_cancels": []})),
    ("counter float", status(counters={"auth_failures": [], "unmatched_cancels": [
        {"upstream_id": "fixture", "reason": "window_expired", "count": 1.0}]})),
    ("counter missing route key", status(counters={"auth_failures": [
        {"reason": "credential_invalid", "count": 1}], "unmatched_cancels": []})),
    ("counters missing list", status(counters={"auth_failures": []})),
    ("1537 counters", status(counters={"auth_failures": [
        {"upstream_id": None, "reason": "credential_missing", "count": 1}] * 1537,
        "unmatched_cancels": []})),
    ("applied_revision zero", status(config=dict(status()["config"], applied_revision=0))),
    ("config state raw", status(config=dict(status()["config"], state="canary"))),
    ("config error raw", status(config=dict(status()["config"], last_update_error="canary"))),
    ("spool state raw", status(spool=dict(spool_ok, state="canary"))),
    ("spool negative", status(spool=dict(spool_ok, bytes=-1))),
    ("spool zero capacity", status(spool=dict(spool_ok, capacity_bytes=0))),
    ("route state raw", status(routes=[{"upstream_id": "fixture", "state": "canary"}])),
    ("route reason raw", status(routes=[{"upstream_id": "fixture", "state": "degraded",
                                         "reason": "canary-secret"}])),
    ("missing epoch", del_field(status(), "epoch_id")),
    ("missing gaps", del_field(status(), "gaps")),
    ("top-level actor", status(actor={"actor_id": "agent-1"})),
    ("top-level token", status(token="canary-secret")),
    ("sent_at not a date", status(sent_at="canary-secret")),
    ("status_sequence zero", status(status_sequence=0)),
    ("schema_version 2", status(schema_version=2)),
]:
    w_neg.append((f"status {label}", stat, doc))

for label, validator, doc in w_pos:
    errors = list(validator.iter_errors(doc))
    assert not errors, f"W2 positive {label}: {[e.message for e in errors][:2]}"
for label, validator, doc in w_neg:
    assert list(validator.iter_errors(doc)), f"W2 negative {label} was accepted"
w_labels = [label for label, _, _ in w_pos]
assert len(w_labels) == len(set(w_labels)), "duplicate W2 positive labels"

# --- L1 retention invariants ------------------------------------------------------------
DAY = 86400
RET_BOUNDS = {"R": (3600, 90 * DAY), "M": (3600, 30 * DAY), "E_max": 365 * DAY,
              "T_max": 730 * DAY, "Q_max": 730 * DAY}


def retention_valid(R, M, E, T, Q):
    lo, hi = RET_BOUNDS["R"]
    mlo, mhi = RET_BOUNDS["M"]
    return (lo <= R <= hi and mlo <= M <= mhi and R + M <= E <= RET_BOUNDS["E_max"]
            and R + M <= T <= RET_BOUNDS["T_max"] and E <= Q <= RET_BOUNDS["Q_max"])


def recognised(accepted_age_at_resubmit, T, E):
    """A resubmission is recognised while it is within max(E, T) of acceptance."""
    return accepted_age_at_resubmit <= max(E, T)


R0, M0, E0 = 30 * DAY, 7 * DAY, 90 * DAY
retention_cases = [
    ("defaults valid", retention_valid(R0, M0, E0, E0, E0), True),
    ("T below R+M refused", retention_valid(R0, M0, E0, R0 + M0 - 1, E0), False),
    ("E below R+M refused", retention_valid(R0, M0, R0 + M0 - 1, E0, E0), False),
    ("Q below E refused", retention_valid(R0, M0, E0, E0, E0 - 1), False),
    ("R above bound refused", retention_valid(91 * DAY, M0, 365 * DAY, 365 * DAY, 365 * DAY), False),
    ("R at lower bound valid", retention_valid(3600, 3600, 7200, 7200, 7200), True),
    # accepted one day after occurred_at, resubmitted at occurred_at + R: age R - 1d
    ("late retransmit recognised", recognised(R0 - DAY, R0 + M0, E0), True),
    ("retransmit at R recognised with T=R+M, E short", recognised(R0, R0 + M0, 2 * DAY), True),
    ("retransmit after both windows", recognised(max(E0, R0 + M0) + 1, R0 + M0, E0), False),
]
for label, got, expected in retention_cases:
    assert got is expected, f"retention {label}"


# --- L2 projection model (order independent) ---------------------------------------------
def content(event):
    return canonical(event["payload"])


UPSTREAM_REASONS = ("upstream_capability_unsupported", "upstream_version_unsupported",
                    "upstream_initialize_unreadable")


def contradicts(start, comp):
    tool = start.get("tool")
    if tool and tool["status"] == "unavailable":
        if not (comp["outcome"] in ("protocol_error", "denied")
                and comp["delivery_state"] == "not_sent"):
            return True
    reason = comp.get("reason")
    if reason in UPSTREAM_REASONS and start["method"] != "initialize":
        return True
    if reason == "modern_request_unsupported" and not (
            start["method"] == "unknown" and start["protocol_version"] == "unknown"):
        return True
    if reason == "task_augmentation_unsupported":
        needed = "unknown" if comp["delivery_state"] == "not_sent" else "tools/call"
        if start["method"] != needed:
            return True
    return False


def project(events, superseded=False):
    starts, comps, cancels = {}, {}, {}
    for event in events:
        bucket = {"invocation.started": starts, "invocation.completed": comps,
                  "invocation.cancel_requested": cancels}[event["event_type"]]
        bucket[event["event_id"]] = event
    flags, conflict = set(), False
    start = None
    start_contents = {content(e) for e in starts.values()}
    if len(starts) > 1:
        if len(start_contents) > 1:
            conflict = True
            flags.add("start_binding_conflict")
        else:
            flags.add("duplicate_start")
    if len(start_contents) == 1:
        start = next(iter(starts.values()))["payload"]
    comp = None
    comp_contents = {content(e) for e in comps.values()}
    if len(comps) > 1:
        flags.add("duplicate_completion")
        if len(comp_contents) > 1:
            conflict = True
    if len(comp_contents) == 1:
        comp = next(iter(comps.values()))["payload"]
    if start is not None:
        for c in comps.values():
            if contradicts(start, c["payload"]):
                conflict = True
                flags.add("completion_contradicts_start")
    if conflict:
        lifecycle = "integrity_conflict"
    elif comps and starts:
        lifecycle = "completed"
    elif comps:
        lifecycle = "completion_without_start"
    elif starts:
        lifecycle = "started"
    elif cancels:
        lifecycle = "cancel_without_start"
    else:
        raise AssertionError("empty invocation")
    shown = comp if lifecycle == "completed" else None
    reported = comp if lifecycle in ("integrity_conflict", "completion_without_start") else None
    return {
        "lifecycle": lifecycle,
        "outcome": shown["outcome"] if shown else None,
        "delivery_state": shown["delivery_state"] if shown else None,
        "reason": shown.get("reason") if shown else None,
        "reported_outcome": reported["outcome"] if reported else None,
        "reported_delivery_state": reported["delivery_state"] if reported else None,
        "reported_reason": reported.get("reason") if reported else None,
        "cancel_observed": bool(cancels),
        "method": start["method"] if start else None,
        "tool": start.get("tool") if start else None,
        "epoch_superseded": lifecycle == "started" and superseded,
        "flags": sorted(flags),
        "decision": None,
    }


inv_start, inv_comp, inv_cancel = example, completion, cancel
malformed_start = variant(example)
malformed_start["payload"]["tool"] = {"status": "unavailable", "reason": "malformed"}
bad_success = variant(completion)           # success/sent against a malformed start
good_denied = variant(completion)
good_denied["payload"].update(outcome="denied", delivery_state="not_sent")
second_comp = variant(completion)
second_comp["payload"].update(outcome="tool_error")
other_ref_start = variant(example)
other_ref_start["payload"]["tool"] = {"status": "identified", "metadata_ref": REF["b"]}
version_comp = variant(completion)
version_comp["payload"].update(outcome="protocol_error", delivery_state="sent",
                               reason="upstream_version_unsupported")
for ev in (malformed_start, bad_success, good_denied, second_comp, other_ref_start, version_comp):
    assert v.is_valid(ev)

headline = project([inv_start, inv_comp])
assert headline["lifecycle"] == "completed" and headline["outcome"] == "success"
projection_cases = []


def pcase(label, ok):
    projection_cases.append(label)
    assert ok, f"projection case {label}"


pcase("start only is not success",
      project([inv_start])["lifecycle"] == "started" and project([inv_start])["outcome"] is None)
pcase("all permutations equal", all(
    project(list(order)) == headline
    for order in itertools.permutations([inv_start, inv_comp])))
three = [inv_start, inv_cancel, inv_comp]
pcase("three-event permutations equal", all(
    project(list(order)) == project(three) for order in itertools.permutations(three)))
pcase("cancel after completion keeps outcome",
      project(three)["outcome"] == "success" and project(three)["cancel_observed"])
pcase("retransmission idempotent", project([inv_start, inv_comp, copy.deepcopy(inv_comp)]) == headline)
orphan = project([inv_comp])
pcase("completion without start", orphan["lifecycle"] == "completion_without_start"
      and orphan["method"] is None)
pcase("completion without start is never success (F1)", orphan["outcome"] is None
      and orphan["delivery_state"] is None and orphan["reported_outcome"] == "success"
      and orphan["reported_delivery_state"] == "sent")
pcase("completion arrives first, start later: completed", all(
    project(list(o))["lifecycle"] == "completed" and project(list(o))["reported_outcome"] is None
    for o in itertools.permutations([inv_comp, inv_start])))
pcase("cancel without start", project([inv_cancel])["lifecycle"] == "cancel_without_start"
      and project([inv_cancel])["outcome"] is None)
pcase("start-only superseded epoch", project([inv_start], superseded=True)["epoch_superseded"]
      and project([inv_start], superseded=True)["outcome"] is None)
pcase("superseded flag only for start-only",
      not project([inv_start, inv_comp], superseded=True)["epoch_superseded"])
for order in itertools.permutations([malformed_start, bad_success]):
    p = project(list(order))
    pcase("malformed start + success conflict", p["lifecycle"] == "integrity_conflict"
          and p["outcome"] is None and p["reported_outcome"] == "success"
          and p["flags"] == ["completion_contradicts_start"])
pcase("malformed start + denied/not_sent", project([malformed_start, good_denied])["lifecycle"]
      == "completed")
pcase("reason vs method contradiction",
      project([inv_start, version_comp])["lifecycle"] == "integrity_conflict")
pcase("reason on initialize start fine", project([init_start, version_comp])["lifecycle"] == "completed")
pcase("two starts, different tool binding", all(
    project(list(o))["lifecycle"] == "integrity_conflict"
    and "start_binding_conflict" in project(list(o))["flags"]
    for o in itertools.permutations([inv_start, other_ref_start])))
dup_start = variant(example)
pcase("duplicate start flagged, headline kept",
      project([inv_start, dup_start, inv_comp])["lifecycle"] == "completed"
      and project([inv_start, dup_start, inv_comp])["flags"] == ["duplicate_start"])
pcase("two completions differ", project([inv_start, inv_comp, second_comp])["lifecycle"]
      == "integrity_conflict")
dup_comp = variant(completion)
pcase("two equal completions flagged",
      project([inv_start, inv_comp, dup_comp])["flags"] == ["duplicate_completion"]
      and project([inv_start, inv_comp, dup_comp])["lifecycle"] == "completed")
pcase("no non-completion projection exposes an outcome", all(
    project(list(subset))["outcome"] is None
    for n in (1, 2) for subset in itertools.combinations([inv_start, inv_cancel], n)))
allowed_fields = {"lifecycle", "outcome", "delivery_state", "reason", "reported_outcome",
                  "reported_delivery_state", "reported_reason",
                  "cancel_observed", "method", "tool", "epoch_superseded", "flags", "decision"}
pcase("projection exposes no raw fields", set(headline) == allowed_fields)

# --- L5 cross-event semantic validation model ---------------------------------------------
class SemanticModel:
    def __init__(self):
        self.registry = {}      # (proxy_id, ref) -> registry entry
        self.owners = {}        # invocation_id -> proxy_id
        self.route_scopes = {}  # (proxy_id, upstream_id, route_revision) -> credential_scope_id

    def check(self, event):
        p = event["payload"]
        proxy = event["proxy_id"]
        owner = self.owners.get(p["invocation_id"])
        if owner is not None and owner != proxy:
            return 409, "invocation_owner_conflict"
        tool = p.get("tool")
        if event["event_type"] == "invocation.started" and tool and tool["status"] == "identified":
            ref = tool["metadata_ref"]
            mine = self.registry.get((proxy, ref))
            if mine is None:
                if any(r == ref for (_, r) in self.registry):
                    return 422, "semantic_invalid"     # registered under another proxy
                return 424, "metadata_ref_pending"
            if mine["upstream_id"] != p["upstream_id"]:
                return 422, "semantic_invalid"
            if p["protocol_version"] not in ("unknown", mine["protocol_version"]):
                return 422, "semantic_invalid"
            assigned = self.route_scopes.get((proxy, p["upstream_id"], p["route_revision"]))
            if assigned is not None and assigned != mine["credential_scope_id"]:
                return 422, "semantic_invalid"         # SV-5, depends on the config DTO (open)
        return 200, None

    def commit(self, event):
        self.owners.setdefault(event["payload"]["invocation_id"], event["proxy_id"])


sem = SemanticModel()
sem.registry[("proxy-demo", example_ref)] = make_entry(tool_def)   # credential scope "scope-1"
sem.registry[("proxy-demo", REF["b"])] = ent_b
sem.registry[("proxy-b", REF["c"])] = dict(ent_c, proxy_id="proxy-b")
sem.route_scopes[("proxy-demo", "fixture", 1)] = "scope-1"
assert sem.check(inv_start) == (200, None)
sem.commit(inv_start)


def sem_start(**payload_over):
    event = variant(example)
    event["payload"]["invocation_id"] = new_uuid()
    event["payload"].update(payload_over)
    return event


def sem_other(event):
    out = variant(event)
    out["payload"]["invocation_id"] = new_uuid()
    return out


foreign = variant(inv_comp)
foreign["proxy_id"] = "proxy-b"
foreign_ref = sem_start(tool={"status": "identified", "metadata_ref": REF["c"]})
unregistered = sem_start(tool={"status": "identified", "metadata_ref": v8_ref(999)})
other_upstream = sem_start(upstream_id="other-upstream",
                           tool={"status": "identified", "metadata_ref": REF["b"]})
unknown_proto = sem_start(protocol_version="unknown")
wrong_scope = sem_start()
semantic_cases = [
    ("completion for unknown invocation accepted", sem.check(sem_other(inv_comp)), (200, None)),
    ("cancel for unknown invocation accepted", sem.check(sem_other(inv_cancel)), (200, None)),
    ("owner conflict", sem.check(foreign), (409, "invocation_owner_conflict")),
    ("ref registered to another proxy", sem.check(foreign_ref), (422, "semantic_invalid")),
    ("unregistered ref pending", sem.check(unregistered), (424, "metadata_ref_pending")),
    ("ref entry for another upstream", sem.check(other_upstream), (422, "semantic_invalid")),
    ("unknown protocol with matching entry accepted", sem.check(unknown_proto), (200, None)),
]
sem.route_scopes[("proxy-demo", "fixture", 1)] = "scope-2"   # server assigned another scope
semantic_cases.append(("credential scope mismatch (SV-5)", sem.check(wrong_scope),
                       (422, "semantic_invalid")))
sem.route_scopes.clear()                                      # config history unavailable
semantic_cases.append(("no config history: SV-5 skipped (open)", sem.check(wrong_scope), (200, None)))
for label, got, expected in semantic_cases:
    assert got == expected, f"semantic {label}: {got} != {expected}"
assert REF["c"] not in json.dumps(sem.check(foreign_ref)), "no cross-proxy hint"

# --- L3 cursor model ------------------------------------------------------------------------
ORDER = {"/v1/proxy-invocations": ("created_seq", True),   # (key, descending)
         "/v1/proxies": ("proxy_id", False)}


def filter_hash(endpoint, filters):
    """F9: the hash binds endpoint, sort definition and normalised filters."""
    key, desc = ORDER[endpoint]
    return hashlib.sha256(canonical({"endpoint": endpoint, "sort": [key, desc],
                                     "filters": filters}).encode()).hexdigest()[:16]


def encode_cursor(endpoint, after, filters):
    raw = json.dumps({"v": 1, "after": after, "filter_hash": filter_hash(endpoint, filters)})
    return base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")


def decode_cursor(text, endpoint, filters):
    try:
        data = json.loads(base64.urlsafe_b64decode(text + "=" * (-len(text) % 4)))
        assert data["v"] == 1
    except Exception:
        return None, False
    ok = data["filter_hash"] == filter_hash(endpoint, filters)
    return (data["after"], ok)


def list_page(rows, filters, limit=2, cursor=None, endpoint="/v1/proxy-invocations",
              in_scope=None):
    key, desc = ORDER[endpoint]
    after = None
    if cursor is not None:
        after, ok = decode_cursor(cursor, endpoint, filters)
        if not ok:
            return 422, "invalid_cursor"
    pool = [r for r in rows if in_scope is None or r["proxy_id"] in in_scope]
    if "proxy_id" in filters and in_scope is not None and filters["proxy_id"] not in in_scope:
        pool = []                      # F10: same as an unknown proxy_id, no existence leak
    matched = [r for r in pool if all(r.get(k) == val for k, val in filters.items())]
    matched.sort(key=lambda r: r[key], reverse=desc)
    if after is not None:
        matched = [r for r in matched if (r[key] < after if desc else r[key] > after)]
    items = matched[:limit]
    more = len(matched) > limit
    return 200, {"items": items,
                 "next_cursor": encode_cursor(endpoint, items[-1][key], filters) if more else None}


def drain(rows, filters, endpoint="/v1/proxy-invocations", limit=2, **kw):
    keys = ORDER[endpoint][0]
    status_, page = list_page(rows, filters, limit=limit, endpoint=endpoint, **kw)
    seen = [r[keys] for r in page["items"]]
    while page["next_cursor"]:
        status_, page = list_page(rows, filters, limit=limit, cursor=page["next_cursor"],
                                  endpoint=endpoint, **kw)
        seen += [r[keys] for r in page["items"]]
    return seen


rows = [{"created_seq": i, "outcome": ("success" if i % 2 else None), "proxy_id": "proxy-demo"}
        for i in range(1, 8)]
cursor_cases = []
status_, first = list_page(rows, {})
rows.append({"created_seq": 8, "outcome": "success", "proxy_id": "proxy-demo"})  # arrives mid-scroll
seen, cur = [r["created_seq"] for r in first["items"]], first["next_cursor"]
while cur:
    status_, page = list_page(rows, {}, cursor=cur)
    seen += [r["created_seq"] for r in page["items"]]
    cur = page["next_cursor"]
cursor_cases.append(("no duplicate or skip while rows arrive", seen == [7, 6, 5, 4, 3, 2, 1]))
status_, filtered = list_page(rows, {"outcome": "success"}, limit=10)
cursor_cases.append(("outcome filter excludes no-completion rows",
                     all(r["outcome"] == "success" for r in filtered["items"])
                     and len(filtered["items"]) == 5))
cursor_cases.append(("cursor bound to filters", list_page(
    rows, {"outcome": "success"}, cursor=first["next_cursor"]) == (422, "invalid_cursor")))
cursor_cases.append(("garbage cursor", list_page(rows, {}, cursor="!!!") == (422, "invalid_cursor")))
cursor_cases.append(("last page has no cursor", list_page(rows, {}, limit=100)[1]["next_cursor"] is None))
# F1/F9: rows derived from real projections; the outcome filter matches lifecycle=completed only.
proj_rows = []
for n, evs in enumerate(([inv_start, inv_comp], [inv_start], [inv_comp],
                         [malformed_start, bad_success]), start=1):
    proj_rows.append(dict(project(evs), created_seq=n, proxy_id="proxy-demo"))
status_, hit = list_page(proj_rows, {"outcome": "success"}, limit=10)
cursor_cases.append(("outcome=success matches only lifecycle=completed (F1)",
                     [r["lifecycle"] for r in hit["items"]] == ["completed"]))
status_, by_life = list_page(proj_rows, {"lifecycle": "completion_without_start"}, limit=10)
cursor_cases.append(("completion_without_start found by lifecycle only",
                     len(by_life["items"]) == 1
                     and by_life["items"][0]["reported_outcome"] == "success"))
# F9: endpoint and sort are part of the cursor hash.
proxies = [{"proxy_id": f"proxy-{c}", "connection_state": "connected"} for c in "abcde"]
status_, p1 = list_page(proxies, {}, endpoint="/v1/proxies")
cursor_cases.append(("proxies cursor ascending pages", drain(proxies, {}, "/v1/proxies") ==
                     [f"proxy-{c}" for c in "abcde"]))
cursor_cases.append(("cursor from another endpoint rejected", list_page(
    rows, {}, cursor=p1["next_cursor"]) == (422, "invalid_cursor")))
# F9: filters on mutable fields are not snapshot-stable: no duplicates, a row may be missed.
mut = [{"created_seq": i, "lifecycle": "started", "proxy_id": "proxy-demo"} for i in range(1, 7)]
status_, m1 = list_page(mut, {"lifecycle": "started"})
mut[2]["lifecycle"] = "completed"            # row 3 leaves the filter between pages
rest, cur = [], m1["next_cursor"]
while cur:
    status_, pg = list_page(mut, {"lifecycle": "started"}, cursor=cur)
    rest += [r["created_seq"] for r in pg["items"]]
    cur = pg["next_cursor"]
got = [r["created_seq"] for r in m1["items"]] + rest
cursor_cases.append(("mutable filter: no duplicates, flipped row absent",
                     got == [6, 5, 4, 2, 1] and len(got) == len(set(got))))
# F10: out-of-scope proxy_id filter equals an unknown proxy_id.
scope_rows = [{"created_seq": 1, "proxy_id": "proxy-demo"}, {"created_seq": 2, "proxy_id": "proxy-x"}]
cursor_cases.append(("out-of-scope proxy filter equals unknown", list_page(
    scope_rows, {"proxy_id": "proxy-x"}, in_scope={"proxy-demo"}) == list_page(
    scope_rows, {"proxy_id": "proxy-none"}, in_scope={"proxy-demo"})
    and list_page(scope_rows, {"proxy_id": "proxy-x"}, in_scope={"proxy-demo"})[1]["items"] == []))
cursor_cases.append(("out-of-scope rows never listed", drain(
    scope_rows, {}, in_scope={"proxy-demo"}) == [1]))
# F10: detail events carry total/truncated.
def detail_events(n):
    return {"events_total": n, "events_truncated": n > 32, "events": min(n, 32)}


cursor_cases.append(("detail events truncated flag", detail_events(33)["events_truncated"]
                     and not detail_events(32)["events_truncated"]))
for label, ok in cursor_cases:
    assert ok, f"cursor case {label}"

# --- R5/R7 inventory and marker model ---------------------------------------------------------
class InventoryModel:
    def __init__(self, registered=None):
        self.reports, self.snaps, self.chains, self.state = {}, {}, {}, {}
        self.pending, self.drift, self.markers, self.gaps = [], [], [], []
        self.registered = registered       # None: I-2 not modelled

    @staticmethod
    def chain_key(r):
        return (r["proxy_id"], tuple(sorted(r["scope"].items())))

    def _derive(self, r, prev):
        """Return (drift list, None) or (None, 'inconsistent')."""
        comp = r["comparison"]
        members, before = set(r["members"]), prev["members"]
        added, removed = members - before, before - members
        covered_added, covered_removed = set(), set()
        for ch in comp["changes"]:
            ref = ch["metadata_ref"]
            if ch["change"] == "added":
                if ref not in added or ref in covered_added:
                    return None, "inconsistent"
                covered_added.add(ref)
            elif ch["change"] == "removed":
                if ref not in removed or ref in covered_removed:
                    return None, "inconsistent"
                covered_removed.add(ref)
            else:
                old = ch["previous_metadata_ref"]
                if (ref not in added or ref in covered_added or old not in removed
                        or old in covered_removed):
                    return None, "inconsistent"
                covered_added.add(ref)
                covered_removed.add(old)
        if covered_added != added or covered_removed != removed:
            return None, "inconsistent"
        return [(ch["change"], ch["metadata_ref"], ch.get("previous_metadata_ref"))
                for ch in comp["changes"]], None

    def _check(self, r, prev):
        """I-3, I-6, I-7, I-8 against a known previous snapshot. Returns drift list or None."""
        comp = r["comparison"]
        if prev["chain"] != self.chain_key(r):                       # I-6
            return None
        same_domain = (prev["canon"], prev["key_id"]) == (r["canon"], r["key_id"])
        if comp["kind"] == "compared":
            if not same_domain:                                      # I-6 (another key/canon)
                return None
            found, bad = self._derive(r, prev)                       # I-3
            return None if bad else found
        if same_domain:                                              # I-7: nothing rebaselined
            return None
        froms = [l["from_metadata_ref"] for l in comp["links"]]       # I-8
        tos = [l["to_metadata_ref"] for l in comp["links"]]
        if (len(set(froms)) != len(froms) or len(set(tos)) != len(tos)
                or not set(froms) <= prev["members"] or not set(tos) <= set(r["members"])):
            return None
        return []

    def ingest(self, r):
        old = self.reports.get(r["report_id"])
        if old is not None:
            return "duplicate" if canonical(old) == canonical(r) else "conflict"
        if r["completeness"] == "incomplete":   # observation + gap only
            self.reports[r["report_id"]] = r
            self.gaps.append({"kind": "inventory_incomplete", "reason": r["incomplete_reason"]})
            return "accepted"
        refs = set(r["members"])
        if self.registered is not None and not refs <= self.registered:   # I-2
            return "424:metadata_ref_pending"
        key = self.chain_key(r)
        comp = r["comparison"]
        if comp["kind"] != "initial_baseline":
            prev = self.snaps.get(comp["previous_inventory_id"])
            if prev is not None and self._check(r, prev) is None:
                return "422:semantic_invalid"     # nothing stored, nothing ACKed
        self.reports[r["report_id"]] = r
        earlier = [self.snaps[i] for i in self.chains.get(key, [])]
        if comp["kind"] == "initial_baseline":
            diff = [s for s in earlier if (s["canon"], s["key_id"]) != (r["canon"], r["key_id"])]
            if diff:
                cause = ("epoch_change_detected" if diff[-1]["epoch_id"] != r["epoch_id"]
                         else "key_change_undeclared")
                self.markers.append({"cause": cause, "inventory_id": r["inventory_id"],
                                     "links_present": False, "drift_computed": False})
            elif earlier:
                self.markers.append({"cause": "baseline_restated", "inventory_id": r["inventory_id"],
                                     "links_present": False, "drift_computed": False})
        self.snaps[r["inventory_id"]] = {
            "members": set(r["members"]), "canon": r["canon"], "key_id": r["key_id"],
            "epoch_id": r["epoch_id"], "chain": key}
        self.chains.setdefault(key, []).append(r["inventory_id"])
        self.state[r["inventory_id"]] = ("baseline" if comp["kind"] == "initial_baseline"
                                         else "pending_previous")
        if comp["kind"] != "initial_baseline":
            self.pending.append(r)
        self._resolve()
        return "accepted"

    def _resolve(self):
        progressed = True
        while progressed:
            progressed = False
            for r in list(self.pending):
                prev = self.snaps.get(r["comparison"]["previous_inventory_id"])
                if prev is None:
                    continue
                self.pending.remove(r)
                progressed = True
                comp = r["comparison"]
                found = self._check(r, prev)
                if found is None:   # deferred failure never un-ACKs: gap, no drift, no marker
                    self.state[r["inventory_id"]] = "inconsistent"
                    self.gaps.append({"kind": "comparison_inconsistent",
                                      "inventory_id": r["inventory_id"]})
                elif comp["kind"] == "rebaseline":
                    self.state[r["inventory_id"]] = "rebaseline"
                    self.markers.append({
                        "cause": ("declared_key_rotation" if comp["reason"] == "key_rotation"
                                  else "declared_canon_change"),
                        "inventory_id": r["inventory_id"], "links_present": bool(comp["links"]),
                        "drift_computed": False})
                else:
                    self.state[r["inventory_id"]] = "compared"
                    self.drift += [(r["inventory_id"],) + d for d in found]


def fresh(**over):
    return report(report_id=new_uuid(), **over)


inventory_cases = []
inv = InventoryModel()
r1 = fresh(inventory_id=INV[0])
assert inv.ingest(r1) == "accepted"
inventory_cases.append(("first complete is baseline, no drift", inv.drift == [] and inv.markers == []))
r2 = fresh(inventory_id=INV[1], members=[REF["a2"], REF["c"]], comparison=rep_compared["comparison"])
assert inv.ingest(r2) == "accepted"
inventory_cases.append(("added/changed/removed -> three drift records",
                        sorted(d[1] for d in inv.drift) == ["added", "changed", "removed"]
                        and len(inv.drift) == 3))
before_members = set(inv.snaps[INV[1]]["members"])
r_inc = fresh(completeness="incomplete", incomplete_reason="access_denied", pages_observed=1)
for field in ("inventory_id", "members", "comparison"):
    del r_inc[field]
drift_before = len(inv.drift)
assert inv.ingest(r_inc) == "accepted"
inventory_cases.append(("incomplete listing removes nothing",
                        len(inv.drift) == drift_before
                        and inv.snaps[INV[1]]["members"] == before_members
                        and inv.gaps == [{"kind": "inventory_incomplete", "reason": "access_denied"}]))
r3 = fresh(inventory_id=INV[2], members=[REF["a2"], REF["c"]], comparison={
    "kind": "compared", "previous_inventory_id": INV[1], "changes": []})
inv.ingest(r3)
inventory_cases.append(("complete after incomplete compares to last complete",
                        len(inv.drift) == drift_before))
r_rot = fresh(inventory_id=INV[3], key_id="kid-" + "ab" * 12, members=[v8_ref(1)], comparison={
    "kind": "rebaseline", "previous_inventory_id": INV[2], "reason": "key_rotation",
    "links": [{"from_metadata_ref": REF["a2"], "to_metadata_ref": v8_ref(1),
               "definition_comparison": "different"}]})
inv.ingest(r_rot)
inventory_cases.append(("declared rotation: marker, no drift",
                        inv.markers == [{"cause": "declared_key_rotation", "inventory_id": INV[3],
                                         "links_present": True, "drift_computed": False}]
                        and len(inv.drift) == drift_before))
r_loss = fresh(inventory_id=INV[4], key_id="kid-" + "cd" * 12,
               epoch_id="9b2e4c71-0d3a-4f6b-8e5c-1a7d9f3b2c64", members=[v8_ref(7)])
inv.ingest(r_loss)
inventory_cases.append(("undeclared key change after epoch change: marker",
                        inv.markers[-1]["cause"] == "epoch_change_detected"
                        and inv.markers[-1]["drift_computed"] is False
                        and len(inv.drift) == drift_before))
other_scope = fresh(inventory_id=INV[5], members=[], scope=dict(SCOPE_DOC, credential_scope_id="scope-9"))
markers_before = len(inv.markers)
chain_before = set(inv.snaps[INV[2]]["members"])
inv.ingest(other_scope)
inventory_cases.append(("different credential scope: separate chain, no removal",
                        len(inv.markers) == markers_before and len(inv.drift) == drift_before
                        and inv.snaps[INV[2]]["members"] == chain_before))
bad_changes = fresh(inventory_id=INV[1], members=[REF["a"]], comparison={
    "kind": "compared", "previous_inventory_id": INV[0], "changes": []})   # b vanished, not covered
known = InventoryModel()
known.ingest(fresh(inventory_id=INV[0]))
inventory_cases.append(("I-3 mismatch with known previous: 422, nothing stored (F7)",
                        known.ingest(bad_changes) == "422:semantic_invalid"
                        and known.drift == [] and known.gaps == []
                        and bad_changes["report_id"] not in known.reports))
deferred = InventoryModel()
assert deferred.ingest(bad_changes) == "accepted"          # previous unknown: pending
deferred.ingest(fresh(inventory_id=INV[0]))
inventory_cases.append(("I-3 mismatch, previous arrives later: gap, no drift",
                        deferred.drift == [] and deferred.state[INV[1]] == "inconsistent"
                        and deferred.gaps == [{"kind": "comparison_inconsistent",
                                               "inventory_id": INV[1]}]))
other_key_compared = fresh(inventory_id=INV[6], key_id="kid-" + "ef" * 12, members=[REF["a"]],
                           comparison={"kind": "compared", "previous_inventory_id": INV[0],
                                       "changes": []})
k2 = InventoryModel()
k2.ingest(fresh(inventory_id=INV[0]))
inventory_cases.append(("I-6 compared against another key, previous known: 422 (F7)",
                        k2.ingest(other_key_compared) == "422:semantic_invalid"))
k3 = InventoryModel()
assert k3.ingest(other_key_compared) == "accepted"
k3.ingest(fresh(inventory_id=INV[0]))
inventory_cases.append(("I-6 deferred: gap, no drift (F7)",
                        k3.state[INV[6]] == "inconsistent" and k3.drift == []
                        and k3.gaps == [{"kind": "comparison_inconsistent", "inventory_id": INV[6]}]))
same_key_rebase = fresh(inventory_id=INV[7], members=[REF["a"], REF["b"]], comparison={
    "kind": "rebaseline", "previous_inventory_id": INV[0], "reason": "key_rotation", "links": []})
k4 = InventoryModel()
k4.ingest(fresh(inventory_id=INV[0]))
inventory_cases.append(("I-7 rebaseline with unchanged key: 422 (F2)",
                        k4.ingest(same_key_rebase) == "422:semantic_invalid" and k4.markers == []))
new_kid = "kid-" + "ab" * 12


def rebase(links, members):
    return fresh(inventory_id=INV[3], key_id=new_kid, members=members, comparison={
        "kind": "rebaseline", "previous_inventory_id": INV[0], "reason": "key_rotation",
        "links": links})


k5 = InventoryModel()
k5.ingest(fresh(inventory_id=INV[0]))
good_link = {"from_metadata_ref": REF["a"], "to_metadata_ref": v8_ref(1),
             "definition_comparison": "identical"}
inventory_cases.append(("I-8 link from not in previous members: 422 (F2)",
                        k5.ingest(rebase([dict(good_link, from_metadata_ref=REF["c"])],
                                         [v8_ref(1)])) == "422:semantic_invalid"))
inventory_cases.append(("I-8 link to not in current members: 422 (F2)",
                        k5.ingest(rebase([good_link], [v8_ref(2)])) == "422:semantic_invalid"))
inventory_cases.append(("I-8 duplicate link side: 422 (F2)",
                        k5.ingest(rebase([good_link, dict(good_link, to_metadata_ref=v8_ref(2))],
                                         [v8_ref(1), v8_ref(2)])) == "422:semantic_invalid"))
inventory_cases.append(("valid rebaseline accepted with marker (F2)",
                        k5.ingest(rebase([good_link], [v8_ref(1)])) == "accepted"
                        and k5.markers[-1]["cause"] == "declared_key_rotation"
                        and k5.state[INV[3]] == "rebaseline"))
reg = InventoryModel(registered={REF["a"]})
inventory_cases.append(("I-2 unregistered member: 424", reg.ingest(fresh(
    inventory_id=INV[0])) == "424:metadata_ref_pending"))
in_order, reordered = InventoryModel(), InventoryModel()
for r in (r1, r2):
    in_order.ingest(r)
for r in (r2, r1):
    reordered.ingest(r)
inventory_cases.append(("report before its previous: same result",
                        sorted(in_order.drift) == sorted(reordered.drift) and reordered.pending == []))
inventory_cases.append(("pending_previous state while previous unknown (F8)", (lambda m: (
    m.ingest(r2), len(m.pending) == 1 and m.drift == []
    and m.state[INV[1]] == "pending_previous")[1])(InventoryModel())))
inventory_cases.append(("report_id retransmission duplicate, change conflict", (lambda m: (
    m.ingest(r1) == "accepted" and m.ingest(copy.deepcopy(r1)) == "duplicate"
    and m.ingest(dict(r1, pages_observed=9)) == "conflict"))(InventoryModel())))
for label, ok in inventory_cases:
    assert ok, f"inventory case {label}"

# --- L6 counters model -------------------------------------------------------------------------
def merge_counters(store, proxy, epoch, counters):
    for kind in ("auth_failures", "unmatched_cancels"):
        for entry_ in counters[kind]:
            key = (proxy, epoch, kind, entry_["upstream_id"], entry_["reason"])
            store[key] = max(store.get(key, 0), entry_["count"])


counter_store = {}
merge_counters(counter_store, "proxy-demo", example["epoch_id"], status()["counters"])
lower = status()["counters"]
lower["auth_failures"][0]["count"] = 1
merge_counters(counter_store, "proxy-demo", example["epoch_id"], lower)   # reordered/lost report
counter_cases = [
    ("stale lower count ignored", counter_store[(
        "proxy-demo", example["epoch_id"], "auth_failures", "fixture", "credential_invalid")] == 3),
    ("unrouted failures keyed by null route", ("proxy-demo", example["epoch_id"], "auth_failures",
                                               None, "credential_missing") in counter_store),
    ("counter entries carry no actor", all(set(e_) == {"upstream_id", "reason", "count"}
                                           for k in ("auth_failures", "unmatched_cancels")
                                           for e_ in status()["counters"][k])),
    ("counter store keyed by epoch", len({k[1] for k in counter_store}) == 1),
]
for label, ok in counter_cases:
    assert ok, f"counter case {label}"


# --- L6b status endpoint model: state snapshot vs gap upsert (F6) -----------------------------
class StatusModel:
    def __init__(self):
        self.gaps, self.state, self.epochs = {}, {}, {}

    def submit(self, identity, doc):
        proxy = doc["proxy_id"]
        if proxy != identity:
            return 403, None
        bad_422 = [{"index": i, "code": "schema_invalid"} for i, g in enumerate(doc["gaps"])
                   if g["kind"] == "registry_conflict"
                   and g["affected_event_count"] < len(g["event_ids"])]
        if bad_422:
            return 422, {"error": {"code": "invalid_status", "message": "Invalid status",
                                   "items": bad_422}}
        conflicts, ack, dup, updates = [], [], [], []
        for i, g in enumerate(doc["gaps"]):
            old = self.gaps.get((proxy, g["gap_id"]))
            if old is None:
                ack.append(g["gap_id"])
                updates.append(g)
            elif canonical(old) == canonical(g):
                dup.append(g["gap_id"])
            elif (old["kind"] == "central_outage" and g["kind"] == "central_outage"
                  and old["ended_at"] is None and g["ended_at"] is not None
                  and {k: x for k, x in old.items() if k != "ended_at"}
                  == {k: x for k, x in g.items() if k != "ended_at"}):
                ack.append(g["gap_id"])
                updates.append(g)
            else:
                conflicts.append({"index": i, "gap_id": g["gap_id"], "code": "conflict"})
        if conflicts:
            return 409, {"error": {"code": "gap_conflict", "message": "Conflicting gaps",
                                   "items": conflicts}}
        for g in updates:
            self.gaps[(proxy, g["gap_id"])] = g
        known = self.epochs.setdefault(proxy, [])
        applied = False
        if doc["epoch_id"] not in known:
            known.append(doc["epoch_id"])
            applied = True
        elif known[-1] == doc["epoch_id"]:
            applied = doc["status_sequence"] > self.state.get(proxy, (None, 0))[1]
        if applied:
            self.state[proxy] = (doc["epoch_id"], doc["status_sequence"])
        return 200, {"state_applied": applied, "acknowledged_gap_ids": ack,
                     "duplicate_gap_ids": dup}


sm = StatusModel()
outage_open = dict(GAPS["central_outage"])
outage_closed = dict(outage_open, ended_at="2026-10-10T01:30:00Z")
quarantine = GAPS["event_quarantined"]
status_cases = []
code, body = sm.submit("proxy-demo", status(status_sequence=5, gaps=[outage_open]))
status_cases.append(("first report stores gap and state", code == 200 and body == {
    "state_applied": True, "acknowledged_gap_ids": [outage_open["gap_id"]],
    "duplicate_gap_ids": []}))
code, body = sm.submit("proxy-demo", status(status_sequence=2, gaps=[quarantine]))
status_cases.append(("lower status_sequence still upserts gaps", code == 200
                     and body["state_applied"] is False
                     and body["acknowledged_gap_ids"] == [quarantine["gap_id"]]
                     and ("proxy-demo", quarantine["gap_id"]) in sm.gaps))
code, body = sm.submit("proxy-demo", status(status_sequence=6, gaps=[quarantine]))
status_cases.append(("equal gap resend is duplicate", body["duplicate_gap_ids"]
                     == [quarantine["gap_id"]] and body["state_applied"] is True))
code, body = sm.submit("proxy-demo", status(status_sequence=7, gaps=[outage_closed]))
status_cases.append(("central_outage ended_at null to value allowed",
                     code == 200 and body["acknowledged_gap_ids"] == [outage_open["gap_id"]]
                     and sm.gaps[("proxy-demo", outage_open["gap_id"])]["ended_at"]
                     == "2026-10-10T01:30:00Z"))
code, body = sm.submit("proxy-demo", status(status_sequence=8, gaps=[outage_open]))
status_cases.append(("ended_at value back to null conflicts", code == 409 and body["error"][
    "items"] == [{"index": 0, "gap_id": outage_open["gap_id"], "code": "conflict"}]))
code, body = sm.submit("proxy-demo", status(status_sequence=8, gaps=[dict(
    quarantine, code="sequence_conflict")]))
status_cases.append(("any other gap difference conflicts, state not applied",
                     code == 409 and sm.state["proxy-demo"][1] == 7))
code, body = sm.submit("proxy-demo", status(status_sequence=1, epoch_id=other_epoch))
status_cases.append(("new epoch resets status_sequence", code == 200 and body["state_applied"]))
code, body = sm.submit("proxy-demo", status(status_sequence=99))   # old epoch after new one
status_cases.append(("older epoch report does not apply state", body["state_applied"] is False))
status_cases.append(("identity mismatch 403", sm.submit("proxy-other", status())[0] == 403))
status_cases.append(("affected_event_count below ids 422 index only", (lambda r: r[0] == 422
                     and r[1]["error"]["items"] == [{"index": 0, "code": "schema_invalid"}])(
    sm.submit("proxy-demo", status(gaps=[dict(GAPS["registry_conflict"], gap_id=new_uuid(),
                                              event_ids=[new_uuid(), new_uuid()],
                                              affected_event_count=1)])))))


# F13: tail-loss detection from last_assigned_sequence (AC-06)
def sequence_gaps(accepted, last_assigned):
    out, top = [], max(accepted, default=0)
    run = None
    for n in range(1, top + 1):
        if n in accepted:
            if run:
                out.append((run[0], run[1], False))
                run = None
        else:
            run = (run[0], n) if run else (n, n)
    if last_assigned > top:
        out.append((top + 1, last_assigned, True))
    return out


status_cases.append(("hole below highest accepted", sequence_gaps({1, 2, 3, 5}, 5)
                     == [(4, 4, False)]))
status_cases.append(("tail loss from last_assigned_sequence", sequence_gaps({1, 2, 3, 5}, 7)
                     == [(4, 4, False), (6, 7, True)]))
status_cases.append(("no gap when everything arrived", sequence_gaps({1, 2, 3}, 3) == []))
status_cases.append(("nothing assigned", sequence_gaps(set(), 0) == []))
status_cases.append(("gap closes when the sequences arrive", sequence_gaps({1, 2, 3, 4, 5, 6, 7}, 7)
                     == []))


# F14: registry_conflict with more than 100 dependent events is split, count preserved
def split_registry_conflict(event_ids, template):
    chunks = [event_ids[i:i + 100] for i in range(0, len(event_ids), 100)]
    return [dict(template, gap_id=new_uuid(), event_ids=c, affected_event_count=len(event_ids))
            for c in chunks]


ids250 = [new_uuid() for _ in range(250)]
chunks = split_registry_conflict(ids250, GAPS["registry_conflict"])
status_cases.append(("overflow split into 3 chunks of 100/100/50", [len(c["event_ids"])
                     for c in chunks] == [100, 100, 50]))
status_cases.append(("every chunk is schema valid with the total count", all(
    stat.is_valid(status(gaps=[c])) and c["affected_event_count"] == 250 for c in chunks)))
status_cases.append(("chunk gap ids distinct", len({c["gap_id"] for c in chunks}) == 3))
sm2 = StatusModel()
status_cases.append(("server accepts all chunks", all(
    sm2.submit("proxy-demo", status(status_sequence=n + 1, gaps=[c]))[0] == 200
    for n, c in enumerate(chunks))))
for label, ok in status_cases:
    assert ok, f"status case {label}"

w2_registry_pos = sum(1 for _, val, _d in w_pos if val not in (stat, stat_resp))
w2_registry_neg = sum(1 for _, val, _d in w_neg if val not in (stat, stat_resp))
w2_status_pos = sum(1 for _, val, _d in w_pos if val in (stat, stat_resp))
w2_status_neg = sum(1 for _, val, _d in w_neg if val in (stat, stat_resp))
_w2_pass_line = (f"PASS W2 (D-03/D-05 candidates): registry/inventory {w2_registry_pos} positive and "
      f"{w2_registry_neg} rejected cases, status {w2_status_pos} positive and {w2_status_neg} "
      f"rejected cases, {len(retention_cases)} retention-model cases, {len(projection_cases)} "
      f"projection-model cases, {len(semantic_cases)} cross-event-validation-model cases, "
      f"{len(cursor_cases)} cursor-model cases, {len(inventory_cases)} inventory/marker-model "
      f"cases, {len(counter_cases)} counter-model cases, {len(status_cases)} "
      f"status-upsert/gap-model cases")

print(_legacy_pass_line)
print(_w2_pass_line)
print("NOT TESTED: producer normalization/provenance, registry sync/authorization, "
      "ingestion/ledger, durability, protocol support or hardware compatibility")
print("NOT TESTED (W2): ledger/SQLite transactions, projection persistence, cursor behaviour under "
      "real load, producer rotation and K handling, registry/inventory endpoints, manager "
      "rendering, permission wiring or hardware compatibility")
