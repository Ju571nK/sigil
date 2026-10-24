#!/usr/bin/env python3
"""Sigil Proxy AWS smoke client (stdlib only).

Subcommands:
  scenario    MCP flow through the proxy: auth/session/protocol rejections,
              initialize, list, call (JSON, SSE, tool error), cancel, inventory
              mutation, cross-session cancel isolation, DELETE.
  call        open one session and make N echo calls (outage / spool tests).
  counters    read the fixture's out-of-band counters (test oracle).
  query       GET one sigil-server read route over mTLS + read bearer.
  ledger      check invocations on the server: uniqueness, lifecycle, outcomes,
              duplicate event ids, and canary absence in ordinary responses.
  scan        count canary / secret occurrences in files (spool, logs).

Secrets (bearer tokens) are read from owner-only files and never printed. Raw
tool results are compared, not printed. No environment proxy is used and no
request is retried.
"""

import argparse
import datetime
import http.client
import json
import os
import secrets
import ssl
import stat
import sys
import threading
import time
import urllib.parse

REVISION = "2025-11-25"
LEGACY_REVISION = "2025-06-18"
BASE_TOOLS = ("smoke_echo", "smoke_sse", "smoke_fail", "smoke_wait", "smoke_inventory_toggle")
EXTRA_TOOL = "smoke_inventory_extra"
MAX_RESPONSE = 4 * 1024 * 1024
TIMEOUT = 40


def read_secret_file(path):
    st = os.lstat(path)
    if not stat.S_ISREG(st.st_mode):
        raise SystemExit("%s: must be a regular file, not a symlink" % path)
    if st.st_mode & 0o077:
        raise SystemExit("%s: must not be group/world accessible (chmod 600)" % path)
    if hasattr(os, "geteuid") and st.st_uid != os.geteuid():
        raise SystemExit("%s: must be owned by the running user" % path)
    with open(path, "rb") as f:
        raw = f.read(4097)
    token = raw.decode("ascii", "replace").strip()
    if len(raw) > 4096 or not token or not all(0x21 <= ord(c) <= 0x7E for c in token):
        raise SystemExit("%s: must hold one printable ASCII token" % path)
    return token


def write_private(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(data)


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------- transport

class Endpoint:
    def __init__(self, url, ca=None, cert=None, key=None):
        u = urllib.parse.urlsplit(url)
        if u.scheme not in ("http", "https") or not u.hostname:
            raise SystemExit("unsupported URL")
        if u.username or u.password or u.query or u.fragment:
            raise SystemExit("URL must not carry userinfo, query or fragment")
        self.scheme, self.host = u.scheme, u.hostname
        self.port = u.port or (443 if u.scheme == "https" else 80)
        self.path = u.path or "/"
        self.ctx = None
        if u.scheme == "https":
            self.ctx = ssl.create_default_context(cafile=ca)
            if cert:
                self.ctx.load_cert_chain(cert, key)

    def request(self, method, path=None, body=None, headers=None):
        if self.scheme == "https":
            conn = http.client.HTTPSConnection(self.host, self.port, timeout=TIMEOUT,
                                               context=self.ctx)
        else:
            conn = http.client.HTTPConnection(self.host, self.port, timeout=TIMEOUT)
        try:
            conn.request(method, path or self.path, body=body, headers=headers or {})
            r = conn.getresponse()
            data = r.read(MAX_RESPONSE + 1)
            hdrs = {}
            for k, v in r.getheaders():
                hdrs.setdefault(k.lower(), []).append(v)
            if len(data) > MAX_RESPONSE:
                return 0, {}, b"ResponseTooLarge"
            return r.status, hdrs, data
        except (OSError, http.client.HTTPException) as e:
            return 0, {}, type(e).__name__.encode()
        finally:
            conn.close()


def decode_message(hdrs, body):
    """JSON body or the last JSON-RPC message of a finite SSE body."""
    ctype = (hdrs.get("content-type") or [""])[0].split(";")[0].strip()
    try:
        if ctype == "application/json":
            return json.loads(body)
        if ctype == "text/event-stream":
            msg, data = None, []
            for line in body.decode("utf-8").replace("\r\n", "\n").split("\n") + [""]:
                if line.startswith("data:"):
                    data.append(line[5:].lstrip(" "))
                elif line == "" and data:
                    msg, data = json.loads("\n".join(data)), []
            return msg
    except (ValueError, UnicodeDecodeError):
        return None
    return None


class McpClient:
    def __init__(self, url, token, ca=None):
        self.ep = Endpoint(url, ca=ca)
        self.token = token
        self.next_id = 1
        self.session = None

    def headers(self, session=True, version=True, token=True, extra=None):
        h = {"Content-Type": "application/json",
             "Accept": "application/json, text/event-stream"}
        if token:
            h["Authorization"] = "Bearer " + (self.token if token is True else token)
        if session and self.session:
            h["Mcp-Session-Id"] = self.session
        if version:
            h["MCP-Protocol-Version"] = REVISION
        h.update(extra or {})
        return h

    def post(self, msg, **kw):
        body = json.dumps(msg, separators=(",", ":")).encode()
        return self.ep.request("POST", body=body, headers=self.headers(**kw))

    def rpc(self, method, params=None, rid=None, **kw):
        if rid is None:
            rid, self.next_id = self.next_id, self.next_id + 1
        msg = {"jsonrpc": "2.0", "id": rid, "method": method}
        if params is not None:
            msg["params"] = params
        st, h, b = self.post(msg, **kw)
        return st, h, decode_message(h, b) if st == 200 else None

    def notify(self, method, params=None, **kw):
        msg = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        st, _, _ = self.post(msg, **kw)
        return st

    def initialize(self, with_session=False, **kw):
        params = {"protocolVersion": REVISION, "capabilities": {},
                  "clientInfo": {"name": "sigil-smoke-client", "version": "0.1.0"}}
        st, h, msg = self.rpc("initialize", params, session=with_session, version=False, **kw)
        sid = (h.get("mcp-session-id") or [None])[0]
        if st == 200 and sid:
            self.session = sid
        return st, h, msg

    def open(self):
        st, h, msg = self.initialize()
        if st != 200 or not self.session:
            return st
        return self.notify("notifications/initialized")

    def delete(self):
        h = self.headers(extra=None)
        h.pop("Content-Type", None)
        st, _, _ = self.ep.request("DELETE", headers=h)
        return st

    def list_all(self, max_pages=20):
        names, cursor = [], None
        for _ in range(max_pages):
            st, _, msg = self.rpc("tools/list", {"cursor": cursor} if cursor else {})
            if st != 200 or not msg or "result" not in msg:
                return None
            names += [t.get("name") for t in msg["result"].get("tools", [])]
            cursor = msg["result"].get("nextCursor")
            if not cursor:
                return names
        return None


def result_text(msg):
    try:
        return msg["result"]["content"][0]["text"], bool(msg["result"].get("isError"))
    except (KeyError, IndexError, TypeError):
        return None, None


# ---------------------------------------------------------------- scenario

class Checks:
    def __init__(self):
        self.items = []

    def add(self, cid, what, ok, actual):
        self.items.append({"id": cid, "check": what, "pass": bool(ok), "actual": actual})
        print("%-4s %-4s %-62s %s" % ("PASS" if ok else "FAIL", cid, what, actual), flush=True)

    def failed(self):
        return [c for c in self.items if not c["pass"]]


def visible_ascii(s):
    return bool(s) and all(0x21 <= ord(c) <= 0x7E for c in s)


def scenario(a):
    token = read_secret_file(a.token_file)
    c = Checks()
    run_id = secrets.token_hex(6)
    canary_args = "SIGIL-CANARY-ARG-%s" % secrets.token_hex(12)
    canary_sse = "SIGIL-CANARY-SSE-%s" % secrets.token_hex(12)
    started_at = utc_now()

    m = McpClient(a.url, token, ca=a.ca)
    # Transport/auth rejections (no invocation expected on the server).
    st, _, _ = m.initialize(token=False)
    c.add("N1", "initialize without bearer -> 401", st == 401, st)
    m.session = None
    st, _, _ = m.initialize(token="wrong-" + secrets.token_hex(16))
    c.add("N2", "initialize with wrong bearer -> 401", st == 401, st)
    m.session = None
    st, _, _ = m.ep.request("GET", headers={"Authorization": "Bearer " + token,
                                            "Accept": "text/event-stream"})
    c.add("N3", "GET (SSE stream) -> 405", st == 405, st)

    # Session establishment.
    st, h, msg = m.initialize()
    sid = m.session
    caps = (msg or {}).get("result", {}).get("capabilities", {})
    c.add("S1", "initialize -> 200 + proxy session id", st == 200 and visible_ascii(sid),
          "%s sid_len=%s" % (st, len(sid or "")))
    c.add("S1a", "negotiated protocolVersion == 2025-11-25",
          (msg or {}).get("result", {}).get("protocolVersion") == REVISION,
          (msg or {}).get("result", {}).get("protocolVersion"))
    c.add("S1b", "no tasks / resources.subscribe advertised",
          "tasks" not in caps and not (caps.get("resources") or {}).get("subscribe"),
          sorted(caps))
    st, _, _ = m.initialize(with_session=True)
    c.add("N4", "initialize carrying Mcp-Session-Id -> 400", st == 400, st)
    m.session = sid
    st = m.notify("notifications/initialized")
    c.add("S2", "notifications/initialized -> 202", st == 202, st)

    saved = m.session
    m.session = None
    st, _, _ = m.rpc("tools/list", {})
    c.add("N5", "tools/list without session -> 400", st == 400, st)
    m.session = "unknown-" + secrets.token_urlsafe(24)
    st, _, _ = m.rpc("tools/list", {})
    c.add("N6", "tools/list with unknown session -> 404", st == 404, st)
    m.session = saved
    st, _, _ = m.rpc("tools/list", {}, version=False)
    c.add("N7", "missing MCP-Protocol-Version -> 400", st == 400, st)
    st, _, _ = m.rpc("tools/list", {}, version=False,
                     extra={"MCP-Protocol-Version": LEGACY_REVISION})
    c.add("N8", "legacy MCP-Protocol-Version -> 400", st == 400, st)

    st, _, msg = m.rpc("ping")
    c.add("S3", "ping -> 200 result", st == 200 and msg and "result" in msg, st)
    names = m.list_all()
    c.add("S4", "tools/list (all pages) has base tools",
          names is not None and set(BASE_TOOLS) <= set(names), "count=%s" % (None if names is None else len(names)))

    st, _, msg = m.rpc("tools/call", {"name": "smoke_echo", "arguments": {"marker": canary_args}})
    text, err = result_text(msg)
    c.add("S5", "tools/call smoke_echo (JSON) -> exact result",
          st == 200 and text == "echo:" + canary_args and not err, st)
    st, h, msg = m.rpc("tools/call", {"name": "smoke_sse", "arguments": {"marker": canary_sse}})
    text, err = result_text(msg)
    ctype = (h.get("content-type") or [""])[0]
    c.add("S6", "tools/call smoke_sse (SSE) -> exact result",
          st == 200 and ctype.startswith("text/event-stream") and text == "sse:" + canary_sse,
          "%s %s" % (st, ctype.split(";")[0]))
    st, _, msg = m.rpc("tools/call", {"name": "smoke_fail", "arguments": {}})
    _, err = result_text(msg)
    c.add("S7", "tools/call smoke_fail -> result.isError", st == 200 and err is True, st)
    st, _, msg = m.rpc("tools/call", {"name": "no_such_tool", "arguments": {}})
    c.add("S7a", "tools/call unknown tool -> JSON-RPC error",
          st == 200 and msg is not None and "error" in msg, st)

    if not a.skip_cancel:
        cancel_check(c, m, rid=5001)
        isolation_check(c, a, token, m)

    # Inventory mutation: base -> +extra -> base, three complete listings.
    st, _, _ = m.rpc("tools/call", {"name": "smoke_inventory_toggle", "arguments": {}})
    names2 = m.list_all()
    c.add("S9", "after smoke_inventory_toggle the list adds the extra tool",
          st == 200 and names2 is not None and EXTRA_TOOL in names2, "count=%s" % (None if names2 is None else len(names2)))
    st, _, _ = m.rpc("tools/call", {"name": "smoke_inventory_toggle", "arguments": {}})
    names3 = m.list_all()
    c.add("S9a", "second toggle restores the base list",
          st == 200 and names3 is not None and EXTRA_TOOL not in names3, "count=%s" % (None if names3 is None else len(names3)))

    st = m.delete()
    c.add("S11", "DELETE session -> 204", st == 204, st)
    st, _, _ = m.rpc("tools/list", {})
    c.add("S11a", "request on the deleted session -> 404", st == 404, st)

    summary = {"run_id": run_id, "started_at": started_at, "finished_at": utc_now(),
               "url_path": m.ep.path, "checks": c.items,
               "failed": [x["id"] for x in c.failed()]}
    if a.out:
        os.makedirs(a.out, mode=0o700, exist_ok=True)
        write_private(os.path.join(a.out, "summary.json"), json.dumps(summary, indent=2))
        write_private(os.path.join(a.out, "canaries.json"), json.dumps(
            {"canaries": [canary_args, canary_sse],
             "tool_names": list(BASE_TOOLS) + [EXTRA_TOOL]}, indent=2))
        print("wrote %s/summary.json and canaries.json (0600)" % a.out)
    print("started_at=%s failed=%s" % (started_at, summary["failed"] or "none"))
    return 1 if summary["failed"] else 0


def cancel_check(c, m, rid):
    box = {}

    def call():
        t0 = time.monotonic()
        box["r"] = m.rpc("tools/call", {"name": "smoke_wait", "arguments": {"seconds": 20}}, rid=rid)
        box["elapsed"] = time.monotonic() - t0

    t = threading.Thread(target=call, daemon=True)
    t.start()
    time.sleep(1.5)
    st = m.notify("notifications/cancelled", {"requestId": rid, "reason": "smoke"})
    c.add("S8", "notifications/cancelled for in-flight smoke_wait -> 202", st == 202, st)
    t.join(30)
    elapsed = box.get("elapsed")
    st = box.get("r", (0, {}, None))[0]
    c.add("S8a", "cancelled wait ends well before 20 s",
          elapsed is not None and elapsed < 15, "http=%s elapsed=%s"
          % (st, None if elapsed is None else round(elapsed, 1)))


def isolation_check(c, a, token, m1):
    """A cancel naming the same request id in another session must not match."""
    m2 = McpClient(a.url, token, ca=a.ca)
    st = m2.open()
    c.add("S10", "second session opens", st == 202, st)
    box = {}

    def call():
        box["r"] = m1.rpc("tools/call", {"name": "smoke_wait", "arguments": {"seconds": 4}}, rid=6001)

    t = threading.Thread(target=call, daemon=True)
    t.start()
    time.sleep(1.0)
    m2.notify("notifications/cancelled", {"requestId": 6001, "reason": "smoke-foreign"})
    t.join(30)
    st, _, msg = box.get("r", (0, {}, None))
    text, _ = result_text(msg)
    c.add("S10a", "foreign-session cancel does not cancel the call",
          st == 200 and text == "waited 4", "%s %s" % (st, text))
    st = m2.delete()
    c.add("S10b", "DELETE second session -> 204", st == 204, st)


# ---------------------------------------------------------------- call loop

def call_loop(a):
    token = read_secret_file(a.token_file)
    m = McpClient(a.url, token, ca=a.ca)
    st = m.open()
    print("open: http=%s" % st, flush=True)
    if st != 202:
        return 1
    statuses = []
    for i in range(a.count):
        marker = "SIGIL-CANARY-LOOP-%s" % secrets.token_hex(8) if a.canary else "loop-%d" % i
        st, h, msg = m.rpc("tools/call", {"name": "smoke_echo", "arguments": {"marker": marker}})
        text, _ = result_text(msg)
        ok = st == 200 and text == "echo:" + marker
        statuses.append(st)
        print("call %d: http=%s %s" % (i + 1, st, "ok" if ok else "not-ok"), flush=True)
        if a.interval:
            time.sleep(a.interval)
    if not a.keep_session:
        print("delete: http=%s" % m.delete())
    counts = {}
    for s in statuses:
        counts[str(s)] = counts.get(str(s), 0) + 1
    print("status_counts=%s" % json.dumps(counts, sort_keys=True))
    return 0


def counters(a):
    token = read_secret_file(a.token_file)
    ep = Endpoint(a.fixture_url, ca=a.ca)
    host = ep.host if ":" not in ep.host else "[%s]" % ep.host
    st, _, body = ep.request("GET", "/_fixture/counters", headers={
        "Authorization": "Bearer " + token, "Host": "%s:%d" % (host, ep.port)})
    if st != 200:
        print("counters: http=%s" % st, file=sys.stderr)
        return 1
    print(json.dumps(json.loads(body), indent=2, sort_keys=True))
    return 0


# ---------------------------------------------------------------- server reads

class Reader:
    def __init__(self, a):
        self.ep = Endpoint(a.server_url, ca=a.ca, cert=a.cert, key=a.key)
        if self.ep.scheme != "https":
            raise SystemExit("--server-url must be https://")
        self.token = read_secret_file(a.token_file)

    def get(self, path):
        st, _, body = self.ep.request("GET", path, headers={
            "Authorization": "Bearer " + self.token, "Accept": "application/json"})
        try:
            doc = json.loads(body) if body else None
        except ValueError:
            doc = None
        return st, body, doc

    def pages(self, path, max_pages=50):
        items, raw = [], []
        cursor = None
        for _ in range(max_pages):
            sep = "&" if "?" in path else "?"
            p = path + (sep + "cursor=" + urllib.parse.quote(cursor, safe="") if cursor else "")
            st, body, doc = self.get(p)
            raw.append(body)
            if st != 200 or not isinstance(doc, dict):
                return (st if st != 200 else 0), items, raw
            if not isinstance(doc.get("items"), list):
                return 0, items, raw
            items += doc["items"]
            cursor = doc.get("next_cursor")
            if not cursor:
                return 200, items, raw
        return 0, items, raw  # bounded pagination exhausted: never claim a complete scan


def query(a):
    st, body, doc = Reader(a).get(a.path)
    print("http=%s" % st, file=sys.stderr)
    print(json.dumps(doc, indent=2, sort_keys=True) if doc is not None
          else body.decode("utf-8", "replace"))
    return 0 if st == 200 else 1


def load_canaries(path):
    if not path:
        return [], []
    with open(path) as f:
        doc = json.load(f)
    return doc.get("canaries", []), doc.get("tool_names", [])


def ledger(a):
    r = Reader(a)
    canaries, tool_names = load_canaries(a.canary_file)
    q = "/v1/proxy-invocations?limit=500&proxy_id=" + urllib.parse.quote(a.proxy_id)
    if a.since:
        q += "&from=" + urllib.parse.quote(a.since)
    st, items, raw = r.pages(q)
    if st != 200:
        print("invocations: http=%s" % st, file=sys.stderr)
        return 1
    ids = [i["invocation_id"] for i in items]
    problems = []
    if len(ids) != len(set(ids)):
        problems.append("duplicate invocation_id in list")
    table = {}
    dup_events = 0
    open_count = 0
    for inv in items:
        tool = (inv.get("tool") or {}).get("status")
        key = (inv.get("method"), inv.get("lifecycle"), inv.get("outcome"),
               inv.get("delivery_state"), inv.get("reason"), tool,
               bool(inv.get("cancel_observed")))
        table[key] = table.get(key, 0) + 1
        if inv.get("lifecycle") != "completed":
            open_count += 1
        if a.details:
            st, body, doc = r.get("/v1/proxy-invocations/" + urllib.parse.quote(inv["invocation_id"]))
            raw.append(body)
            if st == 200 and isinstance(doc, dict):
                evs = [e["event_id"] for e in doc.get("events", [])]
                if len(evs) != len(set(evs)):
                    dup_events += 1
            else:
                problems.append("invocation detail unavailable or invalid")
    st, body, _ = r.get("/v1/proxies/" + urllib.parse.quote(a.proxy_id))
    raw.append(body)
    if st != 200:
        problems.append("proxy detail unavailable")
    if not items:
        problems.append("no invocations in requested window")
    print("invocations=%d not_completed=%d detail_dup_event_sets=%d proxy_detail_http=%s"
          % (len(items), open_count, dup_events, st))
    print("%-11s %-10s %-15s %-12s %-26s %-22s %s" % (
        "method", "lifecycle", "outcome", "delivery", "reason", "tool", "cancel  count"))
    for k in sorted(table, key=lambda x: tuple(str(v) for v in x)):
        print("%-11s %-10s %-15s %-12s %-26s %-22s %-7s %d" % tuple(
            [str(v) for v in k] + [table[k]]))
    if dup_events:
        problems.append("an invocation detail lists one event_id twice")
    blob = b"".join(x or b"" for x in raw)
    for label, values in (("canary", canaries), ("tool_name", tool_names)):
        hits = sum(blob.count(v.encode()) for v in values)
        print("ordinary-query %s occurrences: %d" % (label, hits))
        if hits:
            problems.append("%s found in ordinary query responses" % label)
    for p in problems:
        print("PROBLEM: " + p)
    return 1 if problems else 0


# ---------------------------------------------------------------- scan

def scan(a):
    needles = []
    canaries, _ = load_canaries(a.canary_file)
    needles += [("canary#%d" % i, c.encode()) for i, c in enumerate(canaries)]
    for i, path in enumerate(a.secret_file or []):
        needles.append(("secret_file#%d" % i, read_secret_file(path).encode()))
    if not needles:
        raise SystemExit("give --canary-file and/or --secret-file")
    files = []
    errors = []
    for p in a.paths:
        if os.path.isdir(p):
            for root, _, names in os.walk(p, onerror=lambda e: errors.append(type(e).__name__)):
                files += [os.path.join(root, n) for n in names]
        else:
            files.append(p)
    total = 0
    scanned = 0
    longest = max(len(n) for _, n in needles)
    for path in sorted(files):
        try:
            if not stat.S_ISREG(os.lstat(path).st_mode):
                errors.append("nonregular")
                continue
            hits = dict.fromkeys([label for label, _ in needles], 0)
            with open(path, "rb") as f:
                tail = b""
                while True:
                    chunk = f.read(1 << 20)
                    if not chunk:
                        break
                    buf = tail + chunk
                    for label, n in needles:
                        # count matches that end inside the new chunk only
                        start = 0
                        while True:
                            j = buf.find(n, start)
                            if j < 0:
                                break
                            if j + len(n) > len(tail):
                                hits[label] += 1
                            start = j + 1
                    tail = buf[-(longest - 1):] if longest > 1 else b""
        except OSError as e:
            print("unreadable %s (%s)" % (path, type(e).__name__))
            errors.append(type(e).__name__)
            continue
        scanned += 1
        found = {k: v for k, v in hits.items() if v}
        total += sum(found.values())
        print("%s %s" % ("FOUND" if found else "clean", path) +
              (" %s" % json.dumps(found, sort_keys=True) if found else ""))
    print("total_occurrences=%d files=%d errors=%d" % (total, scanned, len(errors)))
    if errors or not scanned:
        return 2
    return 1 if total else 0


# ---------------------------------------------------------------- cli

def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scenario")
    s.add_argument("--url", required=True, help="proxy route URL, e.g. http://127.0.0.1:8480/mcp/r1")
    s.add_argument("--token-file", required=True, help="downstream client bearer (0600)")
    s.add_argument("--ca", help="CA bundle for an https:// proxy listener")
    s.add_argument("--out", help="directory for summary.json / canaries.json (0600)")
    s.add_argument("--skip-cancel", action="store_true")
    s.set_defaults(fn=scenario)

    s = sub.add_parser("call")
    s.add_argument("--url", required=True)
    s.add_argument("--token-file", required=True)
    s.add_argument("--ca")
    s.add_argument("--count", type=int, default=1)
    s.add_argument("--interval", type=float, default=0.0)
    s.add_argument("--canary", action="store_true", help="random canary markers")
    s.add_argument("--keep-session", action="store_true")
    s.set_defaults(fn=call_loop)

    s = sub.add_parser("counters")
    s.add_argument("--fixture-url", required=True, help="e.g. http://127.0.0.1:18080")
    s.add_argument("--token-file", required=True, help="the fixture's upstream token (0600)")
    s.add_argument("--ca")
    s.set_defaults(fn=counters)

    for name, fn in (("query", query), ("ledger", ledger)):
        s = sub.add_parser(name)
        s.add_argument("--server-url", required=True)
        s.add_argument("--cert", required=True, help="host-class READER client cert (not management)")
        s.add_argument("--key", required=True)
        s.add_argument("--ca", required=True, help="CA that signed the server certificate")
        s.add_argument("--token-file", required=True, help="server read bearer (0600)")
        if name == "query":
            s.add_argument("path", help="e.g. /v1/proxies/px-aws-01")
        else:
            s.add_argument("--proxy-id", required=True)
            s.add_argument("--since", help="RFC 3339 UTC lower bound (scenario started_at)")
            s.add_argument("--canary-file")
            s.add_argument("--details", action="store_true", help="also GET every invocation detail")
        s.set_defaults(fn=fn)

    s = sub.add_parser("scan")
    s.add_argument("--canary-file")
    s.add_argument("--secret-file", action="append")
    s.add_argument("paths", nargs="+")
    s.set_defaults(fn=scan)

    a = p.parse_args(argv)
    if getattr(a, "count", 1) < 1 or getattr(a, "count", 1) > 10000:
        p.error("--count must be 1..10000")
    if not 0 <= getattr(a, "interval", 0) <= 60:
        p.error("--interval must be 0..60 seconds")
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
