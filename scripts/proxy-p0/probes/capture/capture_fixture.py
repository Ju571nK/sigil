#!/usr/bin/env python3
"""T-01 probe-local capture wrapper around scripts/proxy-p0/fixture.py.

Throwaway research tool (2026-10-10). It does NOT change the base fixture or its
revision string ("2025-11-25"); it subclasses the handler to add, for probing only:

- a JSONL wire log (allow-listed headers; session ids and bearer values redacted);
- an optional synthetic bearer requirement (random per run, never a real credential);
- a fifth tool `slow_ok` that waits up to SLOW_SECONDS and honours
  `notifications/cancelled` (the base fixture rejects every notification other than
  notifications/initialized with HTTP 400; this wrapper accepts and logs cancellation).

Loopback only, ephemeral port. Usage:
    python3 -B scripts/proxy-p0/probes/capture/capture_fixture.py --log OUT.jsonl \
        [--bearer-file PATH] [--slow-seconds 20] [--strict-cancel-400]
First stdout line is JSON with the endpoint. --bearer-file writes a random token to
PATH (mode 0600) and requires `Authorization: Bearer <token>`.
"""

import argparse
import io
import json
import os
import secrets
import sys
import threading
import time
from http.server import ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.normpath(os.path.join(HERE, "..", "..")))
import fixture  # noqa: E402  (base fixture, unmodified)

fixture.TOOLS = fixture.TOOLS + ("slow_ok",)

LOGGED_HEADERS = ("Accept", "Content-Type", "MCP-Protocol-Version", "User-Agent",
                  "Origin", "Last-Event-ID", "Content-Length", "Transfer-Encoding")


class CaptureServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, log_path, token, slow_seconds, strict_cancel):
        ThreadingHTTPServer.__init__(self, ("127.0.0.1", 0), CaptureHandler)
        self.lock = threading.Lock()
        self.sessions = {}
        self.invocations = fixture.Counter()
        self.call_ids = fixture.Counter()
        self.authority = "127.0.0.1:%d" % self.server_port
        self.log_lock = threading.Lock()
        self.log_file = open(log_path, "a", encoding="utf-8")
        self.token = token
        self.slow_seconds = slow_seconds
        self.strict_cancel = strict_cancel
        self.sid_alias = {}
        self.cancel_events = {}
        self.t0 = time.monotonic()

    counts = fixture.FixtureServer.counts

    def alias(self, sid):
        if sid is None:
            return None
        with self.log_lock:
            return self.sid_alias.setdefault(sid, "sid#%d" % (len(self.sid_alias) + 1))

    def log(self, record):
        record["t_done"] = round(time.monotonic() - self.t0, 3)
        with self.log_lock:
            self.log_file.write(json.dumps(record, sort_keys=True) + "\n")
            self.log_file.flush()


class CaptureHandler(fixture.Handler):
    def send_response(self, code, message=None):
        self._status = code
        super().send_response(code, message)

    def send_header(self, keyword, value):
        if keyword.lower() == "mcp-session-id":
            self._resp_sid = self.server.alias(value)
        super().send_header(keyword, value)

    def _record(self, body=None, note=None):
        hdrs = {k: self.headers.get(k) for k in LOGGED_HEADERS if self.headers.get(k) is not None}
        sid = self.headers.get("MCP-Session-Id")
        auth = self.headers.get("Authorization")
        auth_desc = None
        if auth is not None:
            scheme = auth.split(" ", 1)[0]
            auth_desc = {"scheme": scheme, "matches_probe_token": auth == "Bearer %s" % self.server.token}
        rec = {"t_recv": round(time.monotonic() - self.server.t0, 3),
               "verb": self.command, "path": self.path, "headers": hdrs,
               "session": self.server.alias(sid), "authorization": auth_desc}
        if body is not None:
            rec["body"] = body
        if note:
            rec["note"] = note
        return rec

    def _auth_ok(self):
        if self.server.token is None:
            return True
        if self.headers.get("Authorization") == "Bearer %s" % self.server.token:
            del self.headers["Authorization"]  # base fixture rejects any Authorization
            return True
        self.reply(401, headers={"WWW-Authenticate": 'Bearer realm="sigil-t01-probe"'})
        return False

    def _finish(self, rec):
        rec["status"] = getattr(self, "_status", None)
        if getattr(self, "_resp_sid", None):
            rec["response_session"] = self._resp_sid
        self.server.log(rec)

    def do_GET(self):
        rec = self._record()
        try:
            if self._auth_ok():
                super().do_GET()
        finally:
            self._finish(rec)

    def do_DELETE(self):
        rec = self._record()
        try:
            if self._auth_ok():
                super().do_DELETE()
        finally:
            self._finish(rec)

    def do_POST(self):
        try:
            size = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            size = -1
        raw = self.rfile.read(size) if 0 <= size <= fixture.MAX_BODY else b""
        try:
            body = json.loads(raw) if raw else None
        except ValueError:
            body = {"_unparsed_bytes": len(raw)}
        rec = self._record(body)
        try:
            if not self._auth_ok():
                return
            method = body.get("method") if isinstance(body, dict) else None
            if method == "notifications/cancelled" and not self.server.strict_cancel:
                if self.session():
                    params = body.get("params") or {}
                    key = (self.headers.get("MCP-Session-Id"), json.dumps(params.get("requestId")))
                    with self.server.lock:
                        ev = self.server.cancel_events.get(key)
                    rec["note"] = "cancel matched in-flight slow_ok" if ev else "cancel for unknown/finished id"
                    if ev:
                        ev.set()
                    self.reply(202)
                return
            if (method == "tools/call" and isinstance(body.get("params"), dict)
                    and body["params"].get("name") == "slow_ok"):
                self._slow(body, rec)
                return
            self.rfile = io.BytesIO(raw)
            super().do_POST()
        finally:
            self._finish(rec)

    def _slow(self, body, rec):
        sid = self.session()
        if not sid:
            return
        rid = body.get("id")
        key = (self.headers.get("MCP-Session-Id"), json.dumps(rid))
        ev = threading.Event()
        with self.server.lock:
            self.server.invocations["slow_ok"] += 1
            self.server.call_ids[json.dumps(rid)] += 1
            self.server.cancel_events[key] = ev
        cancelled = ev.wait(self.server.slow_seconds)
        with self.server.lock:
            self.server.cancel_events.pop(key, None)
        if cancelled:
            # Spec: receiver SHOULD NOT respond to a cancelled request. Close instead.
            rec["note"] = "slow_ok cancelled by client notification; closing without response"
            self.close_connection = True
            try:
                self.connection.shutdown(fixture.socket.SHUT_RDWR)
            except OSError:
                pass
            return
        rec["note"] = "slow_ok completed after %ss" % self.server.slow_seconds
        try:
            self.result(rid, {"content": [{"type": "text", "text": "synthetic slow_ok"}],
                              "isError": False})
        except OSError as exc:
            rec["note"] += "; client gone: %s" % type(exc).__name__


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", required=True)
    ap.add_argument("--bearer-file")
    ap.add_argument("--slow-seconds", type=float, default=20.0)
    ap.add_argument("--strict-cancel-400", action="store_true",
                    help="keep base behaviour: reject notifications/cancelled with 400")
    args = ap.parse_args()
    token = None
    if args.bearer_file:
        token = "t01probe-" + secrets.token_hex(16)  # synthetic, per-run, loopback only
        fd = os.open(args.bearer_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(token)
    server = CaptureServer(args.log, token, args.slow_seconds, args.strict_cancel_400)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(json.dumps({"endpoint": "http://%s/mcp" % server.authority,
                      "revision": fixture.REVISION, "bearer_required": token is not None,
                      "status": "T-01 probe-local capture wrapper"}), flush=True)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
