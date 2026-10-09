#!/usr/bin/env python3
"""Local-only MCP candidate fixture; no proxy, credentials, or external I/O.

Revision 2025-11-25 is provisional pending T-01. Python standard library only.
"""

import json
import socket
import threading
import uuid
from collections import Counter
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

REVISION = "2025-11-25"
MAX_BODY = 64 * 1024
TOOLS = ("json_ok", "sse_ok", "tool_error", "drop_after_accept")


class FixtureServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self):
        # No configurable host/port: every run is isolated on IPv4 loopback.
        super().__init__(("127.0.0.1", 0), Handler)
        self.lock = threading.Lock()
        self.sessions = {}
        self.invocations = Counter()
        self.call_ids = Counter()
        self.authority = "127.0.0.1:%d" % self.server_port

    def counts(self):
        with self.lock:
            return {"total": sum(self.invocations.values()),
                    "by_tool": dict(self.invocations), "by_id": dict(self.call_ids)}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def setup(self):
        super().setup()
        self.connection.settimeout(3)

    def log_message(self, *_args):
        pass  # Never log request bodies, headers, or tool arguments.

    def reply(self, status, body=b"", content_type="application/json", headers=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def json_reply(self, status, value, headers=None):
        self.reply(status, json.dumps(value).encode(), headers=headers)

    def guard(self):
        if self.headers.get("Host") != self.server.authority:
            self.reply(403)
            return False
        origin = self.headers.get("Origin")
        if origin is not None and origin != "http://" + self.server.authority:
            self.reply(403)
            return False
        # This deliberately unauthenticated test service never needs secrets.
        if self.headers.get("Authorization") is not None:
            self.reply(400)
            return False
        return True

    def session(self):
        sid = self.headers.get("MCP-Session-Id")
        if not sid:
            self.reply(400)
            return None
        with self.server.lock:
            known = sid in self.server.sessions
        if not known:
            self.reply(404)
            return None
        revision = self.headers.get("MCP-Protocol-Version")
        if revision is not None and revision != REVISION:
            self.reply(400)
            return None
        # Missing version can be inferred from this already-negotiated session.
        return sid

    def do_GET(self):
        if not self.guard():
            return
        if self.path == "/_fixture/counters":
            self.json_reply(200, self.server.counts())
        elif self.path == "/mcp":
            if self.session():
                self.reply(405, headers={"Allow": "POST, DELETE"})
        else:
            self.reply(404)

    def do_DELETE(self):
        if not self.guard():
            return
        if self.path != "/mcp":
            self.reply(404)
            return
        sid = self.session()
        if sid:
            with self.server.lock:
                self.server.sessions.pop(sid, None)
            self.reply(204)

    def do_POST(self):
        if not self.guard():
            return
        if self.path != "/mcp":
            self.reply(404)
            return
        version = self.headers.get("MCP-Protocol-Version")
        if version is not None and version != REVISION:
            self.reply(400)
            return
        if self.headers.get("Transfer-Encoding"):
            self.reply(400)
            return
        try:
            size = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            size = -1
        if size < 0 or size > MAX_BODY:
            self.reply(413 if size > MAX_BODY else 400)
            return
        if self.headers.get_content_type() != "application/json":
            self.reply(415)
            return
        accept = self.headers.get("Accept", "")
        if not all(kind in accept for kind in ("application/json", "text/event-stream")):
            self.reply(406)
            return
        try:
            raw = self.rfile.read(size)
            if len(raw) != size:
                self.reply(400)
                return
            request = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            self.rpc_error(None, -32700, "Parse error")
            return
        if not isinstance(request, dict) or request.get("jsonrpc") != "2.0":
            self.rpc_error(None, -32600, "Invalid request")
            return
        rid, method = request.get("id"), request.get("method")
        if (not isinstance(method, str) or
                ("id" in request and (isinstance(rid, bool) or not isinstance(rid, (str, int))))):
            self.rpc_error(None, -32600, "Invalid request")
            return
        params = request.get("params", {})
        if not isinstance(params, dict):
            self.rpc_error(rid, -32602, "Invalid params")
            return
        if method == "initialize":
            if (rid is None or not isinstance(params.get("protocolVersion"), str) or
                    not isinstance(params.get("capabilities"), dict) or
                    not isinstance(params.get("clientInfo"), dict)):
                self.rpc_error(rid, -32602, "Invalid initialize params")
                return
            sid = uuid.uuid4().hex
            with self.server.lock:
                self.server.sessions[sid] = False
            self.result(rid, {"protocolVersion": REVISION, "capabilities": {"tools": {}},
                              "serverInfo": {"name": "sigil-p0-fixture", "version": "0.1.0"}},
                        headers={"MCP-Session-Id": sid})
            return
        sid = self.session()
        if not sid:
            return
        if method == "notifications/initialized" and rid is None:
            with self.server.lock:
                self.server.sessions[sid] = True
            self.reply(202)
            return
        if rid is None:
            # Other notifications are outside this deliberately narrow fixture.
            self.reply(400)
            return
        with self.server.lock:
            ready = self.server.sessions.get(sid, False)
        if not ready:
            self.rpc_error(rid, -32600, "Initialization incomplete")
        elif method == "ping":
            self.result(rid, {})
        elif method == "tools/list":
            cursor = params.get("cursor")
            if cursor not in (None, "page-2"):
                self.rpc_error(rid, -32602, "Invalid cursor")
                return
            names = TOOLS[:2] if cursor is None else TOOLS[2:]
            result = {"tools": [{"name": name, "description": "Synthetic local fixture",
                                 "inputSchema": {"type": "object", "properties": {},
                                                 "additionalProperties": False}}
                                for name in names]}
            if cursor is None:
                result["nextCursor"] = "page-2"
            self.result(rid, result)
        elif method == "tools/call":
            name = params.get("name")
            if name not in TOOLS or params.get("arguments", {}) != {}:
                self.rpc_error(rid, -32602, "Unknown tool or invalid arguments")
                return
            # Acceptance is an in-memory synthetic side effect, before any reply.
            # Count duplicates too: never deduplicate and hide an accidental retry.
            with self.server.lock:
                self.server.invocations[name] += 1
                self.server.call_ids[json.dumps(rid)] += 1
            if name == "drop_after_accept":
                self.close_connection = True
                self.connection.shutdown(socket.SHUT_RDWR)
                self.connection.close()
                return
            result = {"content": [{"type": "text", "text": "synthetic " + name}],
                      "isError": name == "tool_error"}
            if name == "sse_ok":
                # Split data across SSE lines and writes to exercise framing.
                payload = json.dumps({"jsonrpc": "2.0", "id": rid, "result": result})
                prefix, rest = payload.split(",", 1)
                data = (": fixture comment\r\nevent: message\r\ndata: " + prefix +
                        ",\r\ndata: " + rest + "\r\n\r\n").encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Connection", "close")
                self.end_headers()
                middle = len(data) // 2
                self.wfile.write(data[:middle])
                self.wfile.flush()
                self.wfile.write(data[middle:])
                self.wfile.flush()
                self.close_connection = True
            else:
                self.result(rid, result)
        else:
            self.rpc_error(rid, -32601, "Method not found")

    def result(self, rid, result, headers=None):
        self.json_reply(200, {"jsonrpc": "2.0", "id": rid, "result": result}, headers)

    def rpc_error(self, rid, code, message):
        self.json_reply(200, {"jsonrpc": "2.0", "id": rid,
                              "error": {"code": code, "message": message}})


@contextmanager
def running_fixture():
    server = FixtureServer()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


if __name__ == "__main__":
    with running_fixture() as fixture:
        print(json.dumps({"endpoint": "http://" + fixture.authority + "/mcp",
                          "revision": REVISION, "status": "candidate awaiting T-01"}), flush=True)
        try:
            threading.Event().wait()
        except KeyboardInterrupt:
            pass
