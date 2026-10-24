#!/usr/bin/env python3
"""Trusted test MCP server for the Sigil Proxy AWS smoke test (stdlib only).

Synthetic, deterministic tools; no real tool execution, no external I/O.
Speaks MCP Streamable HTTP for revision 2025-11-25 only and advertises the
`tools` capability only (no tasks, no resources, no subscribe).

Security posture (test fixture, not production):
* binds 127.0.0.1 by default; a non-loopback bind requires --tls-cert/--tls-key;
* every request needs `Authorization: Bearer <token>`, the token read from an
  owner-only file (never an argument, never printed);
* checks Host (DNS rebinding) and rejects any Origin;
* logs nothing about requests: no headers, bodies, arguments or results;
* bounded: connections, sessions, in-flight waits, body size, wait duration.
"""

import argparse
import hmac
import ipaddress
import json
import os
import secrets
import socket
import ssl
import stat
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

REVISION = "2025-11-25"
MAX_BODY = 64 * 1024
MAX_MARKER = 256
MAX_WAIT_SECONDS = 30
PAGE_SIZE = 2
SESSION_IDLE_SECONDS = 900
BASE_TOOLS = ("smoke_echo", "smoke_sse", "smoke_fail", "smoke_wait", "smoke_inventory_toggle")
EXTRA_TOOL = "smoke_inventory_extra"


def read_secret_file(path):
    """Read a one-line token from an owner-only regular file (not a symlink)."""
    st = os.lstat(path)
    if not stat.S_ISREG(st.st_mode):
        raise ValueError("token file must be a regular file, not a symlink")
    if st.st_mode & 0o077:
        raise ValueError("token file must not be group/world accessible (chmod 600)")
    if hasattr(os, "geteuid") and st.st_uid != os.geteuid():
        raise ValueError("token file must be owned by the running user")
    with open(path, "rb") as f:
        raw = f.read(4097)
    if len(raw) > 4096:
        raise ValueError("token file too large")
    token = raw.decode("ascii").strip()
    if not token or not all(0x21 <= ord(c) <= 0x7E for c in token):
        raise ValueError("token file must hold one printable ASCII token")
    return token


def tool_defs(extra):
    schema = {"type": "object", "additionalProperties": False}
    defs = {
        "smoke_echo": dict(schema, properties={"marker": {"type": "string", "maxLength": MAX_MARKER}}),
        "smoke_sse": dict(schema, properties={"marker": {"type": "string", "maxLength": MAX_MARKER}}),
        "smoke_fail": dict(schema, properties={}),
        "smoke_wait": dict(schema, properties={"seconds": {"type": "integer", "minimum": 1,
                                                     "maximum": MAX_WAIT_SECONDS}}),
        "smoke_inventory_toggle": dict(schema, properties={}),
        EXTRA_TOOL: dict(schema, properties={}),
    }
    names = list(BASE_TOOLS) + ([EXTRA_TOOL] if extra else [])
    return [{"name": n, "description": "Sigil smoke fixture tool " + n,
             "inputSchema": defs[n]} for n in names]


class FixtureServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr, opts, token):
        self.opts = opts
        self.token = token.encode()
        self.lock = threading.Lock()
        self.conn_slots = threading.BoundedSemaphore(opts.max_connections)
        self.sessions = {}  # sid -> {"ready": bool, "last": monotonic}
        self.waits = {}  # (sid, request id json) -> threading.Event
        self.inventory_extra = False
        self.inventory_generation = 0
        self.c = {"posts": 0, "initialize": 0, "initialized": 0, "tools_list": 0,
                  "calls_by_tool": {}, "cancels_received": 0, "cancels_matched": 0,
                  "deletes": 0, "unauthorized": 0, "rejected_busy": 0}
        family = socket.AF_INET6 if ":" in addr[0] else socket.AF_INET
        self.address_family = family
        super().__init__(addr, Handler)
        host = addr[0] if family == socket.AF_INET else "[%s]" % addr[0]
        self.authority = "%s:%d" % (host, self.server_address[1])
        self.allowed_hosts = {self.authority} | set(opts.allow_host or [])

    # Bounded concurrency: refuse instead of spawning unbounded threads.
    def process_request(self, request, client_address):
        if not self.conn_slots.acquire(blocking=False):
            with self.lock:
                self.c["rejected_busy"] += 1
            try:
                request.sendall(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n"
                                b"Connection: close\r\n\r\n")
            except OSError:
                pass
            self.shutdown_request(request)
            return
        super().process_request(request, client_address)

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.conn_slots.release()

    def counters(self):
        with self.lock:
            out = json.loads(json.dumps(self.c))
            out["sessions_active"] = len(self.sessions)
            out["waits_in_flight"] = len(self.waits)
            out["inventory_generation"] = self.inventory_generation
            out["inventory_extra"] = self.inventory_extra
            out["calls_total"] = sum(self.c["calls_by_tool"].values())
        return out

    def expire_sessions(self):
        now = time.monotonic()
        for sid in [s for s, v in self.sessions.items() if now - v["last"] > SESSION_IDLE_SECONDS]:
            del self.sessions[sid]


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "sigil-smoke-fixture"
    sys_version = ""

    def setup(self):
        super().setup()
        self.connection.settimeout(10)

    def log_message(self, *_args):
        pass  # never log request lines, headers, bodies, arguments or results

    # ---- responses ---------------------------------------------------------
    def reply(self, status, body=b"", content_type=None, headers=None):
        self.send_response(status)
        if content_type:
            self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def rpc(self, rid, result=None, error=None, headers=None, sse=False):
        msg = {"jsonrpc": "2.0", "id": rid}
        if error is not None:
            msg["error"] = error
        else:
            msg["result"] = result
        data = json.dumps(msg, separators=(",", ":")).encode()
        if sse:
            body = b": sigil-smoke\r\n\r\nevent: message\r\ndata: " + data + b"\r\n\r\n"
            self.reply(200, body, "text/event-stream", headers)
        else:
            self.reply(200, data, "application/json", headers)

    def rpc_error(self, rid, code, message):
        self.rpc(rid, error={"code": code, "message": message})

    # ---- guards ------------------------------------------------------------
    def guard(self):
        srv = self.server
        if self.headers.get("Host") not in srv.allowed_hosts:
            self.reply(403)
            return False
        if self.headers.get("Origin") is not None:
            self.reply(403)
            return False
        auth = self.headers.get_all("Authorization") or []
        ok = (len(auth) == 1 and auth[0].startswith("Bearer ")
              and hmac.compare_digest(auth[0][7:].encode(), srv.token))
        if not ok:
            with srv.lock:
                srv.c["unauthorized"] += 1
            self.reply(401, headers={"WWW-Authenticate": "Bearer"})
            return False
        return True

    def session(self):
        """Return the session id, or None after replying (stateful mode only)."""
        srv = self.server
        sids = self.headers.get_all("Mcp-Session-Id") or []
        if len(sids) != 1:
            self.reply(400)
            return None
        with srv.lock:
            entry = srv.sessions.get(sids[0])
            if entry is not None:
                entry["last"] = time.monotonic()
        if entry is None:
            self.reply(404)
            return None
        return sids[0]

    def version_ok(self):
        v = self.headers.get_all("MCP-Protocol-Version") or []
        if len(v) > 1 or (v and v[0] != REVISION):
            self.reply(400)
            return False
        return True

    # ---- methods -----------------------------------------------------------
    def do_GET(self):
        if not self.guard():
            return
        if self.path == "/_fixture/counters":
            self.reply(200, json.dumps(self.server.counters()).encode(), "application/json")
        elif self.path == self.server.opts.path:
            self.reply(405, headers={"Allow": "POST, DELETE"})
        else:
            self.reply(404)

    def do_DELETE(self):
        srv = self.server
        if not self.guard():
            return
        if self.path != srv.opts.path:
            self.reply(404)
            return
        if srv.opts.stateless:
            self.reply(405, headers={"Allow": "POST"})
            return
        sid = self.session()
        if sid is None:
            return
        with srv.lock:
            srv.sessions.pop(sid, None)
            srv.c["deletes"] += 1
            for key in [k for k in srv.waits if k[0] == sid]:
                srv.waits[key].set()
        self.reply(204)

    def do_PUT(self):
        self.reply(405, headers={"Allow": "POST, DELETE"})

    do_PATCH = do_PUT

    def do_POST(self):
        srv = self.server
        if not self.guard():
            return
        if self.path != srv.opts.path:
            self.reply(404)
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
        if "application/json" not in accept or "text/event-stream" not in accept:
            self.reply(406)
            return
        raw = self.rfile.read(size)
        with srv.lock:
            srv.c["posts"] += 1
        try:
            msg = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            self.rpc_error(None, -32700, "Parse error")
            return
        if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0":
            self.rpc_error(None, -32600, "Invalid Request")
            return
        method, rid = msg.get("method"), msg.get("id")
        params = msg.get("params", {})
        if method is None and ("result" in msg or "error" in msg):
            self.reply(202)  # a client response; this fixture sends no server requests
            return
        if not isinstance(method, str) or not isinstance(params, dict):
            self.rpc_error(rid, -32600, "Invalid Request")
            return
        if "id" in msg and (isinstance(rid, bool) or not isinstance(rid, (str, int))):
            self.rpc_error(None, -32600, "Invalid Request")
            return

        if method == "initialize":
            self.initialize(rid, params)
            return
        if not self.version_ok():
            return
        sid = None
        if not srv.opts.stateless:
            sid = self.session()
            if sid is None:
                return
        if "id" not in msg:
            self.notification(sid, method, params)
            return
        if method == "ping":
            self.rpc(rid, {})
        elif method == "tools/list":
            self.tools_list(rid, params)
        elif method == "tools/call":
            self.tools_call(sid, rid, params)
        else:
            self.rpc_error(rid, -32601, "Method not found")

    def initialize(self, rid, params):
        srv = self.server
        if (rid is None or self.headers.get("Mcp-Session-Id") is not None
                or not isinstance(params.get("protocolVersion"), str)
                or not isinstance(params.get("capabilities"), dict)
                or not isinstance(params.get("clientInfo"), dict)):
            if rid is None or self.headers.get("Mcp-Session-Id") is not None:
                self.reply(400)
            else:
                self.rpc_error(rid, -32602, "Invalid params")
            return
        headers = {}
        with srv.lock:
            srv.c["initialize"] += 1
            if not srv.opts.stateless:
                srv.expire_sessions()
                if len(srv.sessions) >= srv.opts.max_sessions:
                    self.reply(503)
                    return
                sid = secrets.token_urlsafe(24)
                srv.sessions[sid] = {"ready": False, "last": time.monotonic()}
                headers["Mcp-Session-Id"] = sid
        result = {"protocolVersion": REVISION,
                  "capabilities": {"tools": {"listChanged": False}},
                  "serverInfo": {"name": "sigil-smoke-fixture", "version": "0.1.0"}}
        self.rpc(rid, result, headers=headers, sse=srv.opts.initialize_sse)

    def notification(self, sid, method, params):
        srv = self.server
        with srv.lock:
            if method == "notifications/initialized":
                srv.c["initialized"] += 1
                if sid in srv.sessions:
                    srv.sessions[sid]["ready"] = True
            elif method == "notifications/cancelled":
                srv.c["cancels_received"] += 1
                key = (sid, json.dumps(params.get("requestId")))
                ev = srv.waits.get(key)
                if ev is not None:
                    srv.c["cancels_matched"] += 1
                    ev.set()
        self.reply(202)

    def tools_list(self, rid, params):
        srv = self.server
        with srv.lock:
            srv.c["tools_list"] += 1
            tools = tool_defs(srv.inventory_extra)
        cursor = params.get("cursor")
        start = 0
        if cursor is not None:
            try:
                start = int(str(cursor).split("page-", 1)[1]) * PAGE_SIZE
            except (IndexError, ValueError):
                start = -1
            if start <= 0 or start >= len(tools):
                self.rpc_error(rid, -32602, "Invalid cursor")
                return
        page = tools[start:start + PAGE_SIZE]
        result = {"tools": page}
        if start + PAGE_SIZE < len(tools):
            result["nextCursor"] = "page-%d" % (start // PAGE_SIZE + 1)
        self.rpc(rid, result)

    def tools_call(self, sid, rid, params):
        srv = self.server
        name, args = params.get("name"), params.get("arguments", {})
        with srv.lock:
            known = name in BASE_TOOLS or (name == EXTRA_TOOL and srv.inventory_extra)
        if not isinstance(name, str) or not known or not isinstance(args, dict):
            self.rpc_error(rid, -32602, "Unknown tool")
            return
        with srv.lock:
            srv.c["calls_by_tool"][name] = srv.c["calls_by_tool"].get(name, 0) + 1
        marker = args.get("marker", "")
        if not isinstance(marker, str) or len(marker) > MAX_MARKER:
            self.rpc_error(rid, -32602, "Invalid params")
            return
        if name == "smoke_echo":
            self.rpc(rid, text_result("echo:" + marker))
        elif name == "smoke_sse":
            self.rpc(rid, text_result("sse:" + marker), sse=True)
        elif name == "smoke_fail":
            self.rpc(rid, text_result("synthetic tool error", is_error=True))
        elif name == "smoke_inventory_toggle":
            with srv.lock:
                srv.inventory_extra = not srv.inventory_extra
                srv.inventory_generation += 1
                gen = srv.inventory_generation
            self.rpc(rid, text_result("inventory generation %d" % gen))
        elif name == EXTRA_TOOL:
            self.rpc(rid, text_result("extra"))
        else:  # wait
            self.wait(sid, rid, args)

    def wait(self, sid, rid, args):
        srv = self.server
        seconds = args.get("seconds", 5)
        if isinstance(seconds, bool) or not isinstance(seconds, int):
            self.rpc_error(rid, -32602, "Invalid params")
            return
        seconds = max(1, min(MAX_WAIT_SECONDS, seconds))
        key = (sid, json.dumps(rid))
        ev = threading.Event()
        with srv.lock:
            if len(srv.waits) >= srv.opts.max_waits or key in srv.waits:
                busy = True
            else:
                busy = False
                srv.waits[key] = ev
        if busy:
            self.rpc_error(rid, -32603, "Internal error")
            return
        try:
            cancelled = ev.wait(seconds)
        finally:
            with srv.lock:
                srv.waits.pop(key, None)
        try:
            if cancelled:
                self.rpc(rid, text_result("cancelled", is_error=True))
            else:
                self.rpc(rid, text_result("waited %d" % seconds))
        except OSError:
            pass  # the proxy or client went away; nothing to report


def text_result(text, is_error=False):
    out = {"content": [{"type": "text", "text": text}]}
    if is_error:
        out["isError"] = True
    return out


def is_loopback(host):
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def parse_args(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    p.add_argument("--bind", default="127.0.0.1", help="IP literal (default 127.0.0.1)")
    p.add_argument("--port", type=int, default=18080, help="0 = ephemeral")
    p.add_argument("--path", default="/mcp")
    p.add_argument("--token-file", required=True,
                   help="owner-only file with the bearer the proxy injects (credential_ref secret)")
    p.add_argument("--allow-host", action="append",
                   help="extra accepted Host header value (host:port); default only the bind authority")
    p.add_argument("--stateless", action="store_true", help="issue no Mcp-Session-Id")
    p.add_argument("--initialize-sse", action="store_true",
                   help="answer initialize as text/event-stream")
    p.add_argument("--tls-cert")
    p.add_argument("--tls-key")
    p.add_argument("--max-connections", type=int, default=32)
    p.add_argument("--max-sessions", type=int, default=64)
    p.add_argument("--max-waits", type=int, default=8)
    o = p.parse_args(argv)
    if not o.path.startswith("/") or o.path.startswith("/_fixture"):
        p.error("--path must start with / and not be under /_fixture")
    if bool(o.tls_cert) != bool(o.tls_key):
        p.error("--tls-cert and --tls-key go together")
    if not is_loopback(o.bind) and not o.tls_cert:
        p.error("a non-loopback --bind requires --tls-cert/--tls-key")
    for name in ("max_connections", "max_sessions", "max_waits"):
        if not 1 <= getattr(o, name) <= 1024:
            p.error("--%s must be 1..1024" % name.replace("_", "-"))
    return o


def build(opts):
    token = read_secret_file(opts.token_file)
    srv = FixtureServer((opts.bind, opts.port), opts, token)
    if opts.tls_cert:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(opts.tls_cert, opts.tls_key)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    return srv


def main(argv=None):
    opts = parse_args(argv)
    try:
        srv = build(opts)
    except (OSError, ValueError) as e:
        print("fixture: %s" % e, file=sys.stderr)
        return 2
    scheme = "https" if opts.tls_cert else "http"
    print("sigil-smoke-fixture listening on %s://%s%s revision=%s stateless=%s initialize_sse=%s"
          % (scheme, srv.authority, opts.path, REVISION, opts.stateless, opts.initialize_sse),
          flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
