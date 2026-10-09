#!/usr/bin/env python3
"""Start a private fixture and exercise it directly using only Python stdlib."""

import http.client
import json
import platform
from collections import Counter

from fixture import REVISION, TOOLS, running_fixture


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def sse_messages(response):
    """Small bounded SSE decoder: comments, CRLF, multi-line data, blank event."""
    data = []
    total = 0
    while True:
        line = response.readline(65537)
        total += len(line)
        if total > 65536:
            raise ValueError("Fixture SSE response exceeded 64 KiB")
        if not line:
            if data:
                raise ValueError("SSE event missing final blank line")
            return
        line = line.decode("utf-8").rstrip("\r\n")
        if not line:
            if data:
                yield json.loads("\n".join(data))
            data = []
        elif line.startswith("data:"):
            data.append(line[5:].removeprefix(" "))


class Client:
    """One HTTP request per send; no retries, redirects, env proxies, or auth."""

    def __init__(self, port):
        self.port = port
        self.sid = None
        self.attempts = Counter()

    def send(self, message=None, *, method="POST", path="/mcp", overrides=None, raw=None):
        headers = {"Content-Type": "application/json",
                   "Accept": "application/json, text/event-stream"}
        if self.sid:
            headers.update({"MCP-Session-Id": self.sid, "MCP-Protocol-Version": REVISION})
        for key, value in (overrides or {}).items():
            if value is None:
                headers.pop(key, None)
            else:
                headers[key] = value
        body = raw if raw is not None else (json.dumps(message).encode() if message else None)
        if message and message.get("method") == "tools/call":
            self.attempts[json.dumps(message["id"])] += 1
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        try:
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            content_type = response.getheader("Content-Type", "").split(";", 1)[0]
            if content_type == "text/event-stream":
                body = list(sse_messages(response))
            else:
                raw_body = response.read(65537)
                require(len(raw_body) <= 65536, "Oversized response")
                body = json.loads(raw_body) if raw_body else None
            return response.status, dict(response.getheaders()), body
        finally:
            connection.close()

    def initialize(self):
        status, headers, body = self.send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                                          "params": {"protocolVersion": REVISION,
                                                     "capabilities": {},
                                                     "clientInfo": {"name": "stdlib-smoke", "version": "0.1.0"}}})
        require(status == 200 and body["id"] == 1, "Initialize failed")
        require(body["result"]["protocolVersion"] == REVISION, "Revision mismatch")
        require(body["result"]["capabilities"] == {"tools": {}}, "Unexpected capabilities")
        self.sid = headers["MCP-Session-Id"]
        status, _, body = self.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        require(status == 202 and body is None, "Initialized notification not accepted")

    def rpc(self, rid, method, params=None):
        return self.send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}})

    def counts(self):
        status, _, body = self.send(method="GET", path="/_fixture/counters")
        require(status == 200, "Counter request failed")
        return body


def run():
    with running_fixture() as server:
        client = Client(server.server_port)
        client.initialize()
        names, cursor, seen = [], None, set()
        for page in range(10):
            status, _, body = client.rpc(10 + page, "tools/list", {"cursor": cursor} if cursor else {})
            require(status == 200 and body["id"] == 10 + page, "List failed")
            names.extend(tool["name"] for tool in body["result"]["tools"])
            cursor = body["result"].get("nextCursor")
            if cursor is None:
                break
            require(cursor not in seen, "Pagination cursor loop")
            seen.add(cursor)
        else:
            raise AssertionError("Pagination did not terminate")
        require(tuple(names) == TOOLS and page == 1, "Incomplete inventory")
        for rid, name in ((20, "json_ok"), (21, "sse_ok"), (22, "tool_error")):
            status, headers, body = client.rpc(rid, "tools/call", {"name": name, "arguments": {}})
            require(status == 200, "Call failed")
            if name == "sse_ok":
                require(headers["Content-Type"] == "text/event-stream" and len(body) == 1,
                        "Expected exactly one SSE response")
                body = body[0]
            else:
                require(headers["Content-Type"] == "application/json", "Expected JSON")
            require(body["jsonrpc"] == "2.0" and body["id"] == rid, "Response ID mismatch")
            require(body["result"]["isError"] == (name == "tool_error"), "Wrong tool status")
            require(body["result"]["content"] == [{"type": "text", "text": "synthetic " + name}],
                    "Wrong tool content")
        before = client.counts()
        try:
            client.rpc(23, "tools/call", {"name": "drop_after_accept", "arguments": {}})
        except http.client.RemoteDisconnected:
            outcome = "unknown"
        else:
            raise AssertionError("Expected controlled response loss")
        after = client.counts()
        require(after["total"] == before["total"] + 1 == 4, "Unexpected invocation count")
        require(after["by_tool"] == dict.fromkeys(TOOLS, 1), "Unexpected tool invocation counts")
        require(after["by_id"]["23"] == 1 and client.attempts["23"] == 1,
                "Dropped call was retried")
        # A fresh successful RPC also proves the fixture remained available.
        require(client.rpc(24, "ping")[2]["result"] == {}, "Fixture unavailable after drop")
        require(client.counts() == after, "Invocation count changed after drop")
        print("PASS initialize + initialized notification; candidate=" + REVISION)
        print("PASS tools/list: pages=2 tools=4 complete=true")
        print("PASS tools/call: JSON, SSE multiline/CRLF, deliberate isError=true")
        print("PASS accepted-call drop: outcome=" + outcome + " client_attempts=1 fixture_invocations=1")
        print("PASS total_invocations=4; no automatic retry in this runner")
        print("ENV Python=" + platform.python_version() + " system=" + platform.system() +
              " release=" + platform.release() + " machine=" + platform.machine())
        print("LIMIT fixture-only; no proxy, vendor client, throughput measurement, or release acceptance")


if __name__ == "__main__":
    run()
