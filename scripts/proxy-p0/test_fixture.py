#!/usr/bin/env python3
"""Fixture self-tests, not Sigil proxy or vendor-client acceptance tests."""

import http.client
import io
import unittest

from fixture import MAX_BODY, REVISION, running_fixture
from smoke import Client, sse_messages


class FixtureTests(unittest.TestCase):
    def setUp(self):
        self.context = running_fixture()
        self.server = self.context.__enter__()
        self.addCleanup(self.context.__exit__, None, None, None)
        self.client = Client(self.server.server_port)
        self.client.initialize()

    def test_loopback_ephemeral_and_fresh_state(self):
        self.assertEqual(self.server.server_address[0], "127.0.0.1")
        self.assertGreater(self.server.server_port, 0)
        self.assertEqual(self.client.counts(), {"total": 0, "by_tool": {}, "by_id": {}})

    def test_two_pages_and_bad_cursor(self):
        page1 = self.client.rpc(2, "tools/list")[2]["result"]
        page2 = self.client.rpc(3, "tools/list", {"cursor": page1["nextCursor"]})[2]["result"]
        self.assertEqual(len(page1["tools"]), 2)
        self.assertEqual(len(page2["tools"]), 2)
        self.assertNotIn("nextCursor", page2)
        self.assertEqual(self.client.rpc(4, "tools/list", {"cursor": "bad"})[2]["error"]["code"], -32602)

    def test_json_sse_and_tool_error_have_distinct_results(self):
        for rid, tool in enumerate(("json_ok", "sse_ok", "tool_error"), 20):
            status, headers, body = self.client.rpc(rid, "tools/call", {"name": tool})
            self.assertEqual(status, 200)
            if tool == "sse_ok":
                self.assertEqual(headers["Content-Type"], "text/event-stream")
                self.assertEqual(len(body), 1)
                body = body[0]
            self.assertEqual(body["id"], rid)
            self.assertNotIn("error", body)
            self.assertEqual(body["result"]["isError"], tool == "tool_error")

    def test_drop_counts_acceptance_without_retry(self):
        with self.assertRaises(http.client.RemoteDisconnected):
            self.client.rpc("lost", "tools/call", {"name": "drop_after_accept"})
        expected = {"total": 1, "by_tool": {"drop_after_accept": 1}, "by_id": {'"lost"': 1}}
        self.assertEqual(self.client.counts(), expected)
        self.assertEqual(self.client.attempts['"lost"'], 1)
        self.assertEqual(self.client.rpc(3, "ping")[2]["result"], {})
        self.assertEqual(self.client.counts(), expected)

    def test_counter_does_not_hide_duplicate_dispatch(self):
        for _ in range(2):
            self.client.rpc(9, "tools/call", {"name": "json_ok"})
        self.assertEqual(self.client.counts()["by_id"]["9"], 2)
        self.assertEqual(self.client.counts()["by_tool"]["json_ok"], 2)

    def test_invalid_call_never_increments_acceptance(self):
        for params in ({"name": "not_a_tool"}, {"name": "json_ok", "arguments": {"x": 1}}):
            body = self.client.rpc(2, "tools/call", params)[2]
            self.assertEqual(body["error"]["code"], -32602)
        self.assertEqual(self.client.counts()["total"], 0)

    def test_origin_host_and_secret_header_rejected(self):
        message = {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "json_ok"}}
        for headers, expected in (({"Origin": "https://invalid.example"}, 403),
                                  ({"Host": "invalid.example"}, 403),
                                  ({"Authorization": "synthetic-placeholder"}, 400)):
            self.assertEqual(self.client.send(message, overrides=headers)[0], expected)
        self.assertEqual(self.client.counts()["total"], 0)

    def test_version_session_and_delete(self):
        message = {"jsonrpc": "2.0", "id": 2, "method": "ping"}
        self.assertEqual(self.client.send(message, overrides={"MCP-Protocol-Version": "invalid"})[0], 400)
        self.assertEqual(self.client.send(message, overrides={"MCP-Session-Id": None})[0], 400)
        self.assertEqual(self.client.send(message, overrides={"MCP-Session-Id": "unknown"})[0], 404)
        self.assertEqual(self.client.send(message, overrides={"MCP-Protocol-Version": None})[0], 200)
        self.assertEqual(self.client.send(method="DELETE")[0], 204)
        self.assertEqual(self.client.send(message)[0], 404)

    def test_initialization_required_and_candidate_negotiation(self):
        other = Client(self.server.server_port)
        status, headers, body = other.rpc(1, "initialize", {
            "protocolVersion": "unsupported-candidate", "capabilities": {},
            "clientInfo": {"name": "fixture-test", "version": "0.1"}})
        self.assertEqual(status, 200)
        self.assertEqual(body["result"]["protocolVersion"], REVISION)
        other.sid = headers["MCP-Session-Id"]
        self.assertNotEqual(other.sid, self.client.sid)
        self.assertEqual(other.rpc(2, "tools/list")[2]["error"]["code"], -32600)

    def test_unsupported_get_and_method(self):
        status, headers, _ = self.client.send(method="GET")
        self.assertEqual(status, 405)
        self.assertEqual(headers["Allow"], "POST, DELETE")
        self.assertEqual(self.client.rpc(2, "resources/list")[2]["error"]["code"], -32601)

    def test_malformed_and_oversized_request(self):
        for raw, code in ((b"{", -32700), (b"[]", -32600),
                          (b'{"jsonrpc":"2.0","id":true,"method":"ping"}', -32600)):
            self.assertEqual(self.client.send(raw=raw)[2]["error"]["code"], code)
        self.assertEqual(self.client.send(raw=b" " * (MAX_BODY + 1))[0], 413)
        self.assertEqual(self.client.counts()["total"], 0)

    def test_content_type_and_accept(self):
        message = {"jsonrpc": "2.0", "id": 2, "method": "ping"}
        self.assertEqual(self.client.send(message, overrides={"Accept": "application/json"})[0], 406)
        self.assertEqual(self.client.send(message, overrides={"Content-Type": "text/plain"})[0], 415)


class SSEDecoderTests(unittest.TestCase):
    def test_comments_crlf_multiline_and_multiple_events(self):
        raw = b': comment\r\nevent: message\r\ndata: {"a":\r\ndata: 1}\r\n\r\ndata: {"b":2}\n\n'
        self.assertEqual(list(sse_messages(io.BytesIO(raw))), [{"a": 1}, {"b": 2}])

    def test_truncated_and_oversized_stream_rejected(self):
        for raw in (b'data: {"a":1}\n', b":" + b"x" * 65536):
            with self.assertRaises(ValueError):
                list(sse_messages(io.BytesIO(raw)))


if __name__ == "__main__":
    unittest.main()
