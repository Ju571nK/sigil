"""Local checks for the smoke fixture, client helpers and fingerprint tool.

Run from the repository root:
  python3 -B -m unittest discover -s scripts/proxy-smoke -p 'test_*.py' -v

No proxy, server, network or credentials: the fixture runs on 127.0.0.1 with an
ephemeral port and a throwaway token file in a temporary directory.
"""

import contextlib
import io
import json
import os
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import b3fp  # noqa: E402
import mcp_fixture  # noqa: E402
import smoke_client  # noqa: E402

TOKEN = "fixture-test-token-0123456789abcdef"


def token_file(directory, value=TOKEN, mode=0o600):
    path = os.path.join(directory, "tok")
    with open(path, "w") as f:
        f.write(value + "\n")
    os.chmod(path, mode)
    return path


@contextlib.contextmanager
def fixture(*extra):
    with tempfile.TemporaryDirectory() as d:
        opts = mcp_fixture.parse_args(["--port", "0", "--token-file", token_file(d)] + list(extra))
        srv = mcp_fixture.build(opts)
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            yield srv, "http://%s/mcp" % srv.authority
        finally:
            srv.shutdown()
            srv.server_close()


class FixtureTest(unittest.TestCase):
    def test_scan_refuses_missing_empty_and_symlink_targets(self):
        with tempfile.TemporaryDirectory() as d:
            secret = token_file(d)
            empty = os.path.join(d, "empty")
            os.mkdir(empty)
            link = os.path.join(d, "link")
            os.symlink(secret, link)
            for target in (empty, link, os.path.join(d, "missing")):
                with self.subTest(target=target), contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(smoke_client.main([
                        "scan", "--secret-file", secret, target]), 2)

    def test_token_file_must_be_private(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):
                mcp_fixture.read_secret_file(token_file(d, mode=0o644))

    def test_non_loopback_bind_requires_tls(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            mcp_fixture.parse_args(["--bind", "0.0.0.0", "--token-file", "x"])

    def test_auth_host_origin(self):
        with fixture() as (srv, url):
            m = smoke_client.McpClient(url, "wrong")
            self.assertEqual(m.initialize()[0], 401)
            ep = smoke_client.Endpoint(url)
            st, _, _ = ep.request("POST", body=b"{}", headers={
                "Authorization": "Bearer " + TOKEN, "Host": "evil.example:80"})
            self.assertEqual(st, 403)
            st, _, _ = ep.request("POST", body=b"{}", headers={
                "Authorization": "Bearer " + TOKEN, "Origin": "https://x.example"})
            self.assertEqual(st, 403)
            self.assertEqual(srv.counters()["posts"], 0)

    def test_flow_list_call_cancel_delete(self):
        with fixture() as (srv, url):
            m = smoke_client.McpClient(url, TOKEN)
            st, h, msg = m.initialize()
            self.assertEqual(st, 200)
            self.assertEqual(msg["result"]["protocolVersion"], "2025-11-25")
            self.assertEqual(msg["result"]["capabilities"], {"tools": {"listChanged": False}})
            self.assertEqual(m.notify("notifications/initialized"), 202)
            self.assertEqual(sorted(m.list_all()), sorted(mcp_fixture.BASE_TOOLS))
            st, _, msg = m.rpc("tools/call", {"name": "smoke_echo", "arguments": {"marker": "m1"}})
            self.assertEqual(smoke_client.result_text(msg), ("echo:m1", False))
            st, h, msg = m.rpc("tools/call", {"name": "smoke_sse", "arguments": {"marker": "m2"}})
            self.assertTrue(h["content-type"][0].startswith("text/event-stream"))
            self.assertEqual(smoke_client.result_text(msg), ("sse:m2", False))
            _, _, msg = m.rpc("tools/call", {"name": "smoke_fail", "arguments": {}})
            self.assertTrue(smoke_client.result_text(msg)[1])
            checks = smoke_client.Checks()
            with contextlib.redirect_stdout(io.StringIO()):
                smoke_client.cancel_check(checks, m, rid=77)
            self.assertEqual(checks.failed(), [])
            m.rpc("tools/call", {"name": "smoke_inventory_toggle", "arguments": {}})
            self.assertIn(mcp_fixture.EXTRA_TOOL, m.list_all())
            self.assertEqual(m.rpc("tools/list", {}, version=False,
                                   extra={"MCP-Protocol-Version": "2025-06-18"})[0], 400)
            self.assertEqual(m.delete(), 204)
            self.assertEqual(m.rpc("tools/list", {})[0], 404)
            c = srv.counters()
            self.assertEqual(c["cancels_matched"], 1)
            self.assertEqual(c["calls_by_tool"]["smoke_wait"], 1)
            self.assertEqual(c["sessions_active"], 0)
            self.assertEqual(c["waits_in_flight"], 0)

    def test_stateless_and_sse_initialize(self):
        with fixture("--stateless", "--initialize-sse") as (srv, url):
            m = smoke_client.McpClient(url, TOKEN)
            st, h, msg = m.initialize()
            self.assertEqual(st, 200)
            self.assertNotIn("mcp-session-id", h)
            self.assertEqual(msg["result"]["protocolVersion"], "2025-11-25")
            self.assertEqual(m.rpc("ping")[0], 200)
            self.assertEqual(m.delete(), 405)

    def test_session_capacity_is_bounded(self):
        with fixture("--max-sessions", "2") as (srv, url):
            for _ in range(2):
                self.assertEqual(smoke_client.McpClient(url, TOKEN).initialize()[0], 200)
            self.assertEqual(smoke_client.McpClient(url, TOKEN).initialize()[0], 503)

    def test_counters_need_bearer(self):
        with fixture() as (srv, url):
            ep = smoke_client.Endpoint(url)
            self.assertEqual(ep.request("GET", "/_fixture/counters")[0], 401)
            st, _, body = ep.request("GET", "/_fixture/counters",
                                     headers={"Authorization": "Bearer " + TOKEN})
            self.assertEqual(st, 200)
            self.assertNotIn(TOKEN.encode(), body)


class ClientTest(unittest.TestCase):
    def test_scan_counts_without_printing_secrets(self):
        with tempfile.TemporaryDirectory() as d:
            canary = os.path.join(d, "canaries.json")
            with open(canary, "w") as f:
                json.dump({"canaries": ["SIGIL-CANARY-X"], "tool_names": []}, f)
            data = os.path.join(d, "data")
            os.mkdir(data)
            with open(os.path.join(data, "a.log"), "wb") as f:
                f.write(b"x" * (1 << 20) + b"SIGIL-CANARY-X" + TOKEN.encode())
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                rc = smoke_client.main(["scan", "--canary-file", canary,
                                        "--secret-file", token_file(d), data])
            self.assertEqual(rc, 1)
            self.assertIn("total_occurrences=2", out.getvalue())
            self.assertNotIn(TOKEN, out.getvalue())

    def test_reader_rejects_incomplete_pagination(self):
        reader = object.__new__(smoke_client.Reader)
        reader.get = lambda path: (200, b"{}", {"items": [], "next_cursor": "again"})
        self.assertEqual(reader.pages("/v1/proxies", max_pages=2)[0], 0)
        reader.get = lambda path: (200, b"bad-json", None)
        self.assertEqual(reader.pages("/v1/proxies")[0], 0)

    def test_private_output_restricts_existing_permissions(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "summary.json")
            with open(path, "w") as f:
                f.write("old")
            os.chmod(path, 0o644)
            smoke_client.write_private(path, "new")
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)

    def test_decode_sse(self):
        body = b": c\r\n\r\nevent: message\r\ndata: {\"jsonrpc\":\"2.0\",\r\ndata: \"id\":1}\r\n\r\n"
        msg = smoke_client.decode_message({"content-type": ["text/event-stream"]}, body)
        self.assertEqual(msg, {"jsonrpc": "2.0", "id": 1})


class FingerprintTest(unittest.TestCase):
    def test_vectors(self):
        # Official BLAKE3 test-vector input (byte i = i % 251); cross-checked
        # against the Rust blake3 1.8.5 crate for multi-chunk tree sizes.
        def h(n):
            return b3fp.blake3(bytes(i % 251 for i in range(n))).hex()
        self.assertEqual(h(0), "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262")
        self.assertEqual(h(1), "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213")

    def test_pem_first_cert(self):
        pem = "junk\n-----BEGIN CERTIFICATE-----\nAAEC\n-----END CERTIFICATE-----\n"
        self.assertEqual(b3fp.first_cert_der(pem), b"\x00\x01\x02")


if __name__ == "__main__":
    unittest.main()
