#!/usr/bin/env python3
"""T-01 driver: raw HTTP requests against the rmcp 0.16.0 Streamable HTTP server probe.

Run from repo root after `cargo build --release` in this directory:
    python3 -B scripts/proxy-p0/probes/rmcp-sdk/server_probe.py [--out DIR]
Writes DIR/server-report.json; DIR defaults to a new mktemp directory outside the repository,
so the committed output/ is never overwritten. Session id values are not recorded.
"""

import argparse
import http.client
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, "target", "release", "rmcp-sdk-probe")
VERSIONS = ["2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25", "2026-07-28",
            "1999-01-01", "not-a-version", "9999-12-31"]


def post(host, port, body, sid=None, version=None, raw=None):
    conn = http.client.HTTPConnection(host, port, timeout=5)
    headers = {"Content-Type": "application/json",
               "Accept": "application/json, text/event-stream"}
    if sid:
        headers["Mcp-Session-Id"] = sid
    if version is not None:
        headers["MCP-Protocol-Version"] = version
    conn.request("POST", "/mcp", raw if raw is not None else json.dumps(body), headers)
    resp = conn.getresponse()
    status, ctype, rsid = resp.status, resp.getheader("Content-Type"), resp.getheader("Mcp-Session-Id")
    messages = []
    if ctype and ctype.startswith("text/event-stream"):
        data = []
        # Read events until the first JSON-RPC response arrives (rmcp keeps streams open).
        while True:
            line = resp.fp.readline()
            if not line:
                break
            line = line.decode().rstrip("\r\n")
            if line.startswith("data:"):
                data.append(line[5:].lstrip())
            elif line == "" and data:
                joined = "\n".join(data)
                data = []
                try:
                    msg = json.loads(joined)
                except ValueError:
                    messages.append({"_non_json_data": joined})
                    continue
                messages.append(msg)
                if "id" in msg and ("result" in msg or "error" in msg):
                    break
    else:
        text = resp.read().decode(errors="replace")
        try:
            messages.append(json.loads(text) if text else None)
        except ValueError:
            messages.append({"_text": text[:300]})
    conn.close()
    return status, ctype, rsid, messages


def init_body(v):
    return {"jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": v, "capabilities": {},
                       "clientInfo": {"name": "t01-raw", "version": "0"}}}


def session(host, port, v):
    st, ct, sid, msgs = post(host, port, init_body(v))
    if sid:
        post(host, port, {"jsonrpc": "2.0", "method": "notifications/initialized"}, sid)
    return st, ct, sid, msgs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", help="output directory (default: new temp dir outside the repo)")
    args = ap.parse_args()
    proc = subprocess.Popen([BIN, "server"], stdout=subprocess.PIPE, text=True)
    try:
        host, port = json.loads(proc.stdout.readline())["listen"].split(":")
        port = int(port)
        report = {"rmcp": "0.16.0", "initialize": [], "header_checks": [], "unknown_fields": None}
        for v in VERSIONS:
            st, ct, sid, msgs = session(host, port, v)
            res = (msgs[-1] or {}).get("result", {}) if msgs else {}
            report["initialize"].append({"client_offered": v, "http_status": st, "content_type": ct,
                                         "session_header": bool(sid),
                                         "server_answered": res.get("protocolVersion"),
                                         "error": (msgs[-1] or {}).get("error") if msgs else None})
        st, ct, sid, _ = session(host, port, "2025-06-18")
        call = {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "x-envelope-unknown": 1,
                "params": {"name": "echo_params", "arguments": {"k": 1}, "x-param-unknown": {"a": 1},
                           "_meta": {"progressToken": "p1", "x-meta-unknown": True}}}
        for hv in [None, "2025-06-18", "2099-01-01", "garbage"]:
            st2, ct2, _, msgs = post(host, port, call, sid, hv)
            echoed = None
            if msgs and isinstance(msgs[-1], dict) and "result" in msgs[-1]:
                echoed = json.loads(msgs[-1]["result"]["content"][0]["text"])
            report["header_checks"].append({"MCP-Protocol-Version": hv, "http_status": st2,
                                            "content_type": ct2, "handler_received": echoed,
                                            "messages": msgs if echoed is None else "ok"})
        report["unknown_fields"] = {"sent_params": call["params"],
                                    "handler_received": report["header_checks"][0]["handler_received"]}
        st, ct, _, msgs = post(host, port, None, None, None,
                               raw=json.dumps([init_body("2025-03-26")]))
        report["batch_initialize"] = {"http_status": st, "content_type": ct, "messages": msgs}
        st, ct, _, msgs = post(host, port, {"jsonrpc": "2.0", "id": 9, "method": "tools/list"},
                               "not-a-real-session")
        report["unknown_session"] = {"http_status": st, "content_type": ct, "messages": msgs}
        out_dir = args.out or tempfile.mkdtemp(prefix="t01-rmcp-server-")
        os.makedirs(out_dir, exist_ok=True)
        out = os.path.join(out_dir, "server-report.json")
        print("report: " + out, file=sys.stderr)
        with open(out, "w") as fh:
            json.dump(report, fh, indent=2, sort_keys=True)
        print(json.dumps(report, indent=2, sort_keys=True))
    finally:
        proc.terminate()
        proc.wait(timeout=5)


if __name__ == "__main__":
    sys.exit(main())
