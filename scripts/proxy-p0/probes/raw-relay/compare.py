#!/usr/bin/env python3
"""Compare direct-to-fixture vs through-raw-relay MCP exchanges byte for byte.

Usage (repo root): python3 -B scripts/proxy-p0/probes/raw-relay/compare.py [--out DIR]
The report goes to DIR/compare-report.json. DIR defaults to a new mktemp directory outside the
repository, so committed outputs under output/ are never overwritten.
"""
import argparse, hashlib, http.client, json, os, shutil, socket, subprocess, sys, tempfile, time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
sys.path.insert(0, str(ROOT / "scripts" / "proxy-p0"))
from fixture import running_fixture  # noqa: E402

MANIFEST = HERE / "Cargo.toml"
BIN = HERE / "target" / "release" / "raw-relay-probe"
ACCEPT = "application/json, text/event-stream"


def rpc(method, rid=None, params=None):
    msg = {"jsonrpc": "2.0", "method": method}
    if rid is not None:
        msg["id"] = rid
    if params is not None:
        msg["params"] = params
    return json.dumps(msg, separators=(",", ":")).encode()


def steps():
    meta = {"progressToken": "p1"}
    call = lambda rid, name: ("POST", rpc("tools/call", rid, {
        "name": name, "arguments": {}, "x-probe-unknown": True, "_meta": meta}))
    return [
        ("initialize", "POST", rpc("initialize", 1, {
            "protocolVersion": "2025-11-25", "capabilities": {},
            "clientInfo": {"name": "probe", "version": "0"},
            "x-probe-unknown": {"a": 1}, "_meta": {"progressToken": "p0"}})),
        ("notifications/initialized", "POST", rpc("notifications/initialized")),
        ("tools/list", "POST", rpc("tools/list", 2, {})),
        ("tools/list page-2", "POST", rpc("tools/list", 3, {"cursor": "page-2"})),
        ("tools/call json_ok", *call(4, "json_ok")),
        ("tools/call sse_ok", *call(5, "sse_ok")),
        ("tools/call tool_error", *call(6, "tool_error")),
        ("tools/call drop_after_accept", *call(7, "drop_after_accept")),
        ("ping", "POST", rpc("ping", 8)),
        ("DELETE session", "DELETE", b""),
    ]


def dechunk(buf):
    out = b""
    while True:
        line, _, buf = buf.partition(b"\r\n")
        size = int(line.split(b";")[0], 16)
        if size == 0:
            return out
        out += buf[:size]
        buf = buf[size + 2:]


def raw_exchange(authority, method, body, sid):
    host, port = authority.split(":")
    hdrs = [f"{method} /mcp HTTP/1.1", f"Host: {authority}", "Connection: close",
            f"Accept: {ACCEPT}"]
    if method == "POST":
        hdrs += ["Content-Type: application/json", f"Content-Length: {len(body)}"]
    if sid:
        hdrs += [f"MCP-Session-Id: {sid}", "MCP-Protocol-Version: 2025-11-25"]
    s = socket.create_connection((host, int(port)), timeout=5)
    s.sendall(("\r\n".join(hdrs) + "\r\n\r\n").encode() + body)
    wire = b""
    while True:
        try:
            d = s.recv(65536)
        except ConnectionResetError:
            break
        if not d:
            break
        wire += d
    s.close()
    head, _, rest = wire.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    headers = [tuple(l.split(":", 1)) for l in lines[1:]]
    headers = [(k.strip().lower(), v.strip()) for k, v in headers]
    hd = dict(headers)
    chunked = "chunked" in hd.get("transfer-encoding", "")
    return {"status": int(lines[0].split()[1]), "headers": headers, "hd": hd,
            "chunked": chunked, "wire_body": rest, "body": dechunk(rest) if chunked else rest}


def drop_exchange(authority, body, sid):
    host, port = authority.split(":")
    c = http.client.HTTPConnection(host, int(port), timeout=5)
    try:
        c.request("POST", "/mcp", body, {"Host": authority, "Content-Type": "application/json",
                                         "Accept": ACCEPT, "MCP-Session-Id": sid,
                                         "MCP-Protocol-Version": "2025-11-25"})
        r = c.getresponse()
        r.read()
        return {"observed_response": True, "status": r.status}
    except Exception as e:  # noqa: BLE001 - recording the exception type is the point
        return {"observed_response": False, "exception": type(e).__name__}
    finally:
        c.close()


def run_leg(authority):
    sid, results, sent = None, [], []
    for name, method, body in steps():
        sent.append(body)
        if name.endswith("drop_after_accept"):
            r = drop_exchange(authority, body, sid)
            r.update(step=name, content_type=None, has_session_id=False, body_len=0)
            results.append(r)
            continue
        r = raw_exchange(authority, method, body, sid)
        if name == "initialize":
            sid = r["hd"].get("mcp-session-id")
        results.append({
            "step": name, "status": r["status"], "content_type": r["hd"].get("content-type"),
            "has_session_id": "mcp-session-id" in r["hd"],
            "body_len": len(r["body"]), "body_sha256": hashlib.sha256(r["body"]).hexdigest(),
            "body": r["body"], "downstream_framing": (
                "chunked" if r["chunked"] else
                "content-length" if "content-length" in r["hd"] else "close-delimited"),
            "header_names": sorted({k for k, _ in r["headers"]}),
        })
    return results, sent


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", help="output directory (default: new temp dir outside the repo)")
    args = ap.parse_args()
    subprocess.run(["cargo", "build", "--release", "--locked", "--manifest-path", str(MANIFEST)],
                   check=True, stderr=subprocess.DEVNULL)
    cap = Path(tempfile.mkdtemp(prefix="raw-relay-cap-"))
    failures, report = [], {}
    with running_fixture() as fx:
        p = subprocess.Popen([str(BIN), "--upstream", "http://" + fx.authority,
                              "--capture-dir", str(cap)], stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True)
        try:
            relay_auth = json.loads(p.stdout.readline())["listen"]
            direct, sent_d = run_leg(fx.authority)
            relayed, sent_r = run_leg(relay_auth)
            time.sleep(0.3)
            c = http.client.HTTPConnection(*fx.authority.split(":"), timeout=5)
            c.request("GET", "/_fixture/counters", headers={"Host": fx.authority})
            counters = json.loads(c.getresponse().read())
        finally:
            p.terminate()
            try:
                err = p.communicate(timeout=5)[1]
            except subprocess.TimeoutExpired:
                p.kill()
                err = ""
        steps_out = []
        for d, r in zip(direct, relayed):
            row = {"step": d["step"], "direct_status": d.get("status"), "relay_status": r.get("status"),
                   "direct_content_type": d["content_type"], "relay_content_type": r["content_type"],
                   "direct_has_session_id": d["has_session_id"], "relay_has_session_id": r["has_session_id"],
                   "direct_sha256": d.get("body_sha256"), "relay_sha256": r.get("body_sha256"),
                   "body_len": d["body_len"]}
            if d["step"].endswith("drop_after_accept"):
                row["direct_observed"] = {k: d.get(k) for k in ("observed_response", "exception")}
                row["relay_observed"] = {k: r.get(k) for k in ("observed_response", "exception")}
                ok = (not d["observed_response"]) and (not r["observed_response"])
                row["downstream_closed_without_response_both"] = ok
            else:
                ok = (d["status"] == r["status"] and d["content_type"] == r["content_type"]
                      and d["has_session_id"] == r["has_session_id"] and d["body"] == r["body"])
                row["direct_framing"], row["relay_framing"] = d["downstream_framing"], r["downstream_framing"]
                row["header_names_only_direct"] = sorted(set(d["header_names"]) - set(r["header_names"]))
                row["header_names_only_relay"] = sorted(set(r["header_names"]) - set(d["header_names"]))
            row["match"] = ok
            if not ok:
                failures.append(d["step"])
            steps_out.append(row)
        # SSE verbatim checks through the relay
        sse = next(r for r in relayed if r["step"].endswith("sse_ok"))["body"]
        lines = sse.split(b"\r\n")
        sse_checks = {
            "comment_line": b": fixture comment\r\n" in sse,
            "event_line": b"event: message\r\n" in sse,
            "two_data_lines_crlf": sum(1 for l in lines if l.startswith(b"data: ")) == 2,
            "no_bare_lf": b"\n" not in sse.replace(b"\r\n", b""),
            "ends_with_blank_line": sse.endswith(b"\r\n\r\n"),
        }
        failures += ["sse:" + k for k, v in sse_checks.items() if not v]
        # request/response capture vs what the client actually sent / received
        sent_relay = sent_r
        cap_checks = []
        for i, body in enumerate(sent_relay, 1):
            rq = (cap / f"{i}.req.bin").read_bytes() if (cap / f"{i}.req.bin").exists() else None
            rs = (cap / f"{i}.resp.bin").read_bytes() if (cap / f"{i}.resp.bin").exists() else None
            got = relayed[i - 1].get("body")
            cap_checks.append({"n": i, "step": relayed[i - 1]["step"], "req_bin_equals_sent": rq == body,
                               "resp_bin_equals_client_body": (rs == got) if got is not None else (rs in (None, b""))})
        failures += [f"capture:{c['n']}" for c in cap_checks
                     if not (c["req_bin_equals_sent"] and c["resp_bin_equals_client_body"])]
        drops = counters["by_tool"].get("drop_after_accept")
        if drops != 2:
            failures.append("retry:drop_after_accept=%s" % drops)
        ids = {k: v for k, v in counters["by_id"].items() if v != 2}
        if ids:
            failures.append("call_id_counts_not_2")
        events = [json.loads(l) for l in err.splitlines() if l.startswith("{")]
        report = {"steps": steps_out, "sse_checks": sse_checks, "capture_checks": cap_checks,
                  "fixture_counters": counters,
                  "relay_stderr_events": {e["event"]: sum(1 for x in events if x["event"] == e["event"])
                                          for e in events},
                  "session_id_values_printed": False, "failures": failures, "ok": not failures}
    shutil.rmtree(cap, ignore_errors=True)
    out = Path(args.out) if args.out else Path(tempfile.mkdtemp(prefix="t01-compare-"))
    out.mkdir(parents=True, exist_ok=True)
    (out / "compare-report.json").write_text(json.dumps(report, indent=2) + "\n")
    print("report: " + str(out / "compare-report.json"), file=sys.stderr)
    print(json.dumps(report))
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
