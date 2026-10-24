# Sigil Proxy AWS two-instance smoke test (runbook)

2026-10-24 · base `e5612f8` plus the uncommitted T-13d/T-12b2 working tree of `feat/proxy-invocations-sessions`
· status: **preparation only. Nothing has been provisioned or run in AWS.**
Traces: PX-003/004/006–011/013–016, AC-03/04/05/06/07/08/12/15 (see [t13d-t12b2.md](t13d-t12b2.md)).
Tools: [`scripts/proxy-smoke/`](../../../scripts/proxy-smoke/README.md).

This runbook prepares a reviewable run on two EC2 instances. It does not provision AWS,
choose an account, region, IP, domain or certificate, or automate deployment. Every value in `<ANGLE_BRACKETS>`
is a placeholder that the operator fills in. Do not commit filled-in copies, tokens, keys or captured outputs
that contain addresses.

## 0. What this proves and what it does not

| Class | Meaning | Where recorded |
|---|---|---|
| F: fixture automation | `python3 -B -m unittest discover -s scripts/proxy-smoke -p 'test_*.py'`: the fixture, client and fingerprint helper run against themselves on loopback. No proxy involved. | the command output |
| L: local rehearsal | The runbook steps (§3–§13) run on one macOS host on loopback, with the real `sigil-server` and `sigil-proxy` built from the working tree. Final frozen-source run passed (§17); earlier worker report remains historical (§15). Not AWS, not a real client. | §17 of this file |
| H: AWS run | The same steps across instance A, instance B and the operator PC, over real cross-instance links. | evidence template, §14 |
| R: real client | Claude Code, Codex or another vendor client pointed at the proxy. **Not part of this runbook.** It needs a separate, explicitly authorised probe (AGENTS.md compatibility gate, [t13d-t12b2.md](t13d-t12b2.md) "Evidence and release boundary"). The smoke client is not a vendor client. | separate probe record |

A passing H run shows that the observation path, session handling, audit ledger, outage replay and spool
fail-closed behaviour work across real hosts with the synthetic fixture. It does **not** show vendor-client compatibility,
P1 release readiness, policy enforcement, manager UI completeness, or support for a private-network MCP destination.

## 1. Topology

```text
 operator PC ──ssh -L 8480 (or SSM port forwarding)──▶ B: 127.0.0.1:8480  sigil-proxy listener (loopback)
                                                        │
                                                        │ control plane: mTLS, private IP  ──▶ A: <A_PRIVATE_IP>:8443  sigil-server
                                                        │
                                                        │ data plane (pick one):
                                                        │  D1  http://127.0.0.1:18080/mcp on B
                                                        │      = ssh -L tunnel B ──(encrypted, SG-limited)──▶ A: 127.0.0.1:18080 fixture
                                                        │  D2  https://<MCP_PUBLIC_FQDN>/mcp ──public IP, SG /32 allowlist──▶ A: fixture behind TLS
 A also: optional existing sigil-manager (read-only consumer; proxy screens may be unfinished)
```

### 1.1 Control plane and data plane are filtered differently

| Leg | Who checks the destination | Private address allowed? |
|---|---|---|
| B → A `control_plane_url` (config GET, events, status, metadata) | Bootstrap only requires `https://` (`bootstrap.rs` `check_control_plane_url`). mTLS both ways. | **Yes.** Use A's private IP. |
| B → upstream MCP (`routes[].upstream_url`) | `dest.rs` checks every resolved address per request. `config_sync::route_specs` always sets `allow_private_destination: false` because the config DTO has no such field yet. | **No.** `http://` must resolve to loopback; `https://` must resolve to a public address. |

Consequences, which this runbook does not try to work around:

- A route such as `http://<A_PRIVATE_IP>:18080/mcp` or `https://<A_PRIVATE_DNS>/mcp` is refused. Do not disable or
  patch destination protection for the test.
- Inside a VPC, an EC2 **public** DNS name resolves to the instance's **private** IPv4 address
  ([AWS: DNS hostnames for EC2 instances](https://docs.aws.amazon.com/vpc/latest/userguide/AmazonDNS-concepts.html#vpc-dns-hostnames)),
  so `https://ec2-…compute.amazonaws.com/…` from B is refused too.
- **Open P1 requirement:** a direct private-VPC MCP route needs the explicit management flag that
  [control-plane.md §6.1](contracts/control-plane.md) requires ("private destinations need an explicit management flag").
  It is not implemented. Record any attempt as "refused by design", not as a bug in this smoke test.

### 1.2 Supported data-plane options

**D1 (recommended for this smoke test): SSH local forward, loopback to loopback.** The fixture binds `127.0.0.1:18080` on A.
B runs `ssh -N -L 127.0.0.1:18080:127.0.0.1:18080 <TUNNEL_USER>@<A_PRIVATE_IP>`. The proxy route is
`http://127.0.0.1:18080/mcp`, which `dest.rs` allows (loopback HTTP). The bytes cross instances inside an encrypted SSH
connection. Use the **same port on both ends** so the `Host` header the proxy sends (`127.0.0.1:18080`) matches the
fixture's bound authority. The tunnel is operator-controlled test plumbing. It is not a product feature, and it does not
exercise `dest.rs` against a non-loopback address.

**D2 (optional): public HTTPS.** The fixture runs on A behind TLS with a certificate that is valid for `<MCP_PUBLIC_FQDN>` and
chains to a CA in B's system trust store. `<MCP_PUBLIC_FQDN>` resolves (public DNS) to A's Elastic IP. SG-A allows
TCP 443 only from B's public egress address `<B_EIP>/32`. AWS security-group references match only private-IP traffic
([AWS: security group referencing](https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html#security-group-referencing)),
so a rule naming SG-B does not admit B's traffic to A's public IP. Obtaining the certificate and the DNS name is the operator's
job and out of scope here. This runbook does not verify D2 end to end. The fixture's `--tls-cert/--tls-key` option exists for it.

### 1.3 Security groups (minimum)

| SG | Direction | Port | Source / destination | Why |
|---|---|---|---|---|
| SG-A | in | TCP 8443 | SG-B | control plane (private IP) |
| SG-A | in | TCP 22 | SG-B | D1 tunnel only |
| SG-A | in | TCP 443 | `<B_EIP>/32` | D2 only |
| SG-A | in | TCP 22 | `<OPERATOR_PC_CIDR>` | admin. Not needed when you use SSM Session Manager. |
| SG-B | in | TCP 22 | `<OPERATOR_PC_CIDR>` | admin + PC→proxy forward. Not needed when you use SSM port forwarding. |
| SG-B | in | TCP 8480 | none | the proxy listener stays on loopback. Never open it. |

Egress can stay at the AWS default for a short test. If you restrict it, B needs SG-A:8443, SG-A:22 (D1) or
`<A_EIP>`:443 (D2), plus package mirrors while building.

AWS DNS, security-group and Session Manager references above/below were checked against official AWS documentation on 2026-10-24.

## 2. Placeholders

| Placeholder | Meaning |
|---|---|
| `<A_PRIVATE_IP>` | A's private IPv4. It goes into the server cert SAN and B's `control_plane_url`. |
| `<A_INSTANCE_ID>`, `<B_INSTANCE_ID>` | for SSM, when used |
| `<B_EIP>`, `<MCP_PUBLIC_FQDN>`, `<A_EIP>` | D2 only |
| `<OPERATOR_PC_CIDR>` | the operator's public address, `/32` |
| `<TUNNEL_USER>` | unprivileged user on A that is allowed only the D1 forward |
| `<SSH_USER>` | login user on A/B (for example `ec2-user` or `rocky`) |
| `<PROXY_ID>` | `px-aws-01` in the examples. Must be a DNS label (server rule) and match `^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$` (proxy rule). |
| `<SHA>` | git commit of the binaries under test |

Working directory on every host: `~/sigil-smoke` (`umask 077`). No system packages or systemd units are installed. CI already
verifies that the `sigil-proxy` package installs disabled (packaging test). This run uses plain binaries as an unprivileged user.

## 3. Build and record versions (A and B)

Build on each instance's own OS/arch (or copy a matching build). Python 3.9+ and OpenSSL are needed on A, B and the PC.
Bash is used for command arrays and brace expansion. `curl` ≥ 7.76 (for `--fail-with-body` and `-H @file`) is needed on A.

```sh
git clone https://github.com/Ju571nK/sigil.git && cd sigil && git checkout <SHA>
cargo build --release -p sigil-server -p sigil-proxy
mkdir -p ~/sigil-smoke/bin && cp target/release/sigil-server target/release/sigil-proxy ~/sigil-smoke/bin/
cp -r scripts/proxy-smoke ~/sigil-smoke/tools
~/sigil-smoke/bin/sigil-proxy version; git rev-parse HEAD; uname -srm; python3 --version; openssl version
```

Record these outputs in the evidence template (§14). B needs only `sigil-proxy` and the tools. The PC needs only `tools/`.

## 4. Test PKI (on A, throwaway, 7 days)

All CA keys stay on A. Two CAs with **different subject DNs** (the server refuses to boot otherwise). Every leaf carries
SKI/AKI: Python 3.13+ rejects leaves without AKI under its default strict X.509 verification. The rehearsal hit this.

```sh
mkdir -p ~/sigil-smoke/pki && cd ~/sigil-smoke/pki && umask 077
for ca in host proxy; do
  openssl req -x509 -new -newkey rsa:2048 -nodes -keyout $ca-ca.key -out $ca-ca.crt -days 7 \
    -subj "/CN=sigil-smoke-$ca-ca" -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" -addext "subjectKeyIdentifier=hash"
done
cat host-ca.crt proxy-ca.crt > client-ca-bundle.pem          # server client_ca_path
LEAF='basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer'
printf "$LEAF\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:%s\n" '<A_PRIVATE_IP>' > server.ext
printf "$LEAF\nextendedKeyUsage=clientAuth\n" > client.ext
printf "$LEAF\nextendedKeyUsage=clientAuth\nsubjectAltName=DNS:%s.proxy.sigil.invalid\n" '<PROXY_ID>' > proxy.ext
leaf() { # <ca> <name> <cn> <extfile>: key + CSR + cert signed by host CA
  openssl req -new -newkey rsa:2048 -nodes -keyout $2.key -out $2.csr -subj "/CN=$3"
  openssl x509 -req -in $2.csr -CA $1.crt -CAkey $1.key -set_serial 0x$(openssl rand -hex 8) \
    -days 7 -extfile $4 -out $2.crt
}
leaf host-ca server sigil-smoke-server server.ext   # A server TLS
leaf host-ca mgmt   sigil-smoke-mgmt   client.ext   # management caller (operator CLI on A)
leaf host-ca reader sigil-smoke-reader client.ext   # read-API caller: a DIFFERENT cert
chmod 644 *.crt client-ca-bundle.pem
```

- The **reader** cert must not be the management cert. Read routes accept only host-class peers that are not management
  callers and not proxy-registry fingerprints (`query.rs` `read_class_guard`). A management cert gets `404 host_unknown` on them.
- The proxy SAN form `<proxy_id>.proxy.sigil.invalid` is the current implementation (`identity.rs`). It is still OPEN
  in control-plane §10 q1.

**Proxy certificate.** Generate the key on B, so it never leaves B, and sign the CSR on A with the pinned profile
(`-extfile` replaces all CSR extensions):

```sh
# B
mkdir -p ~/sigil-smoke/b && cd ~/sigil-smoke/b && umask 077
openssl req -new -newkey rsa:2048 -nodes -keyout proxy.key -out proxy.csr -subj "/CN=<PROXY_ID>"
# copy proxy.csr to A (operator-controlled scp), then on A:
cd ~/sigil-smoke/pki && openssl x509 -req -in proxy.csr -CA proxy-ca.crt -CAkey proxy-ca.key \
  -set_serial 0x$(openssl rand -hex 8) -days 7 -extfile proxy.ext -out proxy.crt
# copy proxy.crt and host-ca.crt back to B as ~/sigil-smoke/b/proxy.crt and ~/sigil-smoke/b/ca.pem; chmod 644 both
```

`python3 ~/sigil-smoke/tools/b3fp.py <cert.pem>` prints the blake3 fingerprint of the first certificate's DER. The server
uses that value for `caller_cert_fingerprint` and proxy fingerprints (stdlib BLAKE3, cross-checked against the Rust crate).

## 5. Instance A: sigil-server

```sh
mkdir -p ~/sigil-smoke/a/{state,events} && cd ~/sigil-smoke/a && umask 077
cp ../pki/{server.crt,server.key,client-ca-bundle.pem,proxy-ca.crt,host-ca.crt,mgmt.crt,mgmt.key,reader.crt,reader.key} .
MGMT_FP=$(python3 ../tools/b3fp.py mgmt.crt | cut -d' ' -f1)
# Management tokens: printed once on stdout -> 0600 file; the verifier entry goes to stderr.
../bin/sigil-server proxy verifier-new --scope identity --caller-fingerprint "$MGMT_FP" --key-id smoke-identity \
  > mgmt-identity.token 2> identity-entry.txt
../bin/sigil-server proxy verifier-new --scope config --caller-fingerprint "$MGMT_FP" --key-id smoke-config \
  > mgmt-config.token 2> config-entry.txt
python3 - identity-entry.txt config-entry.txt > management-verifiers.json <<'EOF'
import json, sys
entries = []
for p in sys.argv[1:]:
    t = open(p).read(); entries.append(json.loads(t[t.index("{"):]))
print(json.dumps({"entries": entries}, indent=2))
EOF
rm identity-entry.txt config-entry.txt; chmod 600 management-verifiers.json
openssl rand -hex 32 > read.token                       # server read bearer (the manager's existing credential class)
printf 'SIGIL_SERVER_READ_TOKEN=%s\n' "$(cat read.token)" > server.env
printf 'Authorization: Bearer %s\n' "$(cat mgmt-config.token)" > mgmt-config.hdr   # for curl -H @file
```

`printf` is a shell builtin, so the tokens never appear in a process argument list. `curl -H @file` keeps them out of `ps`
too. The `sigil-server proxy` CLI reads its bearer from `--token-file`.

`~/sigil-smoke/a/server.yaml` (absolute paths, replace `<HOME>`):

```yaml
bind: "<A_PRIVATE_IP>:8443"          # private interface only
tls_cert_path: "<HOME>/sigil-smoke/a/server.crt"
tls_key_path: "<HOME>/sigil-smoke/a/server.key"
client_ca_path: "<HOME>/sigil-smoke/a/client-ca-bundle.pem"
events_out_dir: "<HOME>/sigil-smoke/a/events"
policy_bundle_path: "<HOME>/sigil-smoke/a/state/signed-policy.json"   # absent file: /v1/policy 404, not used here
high_water_path: "<HOME>/sigil-smoke/a/state/high_water.json"         # management audit + ledger default next to it
proxy:
  ca_path: "<HOME>/sigil-smoke/a/proxy-ca.crt"
  registry_path: "<HOME>/sigil-smoke/a/state/proxies.json"
  registry_init: true                # first boot only; remove afterwards
  management_verifiers: "<HOME>/sigil-smoke/a/management-verifiers.json"
  config_ttl_seconds: 900            # test value: the maximum, so outage windows (§11) fit inside the TTL
```

Start (foreground, or `nohup … &`). The read token reaches the process through the environment, never through argv:

```sh
cd ~/sigil-smoke/a
(set -a; . ./server.env; set +a; exec ../bin/sigil-server serve --config server.yaml) >> server.log 2>&1 &
echo $! > server.pid
```

**Optional manager.** An existing sigil-manager may point at this server with the read token. It never gates any check
here, and its proxy screens may be unfinished (sigil-manager#37). Record only what it shows. The server read API (§9) is
the evidence.

## 6. Instance B: proxy bootstrap and client token

Generate the upstream secret once, put it on both hosts as an owner-only file (A: fixture `--token-file`; B: credential
`secret_file`), and move it only over operator-controlled `scp`:

```sh
umask 077; openssl rand -hex 32 > upstream.secret      # then copy to A:~/sigil-smoke/a/upstream.secret, chmod 600
```

`~/sigil-smoke/b/proxy.yaml`:

```yaml
proxy_id: "<PROXY_ID>"
listen: "127.0.0.1:8480"             # loopback; Host must then be 127.0.0.1:8480 or localhost:8480
control_plane_url: "https://<A_PRIVATE_IP>:8443"
state_dir: "<HOME>/sigil-smoke/b/state"   # mkdir -m 700 first
client_cert_file: "<HOME>/sigil-smoke/b/proxy.crt"
client_key_file: "<HOME>/sigil-smoke/b/proxy.key"
ca_file: "<HOME>/sigil-smoke/b/ca.pem"     # host CA: verifies the server certificate
credentials:
  smoke-upstream:
    secret_file: "<HOME>/sigil-smoke/b/upstream.secret"
    upstream_origins: ["http://127.0.0.1:18080"]     # D2: ["https://<MCP_PUBLIC_FQDN>"]
```

```sh
mkdir -m 700 -p ~/sigil-smoke/b/state && cd ~/sigil-smoke/b
../bin/sigil-proxy check-config --config proxy.yaml            # exit 0 "config ok"
../bin/sigil-proxy token new --config proxy.yaml --principal smoke-client > token-new.out
sed -n 's/^token: //p' token-new.out > client.token && chmod 600 client.token     # deliver to the PC, then delete here
sed -n 's/^verifier_sha256: //p' token-new.out > client.verifier && rm token-new.out
```

Only `client.verifier` goes into the server config. The token is shown once and is not stored by the proxy. Move
`client.token` to the PC (`~/sigil-smoke/pc/client.token`, 0600) and remove it from B after the privacy scan (§10) has
used a copy.

## 7. Register, fingerprint, configure (operator CLI on A)

```sh
cd ~/sigil-smoke/a
CONN=(--server-url https://<A_PRIVATE_IP>:8443 --cert mgmt.crt --key mgmt.key --ca host-ca.crt)
../bin/sigil-server proxy register "${CONN[@]}" --token-file mgmt-identity.token --requested-by <OPERATOR_NAME> \
  --proxy-id <PROXY_ID> --display-name "AWS smoke B"                                  # state: pending
../bin/sigil-server proxy fingerprint "${CONN[@]}" --token-file mgmt-identity.token \
  --proxy-id <PROXY_ID> --cert-file ../pki/proxy.crt                                  # state: active, fp_current set
```

There is no CLI subcommand for `PUT /v1/proxies/{id}/config`. Use `curl` with the `config`-scope token. Template
`config-put.json` (replace the verifier from §6. D2: `"upstream_url": "https://<MCP_PUBLIC_FQDN>/mcp"`):

```json
{"expected_revision": 0,
 "config": {
  "schema_version": 1,
  "proxy_id": "<PROXY_ID>",
  "allowed_origins": [],
  "routes": [{"route_id": "r1", "upstream_id": "smoke-mcp",
              "upstream_url": "http://127.0.0.1:18080/mcp",
              "upstream_protocol": "2025-11-25",
              "credential_ref": "smoke-upstream"}],
  "principals": [{"principal_id": "smoke-client", "actor_kind": "non_human",
                  "verifiers": [{"key_id": "smoke-k1", "verifier": "<CLIENT_VERIFIER_SHA256>"}],
                  "routes": ["r1"]}]}}
```

```sh
curl -sS --fail-with-body --cacert host-ca.crt --cert mgmt.crt --key mgmt.key -H @mgmt-config.hdr \
  -H 'Content-Type: application/json' -X PUT --data-binary @config-put.json \
  https://<A_PRIVATE_IP>:8443/v1/proxies/<PROXY_ID>/config
# 200 {"config_hash":"…","request_id":"…","revision":1}; a later PUT needs "expected_revision": <current>
```

The server assigns `credential_scope_id`, TTL and retention defaults. `allowed_origins: []` refuses every browser `Origin`.
Non-browser clients send none.

## 8. Data plane, proxy start, PC access

**Fixture on A** (D1: loopback, port 18080):

```sh
cd ~/sigil-smoke/a
nohup python3 -u -B ../tools/mcp_fixture.py --token-file upstream.secret > fixture.log 2>&1 &
echo $! > fixture.pid
head -1 fixture.log    # "listening on http://127.0.0.1:18080/mcp revision=2025-11-25 …"
```

Variants: `--stateless` (no upstream session id, so DELETE is answered by the proxy locally) and `--initialize-sse`
(initialize answered as SSE, the T-12b2 buffered-initialize path). D2: `--bind <A_PRIVATE_IP> --port 443 --tls-cert … --tls-key …
--allow-host <MCP_PUBLIC_FQDN> --allow-host <MCP_PUBLIC_FQDN>:443`. Binding a privileged port needs a capability or a TLS terminator in front, which is the operator's choice.

**D1 tunnel.** On A, add a restricted key for `<TUNNEL_USER>` (OpenSSH `restrict` then re-allow only this forward):

```text
restrict,port-forwarding,permitopen="127.0.0.1:18080" ssh-ed25519 AAAA…<B_TUNNEL_PUBKEY> sigil-smoke-tunnel
```

On B:

```sh
ssh -N -o ExitOnForwardFailure=yes -o ServerAliveInterval=15 -i ~/.ssh/sigil-smoke-tunnel \
  -L 127.0.0.1:18080:127.0.0.1:18080 <TUNNEL_USER>@<A_PRIVATE_IP> &
```

**Proxy on B:**

```sh
cd ~/sigil-smoke/b
nohup ../bin/sigil-proxy run --config proxy.yaml > proxy.log 2>&1 &
echo $! > proxy.pid
../bin/sigil-proxy health --config proxy.yaml   # expect alive: true, config_state: Valid, forwarding: true
```

**PC to B listener.** The loopback listener refuses a `Host` whose port differs from the bound port (`server.rs` `HostPolicy`),
so forward the **same** port:

```sh
ssh -N -L 127.0.0.1:8480:127.0.0.1:8480 <SSH_USER>@<B_ADDRESS>
# or, without inbound SSH (Session Manager plugin installed; AWS docs "Starting a session (port forwarding)"):
aws ssm start-session --target <B_INSTANCE_ID> --document-name AWS-StartPortForwardingSession \
  --parameters '{"portNumber":["8480"],"localPortNumber":["8480"]}'
```

SSM requires a configured managed node, appropriate IAM permissions, SSM Agent 2.3.672.0 or later,
and the Session Manager plugin on the PC; forwarding alone does not configure those prerequisites.

([AWS: start a port forwarding session](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-sessions-start.html#sessions-start-port-forwarding))

## 9. Scenario and server verification

**PC:**

```sh
cd ~/sigil-smoke && python3 -B tools/smoke_client.py scenario --url http://127.0.0.1:8480/mcp/r1 \
  --token-file pc/client.token --out pc/run1
```

Each line prints PASS/FAIL. Exit 0 only if all pass. `pc/run1/summary.json` holds the checks and `started_at`.
`pc/run1/canaries.json` holds the random canaries and fixture tool names for §10 (synthetic, not secrets; 0600). Expected
results are taken from [t13d-t12b2.md](t13d-t12b2.md) and must be measured on the build under test:

| ID | Request | Expected |
|---|---|---|
| N1/N2 | initialize without / with wrong bearer | 401, no invocation |
| N3 | GET (SSE) | 405, no upstream contact |
| S1/S1a/S1b | initialize | 200, proxy `Mcp-Session-Id` (visible ASCII; the upstream id is never exposed), `protocolVersion` 2025-11-25, only `tools` advertised |
| N4 | initialize carrying a session id | 400 empty, no invocation |
| S2 | `notifications/initialized` | 202, no invocation |
| N5/N6 | tools/list without / with unknown session | 400 / 404, no invocation |
| N7/N8 | missing / legacy `MCP-Protocol-Version` | 400, audited `protocol_error`/`not_sent` |
| S3–S7a | ping, paged tools/list, JSON call, SSE call, tool error, unknown tool | 200 with exact synthetic results |
| S8/S8a | `notifications/cancelled` for an in-flight `smoke_wait` | 202. The call ends early. The invocation has `cancel_observed=true`. |
| S10–S10b | second session cancels the same request id | not matched: the first call finishes normally (isolation) |
| S9/S9a | `smoke_inventory_toggle` twice + full listings | listing gains then loses `smoke_inventory_extra` |
| S11/S11a | DELETE, then reuse | 204, then 404 |

**Fixture oracle (A):** `python3 -B tools/smoke_client.py counters --fixture-url http://127.0.0.1:18080 --token-file a/upstream.secret`
(bearer required). `calls_by_tool` counts recognized fixture tools only: the unknown-tool call is rejected
before this counter increments. Compare the per-tool delta for a known tool such as `smoke_echo` with its successful
forwarded requests; do not compare this sum with all audited `tools/call` events. Refused proxy requests add zero. `deletes`
is 2 in stateful mode and 0 in `--stateless` mode (the proxy answers DELETE locally).

**Server read API (A).** Use the reader cert and read bearer. Wait until `GET /v1/proxies/<PROXY_ID>` shows
`spool.unsent_events: 0` with a `status_as_of` later than your last call (poll for at most 120 seconds, then record a failure and retain evidence): replay is asynchronous, and an early query
undercounts (the rehearsal hit this).

```sh
cd ~/sigil-smoke/a
RD=(--server-url https://<A_PRIVATE_IP>:8443 --cert reader.crt --key reader.key --ca host-ca.crt --token-file read.token)
python3 -B ../tools/smoke_client.py query "${RD[@]}" /v1/proxies
python3 -B ../tools/smoke_client.py query "${RD[@]}" /v1/proxies/<PROXY_ID>
python3 -B ../tools/smoke_client.py ledger "${RD[@]}" --proxy-id <PROXY_ID> --since <STARTED_AT> \
  --canary-file canaries.json --details   # canaries.json copied from the PC
python3 -B ../tools/smoke_client.py query "${RD[@]}" /v1/proxies/<PROXY_ID>/drift
python3 -B ../tools/smoke_client.py query "${RD[@]}" /v1/proxies/<PROXY_ID>/inventory-snapshots
../bin/sigil-server proxy audit --server-url https://<A_PRIVATE_IP>:8443 --cert mgmt.crt --key mgmt.key \
  --ca host-ca.crt --token-file read.token          # management audit (not run in the rehearsal; e2e uses this cert/token pairing)
```

`ledger` fails on a duplicate `invocation_id`, a duplicate `event_id` inside one invocation detail, or any canary or fixture
tool name in the ordinary list/detail/proxy-detail responses. It prints a table of
method/lifecycle/outcome/delivery/reason/tool/cancel. The rehearsal produced, for one scenario run:

| method | lifecycle | outcome | delivery | tool | cancel | count |
|---|---|---|---|---|---|---|
| initialize | completed | success | sent | – | no | 2 |
| ping | completed | success | sent | – | no | 1 |
| tools/list | completed | success | sent | – | no | 9 |
| tools/list | completed | protocol_error | not_sent | – | no | 2 (N7, N8) |
| tools/call | completed | success | sent | identified | no | 5 |
| tools/call | completed | tool_error | sent | identified | no | 1 |
| tools/call | completed | tool_error | sent | identified | **yes** (S8 cancel) | 1 |
| tools/call | completed | protocol_error | sent | metadata_unavailable | no | 1 (unknown tool) |

The actor is `smoke-client` / `non_human` from config, never client-reported. Drift shows `added` then `removed` for one
`metadata_ref` (the extra tool). Raw tool names live only in the metadata store, never in these responses.

## 10. Privacy canaries

Copy `pc/run1/canaries.json` to A and B (synthetic markers only). On B, scan with a temporary 0600 copy of
`client.token` and with `upstream.secret`. The scanner prints counts only, never values:

```sh
# B: spool, registry, status files, proxy log
python3 -B ../tools/smoke_client.py scan --canary-file canaries.json --secret-file client.token.copy \
  --secret-file upstream.secret state proxy.log
# A: ledger, metadata, registry, state, audit, events, server and fixture logs (NOT the dirs holding the token files)
python3 -B ../tools/smoke_client.py scan --canary-file canaries.json --secret-file client.token.copy \
  --secret-file upstream.secret --secret-file mgmt-config.token --secret-file mgmt-identity.token \
  --secret-file read.token state events server.log fixture.log
# positive control: must report FOUND (proves the scanner sees the markers)
python3 -B ../tools/smoke_client.py scan --canary-file canaries.json canaries.json
```

Expected: `total_occurrences=0`, `files>0`, `errors=0` on A and B (exit 0).
The scanner exits 2 for unreadable, missing, nonregular or empty scan targets; those are incomplete evidence. If the proxy runs under systemd, scan
`journalctl -u <unit> -o cat > proxy.log` instead. Delete the copies afterwards.

## 11. Outage, replay and de-duplication

1. **Stop A's server** (`kill "$(cat ~/sigil-smoke/a/server.pid)"` on A; avoid using SG edits as an immediate outage oracle because established tracked connections can survive rule removal). Note the time.
2. **Within the config TTL** (900 s here; forwarding stops when TTL lapses without a fetch, control-plane §6.3), on the PC:
   `python3 -B tools/smoke_client.py call --url http://127.0.0.1:8480/mcp/r1 --token-file pc/client.token --count 5 --canary`.
   Expected: `open: http=202`, five `http=200 ok`. Calls keep flowing and their events wait in B's spool.
3. **Restart the server** (§5 start command; registry_init removed). Wait for `unsent_events: 0` (§9).
4. `ledger --since <outage start> --details`. Expected in the rehearsal: exactly 1 initialize + 5 calls, all `completed`,
   no duplicates.
5. **De-duplication.** `ledger` treats any duplicate invocation or event id as a failure. A deterministic duplicate
   delivery (ack lost after the server stored the batch) is proven by the automated e2e tests
   (`crates/sigil-proxy-e2e/tests/spool_ingest_e2e.rs`, `server_proxy_ingest_e2e.rs`), not here. Optional best effort: while
   a large backlog drains after step 3, `kill -9` the proxy, restart it, and re-run `ledger`. The result must still be
   duplicate-free. Record it as best-effort evidence only.
6. **Restart fail-closed** (decided 2026-10-10): stop the server, restart the proxy, call → `open: http=401` and
   `health` shows `forwarding: false`. Start the server → forwarding resumes and the next call returns 200.

## 12. Spool fail-closed (refusal means zero upstream calls)

1. With the server **up**, stop the proxy and append test-only limits to `proxy.yaml` (config can only lower defaults;
   admission stops at `spool_max_bytes − spool_gap_reserve_bytes` of unsent event bytes, about 32 KiB here):
   ```yaml
   limits:
     spool_max_bytes: 49152        # test value, unmeasured, never a recommendation
     spool_gap_reserve_bytes: 16384
   ```
   Run `check-config`, start the proxy, and wait for `forwarding: true` (the restart needs a fresh fetch).
2. Save fixture counters (A), stop the server, then on the PC: `call … --count 80`.
3. Require both successful and refused calls, and fixture `smoke_echo` delta **exactly equal** to the 200
   count. Every 503 must have zero upstream contact. Historical WIP gave 32/48; final-source local evidence gave 31/49.
   Exact fill counts depend on record bytes and are observations, not the acceptance threshold.
4. Start the server, wait for drain, then call again (200). `ledger --since …`: the call at the fill boundary may remain
   `lifecycle: started` with an open `local_record_failed` gap on the proxy detail. That is the designed visibility for a
   completion that could not be recorded. It is not a duplicate or a lost start.
5. Restore the original `proxy.yaml` (remove `limits`) and restart.

## 13. Optional: disable / enable

`sigil-server proxy disable` (config token) → within one poll interval, calls get 401 and `health` shows
`config_state: Disabled`. `sigil-server proxy enable` (identity token) → forwarding resumes. Both appear in the management audit.

## 14. Evidence template (H run)

Record per step: date/time (UTC), `<SHA>`, instance OS/arch, `sigil-proxy version`, Python/OpenSSL versions, data-plane
option (D1/D2), scenario `summary.json` failed list, `ledger` table and exit code, counters before/after, scan totals,
§11–§12 status counts, and any deviation. Mark each item H. Keep addresses, tokens and certificates out of committed files.
Real-client (R) results, if a separately authorised probe runs, go into their own record with exact client versions.

## 15. Prior worker rehearsal report (L, 2026-10-24; unverified after recovery)

The previous worker left the following observations before its provider session ended.
The recovery writer did not reproduce the proxy/server rehearsal; these counts are historical
claims, not final-code verification. Do not use them as an AWS or current-build pass.
Recovery did run the fixture-only unittest suite (see tools README).

macOS 26.6 arm64, Python 3.15.0, Homebrew OpenSSL. `sigil-server` and `sigil-proxy` were debug-built from the working tree
(base `e5612f8` + uncommitted T-13d/T-12b2 files) into a separate target dir. All three roles ran on 127.0.0.1 (server
18443, fixture 18080, proxy 18480), with the same PKI, verifier-file, register/fingerprint/PUT, bootstrap and token
commands as §4–§8. There was no tunnel and no AWS.

| Step | Result |
|---|---|
| PKI, verifier file, register → fingerprint (b3fp value equalled the server's `fp_current`) → PUT rev 1 | OK |
| Scenario, stateful fixture | 27/27 PASS |
| Scenario, `--stateless --initialize-sse` fixture | 27/27 PASS; fixture `deletes=0`, 1 forwarded cancel |
| `ledger --details` | 22 invocations, all completed, no duplicate ids, canary/tool-name hits 0 (table in §9) |
| Drift | `added` then `removed`; tool refs `identified` |
| Privacy scan, B (15 files incl. spool/registry WAL) and A (12 files incl. ledger/metadata WAL) | 0 occurrences of canaries, client token, upstream secret, management/read tokens |
| Outage (server stopped, 5 calls) → restart | 5×200 during outage; ledger later showed exactly 1+5, no duplicates |
| Spool fail-closed (49152/16384) | 32×200, 48×503; fixture delta 32. After restart: 3 init + 40 calls received, one boundary call `started` + `local_record_failed` gap |
| Proxy restart with server down | 401 until the server returned, then 200 |

Rehearsal observations for review (not runbook failures):

- `counters.auth_failures` / `unmatched_cancels` stay empty after the 401s, because the proxy status report hard-codes them
  empty (`crates/sigil-proxy/src/status_report.rs`, `"counters": {"auth_failures": [], "unmatched_cancels": []}`). Do not
  use them as evidence until they are produced.
- `outages: []` after a roughly 1-minute server stop. The central-outage gap threshold was not examined. Record what you see; do not
  claim outage visibility from this field.
- Right after `sigil-proxy run`, `health` can show the previous process's status file (`alive: false`) for a few seconds.
- The fixture tool names carry a `smoke_` prefix. A name such as `tool_error` collides with the outcome enum and makes the
  tool-name absence check report a false positive.

Recovery checks (2026-10-24): fixture/helper unittest suite **13/13 passed**, both script `--help` commands succeeded,
and no matching historical fixture/proxy/server rehearsal process remained. No final Rust build or proxy/server
rehearsal was attempted during recovery because the production tree remains under active implementation.

## 16. Known limits and open items

- Direct private-VPC MCP destinations: not supported (management flag OPEN, §1.1). Only D1/D2 are valid test paths.
- Grace expiry ends relay work before audit cleanup. If final loss accounting cannot be handed over or gap persistence fails,
  shutdown must report an error and retain `Stopping` rather than claim `Stopped`; investigate storage before restarting.
- D1 does not exercise `dest.rs` on a non-loopback address. D2 does, but is unverified here.
- Real-client compatibility (R) and hardware status stay unverified. Earlier Claude Code/Codex measurements must not be
  promoted to current-version claims ([t13d-t12b2.md](t13d-t12b2.md)).
- Manager proxy UI completeness is not claimed. The server read API is the evidence.
- M2/m3 registration and health-check unsupported verdicts and proactive upstream probes are outside this test.
- TTL, poll, spool and limit numbers used here are test values, not measurements or recommendations (validation.md D-04).
- Teardown: stop processes, terminate the instances or remove `~/sigil-smoke`, delete the tunnel key from A's
  `authorized_keys`, and revoke the temporary SG rules. The PKI is throwaway (7 days) and must not be reused.


## 17. Final-source local rehearsal (L, 2026-10-24 UTC)

Independent verifier `ctx_d8d4dce093de` copied frozen source before building real server/proxy binaries.
Base `e5612f8` + this patch; 395-file code/manifests/tools manifest SHA256
`f79aad43d743c7458058c9878deee5d6629e36fec492d8b967e29257797cee9e`.
Producer and lifecycle hashes match the final review in [execution.md](execution.md).
`cargo build --locked -p sigil-server -p sigil-proxy --target-dir <private-lab>/target` and
bounded local rehearsal runner both exited 0. Relevant source/tool hashes were unchanged afterwards.
All roles used loopback; this did not measure AWS networking or a tunnel.

| Check | Measured result |
|---|---|
| Stateful scenario | 27/27 passed, 22 completed ledger invocations, zero duplicate invocation/event sets |
| Stateless + SSE initialize | 27/27 passed, 22 completed invocations; upstream DELETE count 0 |
| Privacy, each scenario | proxy 15 / server 12 readable files; zero canary/secret occurrences or errors; positive control FOUND |
| Server offline within TTL | initialize 202, five calls 200; replay exactly six completed invocations, no duplicate sets |
| Spool 49152 / reserve 16384 | 31 calls 200, 49 calls 503; upstream echo delta exactly 31 |
| Drain and recovery | next call 200; window ledger 34 completed (two initialize + 32 calls), no duplicates |
| Proxy restart with server down | initialize 401, forwarding false; server recovery restored initialize 202 / call 200 |
| Final stopped-state scans | proxy 11 / server 12 readable files per scenario canary set; zero occurrences/errors |
| Cleanup | all owned fixture/server/proxy processes exited; verifier terminal released |

This run did not show a boundary start-only invocation/gap; §15's historical boundary count is not a current result.
Deterministic lost-ACK replay/de-duplication remains automated E2E evidence. Management audit CLI, optional disable/enable,
manager UI, systemd/SELinux, real vendor clients and AWS remain unmeasured.
A disposable lab certificate CN mistake was rejected as `proxy_unknown`, corrected to the documented proxy ID, and
rerun using the same source/binaries. A checkpoint initially repeated historical 32/48 spool counts; the verified current
artifact is 31/49 and is the only final count used here. No production source change was needed for the rehearsal.
