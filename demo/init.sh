#!/bin/sh
# One-shot bootstrap for the Sigil docker-compose demo:
#   * a throwaway demo CA + server/client TLS certs (mTLS on the sender->server hop)
#   * a throwaway ed25519 policy-signing key + the agent's pubkey keystore
#   * signs demo/policy.demo.yaml and drops the bundle where sigil-server serves it
#   * writes sender.yaml / server.yaml / policy.yaml into the shared volumes
#
# Idempotent: if the signed bundle already exists, this does nothing — so a plain
# `docker compose up` after the first run reuses the same PKI. For a fresh demo:
#   docker compose down -v && docker compose up --build
set -eu

SIGIL_ETC=/etc/sigil
SERVER_ETC=/etc/sigil-server
SEED_POLICY=/seed/policy.yaml

if [ -f "$SERVER_ETC/signed-policy.json" ]; then
  echo "init: bootstrap already done — reusing existing PKI / signed policy."
  exit 0
fi

mkdir -p "$SIGIL_ETC" "$SERVER_ETC"

echo "init: generating throwaway demo CA + TLS certs..."
cd "$SERVER_ETC"

openssl req -x509 -newkey rsa:2048 -nodes -days 36500 \
  -keyout ca.key -out ca.crt -subj "/CN=sigil-demo-ca" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" >/dev/null 2>&1

cat > server.ext <<'EOF'
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:sigil-server, DNS:localhost, IP:127.0.0.1
EOF
openssl req -new -newkey rsa:2048 -nodes -keyout server.key -out server.csr \
  -subj "/CN=sigil-server" >/dev/null 2>&1
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -days 36500 -extfile server.ext -out server.crt >/dev/null 2>&1

cat > client.ext <<'EOF'
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth
EOF
openssl req -new -newkey rsa:2048 -nodes -keyout client.key -out client.csr \
  -subj "/CN=demo-sender" >/dev/null 2>&1
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -days 36500 -extfile client.ext -out client.crt >/dev/null 2>&1

rm -f server.csr client.csr server.ext client.ext ca.srl
# The sender lives behind a different volume; give it the same CA + client cert.
cp ca.crt client.crt client.key "$SIGIL_ETC/"

echo "init: generating policy-signing key + agent keystore..."
sigil-sign keygen --id demo-key --out "$SIGIL_ETC/signing-key.json" >/dev/null
PUB=$(jq -r .ed25519_pubkey_b64 "$SIGIL_ETC/signing-key.json")
cat > "$SIGIL_ETC/policy-signing-pubkeys.pem" <<EOF
{ "pubkeys": [ { "id": "demo-key", "ed25519_pubkey_b64": "$PUB", "valid_from": "2020-01-01T00:00:00Z", "valid_until": "2099-01-01T00:00:00Z" } ] }
EOF

echo "init: copying + signing the demo policy..."
cp "$SEED_POLICY" "$SIGIL_ETC/policy.yaml"
sigil-sign sign \
  --in "$SIGIL_ETC/policy.yaml" \
  --key "$SIGIL_ETC/signing-key.json" \
  --policy-version 1 \
  --valid-until 2099-01-01T00:00:00Z \
  --out "$SERVER_ETC/signed-policy.json" >/dev/null

echo "init: writing sender.yaml / server.yaml..."
cat > "$SIGIL_ETC/sender.yaml" <<'EOF'
server_base_url: "https://sigil-server:8443"
client_cert_path: "/etc/sigil/client.crt"
client_key_path: "/etc/sigil/client.key"
server_ca_path: "/etc/sigil/ca.crt"
events_dir: "/var/log/sigil"
offset_path: "/var/lib/sigil/sender-offset.json"
agent_control: "/var/run/sigil/control.sock"
dead_letter_dir: "/var/log/sigil/dead-letter"
policy_poll_interval: 10
EOF
cat > "$SERVER_ETC/server.yaml" <<'EOF'
bind: "0.0.0.0:8443"
tls_cert_path: "/etc/sigil-server/server.crt"
tls_key_path: "/etc/sigil-server/server.key"
client_ca_path: "/etc/sigil-server/ca.crt"
events_out_dir: "/var/lib/sigil-server/events"
policy_bundle_path: "/etc/sigil-server/signed-policy.json"
EOF

echo "init: done."
