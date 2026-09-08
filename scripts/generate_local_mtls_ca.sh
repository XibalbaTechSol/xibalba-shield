#!/usr/bin/env bash
set -euo pipefail

out_dir="${1:-$HOME/.xibalba-shield/dev-mtls}"
umask 077
mkdir -p "$out_dir"

if [[ -s "$out_dir/ca.crt" && -s "$out_dir/server.crt" && -s "$out_dir/client.crt" ]]; then
  echo "Local mTLS material already exists at $out_dir"
  exit 0
fi

openssl genrsa -out "$out_dir/ca.key" 4096 >/dev/null 2>&1
openssl req -x509 -new -nodes -key "$out_dir/ca.key" -sha256 -days 365 \
  -subj '/CN=Xibalba Shield Local Dev CA' -out "$out_dir/ca.crt" >/dev/null 2>&1

cat > "$out_dir/server.ext" <<'EOF'
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1
EOF
openssl genrsa -out "$out_dir/server.key" 2048 >/dev/null 2>&1
openssl req -new -key "$out_dir/server.key" -subj '/CN=localhost' -out "$out_dir/server.csr" >/dev/null 2>&1
openssl x509 -req -in "$out_dir/server.csr" -CA "$out_dir/ca.crt" -CAkey "$out_dir/ca.key" -CAcreateserial \
  -out "$out_dir/server.crt" -days 90 -sha256 -extfile "$out_dir/server.ext" >/dev/null 2>&1

cat > "$out_dir/client.ext" <<'EOF'
basicConstraints=CA:FALSE
keyUsage=digitalSignature
extendedKeyUsage=clientAuth
EOF
openssl genrsa -out "$out_dir/client.key" 2048 >/dev/null 2>&1
openssl req -new -key "$out_dir/client.key" -subj '/CN=shield-local-test-client' -out "$out_dir/client.csr" >/dev/null 2>&1
openssl x509 -req -in "$out_dir/client.csr" -CA "$out_dir/ca.crt" -CAkey "$out_dir/ca.key" -CAcreateserial \
  -out "$out_dir/client.crt" -days 90 -sha256 -extfile "$out_dir/client.ext" >/dev/null 2>&1

rm -f "$out_dir"/*.csr "$out_dir"/*.ext "$out_dir"/*.srl
chmod 600 "$out_dir"/*.key
chmod 644 "$out_dir"/*.crt
echo "Generated local-only CA and mTLS certificates in $out_dir"
