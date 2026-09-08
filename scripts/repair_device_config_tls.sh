#!/usr/bin/env bash
set -euo pipefail

source_config="${1:-$HOME/.xibalba-shield/device.json}"
target_config="/etc/xibalba-shield/device.json"

if [[ ! -f "$source_config" ]]; then
  echo "source device config not found: $source_config" >&2
  exit 1
fi

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
python3 - "$source_config" "$tmp" <<'PY'
import json, sys
from pathlib import Path
source, output = map(Path, sys.argv[1:])
doc = json.loads(source.read_text())
doc.update({
    "backend_url": "https://127.0.0.1:8443",
    "backend_ca_file": "/etc/xibalba-shield/tls/ca.crt",
    "backend_client_cert": "/etc/xibalba-shield/tls/client.crt",
    "backend_client_key": "/etc/xibalba-shield/tls/client.key",
})
output.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
PY

sudo install -o root -g xibalba-shield -m 0640 "$tmp" "$target_config"
sudo systemctl restart xibalba-shield.service
systemctl is-active xibalba-shield.service
echo "Shield device config repaired and switched to mTLS on https://127.0.0.1:8443"
