#!/usr/bin/env bash
set -euo pipefail

# Enable Shield telemetry export to the disposable local Integrity lab.
# This deliberately does not enable kill, cgroup freeze, or network blocking.

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run with sudo: sudo ./scripts/enable_local_integrity_export.sh" >&2
  exit 1
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
env_file="${SHIELD_ENV_FILE:-/etc/xibalba-shield/shield.env}"
did_file="${INTEGRITY_DID_HOME:-/var/lib/xibalba-shield/integrity/did}/xibalba-shield/document.json"
did_root="$(dirname "$(dirname "$did_file")")"
device_config="${SHIELD_DEVICE_CONFIG:-/etc/xibalba-shield/device.json}"
rpc_url="${RPC_URL:-http://127.0.0.1:8545}"
oracle_url="${ORACLE_URL:-http://127.0.0.1:8080}"
bcc_url="${BCC_MIDDLEWARE_URL:-http://127.0.0.1:8001}"
deployments_file="${DEPLOYMENTS_FILE:-/home/xibalba/Projects/integrity-core/deployments.local.json}"
backend_health_url="${SHIELD_BACKEND_HEALTH_URL:-http://127.0.0.1:8421/api/shield/health}"

need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing command: $1" >&2; exit 1; }; }
need curl
need python3
need systemctl

echo "Checking local Integrity lab..."
curl --fail --silent --show-error "$oracle_url/healthz" >/dev/null || {
  echo "Oracle is not healthy at $oracle_url/healthz" >&2
  exit 1
}
curl --fail --silent --show-error "$bcc_url/health" >/dev/null || {
  echo "BCC middleware is not healthy at $bcc_url/health" >&2
  exit 1
}

[[ -f "$did_file" ]] || { echo "Active DID document not found: $did_file" >&2; exit 1; }
active_did="$(python3 - "$did_file" <<'PY'
import json, sys
data = json.load(open(sys.argv[1], encoding="utf-8"))
value = data.get("id")
if not isinstance(value, str) or not value.startswith("did:integrity:"):
    raise SystemExit("DID document has no valid public id")
print(value)
PY
)"

echo "Active Shield DID: $active_did"
echo "Verifying DID against the local chain..."
verification="$(cd "$repo_root" && RPC_URL="$rpc_url" DEPLOYMENTS_FILE="$deployments_file" \
  INTEGRITY_DID_HOME="$did_root" \
  /home/xibalba/.local/bin/uv run --link-mode=copy python scripts/verify_oracle_registration.py 2>&1)" || {
  echo "$verification" >&2
  echo "DID verification failed; shield.env was not changed." >&2
  exit 1
}
printf '%s\n' "$verification" | grep -Fq '"did": "' || {
  echo "$verification" >&2
  echo "DID verification returned no registration record; shield.env was not changed." >&2
  exit 1
}
registered_did="$(printf '%s\n' "$verification" | python3 -c '
import json, sys
raw = sys.stdin.read()
decoder = json.JSONDecoder()
for index, char in enumerate(raw):
    if char != "{":
        continue
    try:
        data, _ = decoder.raw_decode(raw[index:])
    except json.JSONDecodeError:
        continue
    if isinstance(data, dict) and isinstance(data.get("did"), str):
        print(data["did"])
        break
else:
    raise SystemExit("registration output did not contain JSON DID")
')"
if [[ "$active_did" != "$registered_did" ]]; then
  echo "Active DID does not match registered DID." >&2
  echo "active:     $active_did" >&2
  echo "registered: $registered_did" >&2
  echo "shield.env was not changed." >&2
  exit 1
fi

[[ -f "$device_config" ]] || { echo "Shield device config not found: $device_config" >&2; exit 1; }
current_backend_url="$(python3 - "$device_config" <<'PY'
import json, sys
print(json.load(open(sys.argv[1], encoding="utf-8")).get("backend_url", ""))
PY
)"
if [[ "$current_backend_url" == "https://127.0.0.1:8443" || "$current_backend_url" == "https://localhost:8443" || "$current_backend_url" == "http://127.0.0.1:8421" ]]; then
  curl --fail --silent --show-error "$backend_health_url" >/dev/null || {
    echo "Expected local Shield backend is not healthy at $backend_health_url; device config was not changed." >&2
    exit 1
  }
  config_backup="${device_config}.before-local-backend-$(date -u +%Y%m%dT%H%M%SZ)"
  cp -p "$device_config" "$config_backup"
  python3 - "$device_config" <<'PY'
import json, os, stat, sys, tempfile
from pathlib import Path

path = Path(sys.argv[1])
st = path.stat()
data = json.loads(path.read_text(encoding="utf-8"))
data["backend_url"] = "http://127.0.0.1:8421"
data["backend_ca_file"] = ""
data["backend_client_cert"] = ""
data["backend_client_key"] = ""
fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
try:
    os.fchmod(fd, stat.S_IMODE(st.st_mode))
    os.fchown(fd, st.st_uid, st.st_gid)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, sort_keys=True)
        handle.write("\n")
    os.replace(tmp, path)
except Exception:
    Path(tmp).unlink(missing_ok=True)
    raise
PY
  echo "Updated backend_url to http://127.0.0.1:8421"
  echo "  Device config backup: $config_backup"
fi

[[ -f "$env_file" ]] || { echo "Shield environment file not found: $env_file" >&2; exit 1; }
backup="${env_file}.before-local-integrity-$(date -u +%Y%m%dT%H%M%SZ)"
cp -p "$env_file" "$backup"

tmp="$(mktemp)"
cleanup() { rm -f "$tmp"; }
trap cleanup EXIT

awk -v value="SHIELD_EXPORTER_ARGS=--agent-label xibalba-shield --bcc-middleware-url $bcc_url --oracle-url $oracle_url" '
  BEGIN { replaced=0 }
  /^SHIELD_EXPORTER_ARGS=/ {
    if (!replaced) { print value; replaced=1 }
    next
  }
  { print }
  END {
    if (!replaced) print value
  }
' "$env_file" > "$tmp"
chown --reference="$env_file" "$tmp"
chmod --reference="$env_file" "$tmp"
mv "$tmp" "$env_file"
trap - EXIT

systemctl daemon-reload
systemctl restart xibalba-shield.service
systemctl is-active --quiet xibalba-shield.service || {
  echo "Shield failed to become active; restoring previous environment." >&2
  cp -p "$backup" "$env_file"
  systemctl daemon-reload
  systemctl restart xibalba-shield.service || true
  exit 1
}

echo
echo "Local Integrity telemetry export enabled."
echo "  DID:      $active_did"
echo "  Oracle:   $oracle_url"
echo "  BCC:      $bcc_url"
echo "  Backup:   $backup"
echo "  Responders remain disabled; no readiness artifact was changed."
echo
systemctl --no-pager --full status xibalba-shield.service | sed -n '1,18p'
