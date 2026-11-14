#!/usr/bin/env bash
set -euo pipefail

# Register the existing Shield DID with the disposable local Oracle.
# Off-chain (gas-free): no wallet, funder key or contract deployment. Does not create a DID
# or replace keys, and does not target production.

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run with sudo: sudo ./scripts/register_active_did_local_oracle.sh" >&2
  exit 1
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
did_home="${INTEGRITY_DID_HOME:-/var/lib/xibalba-shield/integrity/did}"
oracle_url="${ORACLE_URL:-http://127.0.0.1:8080}"
agent_label="xibalba-shield"

need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing command: $1" >&2; exit 1; }; }
need curl
need python3
need systemctl

did_file="$did_home/$agent_label/document.json"
[[ -f "$did_file" ]] || { echo "Active DID document missing: $did_file" >&2; exit 1; }

active_did="$(python3 - "$did_file" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8")).get("id")
if not isinstance(value, str) or not value.startswith("did:integrity:"):
    raise SystemExit("active DID document has no valid DID")
print(value)
PY
)"
echo "Existing Shield DID: $active_did"

curl --fail --silent --show-error "$oracle_url/healthz" >/dev/null || {
  echo "Oracle is not healthy at $oracle_url/healthz" >&2
  exit 1
}

oracle_state="$(curl --fail --silent --show-error \
  "$oracle_url/v1/agent/$active_did" 2>/dev/null || true)"
if printf '%s' "$oracle_state" | grep -q '"oracle_registered"[[:space:]]*:[[:space:]]*true'; then
  echo "Oracle already recognizes this DID; no registration required."
  exit 0
fi

echo "Posting the existing DID registration to the local Oracle..."
cd "$repo_root"
ORACLE_URL="$oracle_url" \
INTEGRITY_DID_HOME="$did_home" \
/home/xibalba/.local/bin/uv run --link-mode=copy python scripts/register_with_oracle.py \
  --agent-id "$agent_label" \
  --oracle-url "$oracle_url"

echo
echo "Confirming Oracle registration..."
curl --fail --silent --show-error "$oracle_url/v1/agent/$active_did" | python3 -m json.tool

echo
echo "Restarting Shield so its exporter refreshes registration and flushes its bounded queue..."
systemctl restart xibalba-shield.service
systemctl is-active --quiet xibalba-shield.service
echo "Shield restarted and active. Responder actions remain disabled."
