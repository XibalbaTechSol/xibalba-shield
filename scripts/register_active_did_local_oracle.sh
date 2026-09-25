#!/usr/bin/env bash
set -euo pipefail

# Register the existing Shield DID with the disposable local Oracle.
# This does not create a DID, replace keys, deploy a new agent, or target production.

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run with sudo: sudo ./scripts/register_active_did_local_oracle.sh" >&2
  exit 1
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
core_root="${INTEGRITY_CORE_ROOT:-/home/xibalba/Projects/integrity-core}"
did_home="${INTEGRITY_DID_HOME:-/var/lib/xibalba-shield/integrity/did}"
wallet_home="${INTEGRITY_WALLET_HOME:-/home/xibalba/.integrity/wallet}"
password_file="${INTEGRITY_WALLET_PASSWORD_FILE:-/home/xibalba/.integrity/secrets/xibalba-shield-wallet-password.txt}"
rpc_url="${RPC_URL:-http://127.0.0.1:8545}"
oracle_url="${ORACLE_URL:-http://127.0.0.1:8080}"
deployments_file="${DEPLOYMENTS_FILE:-$core_root/deployments.local.json}"
agent_label="xibalba-shield"

need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing command: $1" >&2; exit 1; }; }
need curl
need python3
need systemctl

did_file="$did_home/$agent_label/document.json"
keystore_file="$wallet_home/$agent_label/keystore.json"
[[ -f "$did_file" ]] || { echo "Active DID document missing: $did_file" >&2; exit 1; }
[[ -f "$keystore_file" ]] || { echo "Existing wallet missing: $keystore_file; refusing to create one." >&2; exit 1; }
[[ -f "$deployments_file" ]] || { echo "Deployments file missing: $deployments_file" >&2; exit 1; }

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

[[ -f "$core_root/.env" ]] || { echo "Integrity .env missing: $core_root/.env" >&2; exit 1; }
provided_wallet_password="${INTEGRITY_WALLET_PASSWORD:-}"
set -a
# shellcheck disable=SC1091
. "$core_root/.env"
set +a
if [[ -z "${ORACLE_SIGNER_PRIVATE_KEY:-}" ]]; then
  echo "ORACLE_SIGNER_PRIVATE_KEY is not set in $core_root/.env" >&2
  exit 1
fi
if [[ -n "$provided_wallet_password" ]]; then
  INTEGRITY_WALLET_PASSWORD="$provided_wallet_password"
elif [[ -f "$password_file" ]]; then
  # Prefer the dedicated Shield wallet secret over any generic .env value.
  INTEGRITY_WALLET_PASSWORD="$(< "$password_file")"
elif [[ -z "${INTEGRITY_WALLET_PASSWORD:-}" ]]; then
  echo "Wallet password file missing: $password_file" >&2
  echo "Set INTEGRITY_WALLET_PASSWORD in the environment without printing it." >&2
  exit 1
fi

echo "Posting the existing DID registration to the local Oracle..."
cd "$repo_root"
RPC_URL="$rpc_url" \
ORACLE_URL="$oracle_url" \
DEPLOYMENTS_FILE="$deployments_file" \
INTEGRITY_DID_HOME="$did_home" \
INTEGRITY_WALLET_HOME="$wallet_home" \
INTEGRITY_WALLET_PASSWORD="$INTEGRITY_WALLET_PASSWORD" \
FUNDER_PRIVATE_KEY="$ORACLE_SIGNER_PRIVATE_KEY" \
/home/xibalba/.local/bin/uv run --link-mode=copy python scripts/register_with_oracle.py \
  --agent-id "$agent_label" \
  --rpc-url "$rpc_url" \
  --oracle-url "$oracle_url" \
  --deployments-file "$deployments_file"

echo
echo "Confirming Oracle registration..."
curl --fail --silent --show-error "$oracle_url/v1/agent/$active_did" | python3 -m json.tool

echo
echo "Restarting Shield so its exporter refreshes registration and flushes its bounded queue..."
systemctl restart xibalba-shield.service
systemctl is-active --quiet xibalba-shield.service
echo "Shield restarted and active. Responder actions remain disabled."
