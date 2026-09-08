#!/usr/bin/env bash
set -euo pipefail

tenant_id="${1:-tenant-a}"
env_file="/etc/xibalba-shield/backend.env"
output_file="${2:-$HOME/.xibalba-shield/${tenant_id}-admin-token}"

global_token="$(sudo awk -F= '$1 == "SHIELD_BACKEND_TOKEN" {print substr($0, index($0, "=") + 1)}' "$env_file")"
if [[ -z "$global_token" ]]; then
  echo "global backend token is unavailable" >&2
  exit 1
fi

response="$(curl -fsS -X POST 'http://127.0.0.1:8421/api/shield/admin-tokens' \
  -H "Authorization: Bearer $global_token" \
  -H 'Content-Type: application/json' \
  --data "{\"tenant_id\":\"$tenant_id\"}")"
unset global_token

token="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["admin_token"])' <<<"$response")"
if [[ -z "$token" ]]; then
  echo "backend did not return a tenant token" >&2
  exit 1
fi

umask 077
mkdir -p "$(dirname "$output_file")"
printf '%s\n' "$token" > "$output_file"
chmod 0600 "$output_file"
unset token response

echo "Tenant token rotated for $tenant_id and stored at $output_file (not printed)."
