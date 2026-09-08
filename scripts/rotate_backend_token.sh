#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="/etc/xibalba-shield/backend.env"
TMP_FILE="$(mktemp)"
trap 'rm -f "$TMP_FILE"' EXIT

umask 077
token="$(openssl rand -hex 32)"
printf 'SHIELD_BACKEND_TOKEN=%s\n' "$token" > "$TMP_FILE"

sudo install -o root -g root -m 0600 "$TMP_FILE" "$ENV_FILE"
sudo systemctl restart xibalba-shield-backend.service

if ! systemctl is-active --quiet xibalba-shield-backend.service; then
  echo "backend failed after token rotation" >&2
  exit 1
fi

echo "Global backend token rotated and stored in $ENV_FILE (not printed). Existing tenant-scoped sessions remain valid until explicitly revoked."
echo "Read it only when signing in: sudo cat $ENV_FILE"
