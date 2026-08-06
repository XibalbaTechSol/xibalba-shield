#!/usr/bin/env bash
set -euo pipefail

DEVICE_CONFIG="${1:?usage: update_policy_bundle.sh DEVICE_CONFIG DESTINATION}"
DESTINATION="${2:?usage: update_policy_bundle.sh DEVICE_CONFIG DESTINATION}"
DEST_DIR="$(dirname "$DESTINATION")"
DEST_BASE="$(basename "$DESTINATION")"
install -d -m 0750 "$DEST_DIR"
STAGED="$(mktemp "${DEST_DIR}/.${DEST_BASE}.staged.XXXXXX")"

cleanup() {
  rm -f "$STAGED"
}
trap cleanup EXIT

shield fetch-policy --device-config "$DEVICE_CONFIG" --output "$STAGED"
shield validate --rules "$STAGED" --device-config "$DEVICE_CONFIG"

if [ -f "$DESTINATION" ]; then
  cp -p "$DESTINATION" "${DESTINATION}.previous"
fi
install -m 0640 "$STAGED" "$DESTINATION"

if command -v systemctl >/dev/null 2>&1; then
  systemctl reload-or-restart xibalba-shield.service
fi
