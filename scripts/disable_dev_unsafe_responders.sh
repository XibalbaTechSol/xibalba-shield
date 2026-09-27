#!/usr/bin/env bash
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run with sudo: sudo ./scripts/disable_dev_unsafe_responders.sh" >&2
  exit 1
fi

env_file="${SHIELD_ENV_FILE:-/etc/xibalba-shield/shield.env}"
service="${SHIELD_SERVICE:-xibalba-shield.service}"
dropin="/etc/systemd/system/${service}.d/dev-unsafe-responders.conf"
[[ -f "$env_file" ]] || { echo "Missing environment file: $env_file" >&2; exit 1; }

tmp="$(mktemp "${env_file}.tmp.XXXXXX")"
cleanup() { rm -f "$tmp"; }
trap cleanup EXIT
awk '!/^SHIELD_ENV=/ && !/^SHIELD_DEV_UNSAFE_RESPONDERS=/ && !/^SHIELD_RESPONDER_ARGS=/' "$env_file" > "$tmp"
install -m 0640 -o root -g root "$tmp" "$env_file"
rm -f "$dropin"
systemctl daemon-reload
systemctl restart "$service"
systemctl is-active --quiet "$service"
echo "Development-only unsafe responders disabled; production gates restored."
