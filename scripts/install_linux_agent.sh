#!/usr/bin/env bash
set -euo pipefail

PREFIX="${PREFIX:-/opt/xibalba-shield}"
SERVICE_DIR="${SERVICE_DIR:-/etc/systemd/system}"
CONFIG_DIR="${CONFIG_DIR:-/etc/xibalba-shield}"
POLICY_DIR="${POLICY_DIR:-${CONFIG_DIR}/policies}"
LOG_DIR="${LOG_DIR:-/var/log/xibalba-shield}"
STATE_DIR="${STATE_DIR:-/var/lib/xibalba-shield}"
PYTHON_BIN="${PYTHON_BIN:-python3}"
ENABLE_SERVICE="${ENABLE_SERVICE:-1}"

if [ "$(id -u)" -ne 0 ]; then
  printf 'install_linux_agent.sh must run as root so it can write systemd/config paths.\n' >&2
  exit 1
fi

command -v "$PYTHON_BIN" >/dev/null 2>&1 || {
  printf 'Python interpreter not found: %s\n' "$PYTHON_BIN" >&2
  exit 1
}

install -d -m 0755 "$PREFIX"
install -d -m 0750 "$CONFIG_DIR" "$POLICY_DIR" "$LOG_DIR" "$STATE_DIR"
"$PYTHON_BIN" -m pip install --upgrade .
install -m 0644 packaging/systemd/xibalba-shield.service "$SERVICE_DIR/xibalba-shield.service"
if [ ! -f "$CONFIG_DIR/shield.env" ]; then
  install -m 0600 packaging/systemd/shield.env.example "$CONFIG_DIR/shield.env"
fi
install -m 0600 packaging/systemd/shield.env.example "$CONFIG_DIR/shield.env.example"

if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload
  if [ "$ENABLE_SERVICE" = "1" ]; then
    systemctl enable xibalba-shield.service
  fi
fi

printf 'Installed xibalba-shield. Edit %s/device.json, %s/shield.env, and %s/current.json before starting xibalba-shield.service.\n' "$CONFIG_DIR" "$CONFIG_DIR" "$POLICY_DIR"
