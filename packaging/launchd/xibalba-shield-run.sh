#!/usr/bin/env bash
set -euo pipefail

# Configuration directories on macOS
CONFIG_DIR="${SHIELD_CONFIG_DIR:-/etc/xibalba-shield}"
LOG_DIR="${SHIELD_DATA_DIR:-/var/log/xibalba-shield}"

mkdir -p "$LOG_DIR" "$CONFIG_DIR"

# Source environment variables if present
if [[ -f "$CONFIG_DIR/shield.env" ]]; then
  # shellcheck source=/dev/null
  source "$CONFIG_DIR/shield.env"
fi

# Fallback sensor on macOS: if no eBPF is available, use semantic guardrails / dev sensor
SENSOR="${SHIELD_SENSOR:-dev}"

args=(
  --log-path "$LOG_DIR/decisions.jsonl"
  run
  --sensor "$SENSOR"
  --opa-url "${SHIELD_OPA_URL:-http://127.0.0.1:8181}"
)

if [[ -f "$CONFIG_DIR/device.json" ]]; then
  args+=(--device-config "$CONFIG_DIR/device.json")
fi

if [[ -f "$CONFIG_DIR/policies/current.json" ]]; then
  args+=(--rules "$CONFIG_DIR/policies/current.json")
fi

if [[ -n "${SHIELD_EXPORTER_ARGS:-}" ]]; then
  read -r -a exporter_args <<<"$SHIELD_EXPORTER_ARGS"
  args+=("${exporter_args[@]}")
fi

SHIELD_BIN="$(command -v shield || echo "/usr/local/bin/shield")"
exec "$SHIELD_BIN" "${args[@]}"
