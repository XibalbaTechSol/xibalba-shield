#!/usr/bin/env bash
set -euo pipefail

# Development-only end-to-end policy harness. Unlike verify_active_policy.sh, this
# sends safe fixture events through the actual Shield EventRouter, decision log, and
# authenticated backend evidence publisher so the dashboard can render the reasoning.
# It never attaches to a kernel sensor and never invokes a responder.

profile="${1:-smb}"
case "$profile" in
  smb|professional-services|regulated) ;;
  *) echo "Unknown profile: $profile" >&2; exit 2 ;;
esac
shield_bin="${SHIELD_BIN:-/opt/xibalba-shield/venv/bin/shield}"
case "$profile" in
  smb) default_fixture_count=5 ;;
  professional-services|regulated) default_fixture_count=4 ;;
esac

if [[ "$(id -u)" -eq 0 ]] && id xibalba-shield >/dev/null 2>&1 && command -v runuser >/dev/null 2>&1; then
  # Do not let sudo/root's Integrity key sign for the enrolled endpoint. The live
  # systemd agent owns the xibalba-shield identity, so fixtures must use that same
  # account or backend assertion authentication correctly fails with HTTP 401.
  exec runuser -u xibalba-shield -- env \
    SHIELD_ENV="${SHIELD_ENV:-development}" \
    SHIELD_BIN="$shield_bin" \
    SHIELD_DEVICE_CONFIG="${SHIELD_DEVICE_CONFIG:-/etc/xibalba-shield/device.json}" \
    SHIELD_POLICY_FILE="${SHIELD_POLICY_FILE:-/etc/xibalba-shield/policies/current.json}" \
    SHIELD_DECISION_LOG="${SHIELD_DECISION_LOG:-/var/log/xibalba-shield/decisions.jsonl}" \
    SHIELD_FIXTURE_EVENT_COUNT="${SHIELD_FIXTURE_EVENT_COUNT:-$default_fixture_count}" \
    "$shield_bin" --log-path "${SHIELD_DECISION_LOG:-/var/log/xibalba-shield/decisions.jsonl}" run \
    --sensor dev \
    --dev-scenario "$profile" \
    --dev-interval 0 \
    --max-events "${SHIELD_FIXTURE_EVENT_COUNT:-$default_fixture_count}" \
    --device-config "${SHIELD_DEVICE_CONFIG:-/etc/xibalba-shield/device.json}" \
    --rules "${SHIELD_POLICY_FILE:-/etc/xibalba-shield/policies/current.json}" \
    --no-containment \
    --no-exporter
fi
if [[ "${SHIELD_ENV:-}" != "development" ]]; then
  echo "Refusing to run outside SHIELD_ENV=development" >&2
  exit 1
fi

device_config="${SHIELD_DEVICE_CONFIG:-/etc/xibalba-shield/device.json}"
policy_file="${SHIELD_POLICY_FILE:-/etc/xibalba-shield/policies/current.json}"
log_path="${SHIELD_DECISION_LOG:-/var/log/xibalba-shield/decisions.jsonl}"

[[ -x "$shield_bin" ]] || { echo "Missing Shield binary: $shield_bin" >&2; exit 1; }
[[ -r "$device_config" ]] || { echo "Missing device config: $device_config" >&2; exit 1; }
[[ -r "$policy_file" ]] || { echo "Missing policy file: $policy_file" >&2; exit 1; }

echo "Running development-only live policy fixtures"
echo "  profile: $profile"
echo "  route:   DevModeSensor -> EventRouter -> policy -> decision log/backend"
echo "  safety:  no containment, no kill, no network changes"

exec "$shield_bin" --log-path "$log_path" run \
  --sensor dev \
  --dev-scenario "$profile" \
  --dev-interval 0 \
  --max-events "${SHIELD_FIXTURE_EVENT_COUNT:-$default_fixture_count}" \
  --device-config "$device_config" \
  --rules "$policy_file" \
  --no-containment \
  --no-exporter
