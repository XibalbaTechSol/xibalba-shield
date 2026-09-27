#!/usr/bin/env bash
set -euo pipefail

# Configure the installed local Integrity runtime: Base Sepolia, BCC on 8000,
# Shield backend on 8435, and observation-only BCC behavior.

[[ "$(id -u)" -eq 0 ]] || { echo "Run with sudo: sudo $0" >&2; exit 1; }
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
core_root="${INTEGRITY_CORE_ROOT:-/home/xibalba/Projects/integrity-core}"
rpc_url="${RPC_URL:-https://sepolia.base.org}"
oracle_url="${ORACLE_URL:-http://127.0.0.1:8080}"
bcc_url="${BCC_MIDDLEWARE_URL:-http://127.0.0.1:8000}"
backend_url="${SHIELD_BACKEND_URL:-http://127.0.0.1:8435}"
deployments_file="${DEPLOYMENTS_FILE:-$core_root/deployments.baseSepolia.json}"
device_config="${SHIELD_DEVICE_CONFIG:-/etc/xibalba-shield/device.json}"
shield_env="${SHIELD_ENV_FILE:-/etc/xibalba-shield/shield.env}"
shield_service="${SHIELD_SERVICE:-xibalba-shield.service}"
bcc_service="${BCC_SERVICE:-bcc-middleware.service}"
user_bcc_service="${BCC_USER_SERVICE:-xibalba-bcc-middleware.service}"
service_user="${BCC_SERVICE_USER:-${SUDO_USER:-xibalba}}"
compose_root="${BCC_COMPOSE_ROOT:-$core_root}"
compose_service="${BCC_COMPOSE_SERVICE:-bcc-middleware}"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"

[[ -f "$device_config" && -f "$shield_env" && -f "$deployments_file" ]] || { echo "Required runtime file is missing" >&2; exit 1; }
health() { local code; code="$(curl --connect-timeout 3 --max-time 8 --silent --output /dev/null --write-out '%{http_code}' "$2" || true)"; [[ "$code" == 200 ]] || { echo "$1 unavailable (HTTP ${code:-000}): $2" >&2; exit 1; }; echo "PASS $1"; }
wait_health() {
  local label="$1" url="$2" attempts="${3:-12}" code=""
  for ((i=1; i<=attempts; i++)); do
    code="$(curl --connect-timeout 3 --max-time 8 --silent --output /dev/null --write-out '%{http_code}' "$url" || true)"
    if [[ "$code" == 200 ]]; then echo "PASS $label"; return 0; fi
    sleep 1
  done
  echo "$label unavailable after ${attempts}s (HTTP ${code:-000}): $url" >&2
  return 1
}
health "Oracle health" "$oracle_url/healthz"
health "BCC health" "$bcc_url/health"
health "Shield backend health" "$backend_url/api/shield/health"

did_file="${INTEGRITY_DID_HOME:-/var/lib/xibalba-shield/integrity/did}/xibalba-shield/document.json"
[[ -f "$did_file" ]] || { echo "Missing active DID: $did_file" >&2; exit 1; }
did_root="$(dirname "$(dirname "$did_file")")"
(cd "$repo_root" && RPC_URL="$rpc_url" ORACLE_URL="$oracle_url" DEPLOYMENTS_FILE="$deployments_file" INTEGRITY_DID_HOME="$did_root" /home/xibalba/.local/bin/uv run --link-mode=copy python scripts/verify_oracle_registration.py)

bcc_mode=""
user_runtime_dir="/run/user/$(id -u "$service_user")"
user_home="$(getent passwd "$service_user" | cut -d: -f6)"
user_systemctl() { runuser -u "$service_user" -- env XDG_RUNTIME_DIR="$user_runtime_dir" systemctl --user "$@"; }
if systemctl cat "$bcc_service" >/dev/null 2>&1; then
  bcc_mode="systemd"
elif [[ -n "$user_home" ]] && user_systemctl cat "$user_bcc_service" >/dev/null 2>&1; then
  bcc_mode="user-systemd"
elif command -v docker >/dev/null 2>&1 && [[ -f "$compose_root/docker-compose.yml" ]] && \
  (cd "$compose_root" && docker compose config --services 2>/dev/null | grep -Fxq "$compose_service"); then
  bcc_mode="compose"
else
  echo "BCC runtime not found: no systemd unit, user unit, or Docker Compose service matched" >&2
  echo "Set BCC_SERVICE, BCC_USER_SERVICE, or BCC_COMPOSE_ROOT if the runtime is non-standard." >&2
  systemctl list-unit-files --type=service --no-legend | awk 'tolower($1)~/bcc|integrity/{print "candidate systemd unit: "$1}' >&2 || true
  exit 1
fi
echo "PASS BCC runtime detected: $bcc_mode"

cp -p "$device_config" "$device_config.before-integrity-runtime-$stamp"
python3 -c 'import json,sys; from pathlib import Path; p=Path(sys.argv[1]); d=json.loads(p.read_text()); d.update(backend_url=sys.argv[2],backend_ca_file="",backend_client_cert="",backend_client_key=""); p.write_text(json.dumps(d,indent=2,sort_keys=True)+"\n")' "$device_config" "$backend_url"
cp -p "$shield_env" "$shield_env.before-integrity-runtime-$stamp"
tmp="$(mktemp)"; trap 'rm -f "$tmp"' EXIT
awk -v value="SHIELD_EXPORTER_ARGS=--agent-label xibalba-shield --bcc-middleware-url $bcc_url --oracle-url $oracle_url" 'BEGIN{done=0} /^SHIELD_EXPORTER_ARGS=/{if(!done)print value;done=1;next} {print} END{if(!done)print value}' "$shield_env" > "$tmp"
chown --reference="$shield_env" "$tmp"; chmod --reference="$shield_env" "$tmp"; mv "$tmp" "$shield_env"; trap - EXIT

if [[ "$bcc_mode" == systemd ]]; then
  dropin_dir="/etc/systemd/system/${bcc_service}.d"; dropin="$dropin_dir/observation.conf"; install -d -m 0755 "$dropin_dir"
  [[ -f "$dropin" ]] && cp -p "$dropin" "$dropin.before-integrity-runtime-$stamp"
  printf '[Service]\nEnvironment=BCC_SHADOW_MODE=true\n' > "$dropin"
  systemctl daemon-reload
  systemctl restart "$bcc_service"
elif [[ "$bcc_mode" == user-systemd ]]; then
  dropin_dir="$user_home/.config/systemd/user/${user_bcc_service}.d"; dropin="$dropin_dir/observation.conf"; install -d -o "$service_user" -g "$(id -gn "$service_user")" -m 0755 "$dropin_dir"
  [[ -f "$dropin" ]] && cp -p "$dropin" "$dropin.before-integrity-runtime-$stamp"
  printf '[Service]\nEnvironment=BCC_SHADOW_MODE=true\n' > "$dropin"
  chown "$service_user:$(id -gn "$service_user")" "$dropin"
  user_systemctl daemon-reload
  user_systemctl restart "$user_bcc_service"
else
  (cd "$compose_root" && BCC_SHADOW_MODE=true docker compose up -d --force-recreate "$compose_service")
fi
systemctl restart "$shield_service"
wait_health "BCC health after restart" "$bcc_url/health"
mode="$(curl --silent "$bcc_url/health" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("mode",""))')"
[[ "$mode" == shadow ]] || { echo "BCC mode is $mode, expected shadow" >&2; exit 1; }
if [[ "$bcc_mode" == systemd ]]; then
  systemctl is-active --quiet "$bcc_service"
elif [[ "$bcc_mode" == user-systemd ]]; then
  user_systemctl is-active --quiet "$user_bcc_service"
else
  (cd "$compose_root" && docker compose ps --status running --services | grep -Fxq "$compose_service")
fi
systemctl is-active --quiet "$shield_service"
echo "PASS observation mode and Shield services are active"
