#!/usr/bin/env bash
set -euo pipefail

# Read-only deployment-boundary check. It never starts, stops, or kills a backend.
unit="${1:-xibalba-shield-backend.service}"
port="${2:-8421}"

active_state="$(systemctl show "$unit" -p ActiveState --value 2>/dev/null || true)"
main_pid="$(systemctl show "$unit" -p MainPID --value 2>/dev/null || true)"
echo "unit=$unit active_state=${active_state:-unknown} main_pid=${main_pid:-unknown}"

mapfile -t listeners < <(ss -lntp 2>/dev/null | awk -v port=":$port" '$4 ~ port {print}')
if ((${#listeners[@]} == 0)); then
  echo "port=$port listener=none"
  exit 0
fi

printf '%s\n' "${listeners[@]}"
if [[ "$active_state" != "active" || ! "$main_pid" =~ ^[1-9][0-9]*$ ]]; then
  echo "DRIFT backend port $port is occupied while $unit is not active; no mutation performed" >&2
  exit 2
fi
if ! printf '%s\n' "${listeners[@]}" | grep -q "pid=$main_pid,"; then
  echo "DRIFT backend port $port is not owned by $unit MainPID=$main_pid; no mutation performed" >&2
  exit 3
fi
echo "PASS backend service owns port $port"
