#!/usr/bin/env bash
set -euo pipefail

# Read-only deployment-boundary check. It never starts, stops, or kills a backend.
unit="${1:-xibalba-shield-backend.service}"
port="${2:-8435}"

systemctl_args=()
user_active_state="$(systemctl --user show "$unit" -p ActiveState --value 2>/dev/null || true)"
user_main_pid="$(systemctl --user show "$unit" -p MainPID --value 2>/dev/null || true)"
if [[ "$user_active_state" == "active" && "$user_main_pid" =~ ^[1-9][0-9]*$ ]]; then
  systemctl_args=(--user)
fi
active_state="$(systemctl "${systemctl_args[@]}" show "$unit" -p ActiveState --value 2>/dev/null || true)"
main_pid="$(systemctl "${systemctl_args[@]}" show "$unit" -p MainPID --value 2>/dev/null || true)"
scope="system"
if ((${#systemctl_args[@]})); then scope="user"; fi
echo "unit=$unit scope=$scope active_state=${active_state:-unknown} main_pid=${main_pid:-unknown}"

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
