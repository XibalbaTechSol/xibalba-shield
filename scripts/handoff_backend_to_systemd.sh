#!/usr/bin/env bash
set -euo pipefail

# Controlled handoff from the known unmanaged local Shield backend to systemd.
# Default mode is read-only. --takeover is an explicit operator authorization.
unit="${SHIELD_BACKEND_UNIT:-xibalba-shield-backend.service}"
port="${SHIELD_BACKEND_PORT:-8421}"
takeover="false"
if [[ "${1:-}" == "--takeover" ]]; then takeover="true"; fi

active_state="$(systemctl show "$unit" -p ActiveState --value 2>/dev/null || true)"
if [[ "$active_state" == "active" ]]; then
  echo "$unit is already active; no handoff required"
  exit 0
fi

listener_line="$(ss -lntp 2>/dev/null | awk -v port=":$port" '$4 ~ port {print; exit}')"
if [[ -z "$listener_line" ]]; then
  if [[ "$takeover" != "true" ]]; then
    echo "DRY RUN: no listener found on port $port; refusing to start $unit" >&2
    echo "Re-run with --takeover to start the managed backend" >&2
    exit 4
  fi
  echo "No listener on port $port; starting $unit"
  systemctl start "$unit"
else
  listener_pid="$(sed -n 's/.*pid=\([0-9][0-9]*\),.*/\1/p' <<<"$listener_line")"
  if [[ -z "$listener_pid" ]]; then
    echo "Unable to identify the port-$port listener; refusing handoff" >&2
    exit 2
  fi
  command_line="$(tr '\0' ' ' </proc/$listener_pid/cmdline 2>/dev/null || true)"
  if [[ "$command_line" != *"-m shield.backend.api"* || "$command_line" != *"--port $port"* ]]; then
    echo "Port $port is owned by an unexpected process; refusing handoff" >&2
    exit 3
  fi
  if [[ "$takeover" != "true" ]]; then
    echo "DRY RUN: verified Shield backend PID $listener_pid on port $port" >&2
    echo "Re-run with --takeover to stop it gracefully and start $unit" >&2
    exit 4
  fi
  echo "Stopping verified Shield backend PID $listener_pid gracefully"
  kill -TERM "$listener_pid"
  for _ in {1..30}; do
    if ! kill -0 "$listener_pid" 2>/dev/null; then break; fi
    sleep 0.5
  done
  if kill -0 "$listener_pid" 2>/dev/null; then
    echo "Backend did not exit within 15 seconds; refusing SIGKILL" >&2
    exit 5
  fi
  systemctl start "$unit"
fi

if ! systemctl is-active --quiet "$unit"; then
  echo "$unit did not become active" >&2
  exit 6
fi

# systemd can report the unit active before Python has bound the socket.
# Give the managed backend a bounded readiness window instead of treating the
# first connection refusal as a failed takeover.
healthy="false"
for _ in {1..30}; do
  if curl --fail --silent --show-error --max-time 2 "http://127.0.0.1:$port/api/shield/health" >/dev/null 2>&1; then
    healthy="true"
    break
  fi
  sleep 0.5
done
if [[ "$healthy" != "true" ]]; then
  echo "$unit is active but health check failed after 15 seconds" >&2
  systemctl --no-pager --full status "$unit" | sed -n '1,24p' >&2 || true
  exit 7
fi
echo "PASS $unit owns a healthy backend on port $port"
