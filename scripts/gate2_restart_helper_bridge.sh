#!/usr/bin/env bash
set -euo pipefail

# Gate 2: recover only the privileged eBPF helper bridge after direct BPF
# verification has passed but the service-owned Unix socket is absent.
# This script does not restart Shield, alter environment files, or touch any
# queue, database, WAL, identity, credential, or log file.

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run with sudo: sudo $0" >&2
  exit 1
fi

unit='xibalba-shield-ebpf-helper.service'
socket_path='/run/xibalba-shield/ebpf.sock'

echo "Before: $(systemctl show "$unit" -p MainPID -p ActiveState -p SubState --value | paste -sd ' ' -)"
if [[ -S "$socket_path" ]]; then
  echo "Before socket: present $socket_path"
else
  echo "Before socket: missing $socket_path"
fi

echo "Restarting only $unit"
systemctl restart "$unit"

deadline=$((SECONDS + 20))
while (( SECONDS < deadline )); do
  if [[ "$(systemctl is-active "$unit" 2>/dev/null || true)" == 'active' ]] && [[ -S "$socket_path" ]]; then
    pid="$(systemctl show "$unit" -p MainPID --value)"
    echo "PASS helper active PID=$pid"
    stat -c 'socket=%n mode=%a owner=%U group=%G inode=%i' "$socket_path"
    echo "Shield was not restarted"
    exit 0
  fi
  sleep 0.5
done

echo "FAIL helper did not expose $socket_path within 20 seconds" >&2
systemctl status "$unit" --no-pager --full >&2 || true
journalctl -u "$unit" --since '2 minutes ago' --no-pager | tail -80 >&2 || true
exit 2
