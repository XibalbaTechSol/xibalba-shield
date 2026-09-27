#!/usr/bin/env bash
set -euo pipefail

# Explicit local development override. This bypasses proof gates only when the
# service is marked development; it never changes the default production path.

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run with sudo: sudo ./scripts/enable_dev_unsafe_responders.sh" >&2
  exit 1
fi

env_file="${SHIELD_ENV_FILE:-/etc/xibalba-shield/shield.env}"
service="${SHIELD_SERVICE:-xibalba-shield.service}"
dropin_dir="/etc/systemd/system/${service}.d"
dropin="$dropin_dir/dev-unsafe-responders.conf"
[[ -f "$env_file" ]] || { echo "Missing environment file: $env_file" >&2; exit 1; }

backup="${env_file}.before-dev-unsafe-$(date -u +%Y%m%dT%H%M%SZ)"
cp -p "$env_file" "$backup"

tmp="$(mktemp "${env_file}.tmp.XXXXXX")"
cleanup() { rm -f "$tmp"; }
trap cleanup EXIT

awk '
  !/^SHIELD_ENV=/ &&
  !/^SHIELD_DEV_UNSAFE_RESPONDERS=/ &&
  !/^SHIELD_RESPONDER_ARGS=/ { print }
  END {
    print "SHIELD_ENV=development"
    print "SHIELD_DEV_UNSAFE_RESPONDERS=true"
    print "SHIELD_RESPONDER_ARGS=--enable-kill-process --enable-freeze-cgroup --enable-block-flow"
  }
' "$env_file" > "$tmp"
install -m 0640 -o root -g root "$tmp" "$env_file"

# Older installed units may only bound CAP_KILL. The development override also
# needs CAP_NET_ADMIN for its explicitly requested nftables path. This drop-in
# is removed by the disable script; it is never part of the normal unit.
install -d -m 0755 "$dropin_dir"
cat > "$dropin" <<'EOF'
[Service]
CapabilityBoundingSet=CAP_KILL CAP_NET_ADMIN
AmbientCapabilities=CAP_KILL CAP_NET_ADMIN
Delegate=yes
EOF
chmod 0644 "$dropin"

systemctl daemon-reload
systemctl restart "$service"
systemctl is-active --quiet "$service"
echo "Development-only unsafe responders enabled for $service."
echo "Backup: $backup"
echo "WARNING: kill and network actions are now available to Shield policy decisions."
echo "Disable with: sudo ./scripts/disable_dev_unsafe_responders.sh"
