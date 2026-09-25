#!/usr/bin/env bash
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "run as root: sudo $0" >&2
  exit 1
fi

repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
service_dir=${SERVICE_DIR:-/etc/systemd/system}
logrotate_dir=${LOGROTATE_DIR:-/etc/logrotate.d}

install -d -m 0755 "$service_dir" "$logrotate_dir"
install -m 0644 "$repo_dir/packaging/systemd/xibalba-shield.service" \
  "$service_dir/xibalba-shield.service"
install -m 0644 "$repo_dir/packaging/systemd/xibalba-shield-ebpf-helper.service" \
  "$service_dir/xibalba-shield-ebpf-helper.service"
install -m 0644 "$repo_dir/packaging/logrotate/xibalba-shield" \
  "$logrotate_dir/xibalba-shield"

systemctl daemon-reload
systemctl restart xibalba-shield-ebpf-helper.service
systemctl restart xibalba-shield.service

"$repo_dir/scripts/verify_resource_controls.sh"
