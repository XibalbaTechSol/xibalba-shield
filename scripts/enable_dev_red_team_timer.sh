#!/usr/bin/env bash
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run with sudo: sudo ./scripts/enable_dev_red_team_timer.sh" >&2
  exit 1
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
unit_dir="/etc/systemd/system"

install -m 0644 "$repo_root/packaging/systemd/xibalba-shield-red-team.service" "$unit_dir/xibalba-shield-red-team.service"
install -m 0644 "$repo_root/packaging/systemd/xibalba-shield-red-team.timer" "$unit_dir/xibalba-shield-red-team.timer"
install -d -m 0750 -o root -g xibalba-shield "$repo_root/artifacts"

systemctl daemon-reload
systemctl enable --now xibalba-shield-red-team.timer
systemctl start xibalba-shield-red-team.service

echo "Development red-team timer enabled."
echo "  cadence: every 15 minutes"
echo "  profile: smb"
echo "  report:  $repo_root/artifacts/safe-red-team-report.json"
echo "  stop:    sudo ./scripts/disable_dev_red_team_timer.sh"
systemctl --no-pager --full status xibalba-shield-red-team.timer || true
