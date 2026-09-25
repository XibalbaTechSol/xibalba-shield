#!/usr/bin/env bash
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run with sudo: sudo bash scripts/enable_aggressive_red_team_burst.sh" >&2
  exit 1
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
unit_dir="/etc/systemd/system"
install -m 0644 "$repo_root/packaging/systemd/xibalba-shield-red-team-aggressive.service" "$unit_dir/xibalba-shield-red-team-aggressive.service"
install -m 0644 "$repo_root/packaging/systemd/xibalba-shield-red-team-aggressive.timer" "$unit_dir/xibalba-shield-red-team-aggressive.timer"
install -d -m 0750 -o root -g xibalba-shield "$repo_root/artifacts"
systemctl daemon-reload
systemctl enable --now xibalba-shield-red-team-aggressive.timer
echo "Aggressive bounded burst armed: 50 iterations per profile (350 fixture events), then automatic timer shutdown."
echo "Start immediately with: sudo systemctl start xibalba-shield-red-team-aggressive.service"
