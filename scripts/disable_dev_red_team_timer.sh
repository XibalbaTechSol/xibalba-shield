#!/usr/bin/env bash
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run with sudo: sudo ./scripts/disable_dev_red_team_timer.sh" >&2
  exit 1
fi

systemctl disable --now xibalba-shield-red-team.timer 2>/dev/null || true
systemctl reset-failed xibalba-shield-red-team.service 2>/dev/null || true
echo "Development red-team timer disabled. Existing reports and audit records were preserved."
