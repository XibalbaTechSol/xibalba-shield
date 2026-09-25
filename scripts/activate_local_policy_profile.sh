#!/usr/bin/env bash
set -euo pipefail

# Explicit local-lab policy activation. This is for the disposable local Shield
# environment only; it does not claim tenant-control-plane deployment.

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run with sudo: sudo ./scripts/activate_local_policy_profile.sh professional-services" >&2
  exit 1
fi

profile="${1:-}"
case "$profile" in
  smb|professional-services|regulated) ;;
  *)
    echo "Usage: sudo ./scripts/activate_local_policy_profile.sh {smb|professional-services|regulated}" >&2
    exit 2
    ;;
esac

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source_policy="$repo_root/policies/defaults/$profile.json"
destination="${SHIELD_POLICY_FILE:-/etc/xibalba-shield/policies/current.json}"
shield_bin="${SHIELD_BIN:-/opt/xibalba-shield/venv/bin/shield}"
service="${SHIELD_SERVICE:-xibalba-shield.service}"
policy_group="${SHIELD_POLICY_GROUP:-xibalba-shield}"

[[ -f "$source_policy" ]] || { echo "Missing source policy: $source_policy" >&2; exit 1; }
[[ -x "$shield_bin" ]] || { echo "Missing Shield binary: $shield_bin" >&2; exit 1; }
install -d -m 0750 "$(dirname "$destination")"

staged="$(mktemp "$(dirname "$destination")/.current.json.staged.XXXXXX")"
cleanup() { rm -f "$staged"; }
trap cleanup EXIT

install -m 0640 "$source_policy" "$staged"
"$shield_bin" validate --rules "$staged"

if [[ -f "$destination" ]]; then
  backup="${destination}.before-profile-$(date -u +%Y%m%dT%H%M%SZ)"
  cp -p "$destination" "$backup"
  echo "Backup: $backup"
fi

if getent group "$policy_group" >/dev/null 2>&1; then
  install -m 0640 -o root -g "$policy_group" "$staged" "$destination"
else
  echo "Missing policy reader group: $policy_group" >&2
  exit 1
fi
echo "Activated local profile: $profile"
echo "Policy: $destination"

if command -v systemctl >/dev/null 2>&1; then
  systemctl reload-or-restart "$service"
  systemctl is-active --quiet "$service"
fi

echo "PASS local policy profile is installed and Shield is active"
