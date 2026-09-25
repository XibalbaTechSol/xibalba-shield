#!/usr/bin/env bash
set -euo pipefail

# Gate 2: route the existing Shield outbox worker to the Shield profile-local
# Cortex API. Run from this checkout as:
#   sudo ./scripts/gate2_route_outbox_to_shield_profile.sh
#
# This changes only XIBALBA_CORTEX_URL in the installed cortex.env and restarts
# only the outbox worker. It does not read, print, replace, or generate tokens;
# it does not mutate the outbox database or any Cortex store.

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run with sudo: sudo $0" >&2
  exit 1
fi

unit="xibalba-shield-cortex-outbox.service"
env_file="/etc/xibalba-shield/cortex.env"
old_url="http://127.0.0.1:8420"
new_url="http://127.0.0.1:8423"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
backup="/etc/xibalba-shield/cortex.env.gate2-backup-${stamp}"

[[ -r "$env_file" && -w "$env_file" ]] || {
  echo "Cannot safely access installed environment file: $env_file" >&2
  exit 2
}

match_count="$(grep -oF -- "$old_url" "$env_file" | wc -l)"
if [[ "$match_count" -ne 1 ]]; then
  echo "Refusing: expected exactly one Cortex URL $old_url, found $match_count" >&2
  exit 3
fi

cp --preserve=mode,ownership,timestamps "$env_file" "$backup"
chmod 600 "$backup"

python3 - "$env_file" "$old_url" "$new_url" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
old = sys.argv[2]
new = sys.argv[3]
text = path.read_text(encoding="utf-8")
if text.count(old) != 1:
    raise SystemExit(f"expected one exact route in {path}")
path.write_text(text.replace(old, new), encoding="utf-8")
PY

if ! grep -qF -- "$new_url" "$env_file" || grep -qF -- "$old_url" "$env_file"; then
  cp --preserve=mode,ownership,timestamps "$backup" "$env_file"
  echo "Refusing: route verification failed; restored $env_file from $backup" >&2
  exit 4
fi

echo "Backed up installed Cortex environment to: $backup"
echo "Changed only Shield outbox destination: $old_url -> $new_url"

systemctl restart "$unit"
main_pid=""
for _ in {1..30}; do
  if systemctl is-active --quiet "$unit"; then
    candidate="$(systemctl show -p MainPID --value "$unit")"
    if [[ "$candidate" =~ ^[1-9][0-9]*$ ]] && [[ -r "/proc/$candidate/environ" ]]; then
      route="$(tr '\0' '\n' < "/proc/$candidate/environ" | sed -n 's/^XIBALBA_CORTEX_URL=//p' | head -1)"
      if [[ "$route" == "$new_url" ]]; then
        main_pid="$candidate"
        break
      fi
    fi
  fi
  sleep 1
done

if [[ -z "$main_pid" ]]; then
  echo "Refusing: outbox worker did not adopt $new_url within 30 seconds; restoring $env_file" >&2
  cp --preserve=mode,ownership,timestamps "$backup" "$env_file"
  systemctl restart "$unit" || true
  exit 5
fi

health_status="$(curl --silent --show-error --max-time 5 -o /dev/null -w '%{http_code}' http://127.0.0.1:8423/health || true)"
case "$health_status" in
  200|401)
    echo "PASS profile-local Cortex listener reachable at $new_url/health (HTTP $health_status; auth boundary preserved)"
    ;;
  *)
    echo "Refusing: unexpected profile-local Cortex health status HTTP $health_status" >&2
    exit 6
    ;;
esac
echo "PASS outbox worker PID $main_pid is using $new_url"
echo "NOTE bearer-token authorization and event persistence still require the disposable Gate 2 event validation"
