#!/usr/bin/env bash
set -euo pipefail

# Gate 2: securely provision the already-authorized Shield profile Cortex token.
# Run as:
#   sudo ./scripts/gate2_provision_profile_token.sh
#
# The token is read from the controlling terminal, never echoed, printed, or
# placed in a command argument. This changes only XIBALBA_CORTEX_TOKEN in the
# installed outbox environment and restarts only the outbox worker.

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run with sudo: sudo $0" >&2
  exit 1
fi

unit="xibalba-shield-cortex-outbox.service"
env_file="/etc/xibalba-shield/cortex.env"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
backup="/etc/xibalba-shield/cortex.env.gate2-token-backup-${stamp}"
tmp="$(mktemp /etc/xibalba-shield/cortex.env.gate2-token.XXXXXX)"
trap 'rm -f "$tmp"' EXIT

[[ -r "$env_file" && -w "$env_file" ]] || {
  echo "Cannot safely access installed environment file: $env_file" >&2
  exit 2
}

if [[ ! -t 0 ]]; then
  echo "Refusing: token must be entered interactively on a terminal" >&2
  exit 3
fi

read -r -s -p "Enter authorized Shield profile Cortex token: " token
printf '\n'
if [[ -z "$token" || "$token" == *$'\n'* || "$token" == *$'\r'* ]]; then
  unset token
  echo "Refusing: token was empty or contained a newline" >&2
  exit 4
fi

cp --preserve=mode,ownership,timestamps "$env_file" "$backup"
chmod 600 "$backup"

# Replace exactly one existing assignment, or append one if absent. Do not
# print the resulting file or token. The temporary file remains mode 600.
TOKEN_VALUE="$token" python3 - "$env_file" "$tmp" <<'PY'
from pathlib import Path
import os
import sys

source = Path(sys.argv[1])
target = Path(sys.argv[2])
value = os.environ["TOKEN_VALUE"]
lines = source.read_text(encoding="utf-8").splitlines(keepends=True)
matches = 0
out = []
for line in lines:
    if line.startswith("XIBALBA_CORTEX_TOKEN="):
        matches += 1
        out.append("XIBALBA_CORTEX_TOKEN=" + value + "\n")
    else:
        out.append(line)
if matches > 1:
    raise SystemExit(f"refusing: found {matches} XIBALBA_CORTEX_TOKEN assignments")
if matches == 0:
    out.append("XIBALBA_CORTEX_TOKEN=" + value + "\n")
target.write_text("".join(out), encoding="utf-8")
PY
unset token TOKEN_VALUE
chmod --reference="$env_file" "$tmp"
mv -f "$tmp" "$env_file"

echo "Backed up installed Cortex environment to: $backup"
echo "Updated only XIBALBA_CORTEX_TOKEN; token value was not displayed"

systemctl restart "$unit"
main_pid=""
for _ in {1..30}; do
  if systemctl is-active --quiet "$unit"; then
    candidate="$(systemctl show -p MainPID --value "$unit")"
    if [[ "$candidate" =~ ^[1-9][0-9]*$ ]] && [[ -r "/proc/$candidate/environ" ]]; then
      route="$(tr '\0' '\n' < "/proc/$candidate/environ" | sed -n 's/^XIBALBA_CORTEX_URL=//p' | head -1)"
      adopted_token="$(tr '\0' '\n' < "/proc/$candidate/environ" | sed -n 's/^XIBALBA_CORTEX_TOKEN=//p' | head -1)"
      if [[ "$route" == "http://127.0.0.1:8423" && -n "$adopted_token" ]]; then
        main_pid="$candidate"
        break
      fi
    fi
  fi
  sleep 1
done

if [[ -z "$main_pid" ]]; then
  echo "Refusing: outbox worker did not adopt the profile route and a non-empty token within 30 seconds" >&2
  echo "The backed-up environment remains at: $backup" >&2
  exit 5
fi

echo "PASS outbox worker PID $main_pid adopted profile route and a non-empty token"
echo "Next: run scripts/trigger_safe_policy_event.sh once; it will validate persistence without printing the token"
