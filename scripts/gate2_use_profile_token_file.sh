#!/usr/bin/env bash
set -euo pipefail

# Gate 2: install the existing Shield-profile Cortex credential without
# displaying, generating, or replacing the credential.

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run with sudo: sudo $0" >&2
  exit 1
fi

token_file="/home/xibalba/.hermes/xibalba-cortex-shield/.viewer-dev.token"
profile_db="/home/xibalba/.hermes/xibalba-cortex-shield/ingest_tokens.sqlite3"
env_file="/etc/xibalba-shield/cortex.env"
unit="xibalba-shield-cortex-outbox.service"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
backup="/etc/xibalba-shield/cortex.env.gate2-profile-token-backup-${stamp}"
tmp="$(mktemp /etc/xibalba-shield/cortex.env.gate2-profile-token.XXXXXX)"
trap 'rm -f "$tmp"' EXIT

[[ -r "$token_file" ]] || { echo "Missing or unreadable profile token file" >&2; exit 2; }
[[ -r "$profile_db" ]] || { echo "Missing or unreadable profile token database" >&2; exit 3; }
[[ -r "$env_file" && -w "$env_file" ]] || { echo "Cannot safely access $env_file" >&2; exit 4; }

token="$(tr -d '\r\n' < "$token_file")"
[[ -n "$token" && "$token" != *[[:space:]]* ]] || {
  unset token
  echo "Refusing: profile token file is empty or contains whitespace" >&2
  exit 5
}

TOKEN_VALUE="$token" PROFILE_DB="$profile_db" python3 - <<'PY'
import hashlib
import os
import sqlite3

candidate = hashlib.sha256(os.environ['TOKEN_VALUE'].encode()).hexdigest()
db = os.environ['PROFILE_DB']
conn = sqlite3.connect(f'file:{db}?mode=ro', uri=True)
try:
    rows = conn.execute(
        'SELECT label, profile_id, revoked_at, expires_at, token_hash '
        'FROM ingest_tokens WHERE token_hash = ?', (candidate,)
    ).fetchall()
finally:
    conn.close()
if len(rows) != 1 or rows[0][2] is not None or rows[0][3] is not None:
    raise SystemExit('Refusing: profile token file does not match exactly one active ingest-token record')
print(f'PASS profile token file matches active record label={rows[0][0]} profile_id={rows[0][1]}')
PY
unset TOKEN_VALUE PROFILE_DB

cp --preserve=mode,ownership,timestamps "$env_file" "$backup"
chmod 600 "$backup"

TOKEN_VALUE="$token" python3 - "$env_file" "$tmp" <<'PY'
from pathlib import Path
import os
import sys

source = Path(sys.argv[1])
target = Path(sys.argv[2])
value = os.environ['TOKEN_VALUE']
lines = source.read_text(encoding='utf-8').splitlines(keepends=True)
matches = 0
out = []
for line in lines:
    if line.startswith('XIBALBA_CORTEX_TOKEN='):
        matches += 1
        out.append('XIBALBA_CORTEX_TOKEN=' + value + '\n')
    else:
        out.append(line)
if matches > 1:
    raise SystemExit(f'refusing: found {matches} XIBALBA_CORTEX_TOKEN assignments')
if matches == 0:
    out.append('XIBALBA_CORTEX_TOKEN=' + value + '\n')
target.write_text(''.join(out), encoding='utf-8')
PY
unset token TOKEN_VALUE
chmod --reference="$env_file" "$tmp"
mv -f "$tmp" "$env_file"

echo "Backed up installed Cortex environment to: $backup"
echo "Installed only the existing Shield-profile token; value was not displayed"

systemctl restart "$unit"
main_pid=""
for _ in {1..30}; do
  if systemctl is-active --quiet "$unit"; then
    candidate="$(systemctl show -p MainPID --value "$unit")"
    if [[ "$candidate" =~ ^[1-9][0-9]*$ ]] && [[ -r "/proc/$candidate/environ" ]]; then
      route="$(tr '\0' '\n' < "/proc/$candidate/environ" | sed -n 's/^XIBALBA_CORTEX_URL=//p' | head -1)"
      adopted="$(tr '\0' '\n' < "/proc/$candidate/environ" | sed -n 's/^XIBALBA_CORTEX_TOKEN=//p' | head -1)"
      if [[ "$route" == "http://127.0.0.1:8423" && -n "$adopted" ]]; then
        main_pid="$candidate"
        break
      fi
    fi
  fi
  sleep 1
done

if [[ -z "$main_pid" ]]; then
  echo "Refusing: worker did not adopt profile route and a non-empty token within 30 seconds" >&2
  echo "Rollback backup: $backup" >&2
  exit 6
fi

echo "PASS outbox worker PID $main_pid adopted profile route and a non-empty token"
echo "Next: run one clean disposable event for authenticated persistence validation"
