#!/usr/bin/env bash
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run with sudo: sudo $0" >&2
  exit 1
fi

token_file='/home/xibalba/.hermes/xibalba-cortex-shield/.viewer-dev.token'
profile_db='/home/xibalba/.hermes/xibalba-cortex-shield/ingest_tokens.sqlite3'
env_file='/etc/xibalba-shield/cortex.env'
unit='xibalba-shield-cortex-outbox.service'
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
backup="${profile_db}.gate2-agent-bind-backup-${stamp}"

[[ -r "$token_file" ]] || { echo "Missing or unreadable profile token file" >&2; exit 2; }
[[ -r "$profile_db" && -w "$profile_db" ]] || { echo "Cannot safely access profile token database" >&2; exit 3; }
[[ -r "$env_file" ]] || { echo "Missing or unreadable $env_file" >&2; exit 4; }

agent_id="$(grep '^XIBALBA_AGENT_ID=' "$env_file" | head -1 | cut -d= -f2-)"
[[ "$agent_id" == did:integrity:* ]] || { echo "Refusing: XIBALBA_AGENT_ID is not canonical" >&2; exit 5; }
token="$(tr -d '\r\n' < "$token_file")"
[[ -n "$token" && "$token" != *[[:space:]]* ]] || { unset token; echo "Refusing: invalid profile token file" >&2; exit 6; }

PROFILE_DB="$profile_db" BACKUP="$backup" python3 - <<'PY'
import os, sqlite3
source = sqlite3.connect(os.environ['PROFILE_DB'], timeout=30)
target = sqlite3.connect(os.environ['BACKUP'])
try:
    source.backup(target)
finally:
    target.close()
    source.close()
PY
chmod 600 "$backup"
echo "Backed up token metadata database to: $backup"

TOKEN_VALUE="$token" PROFILE_DB="$profile_db" AGENT_ID="$agent_id" python3 - <<'PY'
import hashlib, json, os, sqlite3
db = os.environ['PROFILE_DB']
agent_id = os.environ['AGENT_ID']
candidate = hashlib.sha256(os.environ['TOKEN_VALUE'].encode()).hexdigest()
conn = sqlite3.connect(db, timeout=30)
conn.row_factory = sqlite3.Row
conn.execute('PRAGMA busy_timeout=30000')
try:
    rows = conn.execute('SELECT id,label,profile_id,revoked_at,expires_at,agent_id,agent_ids_json FROM ingest_tokens WHERE token_hash=?', (candidate,)).fetchall()
    if len(rows) != 1:
        raise SystemExit('Refusing: token does not match exactly one record')
    row = rows[0]
    if row['revoked_at'] is not None or row['expires_at'] is not None:
        raise SystemExit('Refusing: token is not active')
    try:
        ids = {str(v).strip() for v in json.loads(row['agent_ids_json'] or '[]') if str(v).strip()}
    except (TypeError, json.JSONDecodeError):
        ids = set()
    if row['agent_id']:
        ids.add(str(row['agent_id']).strip())
    before = sorted(ids)
    ids.add(agent_id)
    after = sorted(ids)
    conn.execute('BEGIN IMMEDIATE')
    conn.execute('UPDATE ingest_tokens SET agent_id=?, agent_ids_json=? WHERE id=?', (after[0] if len(after) == 1 else None, json.dumps(after), row['id']))
    conn.commit()
    print(f"PASS bound existing token label={row['label']} profile_id={row['profile_id']} agent_ids={after}")
    print(f"Previous agent_ids={before or ['<none>']}")
finally:
    conn.close()
PY
unset TOKEN_VALUE PROFILE_DB AGENT_ID token

systemctl restart "$unit"
for _ in {1..30}; do
  if systemctl is-active --quiet "$unit"; then
    pid="$(systemctl show -p MainPID --value "$unit")"
    if [[ "$pid" =~ ^[1-9][0-9]*$ ]]; then
      route="$(tr '\0' '\n' < "/proc/$pid/environ" | sed -n 's/^XIBALBA_CORTEX_URL=//p' | head -1)"
      adopted="$(tr '\0' '\n' < "/proc/$pid/environ" | sed -n 's/^XIBALBA_CORTEX_TOKEN=//p' | head -1)"
      if [[ "$route" == 'http://127.0.0.1:8423' && -n "$adopted" ]]; then
        echo "PASS outbox worker PID $pid adopted profile route and a non-empty token"
        echo "Shield was not restarted; raw token was not displayed"
        exit 0
      fi
    fi
  fi
  sleep 1
done

echo "FAIL outbox worker did not adopt the profile route and token" >&2
echo "Rollback backup: $backup" >&2
exit 7
