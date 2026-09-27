#!/usr/bin/env bash
set -euo pipefail

# Gate 2: read-only verification of the installed Shield token against the
# Shield profile's Cortex ingest-token store. Never prints the raw token or
# its hash, and never changes the environment, token database, or service.

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run with sudo: sudo $0" >&2
  exit 1
fi

python3 - <<'PY'
import hashlib
import sqlite3
from pathlib import Path

env_path = Path('/etc/xibalba-shield/cortex.env')
db_path = Path('/home/xibalba/.hermes/xibalba-cortex-shield/ingest_tokens.sqlite3')
values = {}
for raw in env_path.read_text(encoding='utf-8').splitlines():
    line = raw.strip()
    if not line or line.startswith('#') or '=' not in line:
        continue
    key, value = line.split('=', 1)
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        value = value[1:-1]
    values[key.strip()] = value

token = values.get('XIBALBA_CORTEX_TOKEN', '').strip()
url = values.get('XIBALBA_CORTEX_URL', '').strip()
if not token:
    raise SystemExit('FAIL installed environment has no XIBALBA_CORTEX_TOKEN')
if not db_path.is_file():
    raise SystemExit(f'FAIL profile ingest-token store missing: {db_path}')

candidate = hashlib.sha256(token.encode('utf-8')).hexdigest()
conn = sqlite3.connect(f'file:{db_path}?mode=ro', uri=True)
try:
    rows = conn.execute(
        'SELECT label,profile_id,roles_json,scopes_json,revoked_at,expires_at,agent_id,agent_ids_json,token_hash '
        'FROM ingest_tokens ORDER BY created_at'
    ).fetchall()
finally:
    conn.close()

matches = [row for row in rows if row[-1] == candidate]
print(f'profile_url={url}')
print(f'profile_token_records={len(rows)}')
print(f'installed_token_hash_match_count={len(matches)}')
for label, profile_id, roles, scopes, revoked, expires, agent_id, agent_ids, _ in rows:
    state = 'revoked' if revoked else 'active'
    print(f'record label={label} profile_id={profile_id} state={state} agent_id={agent_id or "<none>"} agent_ids={agent_ids}')
if len(matches) != 1:
    raise SystemExit('FAIL installed token does not match exactly one profile ingest-token record')
print('PASS installed token matches exactly one profile ingest-token record')
PY
