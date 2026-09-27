#!/usr/bin/env bash
set -euo pipefail

# Gate 2: narrowly repair the installed Shield -> local BCC route.
# Run from this checkout as:
#   sudo ./scripts/gate2_repair_bcc_route.sh
#
# This script changes only the installed EnvironmentFile's BCC URL, restarts
# only xibalba-shield.service, and leaves all databases, WALs, queues, keys,
# identities, and other services untouched.

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run with sudo: sudo $0" >&2
  exit 1
fi

unit="xibalba-shield.service"
env_file="/etc/xibalba-shield/shield.env"
old_url="http://127.0.0.1:8001"
new_url="http://127.0.0.1:8000"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
backup="/etc/xibalba-shield/shield.env.gate2-backup-${stamp}"

[[ -r "$env_file" && -w "$env_file" ]] || {
  echo "Cannot safely access installed environment file: $env_file" >&2
  exit 2
}

match_count="$(grep -oF -- "$old_url" "$env_file" | wc -l)"
if [[ "$match_count" -ne 1 ]]; then
  echo "Refusing: expected exactly one BCC URL $old_url, found $match_count" >&2
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

echo "Backed up installed Shield environment to: $backup"
echo "Changed only Shield BCC route: $old_url -> $new_url"

systemctl restart "$unit"

# The agent may perform one ordinary systemd restart while it initializes its
# sensor/exporter. Wait for a stable active PID instead of treating that
# expected startup transition as a failed route repair.
main_pid=""
cmdline=""
for _ in {1..30}; do
  if systemctl is-active --quiet "$unit"; then
    candidate="$(systemctl show -p MainPID --value "$unit")"
    if [[ "$candidate" =~ ^[1-9][0-9]*$ ]] && [[ -r "/proc/$candidate/cmdline" ]]; then
      candidate_cmdline="$(tr '\0' ' ' < "/proc/$candidate/cmdline")"
      if [[ "$candidate_cmdline" == *"--bcc-middleware-url $new_url"* && "$candidate_cmdline" != *"--bcc-middleware-url $old_url"* ]]; then
        main_pid="$candidate"
        cmdline="$candidate_cmdline"
        break
      fi
    fi
  fi
  sleep 1
done

if [[ -z "$main_pid" ]]; then
  echo "Refusing: no stable Shield PID adopted $new_url within 30 seconds; restoring $env_file" >&2
  cp --preserve=mode,ownership,timestamps "$backup" "$env_file"
  systemctl restart "$unit" || true
  exit 5
fi

curl --fail --silent --show-error --max-time 5 http://127.0.0.1:8000/health >/dev/null
echo "PASS active BCC middleware health at $new_url/health"
echo "PASS Shield PID $main_pid is using the repaired BCC route"

echo "Running read-only Gate 2 sampler; Oracle/OTLP limitations remain evidence, not success claims"
exec "$(dirname "$0")/verify_realtime_data_flow.sh" --duration 10 --interval 5 --json
