#!/usr/bin/env bash
set -euo pipefail

# Gate 2 handoff: install only the bounded SQLite lock-wait repair into the
# already documented Shield venv, preserving a recoverable target backup.
# This script does not touch runtime databases, queues, identities, or secrets.

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run with sudo: sudo ./scripts/gate2_install_spool_lock_fix.sh" >&2
  exit 1
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source_file="$repo_root/shield/integrity_exporter/spool.py"
target_file="/opt/xibalba-shield/venv/lib/python3.12/site-packages/shield/integrity_exporter/spool.py"

[[ -r "$source_file" ]] || { echo "Missing source file: $source_file" >&2; exit 1; }
[[ -f "$target_file" ]] || { echo "Missing installed file: $target_file" >&2; exit 1; }
grep -Fq 'sqlite3.connect(str(path), timeout=5.0)' "$source_file" || {
  echo "Source does not contain the expected bounded timeout repair" >&2
  exit 1
}

backup_file="${target_file}.gate2-backup-$(date -u +%Y%m%dT%H%M%SZ)"
cp -- "$target_file" "$backup_file"
cp -- "$source_file" "$target_file"
echo "Backed up installed Shield spool to: $backup_file"
echo "Installed only: $target_file"

systemctl restart xibalba-shield.service

for _ in $(seq 1 30); do
  [[ "$(systemctl is-active xibalba-shield.service)" == "active" ]] && break
  sleep 1
done

if [[ "$(systemctl is-active xibalba-shield.service)" != "active" ]]; then
  echo "Refusing: xibalba-shield.service is not active after restart" >&2
  exit 1
fi

main_pid="$(systemctl show xibalba-shield.service -p MainPID --value)"
[[ "$main_pid" =~ ^[1-9][0-9]*$ ]] || { echo "Refusing: invalid Shield MainPID" >&2; exit 1; }

grep -Fq 'sqlite3.connect(str(path), timeout=5.0)' "$target_file" || {
  echo "Refusing: installed file does not contain the bounded timeout repair" >&2
  exit 1
}

echo "Shield active with MainPID=$main_pid"
echo "Verified installed spool timeout repair; no other service was restarted"
