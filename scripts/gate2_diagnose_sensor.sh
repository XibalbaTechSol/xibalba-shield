#!/usr/bin/env bash
set -euo pipefail

# Gate 2: read-only diagnosis for a missing live Shield decision.
# This script does not restart services, read credentials, or mutate queues,
# databases, WALs, logs, or test fixtures.

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run with sudo: sudo $0" >&2
  exit 1
fi

echo '=== time ==='
date -Is

echo '=== Shield service ==='
systemctl status xibalba-shield.service --no-pager || true
systemctl show xibalba-shield.service \
  -p ActiveState -p SubState -p MainPID -p ExecStart -p EnvironmentFiles

echo '=== eBPF helper and socket ==='
systemctl status xibalba-shield-ebpf-helper.service --no-pager || true
systemctl show xibalba-shield-ebpf-helper.service \
  -p ActiveState -p SubState -p MainPID -p ExecStart -p RuntimeDirectory
helper_socket='/run/xibalba-shield/ebpf.sock'
if [[ -S "$helper_socket" ]]; then
  stat -c 'socket=%n mode=%a owner=%U group=%G inode=%i' "$helper_socket"
else
  echo "missing-socket $helper_socket"
fi
journalctl -u xibalba-shield-ebpf-helper.service --since '20 minutes ago' --no-pager \
  | tail -80 || true

echo '=== installed launcher and service drop-in ==='
if [[ -r /usr/local/bin/xibalba-shield-run ]]; then
  sed -n '1,240p' /usr/local/bin/xibalba-shield-run
else
  echo 'missing /usr/local/bin/xibalba-shield-run'
fi
for dropin in /etc/systemd/system/xibalba-shield.service.d/*.conf; do
  [[ -r "$dropin" ]] || continue
  echo "--- $dropin ---"
  sed -n '1,240p' "$dropin"
done

echo '=== recent Shield decision-related journal ==='
journalctl -u xibalba-shield.service --since '20 minutes ago' --no-pager \
  | grep -E 'policy-test|shadow-ai|smb-contain-shadow-ai-processes|decision|contain|ActionBroker|error|Error|failed|Failed' \
  | tail -120 || true

echo '=== runtime files ==='
for root in /var/log/xibalba-shield /var/lib/xibalba-shield; do
  if [[ -d "$root" ]]; then
    find "$root" -maxdepth 3 -type f -printf '%p %s bytes\n' | sort
  else
    echo "missing $root"
  fi
done

echo '=== decision-log candidates ==='
for path in /var/log/xibalba-shield/decisions.jsonl /var/lib/xibalba-shield/decisions.jsonl; do
  if [[ -r "$path" ]]; then
    echo "readable $path"
    tail -5 "$path" \
      | sed -E 's/(cmdline|command_line|argv|path|executable)("?[[:space:]]*:[[:space:]]*)[^,}]*/\1\2[redacted]/g'
  else
    echo "not-readable-or-missing $path"
  fi
done

echo '=== latest target correlation (metadata only) ==='
if [[ -r /var/log/xibalba-shield/decisions.jsonl ]]; then
  grep -nE '431874|Q1WDpK|policy-test|shadow-agent|smb-contain-shadow-ai-processes' \
    /var/log/xibalba-shield/decisions.jsonl | tail -60 || true
fi

echo '=== listeners ==='
ss -ltnp | grep -E ':(8000|8001|8421|8423)\b' || true

echo '=== bounded outbox/profile counts (read-only) ==='
if command -v python3 >/dev/null; then
  python3 - <<'PY'
import sqlite3

def ro(path, statements):
    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    except Exception as exc:
        print(f"{path}: unavailable: {exc}")
        return
    try:
        for label, sql in statements:
            try:
                print(label, list(conn.execute(sql)))
            except Exception as exc:
                print(label, f"unavailable: {exc}")
    finally:
        conn.close()

ro('/var/lib/xibalba-shield/cortex/outbox.sqlite3', [
    ('outbox_metrics', 'select name,value from cortex_outbox_metrics order by name'),
    ('outbox_status', 'select status,count(*),coalesce(sum(attempts),0),max(attempts) from cortex_outbox group by status'),
])
ro('/home/xibalba/.hermes/xibalba-cortex-shield/graph-memory.sqlite3', [
    ('profile_counts', "select 'memories',count(*) from memories union all select 'sources',count(*) from sources union all select 'otel_events',count(*) from otel_events"),
])
PY
fi
