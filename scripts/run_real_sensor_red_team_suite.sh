#!/usr/bin/env bash
set -euo pipefail

# High-fidelity local red-team suite. Uses the installed real sensors/eBPF bridge,
# but confines activity to disposable local targets and loopback. No credentials,
# external network, persistence, kill action, or production firewall change.

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run with sudo." >&2
  exit 1
fi
if [[ "${SHIELD_ENV:-}" != "development" ]]; then
  echo "Refusing to run outside SHIELD_ENV=development" >&2
  exit 1
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
log_path="${SHIELD_DECISION_LOG:-/var/log/xibalba-shield/decisions.jsonl}"
report_path="${SHIELD_REAL_SENSOR_REPORT:-$repo_root/artifacts/real-sensor-red-team-report.json}"
device_id="$(python3 -c 'import json; print(json.load(open("/etc/xibalba-shield/device.json"))["device_id"])')"
work_dir="$(mktemp -d /tmp/xibalba-shield-real-red-team.XXXXXX)"
listener_pid=""
canary_pid=""
before_lines=0
[[ -f "$log_path" ]] && before_lines="$(wc -l < "$log_path")"

cleanup() {
  if [[ -n "$canary_pid" ]] && kill -0 "$canary_pid" 2>/dev/null; then
    kill -CONT "$canary_pid" 2>/dev/null || true
    kill "$canary_pid" 2>/dev/null || true
  fi
  if [[ -n "$listener_pid" ]] && kill -0 "$listener_pid" 2>/dev/null; then
    kill "$listener_pid" 2>/dev/null || true
  fi
  rm -rf "$work_dir"
  rm -f /etc/xibalba-shield/.red-team-write-test
}
trap cleanup EXIT

echo "Real-sensor red-team suite"
echo "  device:   $device_id"
echo "  scope:    disposable local process/file activity and 127.0.0.1 TCP"

# 1. Real process-exec event matching the SMB shadow-AI rule.
mkdir -p "$work_dir/ai/shadow-agent"
cp /bin/sleep "$work_dir/ai/shadow-agent/model-runner"
chmod 0700 "$work_dir/ai/shadow-agent/model-runner"
"$work_dir/ai/shadow-agent/model-runner" 30 &
canary_pid="$!"
echo "process_exec pid=$canary_pid path=$work_dir/ai/shadow-agent/model-runner"

# 2. Real write-open event against a disposable file under the configured sensitive prefix.
mkdir -p /etc/xibalba-shield
dd if=/dev/zero of=/etc/xibalba-shield/.red-team-write-test bs=1 count=1 status=none
echo "file_write path=/etc/xibalba-shield/.red-team-write-test"

# 3. Real loopback-only TCP connect. No external address is contacted.
python3 - "$work_dir" <<'PY' &
import socket, sys, time
marker = sys.argv[1] + "/tcp-ready"
server = socket.socket()
server.bind(("127.0.0.1", 0))
server.listen(1)
open(marker, "w", encoding="ascii").write(str(server.getsockname()[1]))
server.settimeout(5)
try:
    conn, _ = server.accept()
    conn.close()
except socket.timeout:
    pass
finally:
    server.close()
PY
listener_pid="$!"
for _ in {1..20}; do [[ -f "$work_dir/tcp-ready" ]] && break; sleep 0.05; done
if [[ -f "$work_dir/tcp-ready" ]]; then
  tcp_port="$(cat "$work_dir/tcp-ready")"
  python3 - "$tcp_port" <<'PY'
import socket, sys
sock = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=2)
sock.close()
PY
  echo "tcp_connect destination=127.0.0.1:$tcp_port"
else
  echo "tcp_connect listener did not become ready" >&2
fi

# Give the real bridge/exporter a bounded window to publish decisions, then safely
# resume/terminate only the disposable canary.
sleep 3
if [[ -r "/proc/$canary_pid/status" ]] && grep -q '^State:.*T' "/proc/$canary_pid/status"; then
  echo "containment=confirmed_sigstop pid=$canary_pid"
  kill -CONT "$canary_pid" 2>/dev/null || true
else
  echo "containment=not_confirmed pid=$canary_pid"
fi

python3 - "$log_path" "$before_lines" "$report_path" "$device_id" <<'PY'
import json, sys
from pathlib import Path
log_path, before, report_path, device_id = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
rows = []
path = Path(log_path)
if path.exists():
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines()[before:]:
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if row.get("class") == "policy_decision":
            rows.append(row)
report = {
    "schema": "shield.real_sensor_red_team_report.v1",
    "synthetic": False,
    "device_id": device_id,
    "scope": ["real_process_exec", "real_file_write", "real_loopback_tcp_connect"],
    "decision_rows_observed": len(rows),
    "decisions": [
        {
            "event_id": (row.get("event_ref") or {}).get("event_id"),
            "action": (row.get("decision") or {}).get("action"),
            "rule_id": (row.get("rule") or {}).get("rule_id"),
            "reason": (row.get("decision") or {}).get("reason"),
            "time": row.get("time"),
        }
        for row in rows
    ],
    "note": "Real local sensor activity only; no external network, credentials, persistence, kill, or production firewall action.",
}
Path(report_path).parent.mkdir(parents=True, exist_ok=True)
Path(report_path).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(json.dumps(report, indent=2, sort_keys=True))
PY
