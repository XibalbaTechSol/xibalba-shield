#!/usr/bin/env bash
# Validate the live process-exec containment path with a harmless disposable process.
# The active SMB policy matches the argv path */ai/* and should freeze this sleep
# process with SIGSTOP. This script never launches malware and always cleans up.

set -Eeuo pipefail

CANARY_DIR="/tmp/ai"
CANARY="${CANARY_DIR}/shadow-canary"
PID=""
RESULT=1

cleanup() {
  if [[ -n "${PID}" ]] && kill -0 "${PID}" 2>/dev/null; then
    # Resume first so cleanup cannot leave a stopped process behind.
    kill -CONT "${PID}" 2>/dev/null || true
    kill -TERM "${PID}" 2>/dev/null || true
    for _ in $(seq 1 20); do
      kill -0 "${PID}" 2>/dev/null || break
      sleep 0.1
    done
    kill -KILL "${PID}" 2>/dev/null || true
  fi
  rm -f "${CANARY}"
}
trap cleanup EXIT INT TERM

mkdir -p "${CANARY_DIR}"
# Use a real copied binary rather than a symlink: execve may report the resolved target
# path, which would bypass the intended */ai/* policy match even when the canary argv path
# contains /ai/. The copied binary is still only /usr/bin/sleep and is removed on exit.
cp /usr/bin/sleep "${CANARY}"
chmod 0755 "${CANARY}"

echo "Starting harmless canary: ${CANARY} 30"
"${CANARY}" 30 &
PID=$!
echo "canary_pid=${PID}"

state=""
for attempt in $(seq 1 20); do
  state="$(ps -o stat= -p "${PID}" 2>/dev/null | tr -d ' ' || true)"
  printf 'poll=%02d state=%s\n' "${attempt}" "${state:-gone}"
  if [[ "${state}" == T* ]]; then
    RESULT=0
    echo "containment=CONFIRMED_SIGSTOP"
    break
  fi
  if [[ -z "${state}" ]]; then
    echo "containment=NOT_CONFIRMED_PROCESS_EXITED"
    break
  fi
  sleep 0.5
done

if [[ "${RESULT}" -ne 0 ]]; then
  echo "containment=NOT_CONFIRMED"
  echo "The policy canary was not observed in stopped state. Check the agent's lost_events status."
fi

echo
echo "Recent matching local audit records:"
for log in \
  "${HOME}/.xibalba-shield/decisions.jsonl" \
  "/root/.xibalba-shield/decisions.jsonl"; do
  if [[ -f "${log}" ]]; then
    echo "-- ${log}"
    rg 'smb-contain-shadow-ai-processes|shadow-canary' "${log}" | tail -5 || true
  fi
done

if command -v curl >/dev/null 2>&1; then
  echo
  echo "Current authenticated runtime status:"
  curl --silent --show-error --connect-timeout 2 \
    -H 'Authorization: Bearer dev' \
    'http://127.0.0.1:8421/api/shield/exporter-status?tenant_id=tenant-a' \
    || echo "backend status unavailable"
fi

exit "${RESULT}"
