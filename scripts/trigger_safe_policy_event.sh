#!/usr/bin/env bash
set -euo pipefail

# End-to-end, harmless policy trigger for the local shadow-AI process rule.
# This copies /bin/sleep into a disposable path containing /ai/shadow-agent,
# executes it briefly, waits for the real Shield event log, then resumes the
# process if the local contain action stopped it. No kill, cgroup freeze, or
# network change is performed.

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run with sudo: sudo ./scripts/trigger_safe_policy_event.sh" >&2
  exit 1
fi

command -v cp >/dev/null || { echo "Missing cp" >&2; exit 1; }
command -v sha256sum >/dev/null || { echo "Missing sha256sum" >&2; exit 1; }
command -v awk >/dev/null || { echo "Missing awk" >&2; exit 1; }

log_path="${SHIELD_DECISION_LOG:-/var/log/xibalba-shield/decisions.jsonl}"
test_seconds="${SHIELD_POLICY_TEST_SECONDS:-600}"
wait_seconds="${SHIELD_POLICY_WAIT_SECONDS:-120}"
root_dir="$(mktemp -d /tmp/xibalba-shield-policy-test.XXXXXX)"
test_dir="$root_dir/ai/shadow-agent"
test_bin="$test_dir/policy-test"
pid=""

cleanup() {
  if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
    # Resume only; never terminate the test workload from this script.
    kill -CONT "$pid" 2>/dev/null || true
  fi
  rm -rf "$root_dir"
}
trap cleanup EXIT

mkdir -p "$test_dir"
cp /bin/sleep "$test_bin"
chmod 0700 "$test_bin"
test_hash="$(sha256sum "$test_bin" | awk '{print $1}')"
before_lines=0
[[ -f "$log_path" ]] && before_lines="$(wc -l < "$log_path")"

echo "Launching harmless policy test binary"
echo "  path:   $test_bin"
echo "  sha256: $test_hash"
echo "  wait:   ${wait_seconds}s (bounded)"
"$test_bin" "$test_seconds" &
pid="$!"
echo "  pid:    $pid"

matched="false"
for _ in $(seq 1 "$((wait_seconds * 2))"); do
  # The installed policy may identify this decision as either the source
  # Rego rule (smb-contain-shadow-ai-processes) or the runtime local-risk
  # gate (_local-risk-containment). Correlate on this exact disposable path
  # and the contain action so stale/unrelated decisions cannot satisfy the
  # observation window.
  if [[ -f "$log_path" ]] && tail -n +$((before_lines + 1)) "$log_path" \
    | grep -F "$test_bin" \
    | grep -Fq '"action": "contain"'; then
    matched="true"
    break
  fi
  sleep 0.5
done

if [[ "$matched" == "true" ]]; then
  echo "PASS Shield emitted a decision for the test process"
  tail -n +$((before_lines + 1)) "$log_path" \
    | grep -F "$test_bin" \
    | grep -F '"action": "contain"' \
    | sed -E 's/(cmdline|command_line|argv)":?[^,}]*/\1":"[redacted]/g' \
    | tail -3
else
  echo "FAIL no matching Shield decision appeared within ${wait_seconds} seconds" >&2
  exit 2
fi

# The contain responder is expected to use SIGSTOP, which is reversible.
if [[ -r "/proc/$pid/status" ]] && grep -q '^State:.*T' "/proc/$pid/status"; then
  echo "INFO Shield stopped the test process; resuming it safely"
  kill -CONT "$pid"
else
  echo "INFO test process was not stopped; no responder action was needed"
fi

wait "$pid" 2>/dev/null || true
echo "PASS harmless policy test process completed; no destructive action was used"
echo "Refresh the authenticated Shield console and inspect the live event stream for:"
echo "  rule=smb-contain-shadow-ai-processes action=contain"
