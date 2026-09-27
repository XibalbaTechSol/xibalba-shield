#!/usr/bin/env bash
set -euo pipefail

# Read-only evidence discovery for the responder readiness workflow.
# This reports locally discoverable candidates and runs safe live sensor proofs.
# It never invents approval, rollback, audit, enrollment, or signature records.

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run this script with sudo: sudo ./scripts/discover_responder_evidence.sh" >&2
  exit 1
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

device_config="${SHIELD_DEVICE_CONFIG:-/etc/xibalba-shield/device.json}"
policy_file="${SHIELD_POLICY_FILE:-/etc/xibalba-shield/policies/current.json}"
proof_dir="${SHIELD_PROOF_DIR:-/var/lib/xibalba-shield/responder-proof}"
mkdir -p "$proof_dir"
chmod 700 "$proof_dir"

echo "Responder evidence discovery (read-only except for proof report files)"
echo "Device config: $device_config"
echo "Policy file:   $policy_file"
echo

echo "== Locally discoverable policy evidence candidate =="
if [[ -f "$policy_file" ]]; then
  policy_hash="$(sha256sum "$policy_file" | awk '{print $1}')"
  echo "policy file exists"
  echo "sha256: $policy_hash"
  echo "candidate reference: policy-file-sha256:$policy_hash"
  echo "IMPORTANT: a file hash is not proof of a verified signature. Use it only if the policy/signature verifier or audit record identifies it as such."
else
  echo "policy file not found"
fi
echo

echo "== Locally discoverable device identity candidate =="
if [[ -f "$device_config" ]]; then
  python3 - "$device_config" <<'PY'
import json
import sys

path = sys.argv[1]
try:
    data = json.load(open(path, encoding="utf-8"))
except Exception as exc:
    print(f"could not parse device config: {exc}")
    raise SystemExit(0)

for key in ("device_id", "did", "agent_id", "integrity_agent_id", "registration_status", "tenant_id"):
    value = data.get(key)
    if value not in (None, ""):
        print(f"{key}: {value}")
PY
  echo "candidate reference: device-config:$device_config"
  echo "IMPORTANT: configuration identity is not proof of an Integrity enrollment record."
else
  echo "device config not found"
fi
echo

uv_bin="$(command -v uv || true)"
if [[ -z "$uv_bin" && -x /home/xibalba/.local/bin/uv ]]; then
  uv_bin=/home/xibalba/.local/bin/uv
fi
if [[ -n "$uv_bin" ]]; then
  runner=("$uv_bin" run --link-mode=copy python)
elif [[ -x /opt/xibalba-shield/venv/bin/python ]]; then
  runner=(/opt/xibalba-shield/venv/bin/python)
else
  echo "Could not find uv or /opt/xibalba-shield/venv/bin/python." >&2
  exit 1
fi

echo "== Safe live kernel proof checks =="
echo "These checks use disposable local activity and do not kill a user workload or install a production network block."
probe_failed=0
for probe in process_exec file_write tcp_connect; do
  report="$proof_dir/${probe}-$(date -u +%Y%m%dT%H%M%SZ).json"
  echo "-- $probe (report: $report)"
  set +e
  "${runner[@]}" "$repo_root/scripts/verify_${probe}_root.py" | tee "$report"
  rc=${PIPESTATUS[0]}
  set -e
  if [[ "$rc" -ne 0 ]]; then
    probe_failed=1
    echo "probe failed with exit code $rc"
  fi
done

echo
if [[ "$probe_failed" -eq 0 ]]; then
  latest_tcp="$(ls -1t "$proof_dir"/tcp_connect-*.json 2>/dev/null | head -1 || true)"
  latest_exec="$(ls -1t "$proof_dir"/process_exec-*.json 2>/dev/null | head -1 || true)"
  echo "kernel probe checks passed. Candidate evidence references:"
  [[ -n "$latest_tcp" ]] && echo "kernel_probe_verified=live-probes:$latest_exec,$latest_tcp"
else
  echo "At least one kernel probe failed; do not mark kernel_probe_verified true."
fi

echo
echo "== Evidence that cannot be safely guessed =="
echo "audit_receipt_verified: obtain the real receipt/acknowledgement ID from the authenticated exporter or Integrity control plane."
echo "rollback_verified: obtain the real change/rollback test ID from a completed disposable rollback test."
echo "operator_approval: obtain the approved change-request ID from Policy & approvals."
echo
echo "No responder-readiness artifact was created. After collecting six real references, run:"
echo "  sudo ./scripts/prepare_responder_readiness.sh"
