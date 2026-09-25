#!/usr/bin/env bash
set -euo pipefail

# Root-only operator wrapper for the gated responder proof workflow.
# It presents numbered evidence choices, rejects placeholders, runs the
# disposable kill/cgroup/nftables probes, and writes the readiness artifact.

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run this script with sudo: sudo ./scripts/prepare_responder_readiness.sh" >&2
  exit 1
fi

usage() {
  cat >&2 <<'EOF'
Usage: sudo ./scripts/prepare_responder_readiness.sh [options]

All six base-proof references must be real, externally issued references.
This script runs only disposable runtime probes and writes the readiness
artifact; it does not enable responders or restart Shield.

Options:
  --device-id REF
  --policy-signature-ref REF
  --agent-identity-ref REF
  --kernel-probe-ref REF
  --audit-receipt-ref REF
  --rollback-ref REF
  --operator-approval-ref REF
  --output PATH
EOF
}

device_id_arg=""
policy_signature_ref="${POLICY_SIGNATURE_REF:-}"
agent_identity_ref="${AGENT_IDENTITY_REF:-}"
kernel_probe_ref="${KERNEL_PROBE_REF:-}"
audit_receipt_ref="${AUDIT_RECEIPT_REF:-}"
rollback_ref="${ROLLBACK_REF:-}"
operator_approval_ref="${OPERATOR_APPROVAL_REF:-}"
output_arg="${SHIELD_READINESS_OUTPUT:-/etc/xibalba-shield/responder-readiness.json}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --device-id) device_id_arg="${2:?missing value for --device-id}"; shift 2 ;;
    --policy-signature-ref) policy_signature_ref="${2:?missing value for --policy-signature-ref}"; shift 2 ;;
    --agent-identity-ref) agent_identity_ref="${2:?missing value for --agent-identity-ref}"; shift 2 ;;
    --kernel-probe-ref) kernel_probe_ref="${2:?missing value for --kernel-probe-ref}"; shift 2 ;;
    --audit-receipt-ref) audit_receipt_ref="${2:?missing value for --audit-receipt-ref}"; shift 2 ;;
    --rollback-ref) rollback_ref="${2:?missing value for --rollback-ref}"; shift 2 ;;
    --operator-approval-ref) operator_approval_ref="${2:?missing value for --operator-approval-ref}"; shift 2 ;;
    --output) output_arg="${2:?missing value for --output}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 2 ;;
  esac
done

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

device_config="${SHIELD_DEVICE_CONFIG:-/etc/xibalba-shield/device.json}"
policy_file="${SHIELD_POLICY_FILE:-/etc/xibalba-shield/policies/current.json}"

choose_device() {
  local -a options=()
  if [[ -f "$device_config" ]]; then
    local configured
    configured="$(python3 - "$device_config" <<'PY'
import json, sys
try:
    data = json.load(open(sys.argv[1], encoding="utf-8"))
    print(data.get("device_id", ""))
except Exception:
    pass
PY
)"
    [[ -n "$configured" ]] && options+=("$configured (from $device_config)")
  fi
  options+=("xibalba-HP-Desktop-M01-F0xxx (default)" "cancel")
  echo "Select target device:" >&2
  local i=1
  local item
  for item in "${options[@]}"; do
    echo "  $i) $item" >&2
    ((i++))
  done
  while true; do
    read -r -p "Selection: " choice
    if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#options[@]} )); then
      if [[ "${options[$((choice-1))]}" == "cancel" ]]; then
        exit 2
      fi
      printf '%s' "${options[$((choice-1))]%% *}"
      return
    fi
    echo "Choose a numbered option." >&2
  done
}

provided_or_choose() {
  local name="$1"; local provided="$2"; shift 2
  if [[ -n "$provided" ]]; then
    case "$provided" in
      REAL_*|YOUR_*|REPLACE_*|UNAVAILABLE::*|*candidate*|*unverified*|*not\ found*)
        echo "$name reference is an unverified candidate: $provided" >&2
        exit 2
        ;;
    esac
    printf '%s' "$provided"
    return
  fi
  choose_proof "$name" "$@"
}

choose_proof() {
  local name="$1"
  shift
  local -a options=("$@")
  options+=("not found — stop without creating readiness")
  echo >&2
  echo "Select $name evidence reference:" >&2
  local i=1
  local item
  for item in "${options[@]}"; do
    echo "  $i) $item" >&2
    ((i++))
  done
  while true; do
    read -r -p "Selection: " choice
    if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#options[@]} )); then
      if (( choice == ${#options[@]} )); then
        echo "$name has no discovered real reference; readiness cannot be created." >&2
        exit 2
      fi
      selected="${options[$((choice-1))]}"
      if [[ "$selected" == UNAVAILABLE::* ]]; then
        echo "${selected#UNAVAILABLE::}" >&2
        echo "$name is not verified; readiness cannot be created." >&2
        exit 2
      fi
      printf '%s' "$selected"
      return
    fi
    echo "Choose a numbered option." >&2
  done
}

if [[ -n "$device_id_arg" ]]; then
  device_id="$device_id_arg"
else
  device_id="$(choose_device)"
fi

policy_options=()
if [[ -f "$policy_file" ]]; then
  policy_hash="$(sha256sum "$policy_file" | awk '{print $1}')"
  policy_options+=("UNAVAILABLE::policy-file-sha256:$policy_hash (unverified candidate; cannot be used as signature proof)")
fi
policy_signature_verified="$(provided_or_choose policy_signature_verified "$policy_signature_ref" "${policy_options[@]}")"

identity_options=()
if [[ -f "$device_config" ]]; then
  identity_options+=("UNAVAILABLE::device-config:$device_config (unverified candidate; cannot be used as enrollment proof)")
fi
agent_identity_verified="$(provided_or_choose agent_identity_verified "$agent_identity_ref" "${identity_options[@]}")"

kernel_options=("UNAVAILABLE::no completed kernel evidence report discovered; run discover_responder_evidence.sh first")
kernel_probe_verified="$(provided_or_choose kernel_probe_verified "$kernel_probe_ref" "${kernel_options[@]}")"
audit_receipt_verified="$(provided_or_choose audit_receipt_verified "$audit_receipt_ref")"
rollback_verified="$(provided_or_choose rollback_verified "$rollback_ref")"
operator_approval="$(provided_or_choose operator_approval "$operator_approval_ref")"

output_path="$output_arg"
group_name="${SHIELD_SERVICE_GROUP:-xibalba-shield}"
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

echo "Running disposable responder probes. No production process or network flow is targeted."
"${runner[@]}" "$repo_root/scripts/verify_responder_gates.py" \
  --device-id "$device_id" \
  --output "$output_path" \
  --group "$group_name" \
  --base-proof "policy_signature_verified=$policy_signature_verified" \
  --base-proof "agent_identity_verified=$agent_identity_verified" \
  --base-proof "kernel_probe_verified=$kernel_probe_verified" \
  --base-proof "audit_receipt_verified=$audit_receipt_verified" \
  --base-proof "rollback_verified=$rollback_verified" \
  --base-proof "operator_approval=$operator_approval"

echo
echo "Readiness artifact created: $output_path"
echo "Next step: configure SHIELD_RESPONDER_ARGS and restart xibalba-shield.service after reviewing the JSON."
