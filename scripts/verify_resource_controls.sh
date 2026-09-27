#!/usr/bin/env bash
set -euo pipefail

agent_unit=${AGENT_UNIT:-xibalba-shield.service}
helper_unit=${HELPER_UNIT:-xibalba-shield-ebpf-helper.service}
logrotate_file=${LOGROTATE_FILE:-/etc/logrotate.d/xibalba-shield}
failed=0

check_unit_property() {
  local unit=$1 property=$2 expected=$3 actual
  actual=$(systemctl show "$unit" -p "$property" --value 2>/dev/null || true)
  if [[ "$actual" == "$expected" ]]; then
    printf 'PASS %s %s=%s\n' "$unit" "$property" "$actual"
  else
    printf 'FAIL %s %s=%s (expected %s)\n' "$unit" "$property" "${actual:-<unset>}" "$expected"
    failed=1
  fi
}

check_unit_property "$agent_unit" MemoryMax 134217728
check_unit_property "$agent_unit" MemorySwapMax 134217728
check_unit_property "$agent_unit" CPUQuotaPerSecUSec 250ms
check_unit_property "$agent_unit" TasksMax 64

check_unit_property "$helper_unit" MemoryMax 268435456
check_unit_property "$helper_unit" MemorySwapMax 268435456
check_unit_property "$helper_unit" CPUQuotaPerSecUSec 500ms
check_unit_property "$helper_unit" TasksMax 64

if [[ -r "$logrotate_file" ]] \
  && grep -Eq '^\s*size\s+100M\s*$' "$logrotate_file" \
  && grep -Eq '^\s*rotate\s+7\s*$' "$logrotate_file" \
  && grep -Eq '^\s*copytruncate\s*$' "$logrotate_file"; then
  printf 'PASS logrotate %s (100M/7/copytruncate)\n' "$logrotate_file"
else
  printf 'FAIL logrotate %s (expected size=100M, rotate=7, copytruncate)\n' "$logrotate_file"
  failed=1
fi

exit "$failed"
