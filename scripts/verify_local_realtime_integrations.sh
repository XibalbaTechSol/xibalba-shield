#!/usr/bin/env bash
set -euo pipefail

# Read-only smoke test for the disposable local Shield + Integrity lab.
# It does not restart services, flush queues, alter configuration, or print
# telemetry payloads, credentials, tokens, or private keys.

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run with sudo: sudo ./scripts/verify_local_realtime_integrations.sh" >&2
  exit 1
fi

device_config="${SHIELD_DEVICE_CONFIG:-/etc/xibalba-shield/device.json}"
did_file="${INTEGRITY_DID_FILE:-/var/lib/xibalba-shield/integrity/did/xibalba-shield/document.json}"
oracle_url="${ORACLE_URL:-http://127.0.0.1:8080}"
bcc_url="${BCC_MIDDLEWARE_URL:-http://127.0.0.1:8001}"
backend_url="${SHIELD_BACKEND_URL:-http://127.0.0.1:8421}"
service="${SHIELD_SERVICE:-xibalba-shield.service}"
backend_service="${SHIELD_BACKEND_SERVICE:-xibalba-shield-backend.service}"
since="$(date --iso-8601=seconds)"
failures=0

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "FAIL missing command: $1"
    failures=$((failures + 1))
  }
}

pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; failures=$((failures + 1)); }
info() { echo "INFO $*"; }

need curl
need python3
need systemctl
[[ "$failures" -eq 0 ]] || exit 2

json_value() {
  python3 - "$1" "$2" <<'PY'
import json, sys
path, key = sys.argv[1:]
try:
    data = json.load(open(path, encoding="utf-8"))
    value = data.get(key, "")
except Exception:
    value = ""
print(value if isinstance(value, str) else "")
PY
}

if [[ -f "$did_file" ]]; then
  active_did="$(json_value "$did_file" id)"
else
  active_did=""
fi
if [[ "$active_did" == did:integrity:* ]]; then
  pass "active DID document is present"
else
  fail "active DID document is missing or invalid: $did_file"
fi

if [[ -f "$device_config" ]]; then
  device_id="$(json_value "$device_config" device_id)"
  configured_backend="$(json_value "$device_config" backend_url)"
  info "device=$device_id backend_url=$configured_backend"
else
  fail "device config is missing: $device_config"
  device_id=""
fi

if systemctl is-active --quiet "$service"; then
  pass "$service is active"
else
  fail "$service is not active"
fi

check_http() {
  local label="$1" url="$2"
  local body status
  body="$(mktemp)"
  status="$(curl --connect-timeout 2 --max-time 5 --silent --show-error \
    --output "$body" --write-out '%{http_code}' "$url" 2>/dev/null || true)"
  if [[ "$status" == "200" ]]; then
    pass "$label HTTP 200"
  else
    fail "$label HTTP ${status:-unreachable} ($url)"
    sed -n '1,3p' "$body" | sed 's/[[:space:]]\+/ /g' | cut -c1-240 | sed 's/^/INFO response: /'
  fi
  rm -f "$body"
}

check_http "Shield backend health" "$backend_url/api/shield/health"
check_http "Integrity Oracle health" "$oracle_url/healthz"
check_http "BCC middleware health" "$bcc_url/health"

if [[ "$active_did" == did:integrity:* ]]; then
  agent_body="$(mktemp)"
  agent_status="$(curl --connect-timeout 2 --max-time 5 --silent --show-error \
    --output "$agent_body" --write-out '%{http_code}' \
    "$oracle_url/v1/agent/$active_did" 2>/dev/null || true)"
  if [[ "$agent_status" == "200" ]]; then
    registered="$(python3 - "$agent_body" <<'PY'
import json, sys
try:
    value = json.load(open(sys.argv[1], encoding="utf-8")).get("oracle_registered")
except Exception:
    value = None
print(str(value).lower())
PY
    )"
    if [[ "$registered" == "true" ]]; then
      pass "active DID is registered with local Oracle"
    else
      fail "local Oracle responded, but active DID is not registered"
    fi
  else
    fail "local Oracle DID lookup HTTP ${agent_status:-unreachable}"
  fi
  rm -f "$agent_body"

  telemetry_body="$(mktemp)"
  telemetry_status="$(curl --connect-timeout 2 --max-time 5 --silent --show-error \
    --output "$telemetry_body" --write-out '%{http_code}' \
    "$oracle_url/v1/agent/$active_did/telemetry" 2>/dev/null || true)"
  if [[ "$telemetry_status" == "200" ]]; then
    telemetry_count="$(python3 - "$telemetry_body" <<'PY'
import json, sys
try:
    value = json.load(open(sys.argv[1], encoding="utf-8"))
    print(len(value) if isinstance(value, list) else "unknown")
except Exception:
    print("unknown")
PY
    )"
    info "Oracle persisted telemetry rows=$telemetry_count"
    if [[ "$telemetry_count" != "0" && "$telemetry_count" != "unknown" ]]; then
      pass "Oracle has persisted telemetry for the active DID"
    else
      fail "Oracle has no persisted telemetry for the active DID"
    fi
  else
    fail "Oracle telemetry lookup HTTP ${telemetry_status:-unreachable}"
  fi
  rm -f "$telemetry_body"
fi

info "fresh Shield exporter/backend log summary since $since"
logs="$(journalctl -u "$service" --since "$since" --no-pager 2>/dev/null || true)"
if [[ -z "$logs" ]]; then
  info "no new Shield journal lines captured; run this while the agent is emitting events"
else
  printf '%s\n' "$logs" | grep -E 'telemetry flush|400 Client|401|403|not registered|RemoteDisconnected|publication failed|re-queued|success' \
    | sed -E 's/CLIENT SIGNABLE BYTES: .*/CLIENT SIGNABLE BYTES: [redacted]/' \
    | tail -40 | sed 's/^/INFO /' || true
  if printf '%s\n' "$logs" | grep -Eq '400 Client|telemetry flush .*failed|re-queued|RemoteDisconnected|publication failed'; then
    fail "fresh logs contain exporter or backend publication errors"
  else
    pass "no known exporter/backend publication errors in fresh Shield logs"
  fi
fi

if systemctl is-active --quiet "$backend_service"; then
  pass "$backend_service is active"
else
  fail "$backend_service is not active"
fi

info "recent backend journal (errors/status only; payloads omitted)"
journalctl -u "$backend_service" --since "$since" --no-pager 2>/dev/null \
  | grep -Ei 'error|exception|traceback|400|401|403|502|500|disconnect|started|active' \
  | tail -30 | sed 's/^/INFO /' || true

if command -v docker >/dev/null 2>&1; then
  if docker inspect integrity-core-oracle-backend-1 >/dev/null 2>&1; then
    info "recent Oracle container status"
    docker inspect --format 'INFO oracle_container status={{.State.Status}} health={{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' integrity-core-oracle-backend-1 2>/dev/null || true
    docker logs integrity-core-oracle-backend-1 --since 2m 2>&1 \
      | grep -Ei 'error|warn|400|401|403|500|bad request|telemetry|panic' \
      | tail -30 | sed 's/^/INFO oracle: /' || true
  else
    info "Oracle container integrity-core-oracle-backend-1 not found"
  fi
fi

echo
if [[ "$failures" -eq 0 ]]; then
  echo "RESULT PASS — local realtime integration checks are healthy."
else
  echo "RESULT FAIL — $failures check(s) need attention. No state was changed."
fi
exit "$([[ "$failures" -eq 0 ]] && echo 0 || echo 1)"
