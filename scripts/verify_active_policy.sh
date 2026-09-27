#!/usr/bin/env bash
set -euo pipefail

# Read-only live policy verification. This evaluates safe JSON fixtures through
# the local OPA sidecar; it never launches, kills, freezes, or blocks anything.

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run with sudo: sudo ./scripts/verify_active_policy.sh" >&2
  exit 1
fi

policy_file="${SHIELD_POLICY_FILE:-/etc/xibalba-shield/policies/current.json}"
device_file="${SHIELD_DEVICE_CONFIG:-/etc/xibalba-shield/device.json}"
opa_url="${SHIELD_OPA_URL:-http://127.0.0.1:8181}"
shield_bin="${SHIELD_BIN:-/opt/xibalba-shield/venv/bin/shield}"

[[ -f "$policy_file" ]] || { echo "Missing policy: $policy_file" >&2; exit 1; }
[[ -f "$device_file" ]] || { echo "Missing device config: $device_file" >&2; exit 1; }
[[ -x "$shield_bin" ]] || { echo "Missing Shield binary: $shield_bin" >&2; exit 1; }

echo "Validating active policy bundle..."
"$shield_bin" validate --rules "$policy_file" --device-config "$device_file"

echo "Checking local OPA..."
curl --fail --silent --show-error --max-time 5 "$opa_url/health" >/dev/null
echo "PASS OPA health"

python3 - "$policy_file" "$opa_url" <<'PY'
import json
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

policy_path, opa_url = sys.argv[1:]
policy = json.load(open(policy_path, encoding="utf-8"))
version = str(policy.get("policy_version", ""))

def event(**fields):
    value = {
        "class": "policy_test",
        "device_id": "policy-test-device",
        "tenant_id": "tenant-a",
        "activity": {"type": "test", "severity": "low", "outcome": "success"},
    }
    value.update(fields)
    return value

cases = [
    ("neutral", event(), {"registered_agent_ids": {}}),
]
if version.startswith("regulated-"):
    cases += [
        ("unregistered-agent", event(agent={"agent_id": "did:test:unregistered"}), {"registered_agent_ids": {}}),
        ("phi-context", event(context={"data_sources": ["patient_record"]}), {"registered_agent_ids": {}}),
        ("high-risk-output", event(activity={"type": "output", "severity": "high", "risk_level": "high", "outcome": "success"}), {"registered_agent_ids": {}}),
        ("sensitive-write", event(file={"path": "/etc/shield/policy-test"}), {"registered_agent_ids": {}}),
    ]
elif version.startswith("smb-"):
    cases += [
        ("shadow-ai-process", event(process={"exe_path": "/opt/ai/shadow-agent/run"}), {"registered_agent_ids": {}}),
        ("unregistered-agent", event(agent={"agent_id": "did:test:unregistered"}), {"registered_agent_ids": {}}),
        ("sensitive-write", event(file={"path": "/etc/shield/policy-test"}), {"registered_agent_ids": {}}),
    ]
elif version.startswith("professional-services-"):
    cases += [
        ("unregistered-agent", event(agent={"agent_id": "did:test:unregistered"}), {"registered_agent_ids": {}}),
        ("sensitive-context", event(context={"data_sources": ["customer_records"]}), {"registered_agent_ids": {}}),
    ]
else:
    print(f"INFO unrecognized policy profile {version!r}; testing neutral case only")

expected = {"regulated-": {"neutral": "log_only", "unregistered-agent": "deny", "phi-context": "deny", "high-risk-output": "deny", "sensitive-write": "escalate"},
            "smb-": {"neutral": "log_only", "shadow-ai-process": "contain", "unregistered-agent": "deny", "sensitive-write": "escalate"},
            "professional-services-": {"neutral": "log_only", "unregistered-agent": "deny", "sensitive-context": "escalate"}}
profile = next((key for key in expected if version.startswith(key)), "")
failures = 0
for name, ev, ctx in cases:
    payload = json.dumps({"input": {"event": ev, "ctx": ctx}}).encode()
    request = Request(f"{opa_url.rstrip('/')}/v1/data/shield/policy", data=payload, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urlopen(request, timeout=5) as response:
            body = json.load(response)
        result = body.get("result") or {}
        action = result.get("action")
        rule_id = result.get("rule_id")
        wanted = expected.get(profile, {}).get(name)
        if wanted is not None and action != wanted:
            print(f"FAIL {name}: action={action!r} rule={rule_id!r}, expected={wanted!r}")
            failures += 1
        else:
            print(f"PASS {name}: action={action!r} rule={rule_id!r}")
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as exc:
        print(f"FAIL {name}: OPA evaluation failed: {exc}")
        failures += 1

if failures:
    raise SystemExit(failures)
print(f"RESULT PASS — {len(cases)} live policy evaluations matched the active profile.")
PY
