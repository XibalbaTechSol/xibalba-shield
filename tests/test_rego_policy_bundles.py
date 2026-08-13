from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).parents[1]
POLICY_DIR = ROOT / "policies" / "rego"


@pytest.fixture(scope="module")
def opa() -> str:
    executable = shutil.which("opa")
    if executable is None:
        pytest.skip("OPA executable is required for Rego policy integration tests")
    return executable


def evaluate(opa: str, policy: str, payload: dict) -> dict:
    result = subprocess.run(
        [opa, "eval", "--format", "json", "-d", str(POLICY_DIR / policy), "data.shield.policy", "-i", "/dev/stdin"],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        check=True,
    )
    return json.loads(result.stdout)["result"][0]["expressions"][0]["value"]


def ctx(*registered: str) -> dict:
    return {"registered_agent_ids": {agent_id: True for agent_id in registered}}


def test_professional_services_rules_and_default(opa: str):
    assert evaluate(opa, "professional-services.rego", {"event": {"agent": {"agent_id": "a"}}, "ctx": ctx()})["rule_id"] == "ps-deny-unregistered-agents"
    assert evaluate(opa, "professional-services.rego", {"event": {"context": {"model_endpoint": "http://example"}}, "ctx": ctx("a")})["rule_id"] == "ps-deny-unapproved-model-routing"
    assert evaluate(opa, "professional-services.rego", {"event": {"context": {"data_sources": ["customer_records"]}}, "ctx": ctx("a")})["rule_id"] == "ps-escalate-client-data-context"
    assert evaluate(opa, "professional-services.rego", {"event": {"context": {"model_endpoint": "https://approved.example"}}, "ctx": ctx("a")})["rule_id"] == "_no_match"


def test_regulated_rules_and_precedence(opa: str):
    assert evaluate(opa, "regulated.rego", {"event": {"agent": {"agent_id": "a"}}, "ctx": ctx()})["rule_id"] == "regulated-deny-unregistered-agents"
    assert evaluate(opa, "regulated.rego", {"event": {"context": {"data_sources": ["claims_phi"]}}, "ctx": ctx("a")})["rule_id"] == "regulated-deny-phi-context"
    assert evaluate(opa, "regulated.rego", {"event": {"activity": {"risk_level": "critical"}}, "ctx": ctx("a")})["rule_id"] == "regulated-deny-high-risk-output"
    assert evaluate(opa, "regulated.rego", {"event": {"file": {"path": "/var/secrets/app.key"}}, "ctx": ctx("a")})["rule_id"] == "regulated-escalate-sensitive-write"


def test_smb_unregistered_agent_is_denied(opa: str):
    denied = evaluate(opa, "smb.rego", {"event": {"agent": {"agent_id": "missing"}}, "ctx": ctx()})
    assert denied["rule_id"] == "smb-deny-unregistered-agent-tools"
    assert denied["action"] == "deny"

    registered = evaluate(opa, "smb.rego", {"event": {"agent": {"agent_id": "known"}}, "ctx": ctx("known")})
    assert registered["rule_id"] == "_no_match"


def test_smb_overlapping_matches_use_json_order(opa: str):
    payload = {"event": {"process": {"exe_path": "/opt/ai/tool"}, "file": {"path": "/etc/shield.conf"}}, "ctx": ctx()}
    result = evaluate(opa, "smb.rego", payload)
    assert result["rule_id"] == "smb-contain-shadow-ai-processes"
    assert result["action"] == "contain"
