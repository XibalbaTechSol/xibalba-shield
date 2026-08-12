from __future__ import annotations

from unittest.mock import patch, AsyncMock

import pytest

from integrity_sdk.policy.opa_client import OPADecision, OPAUnavailableError
from shield.policy_engine.engine import EvaluationContext, PolicyEngine
from shield.schemas.events import (
    Activity,
    ProcessActivity,
    ProcessInfo,
)


def _ctx(**kwargs) -> EvaluationContext:
    return EvaluationContext(tenant_id="tenant-xyz", device_role="clinical_desktop", device_id="dev-1", **kwargs)


@patch("shield.policy_engine.engine.opa_evaluate", new_callable=AsyncMock)
def test_opa_decision_translates_to_policy_decision(mock_evaluate):
    mock_evaluate.return_value = OPADecision(
        allow=False,
        raw_result={
            "action": "contain",
            "message": "Blocked shadow AI",
            "rule_id": "proc-restrict-shadow-ai",
            "name": "Restrict shadow AI processes",
            "version": "1.0.0"
        }
    )
    
    engine = PolicyEngine(policy_version="pilot-1", policy_hash="sha256:abc")
    event = ProcessActivity(
        device_id="dev-1",
        process=ProcessInfo(pid=1, name="shadow.exe", exe_path="/opt/ai/shadow.exe"),
        activity=Activity(type="launch"),
    )
    decision = engine.evaluate(event, _ctx())
    
    assert decision.decision.action == "contain"
    assert decision.rule.rule_id == "proc-restrict-shadow-ai"
    assert decision.policy.version == "pilot-1"
    assert decision.policy.hash == "sha256:abc"
    
    mock_evaluate.assert_called_once()
    args, kwargs = mock_evaluate.call_args
    assert "opa_input" in kwargs
    assert "event" in kwargs["opa_input"]
    assert "ctx" in kwargs["opa_input"]


@patch("shield.policy_engine.engine.opa_evaluate", new_callable=AsyncMock)
def test_opa_allow_translates_to_policy_decision(mock_evaluate):
    mock_evaluate.return_value = OPADecision(
        allow=True,
        raw_result={
            "action": "allow",
            "message": "no policy rule matched",
        }
    )
    
    engine = PolicyEngine()
    event = ProcessActivity(
        device_id="dev-1",
        process=ProcessInfo(pid=1, name="bash", exe_path="/bin/bash"),
        activity=Activity(type="launch"),
    )
    decision = engine.evaluate(event, _ctx())
    
    assert decision.decision.action == "allow"
    assert decision.rule.rule_id == "_no_match"


@patch("shield.policy_engine.engine.opa_evaluate", new_callable=AsyncMock)
def test_opa_unavailable_fails_closed(mock_evaluate):
    mock_evaluate.side_effect = OPAUnavailableError("Connection refused")
    
    engine = PolicyEngine()
    event = ProcessActivity(
        device_id="dev-1",
        process=ProcessInfo(pid=1, name="bash", exe_path="/bin/bash"),
        activity=Activity(type="launch"),
    )
    decision = engine.evaluate(event, _ctx())
    
    assert decision.decision.action == "deny"
    assert decision.decision.severity == "high"
    assert decision.rule.rule_id == "_opa_unavailable"

