from __future__ import annotations

from unittest.mock import patch, AsyncMock

import pytest

from integrity_sdk.policy.opa_client import OPADecision, OPAUnavailableError
from shield.policy_engine.engine import EvaluationContext, PolicyEngine
from shield.opa_local import selected_profile_metadata, supervised_opa
from shield.schemas.events import (
    Activity,
    AgentActivity,
    AgentContext,
    AgentEvent,
    AgentInfo,
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


@pytest.mark.parametrize(
    (
        "registered_agent_ids",
        "model_endpoint",
        "data_sources",
        "expected_action",
        "expected_rule_id",
        "expected_reason",
    ),
    [
        (
            frozenset(),
            "https://unapproved.example/v1/chat/completions",
            ["customer_records"],
            "deny",
            "ps-deny-unregistered-agents",
            "Unregistered agent activity denied.",
        ),
        (
            frozenset({"agent-1"}),
            "https://unapproved.example/v1/chat/completions",
            ["customer_records"],
            "deny",
            "ps-deny-unapproved-model-routing",
            "Model endpoint is not approved for this tenant.",
        ),
        (
            frozenset({"agent-1"}),
            "https://approved.example/v1/chat/completions",
            ["customer_records"],
            "escalate",
            "ps-escalate-client-data-context",
            "Client data source attached to agent context.",
        ),
    ],
)
def test_professional_services_combined_agent_context_precedence_with_real_opa(
    registered_agent_ids,
    model_endpoint,
    data_sources,
    expected_action,
    expected_rule_id,
    expected_reason,
):
    policy_version, policy_hash = selected_profile_metadata("professional-services")
    event = AgentEvent(
        device_id="dev-1",
        agent=AgentInfo(agent_id="agent-1", name="Case Review Agent"),
        context=AgentContext(
            model_endpoint=model_endpoint,
            data_sources=data_sources,
            tools_called=["summarize_contract"],
        ),
        activity=AgentActivity(type="inference", risk_level="medium"),
    )

    with supervised_opa("professional-services") as opa_url:
        decision = PolicyEngine(
            opa_url=opa_url,
            policy_version=policy_version,
            policy_hash=policy_hash,
        ).evaluate(event, _ctx(registered_agent_ids=registered_agent_ids))

    assert decision.event_ref.klass == "agent_event"
    assert decision.policy.version == policy_version
    assert decision.policy.hash == policy_hash
    assert decision.decision.action == expected_action
    assert decision.decision.reason == expected_reason
    assert decision.decision.severity == "medium"
    assert decision.rule.rule_id == expected_rule_id
    assert decision.rule.version == "1.0.0"
