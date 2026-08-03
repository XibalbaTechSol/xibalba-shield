"""
Tests for the five guardrail hooks in shield/guardrail_hooks/ (spec §4.4), beyond
tool_execution.py (already covered indirectly via test_agent_core.py's router tests).

Each hook is tested for both directions: an allow-path invokes the wrapped call and returns
its result, and a deny-path raises the hook's own exception WITHOUT invoking the call --
proving the gate actually gates, not just logs. post_action_verification has no call to
wrap (the action already happened), so its tests check the returned PolicyDecision/exception
directly instead.
"""

from __future__ import annotations

import pytest

from shield.agent_core.registry import AgentRegistry, DeviceContext
from shield.agent_core.router import EventRouter
from shield.guardrail_hooks import (
    IngressDenied,
    ModelRoutingDenied,
    OutputBlocked,
    PostActionAnomaly,
    RetrievalDenied,
    guard_ingress,
    guard_model_routing,
    guard_output,
    guard_retrieval,
    verify_post_action,
)
from shield.policy_engine.engine import PolicyEngine
from shield.schemas.policy_rule import PolicyRule


class _RecordingExporter:
    def export_event(self, event):
        pass

    def export_decision(self, decision):
        return {"authorized": True}


def _router(rules=()):
    return EventRouter(
        device=DeviceContext(device_id="dev-1", tenant_id="t", device_role="workstation"),
        registry=AgentRegistry(),
        policy_engine=PolicyEngine(rules=list(rules)),
        exporter=_RecordingExporter(),
    )


def _deny_rule(rule_id: str, condition_type: str, match: dict) -> PolicyRule:
    return PolicyRule.from_dict({
        "rule_id": rule_id,
        "name": rule_id,
        "version": "1.0.0",
        "conditions": [{"type": condition_type, "match": match}],
        "actions": [{"type": "deny", "message": f"blocked by {rule_id}"}],
    })


# ---- ingress ----

def test_guard_ingress_allows_and_invokes_call_by_default():
    calls = []
    result = guard_ingress(_router(), agent_id="a1", agent_name="Agent", call=lambda: calls.append(1) or "ok")
    assert result == "ok"
    assert calls == [1]


def test_guard_ingress_denies_and_never_invokes_call():
    router = _router(rules=[_deny_rule("deny-all-agents", "agent", {"agent_id": ["a1"]})])
    calls = []
    with pytest.raises(IngressDenied):
        guard_ingress(router, agent_id="a1", agent_name="Agent", call=lambda: calls.append(1))
    assert calls == []


# ---- retrieval/context ----

def test_guard_retrieval_allows_and_invokes_call_by_default():
    calls = []
    result = guard_retrieval(
        _router(), agent_id="a1", agent_name="Agent", data_sources=["billing_db"],
        call=lambda: calls.append(1) or "retrieved",
    )
    assert result == "retrieved"
    assert calls == [1]


def test_guard_retrieval_denies_ehr_access_and_never_invokes_call():
    router = _router(rules=[_deny_rule("deny-ehr", "context", {"data_sources": ["ehr_encounter"]})])
    calls = []
    with pytest.raises(RetrievalDenied):
        guard_retrieval(
            router, agent_id="a1", agent_name="Agent", data_sources=["ehr_encounter"],
            call=lambda: calls.append(1),
        )
    assert calls == []


def test_guard_retrieval_allows_unrelated_data_source():
    router = _router(rules=[_deny_rule("deny-ehr", "context", {"data_sources": ["ehr_encounter"]})])
    result = guard_retrieval(router, agent_id="a1", agent_name="Agent", data_sources=["billing_db"], call=lambda: "ok")
    assert result == "ok"


# ---- model routing ----

def test_guard_model_routing_allows_and_invokes_call_by_default():
    result = guard_model_routing(
        _router(), agent_id="a1", agent_name="Agent", model_endpoint="https://approved.example/v1",
        call=lambda: "routed",
    )
    assert result == "routed"


def test_guard_model_routing_denies_unapproved_endpoint_and_never_invokes_call():
    router = _router(rules=[_deny_rule("deny-unapproved", "context", {"model_endpoint": ["https://unapproved.example/*"]})])
    calls = []
    with pytest.raises(ModelRoutingDenied):
        guard_model_routing(
            router, agent_id="a1", agent_name="Agent", model_endpoint="https://unapproved.example/v1",
            call=lambda: calls.append(1),
        )
    assert calls == []


# ---- output ----

def test_guard_output_allows_low_risk_by_default():
    result = guard_output(_router(), agent_id="a1", agent_name="Agent", risk_level="low", call=lambda: "released")
    assert result == "released"


def test_guard_output_denies_high_risk_and_never_invokes_call():
    router = _router(rules=[_deny_rule("deny-high-risk", "activity", {"risk_level": ["high", "critical"]})])
    calls = []
    with pytest.raises(OutputBlocked):
        guard_output(
            router, agent_id="a1", agent_name="Agent", risk_level="high", categories=["phi"],
            call=lambda: calls.append(1),
        )
    assert calls == []


# ---- post-action verification ----

def test_verify_post_action_matching_hashes_is_low_risk_and_returns_decision():
    router = _router()
    decision = verify_post_action(
        router, agent_id="a1", agent_name="Agent", tool_name="write_file",
        expected_state_hash="0xabc", actual_state_hash="0xabc",
    )
    assert decision.decision.action == "allow"


def test_verify_post_action_mismatched_hashes_raises_when_a_rule_flags_it():
    router = _router(rules=[_deny_rule("flag-mismatch", "activity", {"policy_violation": [True]})])
    with pytest.raises(PostActionAnomaly):
        verify_post_action(
            router, agent_id="a1", agent_name="Agent", tool_name="write_file",
            expected_state_hash="0xabc", actual_state_hash="0xdef",
        )


def test_verify_post_action_mismatch_without_a_matching_rule_still_returns_a_decision():
    """No exception when nothing is configured to react to the mismatch -- the hook still
    reports it (policy_violation would be visible in the exported event), it just doesn't
    force an exception on a caller who hasn't asked to be told."""
    router = _router()
    decision = verify_post_action(
        router, agent_id="a1", agent_name="Agent", tool_name="write_file",
        expected_state_hash="0xabc", actual_state_hash="0xdef",
    )
    assert decision.decision.action == "allow"  # no rule matched -> default allow, per engine's own rule
