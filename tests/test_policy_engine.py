from __future__ import annotations

from shield.policy_engine.engine import EvaluationContext, PolicyEngine
from shield.schemas.events import (
    Activity,
    AgentActivity,
    AgentContext,
    AgentEvent,
    AgentInfo,
    ProcessActivity,
    ProcessInfo,
)
from shield.schemas.policy_rule import Condition, PolicyRule, RuleAction


def _ctx(**kwargs) -> EvaluationContext:
    return EvaluationContext(tenant_id="tenant-xyz", device_role="clinical_desktop", device_id="dev-1", **kwargs)


def test_no_rules_allows_by_default():
    engine = PolicyEngine(rules=[])
    event = ProcessActivity(
        device_id="dev-1",
        process=ProcessInfo(pid=1, name="python"),
        activity=Activity(type="launch"),
    )
    decision = engine.evaluate(event, _ctx())
    assert decision.decision.action == "allow"
    assert decision.rule.rule_id == "_no_match"


def test_decision_includes_policy_identity_when_configured():
    engine = PolicyEngine(rules=[], policy_version="pilot-1", policy_hash="sha256:abc")
    event = ProcessActivity(
        device_id="dev-1",
        process=ProcessInfo(pid=1, name="python"),
        activity=Activity(type="launch"),
    )

    decision = engine.evaluate(event, _ctx())

    assert decision.policy.version == "pilot-1"
    assert decision.policy.hash == "sha256:abc"
    assert decision.to_dict()["policy"] == {"version": "pilot-1", "hash": "sha256:abc"}


def test_glob_match_on_exe_path_denies():
    rule = PolicyRule.from_dict({
        "rule_id": "proc-restrict-shadow-ai",
        "name": "Restrict shadow AI processes",
        "version": "1.0.0",
        "conditions": [{"type": "process", "match": {"exe_path": ["*/ai/*.exe"]}}],
        "actions": [{"type": "contain", "message": "Unregistered AI tool blocked."}],
    })
    engine = PolicyEngine(rules=[rule])
    event = ProcessActivity(
        device_id="dev-1",
        process=ProcessInfo(pid=1, name="shadow.exe", exe_path="/opt/ai/shadow.exe"),
        activity=Activity(type="launch"),
    )
    decision = engine.evaluate(event, _ctx())
    assert decision.decision.action == "contain"
    assert decision.rule.rule_id == "proc-restrict-shadow-ai"


def test_non_matching_path_falls_through_to_allow():
    rule = PolicyRule.from_dict({
        "rule_id": "proc-restrict-shadow-ai",
        "name": "x",
        "version": "1.0.0",
        "conditions": [{"type": "process", "match": {"exe_path": ["*/ai/*.exe"]}}],
        "actions": [{"type": "contain"}],
    })
    engine = PolicyEngine(rules=[rule])
    event = ProcessActivity(
        device_id="dev-1",
        process=ProcessInfo(pid=1, name="bash", exe_path="/bin/bash"),
        activity=Activity(type="launch"),
    )
    decision = engine.evaluate(event, _ctx())
    assert decision.decision.action == "allow"


def test_unregistered_agent_condition_matches_when_not_in_registry():
    rule = PolicyRule.from_dict({
        "rule_id": "agent-restrict-unregistered",
        "name": "x",
        "version": "1.0.0",
        "conditions": [{"type": "agent", "match": {"registered": [False]}}],
        "actions": [{"type": "deny"}],
    })
    engine = PolicyEngine(rules=[rule])
    event = AgentEvent(
        device_id="dev-1",
        agent=AgentInfo(agent_id="unknown-agent", name="unknown"),
        context=AgentContext(),
        activity=AgentActivity(type="inference"),
    )
    decision = engine.evaluate(event, _ctx(registered_agent_ids=frozenset()))
    assert decision.decision.action == "deny"


def test_unregistered_agent_condition_does_not_match_non_agent_event():
    rule = PolicyRule.from_dict({
        "rule_id": "agent-restrict-unregistered",
        "name": "x",
        "version": "1.0.0",
        "conditions": [{"type": "agent", "match": {"registered": [False]}}],
        "actions": [{"type": "deny"}],
    })
    engine = PolicyEngine(rules=[rule])
    event = ProcessActivity(
        device_id="dev-1",
        process=ProcessInfo(pid=1, name="bash"),
        activity=Activity(type="launch"),
    )

    decision = engine.evaluate(event, _ctx(registered_agent_ids=frozenset()))

    assert decision.decision.action == "allow"
    assert decision.rule.rule_id == "_no_match"


def test_registered_agent_does_not_match_unregistered_condition():
    rule = PolicyRule.from_dict({
        "rule_id": "agent-restrict-unregistered",
        "name": "x",
        "version": "1.0.0",
        "conditions": [{"type": "agent", "match": {"registered": [False]}}],
        "actions": [{"type": "deny"}],
    })
    engine = PolicyEngine(rules=[rule])
    event = AgentEvent(
        device_id="dev-1",
        agent=AgentInfo(agent_id="known-agent", name="known"),
        context=AgentContext(),
        activity=AgentActivity(type="inference"),
    )
    decision = engine.evaluate(event, _ctx(registered_agent_ids=frozenset({"known-agent"})))
    assert decision.decision.action == "allow"
    assert decision.rule.rule_id == "_no_match"


def test_scope_mismatch_skips_rule():
    rule = PolicyRule.from_dict({
        "rule_id": "scoped-rule",
        "name": "x",
        "version": "1.0.0",
        "scope": {"tenants": ["some-other-tenant"]},
        "conditions": [{"type": "process", "match": {"name": ["python"]}}],
        "actions": [{"type": "deny"}],
    })
    engine = PolicyEngine(rules=[rule])
    event = ProcessActivity(device_id="dev-1", process=ProcessInfo(pid=1, name="python"), activity=Activity(type="launch"))
    decision = engine.evaluate(event, _ctx())  # tenant-xyz, not in scope's tenants list
    assert decision.decision.action == "allow"
    assert decision.rule.rule_id == "_no_match"


def test_first_match_wins_over_later_matching_rule():
    rule_a = PolicyRule.from_dict({
        "rule_id": "a-allow",
        "name": "x", "version": "1.0.0",
        "conditions": [{"type": "process", "match": {"name": ["python"]}}],
        "actions": [{"type": "log_only"}],
    })
    rule_b = PolicyRule.from_dict({
        "rule_id": "b-deny",
        "name": "x", "version": "1.0.0",
        "conditions": [{"type": "process", "match": {"name": ["python"]}}],
        "actions": [{"type": "deny"}],
    })
    engine = PolicyEngine(rules=[rule_a, rule_b])
    event = ProcessActivity(device_id="dev-1", process=ProcessInfo(pid=1, name="python"), activity=Activity(type="launch"))
    decision = engine.evaluate(event, _ctx())
    assert decision.rule.rule_id == "a-allow"
    assert decision.decision.action == "log_only"


def test_every_evaluation_produces_a_decision_even_when_allowed():
    """spec §4.3: log_only and allow are as visible in the audit trail as a deny."""
    engine = PolicyEngine(rules=[])
    event = ProcessActivity(device_id="dev-1", process=ProcessInfo(pid=1, name="bash"), activity=Activity(type="launch"))
    decision = engine.evaluate(event, _ctx())
    assert decision is not None
    assert decision.event_ref.event_id.startswith("evt-")


def test_context_condition_matches_model_endpoint():
    """The model-routing guardrail hook depends entirely on this: a rule naming
    context.model_endpoint must be able to actually match."""
    rule = PolicyRule.from_dict({
        "rule_id": "block-unapproved-model",
        "name": "x", "version": "1.0.0",
        "conditions": [{"type": "context", "match": {"model_endpoint": ["https://unapproved.example/*"]}}],
        "actions": [{"type": "deny"}],
    })
    engine = PolicyEngine(rules=[rule])
    event = AgentEvent(
        device_id="dev-1",
        agent=AgentInfo(agent_id="a1", name="a1"),
        context=AgentContext(model_endpoint="https://unapproved.example/v1"),
        activity=AgentActivity(type="model_routing"),
    )
    decision = engine.evaluate(event, _ctx())
    assert decision.decision.action == "deny"


def test_context_condition_matches_element_inside_data_sources_list():
    """context.data_sources is a list -- the rule names one value, the event carries several;
    the match must be containment, not list equality."""
    rule = PolicyRule.from_dict({
        "rule_id": "flag-ehr-access",
        "name": "x", "version": "1.0.0",
        "conditions": [{"type": "context", "match": {"data_sources": ["ehr_encounter"]}}],
        "actions": [{"type": "escalate"}],
    })
    engine = PolicyEngine(rules=[rule])
    event = AgentEvent(
        device_id="dev-1",
        agent=AgentInfo(agent_id="a1", name="a1"),
        context=AgentContext(data_sources=["billing_db", "ehr_encounter"]),
        activity=AgentActivity(type="retrieval"),
    )
    decision = engine.evaluate(event, _ctx())
    assert decision.decision.action == "escalate"


def test_activity_condition_matches_risk_level():
    """The output guardrail hook depends entirely on this: a rule naming activity.risk_level
    must be able to actually match."""
    rule = PolicyRule.from_dict({
        "rule_id": "block-high-risk-output",
        "name": "x", "version": "1.0.0",
        "conditions": [{"type": "activity", "match": {"risk_level": ["high", "critical"]}}],
        "actions": [{"type": "deny"}],
    })
    engine = PolicyEngine(rules=[rule])
    event = AgentEvent(
        device_id="dev-1",
        agent=AgentInfo(agent_id="a1", name="a1"),
        context=AgentContext(),
        activity=AgentActivity(type="output:phi", risk_level="high"),
    )
    decision = engine.evaluate(event, _ctx())
    assert decision.decision.action == "deny"
