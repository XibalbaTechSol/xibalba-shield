from __future__ import annotations

from unittest.mock import Mock, patch

import pytest

from integrity_sdk.core.opa import OpaError
from shield.policy_engine.engine import EvaluationContext, PolicyEngine
from shield.opa_local import load_signed_profile_pack, supervised_opa
from shield.pack_profiles import PACK_DIRS_BY_PROFILE
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


def _mock_engine(raw_result=None, *, error=None, profile="smb"):
    pack = load_signed_profile_pack(profile)
    client = Mock()
    if error is not None:
        client.query.side_effect = error
    else:
        client.query.return_value = raw_result or {}
    return pack, patch("shield.policy_engine.engine.OpaClient", return_value=client), client


def test_opa_decision_translates_to_policy_decision():
    raw_result = {
            "action": "contain",
            "message": "Blocked shadow AI",
            "rule_id": "proc-restrict-shadow-ai",
            "name": "Restrict shadow AI processes",
            "version": "1.0.0",
            # decision/reason_code carry the C3 decision contract a real matching rule
            # always emits alongside the legacy fields above (shield/policies/rego/*.rego);
            # without these two keys, `resolve()` treats the result as NO_MATCH and applies
            # this event class's pack default instead of the mocked "contain".
            "decision": "deny",
            "reason_code": "SMB_CONTAIN_SHADOW_AI_PROCESS",
        }
    pack, client_patch, mock_client = _mock_engine(raw_result)
    with client_patch:
        engine = PolicyEngine(pack=pack)
    event = ProcessActivity(
        device_id="dev-1",
        process=ProcessInfo(pid=1, name="shadow.exe", exe_path="/opt/ai/shadow.exe"),
        activity=Activity(type="launch"),
    )
    decision = engine.evaluate(event, _ctx())
    
    assert decision.decision.action == "contain"
    assert decision.rule.rule_id == "proc-restrict-shadow-ai"
    assert decision.policy.version == pack.manifest["version"]
    assert decision.policy.hash == pack.pack_hash
    
    mock_client.query.assert_called_once()
    assert "event" in mock_client.query.call_args.args[1]
    assert "ctx" in mock_client.query.call_args.args[1]


# The mocked test formerly here (`test_opa_allow_translates_to_policy_decision`) asserted
# that a real OPA "no rule matched" result translates to `action == "allow"`. Real Rego
# (shield/policies/rego/*.rego) never emits that -- `default action := "log_only"`, and no
# rule ever produces `action := "allow"` either -- so the mock was testing a result no real
# OPA evaluation can produce; that's the exact "mocked test hid a bug" case
# docs/EXECUTION_PLAN.md A3 and integrity_sdk.core.decision's own module docstring both name.
# The real behavior is already covered against real OPA, for all three profiles, by
# `test_real_opa_unmatched_process_is_log_only` below.


def test_opa_unavailable_fails_closed():
    pack, client_patch, _ = _mock_engine(error=OpaError("OPA_UNAVAILABLE", "Connection refused"))
    with client_patch:
        engine = PolicyEngine(pack=pack)
    event = ProcessActivity(
        device_id="dev-1",
        process=ProcessInfo(pid=1, name="bash", exe_path="/bin/bash"),
        activity=Activity(type="launch"),
    )
    decision = engine.evaluate(event, _ctx())
    
    assert decision.decision.action == "deny"
    assert decision.decision.severity == "low"
    assert decision.rule.rule_id == "_no_match"


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
    pack = load_signed_profile_pack("professional-services")
    policy_version, policy_hash = pack.manifest["version"], pack.pack_hash
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

    with supervised_opa("professional-services") as (opa_url, pack):
        decision = PolicyEngine(opa_url=opa_url, pack=pack).evaluate(
            event, _ctx(registered_agent_ids=registered_agent_ids)
        )

    assert decision.event_ref.klass == "agent_event"
    assert decision.policy.version == policy_version
    assert decision.policy.hash == policy_hash
    assert decision.decision.action == expected_action
    assert decision.decision.reason == expected_reason
    assert decision.decision.severity == "medium"
    assert decision.rule.rule_id == expected_rule_id
    assert decision.rule.version == "1.0.0"


@pytest.mark.parametrize("profile", ["smb", "professional-services", "regulated"])
def test_real_opa_unmatched_process_is_log_only(profile):
    event = ProcessActivity(
        device_id="dev-1",
        process=ProcessInfo(pid=1, name="bash", exe_path="/usr/bin/bash"),
        activity=Activity(type="launch"),
    )
    with supervised_opa(profile) as (opa_url, pack):
        decision = PolicyEngine(opa_url=opa_url, pack=pack).evaluate(event, _ctx())
    assert decision.decision.action == "log_only"
    assert decision.rule.rule_id == "_no_match"


def test_real_opa_unmatched_agent_event_defaults_to_deny_on_the_regulated_profile():
    """docs/EXECUTION_PLAN.md A3, literally: "hipaa agent tool calls deny; device sensor
    events are log_only." This is the actual per-event-class default the plan item names,
    not just the process/device-sensor default every profile already shared."""
    event = AgentEvent(
        device_id="dev-1",
        agent=AgentInfo(agent_id="agent-1", name="Case Review Agent"),
        context=AgentContext(model_endpoint="https://approved.example/v1/chat/completions"),
        activity=AgentActivity(type="inference", risk_level="low"),
    )
    with supervised_opa("regulated") as (opa_url, pack):
        decision = PolicyEngine(opa_url=opa_url, pack=pack).evaluate(
            event, _ctx(registered_agent_ids=frozenset({"agent-1"}))
        )
    assert decision.decision.action == "deny"
    assert decision.rule.rule_id == "_no_match"  # no rule matched -- this is the pack default, not a rule


def test_real_opa_unmatched_agent_event_uses_the_loaded_pack_default():
    """The loaded pack, rather than a caller-supplied default map, owns no-match behavior."""
    event = AgentEvent(
        device_id="dev-1",
        agent=AgentInfo(agent_id="agent-1", name="Case Review Agent"),
        context=AgentContext(model_endpoint="https://approved.example/v1/chat/completions"),
        activity=AgentActivity(type="inference", risk_level="low"),
    )
    with supervised_opa("regulated") as (opa_url, pack):
        decision = PolicyEngine(opa_url=opa_url, pack=pack).evaluate(event, _ctx(registered_agent_ids=frozenset({"agent-1"})))
    assert decision.decision.action == "deny"


def test_no_verified_pack_denies_in_enforce_mode():
    """No pack means there is no trusted policy source, so the engine fails closed."""
    engine = PolicyEngine()
    event = ProcessActivity(
        device_id="dev-1",
        process=ProcessInfo(pid=1, name="bash", exe_path="/usr/bin/bash"),
        activity=Activity(type="launch"),
    )
    decision = engine.evaluate(event, _ctx())
    assert decision.decision.action == "deny"


@pytest.mark.parametrize("profile", sorted(PACK_DIRS_BY_PROFILE))
def test_pack_manifest_declares_event_defaults(profile):
    pack = load_signed_profile_pack(profile)
    assert set(pack.event_defaults) == {"process_activity", "file_activity", "network_flow", "agent_event"}
    assert pack.event_defaults["agent_event"] == ("deny" if profile == "regulated" else "log_only")


def test_malformed_raw_decision_denies_in_enforce_mode():
    """A `decision` value outside {permit, deny, log_only} can't come from this repo's own
    Rego, but `resolve()` must still defend against it rather than trust an unverified
    string -- same "missing, malformed, unknown ... denies" plan item as above."""
    pack, client_patch, _ = _mock_engine(
        {"decision": "not-a-real-decision", "reason_code": "SOMETHING"}
    )
    with client_patch:
        engine = PolicyEngine(pack=pack)
        event = ProcessActivity(
            device_id="dev-1",
            process=ProcessInfo(pid=1, name="bash", exe_path="/usr/bin/bash"),
            activity=Activity(type="launch"),
        )
        decision = engine.evaluate(event, _ctx())
    assert decision.decision.action == "deny"
