from __future__ import annotations

from shield.agent_core.registry import AgentRegistry, DeviceContext
from shield.agent_core.router import EventRouter
from shield.policy_engine.engine import PolicyEngine
from shield.schemas.events import (
    Activity,
    AgentActivity,
    AgentContext,
    AgentEvent,
    AgentInfo,
    ProcessActivity,
    ProcessInfo,
)
from shield.schemas.policy_rule import PolicyRule

from unittest.mock import AsyncMock, patch

import pytest
from integrity_sdk.policy.opa_client import OPADecision

@pytest.fixture(autouse=True)
def mock_opa():
    with patch("shield.policy_engine.engine.opa_evaluate", new_callable=AsyncMock) as mock_eval:
        mock_eval.return_value = OPADecision(allow=True, raw_result={"action": "allow"})
        yield mock_eval

def _router(**kwargs):
    device = DeviceContext(device_id="dev-1", tenant_id="t", device_role="workstation")
    return EventRouter(
        device=device,
        registry=kwargs.get("registry", AgentRegistry()),
        policy_engine=kwargs.get("policy_engine", PolicyEngine()),
        guardrail_hooks=kwargs.get("guardrail_hooks", ()),
        event_log=kwargs.get("event_log"),
    )


def test_registry_register_is_idempotent_and_tracks_last_seen():
    registry = AgentRegistry()
    a = registry.register("agent-1", "Agent One")
    b = registry.register("agent-1", "Agent One")
    assert a is b
    assert registry.is_registered("agent-1")
    assert "agent-1" in registry.registered_ids()


def test_touch_does_not_register_an_unknown_agent():
    registry = AgentRegistry()
    registry.touch("never-registered")
    assert not registry.is_registered("never-registered")


def test_router_touches_registry_for_agent_events():
    registry = AgentRegistry()
    registry.register("known-agent", "Known")
    router = _router(registry=registry)
    event = AgentEvent(
        device_id="dev-1",
        agent=AgentInfo(agent_id="known-agent", name="Known"),
        context=AgentContext(),
        activity=AgentActivity(type="inference"),
    )
    router.handle(event)
    assert registry.is_registered("known-agent")




def test_guardrail_hook_fires_only_for_agent_events():
    calls = []
    router = _router(guardrail_hooks=[lambda event, decision: calls.append(event)])

    router.handle(ProcessActivity(device_id="dev-1", process=ProcessInfo(pid=1, name="bash"), activity=Activity(type="launch")))
    assert calls == []

    router.handle(AgentEvent(
        device_id="dev-1",
        agent=AgentInfo(agent_id="a1", name="a1"),
        context=AgentContext(),
        activity=AgentActivity(type="inference"),
    ))
    assert len(calls) == 1


def test_raising_guardrail_hook_does_not_break_the_router():
    def _bad_hook(event, decision):
        raise RuntimeError("hook bug")

    router = _router(guardrail_hooks=[_bad_hook])
    decision = router.handle(AgentEvent(
        device_id="dev-1",
        agent=AgentInfo(agent_id="a1", name="a1"),
        context=AgentContext(),
        activity=AgentActivity(type="inference"),
    ))
    assert decision is not None  # did not raise


def test_router_exports_telemetry_for_every_decision():
    """router.handle() emits an OTel span unconditionally (agent_core/router.py) --
    on the success path this must mark the decision as exported."""
    router = _router()
    decision = router.handle(AgentEvent(
        device_id="dev-1",
        agent=AgentInfo(agent_id="a1", name="a1"),
        context=AgentContext(),
        activity=AgentActivity(type="inference"),
    ))
    assert decision.export.attempted is True
    assert decision.export.event_exported is True
    assert decision.export.decision_exported is True
    assert decision.export.authorized is True


def test_router_survives_a_raising_tracer():
    """A telemetry/span failure must not take down the router -- matches the
    guardrail-hook resilience contract above, applied to the export path
    (agent_core/router.py's own try/except around tracer.start_as_current_span)."""
    from shield.agent_core import router as router_module

    router = _router()
    with patch.object(router_module.tracer, "start_as_current_span", side_effect=RuntimeError("span bug")):
        decision = router.handle(AgentEvent(
            device_id="dev-1",
            agent=AgentInfo(agent_id="a1", name="a1"),
            context=AgentContext(),
            activity=AgentActivity(type="inference"),
        ))
    assert decision is not None  # did not raise
    assert decision.export.attempted is True
    assert decision.export.event_exported is False
    assert decision.export.reason == "telemetry export raised"
