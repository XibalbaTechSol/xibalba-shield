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
        exporter=kwargs.get("exporter"),
        action_broker=kwargs.get("action_broker"),
        guardrail_hooks=kwargs.get("guardrail_hooks", ()),
        event_log=kwargs.get("event_log"),
    )


def _force_action(engine, action):
    """Wraps a real PolicyEngine.evaluate so tests can exercise a specific decision.action
    (e.g. "contain") without needing a real policy rule file that produces it."""
    original = engine.evaluate

    def _evaluate(event, context):
        decision = original(event, context)
        decision.decision.action = action
        return decision

    engine.evaluate = _evaluate
    return engine


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
    on the success path this must mark the event as telemetry-exported. With no
    exporter configured, decision_exported/authorized stay False/None -- OTel spans
    are not evidence of a signed commitment, and must not be reported as if they were."""
    router = _router()
    decision = router.handle(AgentEvent(
        device_id="dev-1",
        agent=AgentInfo(agent_id="a1", name="a1"),
        context=AgentContext(),
        activity=AgentActivity(type="inference"),
    ))
    assert decision.export.attempted is True
    assert decision.export.event_exported is True
    assert decision.export.decision_exported is False
    assert decision.export.authorized is None


def test_router_reports_real_exporter_result_when_configured():
    """When an Integrity Exporter is configured, decision_exported/authorized must
    reflect its real result, not a stub."""
    class _StubExporter:
        def export_event(self, event):
            pass

        def export_decision(self, decision):
            return {"authorized": True}

    router = _router(exporter=_StubExporter())
    decision = router.handle(AgentEvent(
        device_id="dev-1",
        agent=AgentInfo(agent_id="a1", name="a1"),
        context=AgentContext(),
        activity=AgentActivity(type="inference"),
    ))
    assert decision.export.event_exported is True
    assert decision.export.decision_exported is True
    assert decision.export.authorized is True


def test_exporter_failure_does_not_suppress_telemetry_export():
    """A failing Integrity Exporter must not roll back or hide that the OTel span
    still succeeded -- the two export paths are independent."""
    class _RaisingExporter:
        def export_event(self, event):
            raise RuntimeError("bcc_middleware unreachable")

        def export_decision(self, decision):
            raise RuntimeError("bcc_middleware unreachable")

    router = _router(exporter=_RaisingExporter())
    decision = router.handle(AgentEvent(
        device_id="dev-1",
        agent=AgentInfo(agent_id="a1", name="a1"),
        context=AgentContext(),
        activity=AgentActivity(type="inference"),
    ))
    assert decision.export.event_exported is True
    assert decision.export.decision_exported is False
    assert decision.export.reason == "integrity export raised"


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


def test_contain_decision_calls_action_broker_with_the_events_pid():
    """The real-time containment step (see router.py's module docstring): a "contain"
    decision on a process-related event must call ActionBroker.contain() with that
    event's real pid -- this is what makes "contain" actually do something instead of
    only being logged/exported after the fact."""
    calls = []

    class _StubBroker:
        def contain(self, pid, **kwargs):
            calls.append(pid)

            class _Result:
                action = "freeze"
                method = "SIGSTOP"

            return _Result()

    engine = _force_action(PolicyEngine(), "contain")
    router = _router(policy_engine=engine, action_broker=_StubBroker())

    router.handle(ProcessActivity(
        device_id="dev-1",
        process=ProcessInfo(pid=4242, name="bash"),
        activity=Activity(type="launch"),
    ))

    assert calls == [4242]


def test_allow_decision_never_calls_action_broker():
    """Containment must only fire for "contain" decisions -- an "allow" must never touch
    a real process, even when an ActionBroker is configured."""
    calls = []

    class _StubBroker:
        def contain(self, pid, **kwargs):
            calls.append(pid)

    router = _router(action_broker=_StubBroker())  # PolicyEngine() with no rules -> default allow

    router.handle(ProcessActivity(
        device_id="dev-1",
        process=ProcessInfo(pid=4242, name="bash"),
        activity=Activity(type="launch"),
    ))

    assert calls == []


def test_contain_decision_on_an_agent_event_does_not_crash_without_a_pid():
    """AgentEvent has no OS process of its own (see _pid_of's docstring in router.py) --
    a "contain" decision on one must not crash trying to extract a pid that doesn't
    exist; it should just log and continue to guardrail hooks/export."""
    calls = []

    class _StubBroker:
        def contain(self, pid, **kwargs):
            calls.append(pid)

    engine = _force_action(PolicyEngine(), "contain")
    router = _router(policy_engine=engine, action_broker=_StubBroker())

    decision = router.handle(AgentEvent(
        device_id="dev-1",
        agent=AgentInfo(agent_id="a1", name="a1"),
        context=AgentContext(),
        activity=AgentActivity(type="inference"),
    ))

    assert calls == []  # never called -- no pid to act on
    assert decision is not None  # did not raise


def test_raising_action_broker_does_not_break_the_router():
    """A broken/unreachable Action Broker must never take down the router or block the
    export/logging steps that follow it -- same resilience contract as guardrail hooks
    and the exporter."""
    class _RaisingBroker:
        def contain(self, pid, **kwargs):
            raise OSError("no such process")

    engine = _force_action(PolicyEngine(), "contain")
    router = _router(policy_engine=engine, action_broker=_RaisingBroker())

    decision = router.handle(ProcessActivity(
        device_id="dev-1",
        process=ProcessInfo(pid=4242, name="bash"),
        activity=Activity(type="launch"),
    ))

    assert decision is not None  # did not raise
    assert decision.export.attempted is True  # export still ran after the broker failed
