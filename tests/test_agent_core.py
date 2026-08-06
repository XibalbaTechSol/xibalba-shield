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


class _RecordingExporter:
    def __init__(self):
        self.events = []
        self.decisions = []

    def export_event(self, event):
        self.events.append(event)

    def export_decision(self, decision):
        self.decisions.append(decision)
        return {"authorized": True}


def _router(**kwargs):
    device = DeviceContext(device_id="dev-1", tenant_id="t", device_role="workstation")
    return EventRouter(
        device=device,
        registry=kwargs.get("registry", AgentRegistry()),
        policy_engine=kwargs.get("policy_engine", PolicyEngine(rules=[])),
        exporter=kwargs.get("exporter", _RecordingExporter()),
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


def test_router_exports_both_event_and_decision():
    exporter = _RecordingExporter()
    router = _router(exporter=exporter)
    event = ProcessActivity(device_id="dev-1", process=ProcessInfo(pid=1, name="bash"), activity=Activity(type="launch"))
    router.handle(event)
    assert len(exporter.events) == 1
    assert len(exporter.decisions) == 1


def test_router_records_successful_export_status_in_decision_log(tmp_path):
    from shield.agent_core.eventlog import EventLog

    log_path = tmp_path / "decisions.jsonl"
    router = _router(event_log=EventLog(log_path))
    event = ProcessActivity(device_id="dev-1", process=ProcessInfo(pid=1, name="bash"), activity=Activity(type="launch"))

    decision = router.handle(event)
    row = EventLog(log_path).recent(1)[0]

    assert decision.export.attempted is True
    assert decision.export.event_exported is True
    assert decision.export.decision_exported is True
    assert row["export"]["decision_exported"] is True


def test_router_survives_a_raising_exporter():
    class _ExplodingExporter:
        def export_event(self, event):
            raise RuntimeError("boom")

        def export_decision(self, decision):
            raise RuntimeError("boom")

    router = _router(exporter=_ExplodingExporter())
    event = ProcessActivity(device_id="dev-1", process=ProcessInfo(pid=1, name="bash"), activity=Activity(type="launch"))
    decision = router.handle(event)  # must not raise
    assert decision.decision.action == "allow"
    assert decision.export.attempted is True
    assert decision.export.reason == "integrity export raised"


def test_router_records_failed_export_status_in_decision_log(tmp_path):
    from shield.agent_core.eventlog import EventLog

    class _DenyingExporter:
        def export_event(self, event):
            pass

        def export_decision(self, decision):
            return {"authorized": False, "reason": "submission failed: test"}

    log_path = tmp_path / "decisions.jsonl"
    router = _router(exporter=_DenyingExporter(), event_log=EventLog(log_path))
    event = ProcessActivity(device_id="dev-1", process=ProcessInfo(pid=1, name="bash"), activity=Activity(type="launch"))

    decision = router.handle(event)
    row = EventLog(log_path).recent(1)[0]

    assert decision.export.decision_exported is False
    assert decision.export.authorized is False
    assert row["export"]["reason"] == "submission failed: test"


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
