from __future__ import annotations

from tests.pack_test_support import install_fake_opa

from shield.agent_core.registry import AgentRegistry, DeviceContext
from shield.agent_core.router import EventRouter
from shield.policy_engine import PolicyEngine
from shield.policy_engine.jev_shadow import JevShadowAnalyzer
from shield.schemas.events import AgentActivity, AgentContext, AgentEvent, AgentInfo


def _event() -> AgentEvent:
    return AgentEvent(
        device_id="dev-1",
        agent=AgentInfo(agent_id="agent-1", name="Agent One"),
        context=AgentContext(tools_called=["shell"]),
        activity=AgentActivity(type="tool_execution"),
    )


def test_shadow_analyzer_emits_advisory_trace_without_changing_decision(monkeypatch):
    install_fake_opa(monkeypatch)
    captured = []
    analyzer = JevShadowAnalyzer(tenant_id="tenant-1", agent_id="agent-1", sink=lambda envelope, analysis: captured.append((envelope, analysis)))
    router = EventRouter(
        device=DeviceContext(device_id="dev-1", tenant_id="tenant-1", device_role="workstation"),
        registry=AgentRegistry(), policy_engine=PolicyEngine(), jev_analyzer=analyzer,
    )

    decision = router.handle(_event())

    assert decision.decision.action == "allow"
    assert len(captured) == 1
    envelope, analysis = captured[0]
    assert envelope.policy_decision == decision.decision.action
    assert analysis.causal_claim is False
    assert analysis.observed_event_hash == envelope.event_hash


def test_shadow_provider_failure_is_unavailable_and_does_not_raise(monkeypatch):
    install_fake_opa(monkeypatch)

    class BrokenProvider:
        provider_id = "jev.broken"

        def analyze(self, event):
            raise TimeoutError("local provider timeout")

    captured = []
    analyzer = JevShadowAnalyzer(tenant_id="tenant-1", agent_id="agent-1", provider=BrokenProvider(), sink=lambda envelope, analysis: captured.append((envelope, analysis)))
    router = EventRouter(
        device=DeviceContext(device_id="dev-1", tenant_id="tenant-1", device_role="workstation"),
        registry=AgentRegistry(), policy_engine=PolicyEngine(), jev_analyzer=analyzer,
    )

    decision = router.handle(_event())
    assert decision.decision.action == "allow"
    assert captured[0][1].status == "unavailable"
