import threading
import time

from shield.agent_core.registry import AgentRegistry, DeviceContext
from shield.agent_core.router import EventRouter
from shield.agent_core.tier3_safety import BoundedAdjudicationStore
from shield.schemas.events import Activity, Decision, EscalationResponse, EventRef, PolicyDecision, ProcessActivity, ProcessInfo, RuleRef


class Engine:
    def evaluate(self, event, context):
        return PolicyDecision("d", EventRef("process_activity", "e"), RuleRef("r", "r", "1"), Decision("escalate"))


class Broker:
    def __init__(self, order): self.order = order
    def contain(self, pid):
        self.order.append("contain")
        return type("Result", (), {"action": "freeze", "method": "test", "completed": True, "escalated": False, "error": None})()


class Backend:
    def __init__(self, order, delay=0, error=None): self.order, self.delay, self.error = order, delay, error
    def adjudicate(self, request):
        if self.delay: time.sleep(self.delay)
        if self.error: raise self.error
        self.order.append("tier3")
        return EscalationResponse(Decision("contain"), verdict="uncertain")


def event():
    return ProcessActivity("d", ProcessInfo(42, "x"), Activity("exec"))


def router(**kwargs):
    return EventRouter(device=DeviceContext("d", "t", "workstation"), registry=AgentRegistry(), policy_engine=Engine(), **kwargs)


def test_containment_precedes_tier3_dispatch():
    order = []
    r = router(action_broker=Broker(order), tier3_backend=Backend(order))
    r.handle(event())
    for _ in range(50):
        if "tier3" in order: break
        time.sleep(.01)
    assert order == ["contain", "tier3"]


def test_slow_backend_does_not_delay_handle():
    r = router(tier3_backend=Backend([], delay=.25))
    start = time.monotonic(); r.handle(event())
    assert time.monotonic() - start < .15


def test_raising_backend_leaves_local_decision_unchanged():
    r = router(tier3_backend=Backend([], error=RuntimeError("offline")))
    assert r.handle(event()).decision.action == "contain"


def test_sink_failure_does_not_escape_and_response_is_persisted():
    store = BoundedAdjudicationStore(1)
    r = router(tier3_backend=Backend([]), tier3_sink=lambda response: (_ for _ in ()).throw(RuntimeError("sink")), tier3_store=store)
    r.handle(event())
    for _ in range(50):
        if store.snapshot(): break
        time.sleep(.01)
    assert len(store.snapshot()) == 1
