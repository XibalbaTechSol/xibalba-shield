"""
Model routing guardrail hook — spec/xibalba-shield-v1.md §4.4, hook point 3 of 6
(`model routing: which model/endpoint`).

Gates which model/endpoint an agent is allowed to route a call to before the call happens —
e.g. blocking a clinical-desktop agent from routing to an unapproved public model endpoint
while a request to an approved internal endpoint passes. Same "context" condition-group
dependency as `retrieval_context.py`.
"""

from __future__ import annotations

from typing import Any, Callable

from ..agent_core.router import EventRouter
from ..schemas.events import AgentActivity, AgentContext, AgentEvent, AgentInfo


class ModelRoutingDenied(Exception):
    """Raised by `guard_model_routing` when the routed decision is not `allow`/`log_only`."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def guard_model_routing(
    router: EventRouter,
    *,
    agent_id: str,
    agent_name: str,
    model_endpoint: str,
    call: Callable[[], Any],
) -> Any:
    """Wraps `call` (the actual model invocation) with a real pre-execution policy check
    against `model_endpoint`. Raises `ModelRoutingDenied` and never invokes `call` if the
    routed decision's action is `deny`/`contain`/`escalate`; otherwise invokes `call` and
    returns its result."""
    event = AgentEvent(
        device_id=router.device.device_id,
        agent=AgentInfo(agent_id=agent_id, name=agent_name, type="llm_tool"),
        context=AgentContext(model_endpoint=model_endpoint),
        activity=AgentActivity(type="model_routing", risk_level="low"),
    )
    decision = router.handle(event)

    if decision.decision.action not in ("allow", "log_only"):
        raise ModelRoutingDenied(decision.decision.reason or f"denied by rule {decision.rule.rule_id}")

    return call()
