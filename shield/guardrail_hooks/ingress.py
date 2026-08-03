"""
Ingress guardrail hook — spec/xibalba-shield-v1.md §4.4, hook point 1 of 6 (`ingress: prompt,
requesting identity`).

The entry boundary: gates whether an incoming request should even be accepted, before any
retrieval, model routing, or tool execution happens downstream. Per §6's governing principle
("behavioral telemetry, not content inspection"), this hook never sees or carries prompt
*content* — only who is asking (`requesting_user_id`) and which agent/tool is fielding the
request. There is nowhere in the canonical `AgentEvent` shape (spec §5.4) for raw prompt text
to go, and this module does not invent one.
"""

from __future__ import annotations

from typing import Any, Callable

from ..agent_core.router import EventRouter
from ..schemas.events import AgentActivity, AgentContext, AgentEvent, AgentInfo


class IngressDenied(Exception):
    """Raised by `guard_ingress` when the routed decision is not `allow`/`log_only`. Carries
    the PolicyDecision's reason so a caller can surface it (e.g. reject the request with a
    4xx before any downstream module runs)."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def guard_ingress(
    router: EventRouter,
    *,
    agent_id: str,
    agent_name: str,
    requesting_user_id: str = "",
    call: Callable[[], Any],
) -> Any:
    """Wraps `call` (whatever accepts/begins processing the incoming request) with a real
    pre-acceptance policy check. Raises `IngressDenied` and never invokes `call` if the routed
    decision's action is `deny`/`contain`/`escalate`; otherwise invokes `call` and returns its
    result — the same allow/deny shape `tool_execution.guard_tool_call` uses, since this is
    the same kind of boundary (gate before proceeding), just earlier in the pipeline."""
    event = AgentEvent(
        device_id=router.device.device_id,
        agent=AgentInfo(agent_id=agent_id, name=agent_name, type="llm_tool", owner_user_id=requesting_user_id),
        context=AgentContext(),
        activity=AgentActivity(type="ingress", risk_level="low"),
    )
    decision = router.handle(event)

    if decision.decision.action not in ("allow", "log_only"):
        raise IngressDenied(decision.decision.reason or f"denied by rule {decision.rule.rule_id}")

    return call()
