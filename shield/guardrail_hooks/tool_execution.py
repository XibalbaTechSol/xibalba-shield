"""
Guardrail hooks — spec/xibalba-shield-v1.md §4.4.

This module implements hook point 5 (`tool_execution`). The repository now implements all six
hook points listed in spec §4.4: ingress, retrieval/context, model routing, output, tool
execution, and post-action verification.

Distinct from the OS-level sensor (§4.1) because this is a semantic layer: it wraps a specific
tool call with a policy check *before* the call runs, the same "gate before execution" shape
`pretool_gate.py` already uses in the parent repo's own Xibalba session hooks — this is that
pattern generalized into a reusable library function rather than a one-off script.
"""

from __future__ import annotations

from typing import Any, Callable

from ..agent_core.router import EventRouter
from ..schemas.events import AgentActivity, AgentContext, AgentEvent, AgentInfo


class ToolCallDenied(Exception):
    """Raised by `guard_tool_call` when the policy engine's decision for this call is not
    `allow`/`log_only`. Carries the PolicyDecision's reason so a caller can surface it."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def guard_tool_call(
    router: EventRouter,
    *,
    agent_id: str,
    agent_name: str,
    tool_name: str,
    call: Callable[[], Any],
    model_endpoint: str = "",
) -> Any:
    """Wraps `call` with a real pre-execution policy check. Raises `ToolCallDenied` and never
    invokes `call` if the routed decision's action is `deny`/`contain`/`escalate`; otherwise
    invokes `call` and returns its result. `contain`/`escalate` are treated as denials here
    deliberately — this hook only has an allow/deny decision to make about ONE call; the
    device-level containment or human escalation those actions imply is Agent Core's job
    (§4.2), not this function's."""
    event = AgentEvent(
        device_id=router.device.device_id,
        agent=AgentInfo(agent_id=agent_id, name=agent_name, type="llm_tool"),
        context=AgentContext(tools_called=[tool_name], model_endpoint=model_endpoint),
        activity=AgentActivity(type="tool_execution", risk_level="low"),
    )
    decision = router.handle(event)

    if decision.decision.action not in ("allow", "log_only"):
        raise ToolCallDenied(decision.decision.reason or f"denied by rule {decision.rule.rule_id}")

    return call()
