"""
Retrieval/context guardrail hook — spec/xibalba-shield-v1.md §4.4, hook point 2 of 6
(`retrieval/context: data sources touched`).

Gates which data sources an agent is allowed to read from before the read happens. Per §6, a
`data_sources` entry names a resource *class* (`ehr_encounter`) never a record identifier or
content — this hook inherits that discipline from the schema, it doesn't add or relax it.

Requires `policy_engine.engine`'s `"context"` condition-group support (added alongside this
hook) — without it, a rule naming `data_sources` in a condition could never match anything,
which would make this hook decorative rather than enforcing.
"""

from __future__ import annotations

from typing import Any, Callable

from ..agent_core.router import EventRouter
from ..schemas.events import AgentActivity, AgentContext, AgentEvent, AgentInfo


class RetrievalDenied(Exception):
    """Raised by `guard_retrieval` when the routed decision is not `allow`/`log_only`."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def guard_retrieval(
    router: EventRouter,
    *,
    agent_id: str,
    agent_name: str,
    data_sources: list[str],
    call: Callable[[], Any],
) -> Any:
    """Wraps `call` (the actual retrieval) with a real pre-execution policy check against the
    named `data_sources`. Raises `RetrievalDenied` and never invokes `call` if the routed
    decision's action is `deny`/`contain`/`escalate`; otherwise invokes `call` and returns its
    result."""
    event = AgentEvent(
        device_id=router.device.device_id,
        agent=AgentInfo(agent_id=agent_id, name=agent_name, type="llm_tool"),
        context=AgentContext(data_sources=list(data_sources)),
        activity=AgentActivity(type="retrieval", risk_level="low"),
    )
    decision = router.handle(event)

    if decision.decision.action not in ("allow", "log_only"):
        raise RetrievalDenied(decision.decision.reason or f"denied by rule {decision.rule.rule_id}")

    return call()
