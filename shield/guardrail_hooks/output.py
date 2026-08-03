"""
Output guardrail hook — spec/xibalba-shield-v1.md §4.4, hook point 4 of 6 (`output: content
classification — PHI, secrets, risk level`).

**This hook enforces policy on a classification; it does not produce one.** Spec §6 states
plainly that no PHI-tagging mechanism or content classifier exists yet in this repo
(`[PLANNED]`) — building one is separate, real work (likely where §6's PHI-tagging design
eventually plugs in). Until then, the caller must supply `risk_level` and `categories` from
whatever classification it already has (a model's own moderation output, a keyword scan, a
human review step, etc.); this module only ever gates on a classification, never invents one.

`categories` (e.g. `["phi", "secrets"]`) has no dedicated field in the canonical `AgentEvent`
shape (spec §5.4) — rather than inventing an unschema'd field, they're folded into
`activity.type` as `output:<sorted,categories>` (`output:none` when empty), which IS a real
`AgentEvent.activity.type` string and so is preserved end-to-end through `to_dict()` /
telemetry export without any wire-format change. `risk_level` uses the schema's own existing
field and is a real, matchable signal.
"""

from __future__ import annotations

from typing import Any, Callable

from ..agent_core.router import EventRouter
from ..schemas.events import AgentActivity, AgentContext, AgentEvent, AgentInfo


class OutputBlocked(Exception):
    """Raised by `guard_output` when the routed decision is not `allow`/`log_only`."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def guard_output(
    router: EventRouter,
    *,
    agent_id: str,
    agent_name: str,
    risk_level: str = "low",
    categories: list[str] = (),
    call: Callable[[], Any],
) -> Any:
    """Wraps `call` (releasing the output to its destination) with a real pre-release policy
    check against the supplied `risk_level`/`categories` classification. Raises
    `OutputBlocked` and never invokes `call` if the routed decision's action is
    `deny`/`contain`/`escalate`; otherwise invokes `call` and returns its result."""
    activity_type = f"output:{','.join(sorted(categories)) if categories else 'none'}"
    event = AgentEvent(
        device_id=router.device.device_id,
        agent=AgentInfo(agent_id=agent_id, name=agent_name, type="llm_tool"),
        context=AgentContext(),
        activity=AgentActivity(type=activity_type, risk_level=risk_level),
    )
    decision = router.handle(event)

    if decision.decision.action not in ("allow", "log_only"):
        raise OutputBlocked(decision.decision.reason or f"denied by rule {decision.rule.rule_id}")

    return call()
