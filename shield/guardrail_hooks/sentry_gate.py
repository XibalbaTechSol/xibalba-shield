"""
Sentry Guardrail Hook: Proof-of-Justification (PoJ) Tool Gating.

Integrates Sentry Phase 2 PoJ authorization directly into the guardrail execution pipeline.
Requires verified execution ticket or valid causal justification before invoking mutating tools.
"""

from __future__ import annotations

from typing import Any, Callable, Mapping, Sequence

from ..agent_core.router import EventRouter
from ..schemas.events import AgentActivity, AgentContext, AgentEvent, AgentInfo
from ..sentry.justification import (
    ProofOfJustificationEngine,
    PoJAuthorizationError,
    ToolRiskLevel,
    ExecutionTicket,
)
from ..sentry.taint import TaintLevel


class SentryGatingError(Exception):
    """Raised when Sentry Proof-of-Justification gates tool execution."""
    def __init__(self, code: str, reason: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(f"{code}: {reason}")
        self.code = code
        self.reason = reason
        self.details = details or {}


def guard_sentry_tool_call(
    router: EventRouter,
    poj_engine: ProofOfJustificationEngine,
    *,
    agent_id: str,
    agent_name: str,
    tool_name: str,
    params: Any,
    causal_memory_hashes: Sequence[str] = (),
    taint_level: TaintLevel | str = TaintLevel.TRUSTED_AXIOM,
    decontamination_proof: Mapping[str, Any] | None = None,
    call: Callable[[], Any],
) -> tuple[Any, ExecutionTicket]:
    """
    Enforces Proof-of-Justification before executing `call()`.
    1. Evaluates tool risk and causal memory hashes.
    2. Enforces taint clearance.
    3. Issues execution ticket and checks with standard router event.
    4. Executes `call()` and returns (result, ticket).
    """
    tenant_id = router.device.tenant_id
    try:
        ticket = poj_engine.authorize_action(
            tenant_id=tenant_id,
            agent_did=agent_id,
            tool_name=tool_name,
            params=params,
            causal_memory_hashes=causal_memory_hashes,
            taint_level=taint_level,
            decontamination_proof=decontamination_proof,
        )
    except PoJAuthorizationError as exc:
        raise SentryGatingError(exc.code, exc.message, exc.details) from exc

    # Record event through standard router
    event = AgentEvent(
        device_id=router.device.device_id,
        agent=AgentInfo(agent_id=agent_id, name=agent_name, type="llm_tool"),
        context=AgentContext(tools_called=[tool_name]),
        activity=AgentActivity(type="tool_execution", risk_level=ticket.risk_level.lower()),
    )
    decision = router.handle(event)
    if decision.decision.action not in ("allow", "log_only"):
        raise SentryGatingError("POLICY_DENIED", decision.decision.reason or f"denied by rule {decision.rule.rule_id}")

    result = call()
    return result, ticket
