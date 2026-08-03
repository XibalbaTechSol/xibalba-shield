"""
Post-action verification guardrail hook — spec/xibalba-shield-v1.md §4.4, hook point 6 of 6
("did the expected state change actually occur — the semantic–physical gap check", also
described at the session level in `integrity-protocol-v0.4.md` §22.4; this hook is one of the
concrete instrumentation points that would feed that broader model when Shield sessions are
Integrity-monitored sessions).

**Structurally different from the other five hooks: the action has already happened by the
time this runs.** There is no `call` to conditionally invoke — nothing here can prevent
anything. Its job is detection and evidence: compare what the caller expected to happen
against what actually happened, and if they diverge, produce a `PolicyDecision` whose action
(`contain`/`escalate`/`deny`) signals the caller should react (kill a session, alert a human,
revoke a capability) — reactively, not preventively. Raising `PostActionAnomaly` on a
non-allow decision is a signal to escalate, not proof that anything was undone.

`expected_state_hash`/`actual_state_hash` are caller-supplied opaque strings (typically a hash
of whatever state description matters for the action — a file's content hash, a record's
version, an API response digest) — this module does not compute or interpret them, only
compares for equality, matching §6's "behavioral telemetry, not content inspection" posture:
comparing hashes never requires seeing the underlying content.
"""

from __future__ import annotations

from ..agent_core.router import EventRouter
from ..schemas.events import AgentActivity, AgentContext, AgentEvent, AgentInfo, PolicyDecision


class PostActionAnomaly(Exception):
    """Raised by `verify_post_action` when the routed decision is not `allow`/`log_only` —
    i.e. the state mismatch itself was judged policy-significant, not merely logged. The
    action this refers to has ALREADY completed; catching this is a cue to escalate or
    investigate, never a cue that anything was rolled back."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def verify_post_action(
    router: EventRouter,
    *,
    agent_id: str,
    agent_name: str,
    tool_name: str,
    expected_state_hash: str,
    actual_state_hash: str,
) -> PolicyDecision:
    """Routes a real comparison of `expected_state_hash` vs. `actual_state_hash` through the
    same Policy Engine every other hook uses. `AgentActivity` has no `outcome` field (that
    exists only on `Activity`, used by Process/File/NetworkFlow, not by AgentEvent) — the
    match result is instead carried by `policy_violation` (set on mismatch, so a rule can key
    on it directly without re-deriving equality itself) and `risk_level` (`"high"` on
    mismatch, `"low"` on match). Always returns the `PolicyDecision` (there's nothing to
    gate); raises `PostActionAnomaly` in addition when the routed decision itself isn't
    `allow`/`log_only`, so a caller can choose to either inspect the returned decision or just
    catch the exception, matching the other hooks' calling convention as closely as this
    hook's different shape allows."""
    matched = expected_state_hash == actual_state_hash
    event = AgentEvent(
        device_id=router.device.device_id,
        agent=AgentInfo(agent_id=agent_id, name=agent_name, type="llm_tool"),
        context=AgentContext(tools_called=[tool_name]),
        activity=AgentActivity(
            type="post_action_verification",
            risk_level="low" if matched else "high",
            policy_violation=not matched,
        ),
    )
    decision = router.handle(event)

    if decision.decision.action not in ("allow", "log_only"):
        raise PostActionAnomaly(decision.decision.reason or f"flagged by rule {decision.rule.rule_id}")

    return decision
