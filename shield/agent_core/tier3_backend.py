"""Post-containment Tier 3 adjudication boundary.

Tier 3 is advisory to the local enforcement plane. Implementations may inspect a
bounded, redacted evidence payload and return an adjudication response, but they
must never be used as an in-path replacement for Tier 1 or Tier 2 policy.
"""

from __future__ import annotations

from typing import Protocol

from shield.schemas.events import Decision, EscalationRequest, EscalationResponse, Tier3Verdict


def parse_verdict(raw: object) -> Tier3Verdict:
    """Parse only the exact, typed verdict vocabulary; all other values are uncertain."""

    if raw == "release":
        return "release"
    if raw == "confirm":
        return "confirm"
    if raw == "uncertain":
        return "uncertain"
    return "uncertain"


class Tier3Backend(Protocol):
    """A post-containment adjudicator; it cannot authorize in-path enforcement."""

    def adjudicate(self, request: EscalationRequest) -> EscalationResponse:
        """Return a strictly typed, fail-closed adjudication response."""


class NullTier3Backend:
    """Real no-op backend used when Tier 3 is unconfigured, not a cloud-call mock."""

    def adjudicate(self, request: EscalationRequest) -> EscalationResponse:
        del request
        return EscalationResponse(
            decision=Decision(action="contain", tier="tier3"),
            verdict="uncertain",
            reason="Tier 3 backend is not configured",
        )
