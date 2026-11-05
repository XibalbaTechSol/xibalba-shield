from __future__ import annotations

import typing

from shield.schemas.events import Decision, EscalationResponse


def test_decision_accepts_tier3():
    # Dataclasses do not enforce Literal at runtime, so constructing Decision(tier="tier3")
    # succeeds even before the vocabulary is extended. Assert the declared vocabulary too,
    # so this test actually fails until "tier3" is part of the Decision.tier annotation.
    hints = typing.get_type_hints(Decision)
    assert "tier3" in typing.get_args(hints["tier"])
    assert "tier1" in typing.get_args(hints["tier"])
    assert Decision(action="allow").tier == "tier1"

    d = Decision(action="contain", tier="tier3")
    assert d.tier == "tier3"


def test_tier3_verdict_vocabulary():
    from shield.schemas.events import Tier3Verdict

    assert typing.get_args(Tier3Verdict) == ("release", "confirm", "uncertain")


def test_escalation_response_defaults_to_uncertain():
    # Fail-closed default: a response that never set a verdict must not read as a release.
    r = EscalationResponse(decision=Decision(action="contain"))
    assert r.verdict == "uncertain"
