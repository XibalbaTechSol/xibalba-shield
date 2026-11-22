from shield.agent_core.tier3_backend import NullTier3Backend, parse_verdict
from shield.schemas.events import Decision, EscalationRequest, ProcessActivity, ProcessInfo, Activity


def _request() -> EscalationRequest:
    event = ProcessActivity(
        device_id="device-1",
        process=ProcessInfo(pid=42, name="example"),
        activity=Activity(type="exec"),
    )
    return EscalationRequest(
        event=event,
        tier1_decision=Decision(action="escalate"),
        tier2_decision=Decision(action="escalate", tier="tier2_unresolved"),
    )


def test_known_verdicts_parse_exactly():
    for raw in ("release", "confirm", "uncertain"):
        assert parse_verdict(raw) == raw


def test_unknown_or_prose_verdicts_become_uncertain():
    for raw in (None, "", "RELEASE ", "allow", "yes", 1, {"verdict": "release"},
                "release; confirm", "I think you should release this process"):
        assert parse_verdict(raw) == "uncertain"


def test_null_backend_is_always_uncertain_and_contained():
    response = NullTier3Backend().adjudicate(_request())
    assert response.verdict == "uncertain"
    assert response.decision.action == "contain"
