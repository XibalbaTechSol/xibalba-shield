"""Pins the exact wire shapes spec/xibalba-shield-v1.md §5 requires — a package implementing
these MUST NOT rename fields. Regression coverage for a real bug found while building the CLI:
`EventRef`'s Python attribute is `klass` (a bare `class` attribute isn't legal), and a naive
`vars()` serialization leaked that Python-side name into the wire format instead of the
canonical "class" key §5.5 specifies."""

from __future__ import annotations

from shield.schemas.events import (
    Activity,
    Decision,
    EventRef,
    PolicyDecision,
    ProcessActivity,
    ProcessInfo,
    RuleRef,
)


def test_process_activity_serializes_class_field_not_klass():
    event = ProcessActivity(device_id="dev-1", process=ProcessInfo(pid=1, name="bash"), activity=Activity(type="launch"))
    d = event.to_dict()
    assert d["class"] == "process_activity"
    assert "klass" not in d


def test_policy_decision_event_ref_serializes_class_field_not_klass():
    decision = PolicyDecision(
        device_id="dev-1",
        event_ref=EventRef(klass="network_flow", event_id="evt-123"),
        rule=RuleRef(rule_id="r1", name="x", version="1.0.0"),
        decision=Decision(action="deny"),
    )
    d = decision.to_dict()
    assert d["event_ref"] == {"class": "network_flow", "event_id": "evt-123"}
    assert "klass" not in d["event_ref"]
