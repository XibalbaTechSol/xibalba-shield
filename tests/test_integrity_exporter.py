"""
Integration test for IntegrityExporter (spec §4.5's "first end-to-end signed event"
milestone). Skips cleanly if bcc_middleware isn't reachable, rather than failing the whole
suite -- CI/local dev shouldn't need a full stack up just to run `pytest`, but a real event
DOES get submitted and DOES get a real authorized/denied response when the stack is up,
matching bcc_middleware's own test conventions in the parent repo (real fixtures over mocks).
"""

from __future__ import annotations

import os

import pytest
import requests

from shield.schemas.events import Activity, Decision, EventRef, PolicyDecision, RuleRef

BCC_MIDDLEWARE_URL = os.environ.get("BCC_MIDDLEWARE_URL", "http://localhost:8000")


def _bcc_middleware_reachable() -> bool:
    try:
        resp = requests.get(f"{BCC_MIDDLEWARE_URL}/health", timeout=2)
        return resp.status_code < 500
    except requests.RequestException:
        return False


pytestmark = pytest.mark.skipif(
    not _bcc_middleware_reachable(),
    reason=f"bcc_middleware not reachable at {BCC_MIDDLEWARE_URL} -- start it from integrity-core to run this test",
)


def test_export_decision_reaches_a_real_bcc_middleware():
    from shield.integrity_exporter import IntegrityExporter

    exporter = IntegrityExporter(bcc_middleware_url=BCC_MIDDLEWARE_URL, agent_label="xibalba-shield-test")
    decision = PolicyDecision(
        device_id="dev-test",
        event_ref=EventRef(klass="network_flow", event_id="evt-test-1"),
        rule=RuleRef(rule_id="test-rule", name="test", version="1.0.0"),
        decision=Decision(action="deny", reason="test decision", severity="medium"),
    )

    result = exporter.export_decision(decision)

    # Either outcome (authorized True/False) proves the wire path works end-to-end -- what
    # this test asserts is that a REAL BCC commitment reached bcc_middleware and got a REAL
    # structured response back, not that the specific policy verdict is any particular value
    # (that depends on OPA/chain state this test doesn't control).
    assert "authorized" in result
    assert isinstance(result["authorized"], bool)
