"""Drift guard for the Python -> Rust contract of the device app.

`device-app/device-core` (Rust) reads the files Shield writes. Its golden fixtures were produced
by the real Python writers. If a field the reader relies on is renamed or removed here, this test
fails, and the fixtures plus the Rust reader must be updated together.
"""
from __future__ import annotations

import json
from pathlib import Path

from shield.schemas.events import EnforcementOutcome

FIXTURES = Path(__file__).resolve().parents[1] / "device-app" / "device-core" / "tests" / "fixtures"

# The fields device-core's frozen_processes() reads. Removing one silently breaks the app.
RELIED_ON = {"action", "completed", "event_id", "pid", "time", "handle_to_contain_ms", "resumes_event_id"}


def test_enforcement_outcome_still_carries_every_field_the_device_app_reads():
    keys = set(EnforcementOutcome(event_id="e", device_id="d", action="freeze", completed=True).to_dict())
    assert RELIED_ON <= keys, f"device-app reads fields Shield no longer writes: {RELIED_ON - keys}"


def test_golden_outcome_fixtures_have_exactly_the_current_outcome_shape():
    current = set(EnforcementOutcome(event_id="e", device_id="d", action="freeze", completed=True).to_dict())
    for line in (FIXTURES / "outcomes.jsonl").read_text().splitlines():
        assert set(json.loads(line)) == current, "regenerate device-core/tests/fixtures/outcomes.jsonl"


def test_golden_decision_fixture_has_the_fields_the_summary_reads():
    row = json.loads((FIXTURES / "decisions.jsonl").read_text().splitlines()[0])
    assert row["decision"]["action"] and row["decision"]["severity"]
    assert row["event_ref"]["class"] and "export" in row and row["time"]
