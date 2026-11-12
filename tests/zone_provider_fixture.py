"""A zone provider reachable only by import path, for `tests/test_gate_zone.py`."""

from __future__ import annotations


def make_provider(_settings):
    return lambda _agent_id: "yellow"
