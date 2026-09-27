from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from shield.hermes_contract import HermesContractError, build_event, validate_event
from shield.schemas.events import Activity, EventRef, PolicyDecision, ProcessActivity, ProcessInfo, Decision, RuleRef

FIXTURES = Path(__file__).parent / "fixtures" / "hermes"


def _sample():
    event = ProcessActivity(
        device_id="opaque-device", tenant_id="opaque-tenant",
        process=ProcessInfo(pid=42, ppid=1, name="python", exe_path="/home/alice/private.py", cmdline="--token secret"),
        activity=Activity(type="exec"),
    )
    decision = PolicyDecision(
        device_id="opaque-device", event_ref=EventRef(klass="process_activity", event_id="evt-1"),
        rule=RuleRef(rule_id="rule-1", name="Process observed", version="1.0.0"), decision=Decision(action="log_only"),
    )
    return event, decision


def test_build_event_is_schema_valid_and_redacted():
    event, decision = _sample()
    payload = build_event(event, decision, sensor="linux-ebpf-process")
    validate_event(payload)
    assert payload["event"]["process"]["path_class"] == "user-home"
    assert "exe_path" not in payload["event"]["process"]
    assert "cmdline" not in payload["event"]["process"]
    assert payload["privacy"]["redaction_proof"].startswith("sha256:")


def test_unknown_control_fields_are_rejected():
    event, decision = _sample()
    payload = build_event(event, decision)
    payload["policy"]["execute_shell"] = "rm -rf /"
    with pytest.raises(HermesContractError):
        validate_event(payload)


def test_secret_and_pii_payloads_are_rejected_at_boundary():
    event, decision = _sample()
    payload = build_event(event, decision)
    unsafe = copy.deepcopy(payload)
    unsafe["event"]["action"] = "Bearer sk-test_123456789012345"
    with pytest.raises(HermesContractError):
        validate_event(unsafe)
        from shield.hermes_contract import assert_safe_payload
        assert_safe_payload(unsafe)


def test_valid_fixture_is_accepted():
    validate_event(json.loads((FIXTURES / "valid_event.json").read_text()))


def test_invalid_fixture_is_rejected():
    with pytest.raises(HermesContractError):
        validate_event(json.loads((FIXTURES / "invalid_unknown_control.json").read_text()))
