from __future__ import annotations

import copy

import pytest

from shield.network_contract import NetworkContractError, assert_safe_network_payload, build_network_event, validate_network_event


def test_network_event_redacts_identifiers_and_validates():
    payload = build_network_event(
        {"class": "flow", "observed_at": "2026-09-19T00:00:00Z", "confidence": 0.8, "flow": {"dst_ip": "203.0.113.8", "dst_port": 443, "protocol": "tcp", "service_class": "web", "destination_class": "new", "bytes_out": 12}},
        network_id="corp", segment_id="users", observation_point="endpoint", sensor_id="sensor-a", device_id="laptop-a", ref_key=b"a" * 32,
        policy={"action": "log_only", "policy_version": "1", "reason_code": "NEW_DESTINATION"},
    )
    validate_network_event(payload)
    assert payload["network"]["network_id"].startswith("sha256:")
    assert payload["event"]["flow"]["destination_ref"].startswith("sha256:")
    assert "203.0.113.8" not in str(payload)
    assert payload["privacy"]["redacted"] is True


def test_network_event_rejects_raw_pii_at_egress():
    payload = build_network_event({}, network_id="n", segment_id="s", observation_point="dns", sensor_id="z", device_id="d")
    unsafe = copy.deepcopy(payload)
    unsafe["event"]["action"] = "contact admin@example.com"
    with pytest.raises(NetworkContractError):
        assert_safe_network_payload(unsafe)


def test_unknown_network_control_field_is_rejected():
    payload = build_network_event({}, network_id="n", segment_id="s", observation_point="dns", sensor_id="z", device_id="d")
    payload["enforcement"]["execute_command"] = "iptables -F"
    with pytest.raises(NetworkContractError):
        validate_network_event(payload)
