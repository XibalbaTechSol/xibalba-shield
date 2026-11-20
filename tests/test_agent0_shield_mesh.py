from __future__ import annotations

import os
import signal
from pathlib import Path
import pytest

from shield.agent_core.cortex_memory import CortexMemoryProvider
from shield.backend.api import (
    _handle_agent0_talk,
    _get_agent0_passport,
    save_opa_policy,
    opa_policy_status,
)
from shield.sensors.network import (
    ProcNetTcpSensor,
    RealLinuxNetworkSensor,
    SUSPICIOUS_OUTBOUND_PORTS,
)


def test_proc_net_tcp_sensor_live_reads():
    """Verify ProcNetTcpSensor reads real host sockets without errors."""
    sensor = ProcNetTcpSensor()
    sockets = sensor.poll()
    assert isinstance(sockets, list)
    # On any running Linux workstation there are always listening/active sockets
    if Path("/proc/net/tcp").exists():
        assert len(sockets) > 0
        s0 = sockets[0]
        assert s0.flow is not None
        assert hasattr(s0.flow, "src_ip")
        assert hasattr(s0.flow, "dst_port")
        assert hasattr(s0, "activity")


def test_find_malicious_flows():
    sensor = ProcNetTcpSensor()
    # Mock socket list with one benign and one suspicious outbound connection
    sample_sockets = [
        {"local_ip": "127.0.0.1", "local_port": 8080, "remote_ip": "127.0.0.1", "remote_port": 35000, "state": "ESTABLISHED", "inode": "123", "pid": 100},
        {"local_ip": "192.168.1.50", "local_port": 54321, "remote_ip": "198.51.100.23", "remote_port": 4444, "state": "ESTABLISHED", "inode": "456", "pid": 9999, "comm": "malicious_c2"},
    ]
    malicious = sensor.find_malicious_flows(sample_sockets)
    assert len(malicious) == 1
    assert malicious[0]["remote_port"] == 4444
    assert malicious[0]["pid"] == 9999
    assert malicious[0]["remote_port"] in SUSPICIOUS_OUTBOUND_PORTS


def test_execute_containment_action(monkeypatch):
    sensor = ProcNetTcpSensor()
    killed_pids = []

    def mock_kill(pid, sig):
        killed_pids.append((pid, sig))

    monkeypatch.setattr(os, "kill", mock_kill)

    flow = {
        "local_ip": "192.168.1.50",
        "local_port": 54321,
        "remote_ip": "198.51.100.23",
        "remote_port": 4444,
        "pid": 8888,
    }
    result = sensor.execute_containment_action(flow, action="kill_process")
    assert result["success"] is True
    assert (8888, signal.SIGTERM) in killed_pids

    # Test unknown action
    unknown = sensor.execute_containment_action(flow, action="invalid")
    assert unknown["success"] is False


def test_cortex_memory_client_telemetry_and_scope(tmp_path):
    client = CortexMemoryProvider(
        base_url="http://127.0.0.1:6767",
        token="test_token",
        agent_id="shield.local",
        device_id="dev_local",
        outbox_path=tmp_path / "outbox.db",
        agent_did="did:integrity:68fed1331613937555a59398223e8e87520a87dd0305aac4fd7ecdc32a14a861",
        scope="agent:shield.local",
    )
    res = client.remember_telemetry(
        {
            "sensor": "proc_net_tcp",
            "active_sockets": 42,
            "anomalies": 0,
        },
        kind="network_telemetry",
    )
    assert res["status"] in ("queued", "saved")
    assert res["scope"] == "agent:shield.local"
    assert res["agent_did"] == "did:integrity:68fed1331613937555a59398223e8e87520a87dd0305aac4fd7ecdc32a14a861"


def test_save_opa_policy_and_status(tmp_path):
    rego_dir = tmp_path / "rego"
    rego_dir.mkdir()

    # Invalid empty or missing package
    with pytest.raises(ValueError, match="missing 'package"):
        save_opa_policy("test_invalid", "default allow = false", deploy=False, rego_dir=rego_dir)

    # Valid policy
    valid_rego = "package shield.policy\n\ndefault allow = true\n"
    saved = save_opa_policy("custom_rule", valid_rego, deploy=False, rego_dir=rego_dir)
    assert saved["id"] == "custom_rule"
    assert saved["file"] == "custom_rule.rego"
    assert saved["saved_to_disk"] is True
    assert (rego_dir / "custom_rule.rego").exists()

    # Status includes custom policy
    status = opa_policy_status("http://127.0.0.1:0", rego_dir=rego_dir, timeout=0.1)
    custom_entry = next((p for p in status["policies"] if p["id"] == "custom_rule"), None)
    assert custom_entry is not None
    assert custom_entry["name"] == "Custom Policy (custom_rule)"
    assert custom_entry["rego"] == valid_rego


def test_handle_agent0_talk_shield_local_and_cloud():
    # shield.local (token 4)
    resp_local = _handle_agent0_talk(
        message="perform socket scan on /proc/net/tcp",
        token_id=4,
        chain_id=84532,
    )
    assert resp_local["status"] == "completed"
    assert "Jev Fast Classifier" in resp_local["response"]
    assert resp_local["a2a_envelope"]["model"] == "jev-fast-classifier"
    assert resp_local["a2a_envelope"]["sender_did"] == "did:integrity:68fed1331613937555a59398223e8e87520a87dd0305aac4fd7ecdc32a14a861"

    # shield.cloud (token 5)
    resp_cloud = _handle_agent0_talk(
        message="correlate threats across the fleet",
        token_id=5,
        chain_id=84532,
    )
    assert resp_cloud["status"] == "completed"
    assert "Hermes 3 Reasoning Engine" in resp_cloud["response"]
    assert resp_cloud["a2a_envelope"]["model"] == "hermes-3-70b"
    assert resp_cloud["a2a_envelope"]["sender_did"] == "did:integrity:2ea17967f7a65589d570ca7e800844701fb36e6aa7374243e8766de8651f6bc4"
