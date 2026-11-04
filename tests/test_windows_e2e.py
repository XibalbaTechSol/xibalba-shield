from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from shield.agent_core.action_broker import ActionBroker
from shield.agent_core.eventlog import EventLog
from shield.agent_core.readiness import ProductionReadiness
from shield.agent_core.registry import AgentRegistry, DeviceContext
from shield.agent_core.router import EventRouter
from shield.opa_local import supervised_opa
from shield.policy_engine import PolicyEngine
from shield.schemas.events import Activity, ProcessActivity, ProcessInfo
from shield.sensors.windows import WindowsNativeSensor


def _passed_readiness() -> ProductionReadiness:
    return ProductionReadiness.from_mapping({
        "policy_signature_verified": True,
        "agent_identity_verified": True,
        "kernel_probe_verified": True,
        "audit_receipt_verified": True,
        "rollback_verified": True,
        "operator_approval": True,
        "kill_runtime_tested": True,
        "cgroup_runtime_tested": True,
        "network_runtime_tested": True,
    })


def _make_shadow_ai_event(pid: int, device_id: str = "win-e2e") -> ProcessActivity:
    return ProcessActivity(
        device_id=device_id,
        process=ProcessInfo(
            pid=pid,
            name="shadow_ai.exe",
            exe_path="/opt/ai/shadow-agent/run",
            ppid=1,
        ),
        activity=Activity(type="launch", severity="high"),
    )


def test_windows_e2e_pipeline_with_broker_injection(tmp_path: Path):
    """Test full Router -> PolicyEngine -> ActionBroker -> EventLog pipeline cross-platform."""
    calls: list[tuple[str, int]] = []

    def mock_win_freeze(pid: int) -> str:
        calls.append(("freeze", pid))
        return "NtSuspendProcess"

    def mock_win_resume(pid: int) -> str:
        calls.append(("resume", pid))
        return "NtResumeProcess"

    def mock_win_kill(pid: int) -> str:
        calls.append(("kill", pid))
        return "TerminateProcess"

    broker = ActionBroker(
        enable_destructive=True,
        readiness=_passed_readiness(),
        win_freeze=mock_win_freeze,
        win_resume=mock_win_resume,
        win_kill=mock_win_kill,
    )

    log_path = tmp_path / "decisions.jsonl"
    key_path = tmp_path / "integrity.key"
    key_path.write_bytes(b"k" * 32)
    event_log = EventLog(log_path, integrity_key_path=key_path)
    device = DeviceContext(device_id="win-e2e", tenant_id="tenant-e2e", device_role="workstation")
    registry = AgentRegistry()

    with supervised_opa("smb") as (opa_url, pack):
        engine = PolicyEngine(opa_url=opa_url, pack=pack)
        router = EventRouter(
            device=device,
            registry=registry,
            policy_engine=engine,
            action_broker=broker,
            event_log=event_log,
            enforcement_mode="enforce",
        )

        event = _make_shadow_ai_event(pid=4321, device_id="win-e2e")
        decision = router.handle(event)

        assert decision.decision.action == "contain"
        assert decision.rule.rule_id == "smb-contain-shadow-ai-processes"
        assert calls == [("freeze", 4321)]

        # Broker manual escalation
        broker.resume(4321)
        broker.kill_process(4321)
        assert calls == [("freeze", 4321), ("resume", 4321), ("kill", 4321)]

    # Verify cryptographic audit trail
    assert log_path.exists()
    assert event_log.count() == 1
    verification = event_log.verify()
    assert verification["ok"] is True
    assert verification["checked"] == 1


@pytest.mark.skipif(sys.platform != "win32", reason="Requires live Windows kernel NT APIs and OPA on Windows")
def test_windows_e2e_live_containment_and_audit(tmp_path: Path):
    """Real Windows E2E: Real worker process -> OPA smb pack -> NtSuspendProcess -> TerminateProcess -> EventLog HMAC."""
    worker = subprocess.Popen(
        [sys.executable, "-c", "import time; [time.sleep(0.05) for _ in range(1000)]"]
    )
    try:
        broker = ActionBroker(enable_destructive=True, readiness=_passed_readiness())
        log_path = tmp_path / "decisions.jsonl"
        key_path = tmp_path / "integrity.key"
        key_path.write_bytes(b"k" * 32)
        event_log = EventLog(log_path, integrity_key_path=key_path)
        device = DeviceContext(device_id="win-live", tenant_id="tenant-live", device_role="workstation")
        registry = AgentRegistry()

        with supervised_opa("smb") as (opa_url, pack):
            engine = PolicyEngine(opa_url=opa_url, pack=pack)
            router = EventRouter(
                device=device,
                registry=registry,
                policy_engine=engine,
                action_broker=broker,
                event_log=event_log,
                enforcement_mode="enforce",
            )

            # 1. Trigger contain against real worker pid
            event = _make_shadow_ai_event(pid=worker.pid, device_id="win-live")
            decision = router.handle(event)

            assert decision.decision.action == "contain"
            assert decision.rule.rule_id == "smb-contain-shadow-ai-processes"

            # Worker is still alive but frozen by NtSuspendProcess
            assert worker.poll() is None

            # 2. Resume process via NtResumeProcess
            resume_result = broker.resume(worker.pid)
            assert resume_result.completed is True
            assert resume_result.action == "resume"
            assert resume_result.method == "NtResumeProcess"
            assert worker.poll() is None

            # 3. Terminate process via TerminateProcess
            kill_result = broker.kill_process(worker.pid)
            assert kill_result.completed is True
            assert kill_result.action == "terminate"
            assert kill_result.method == "TerminateProcess"

            worker.wait(timeout=5)
            assert worker.poll() is not None

        # 4. Verify decision log and cryptographic signature on Windows
        assert log_path.exists()
        assert event_log.count() == 1
        verification = event_log.verify()
        assert verification["ok"] is True
        assert verification["checked"] == 1
    finally:
        if worker.poll() is None:
            worker.kill()


@pytest.mark.skipif(sys.platform != "win32", reason="Requires real Windows kernel for live sensor + router integration")
def test_windows_e2e_sensor_to_router_live(tmp_path: Path):
    """Real Windows E2E: Sensor discovers real process -> Router evaluates against OPA."""
    sensor = WindowsNativeSensor(device_id="win-sensor-e2e", seed_existing=True)

    worker = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(10)"])
    try:
        new_events = sensor.scan_processes()
        target_events = [e for e in new_events if e.process.pid == worker.pid]
        assert len(target_events) == 1
        observed_event = target_events[0]

        device = DeviceContext(device_id="win-sensor-e2e", tenant_id="tenant-1", device_role="workstation")
        registry = AgentRegistry()

        with supervised_opa("smb") as (opa_url, pack):
            engine = PolicyEngine(opa_url=opa_url, pack=pack)
            router = EventRouter(
                device=device,
                registry=registry,
                policy_engine=engine,
                enforcement_mode="observe",
            )
            # Route observed event
            decision = router.handle(observed_event)
            # Default python worker does not match shadow AI path, so it's logged
            assert decision.decision.action in ("log_only", "allow")
    finally:
        worker.terminate()
        worker.wait(timeout=5)
