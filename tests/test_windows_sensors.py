from __future__ import annotations

import platform
import subprocess
import sys
import pytest

from shield.sensors.windows import WindowsNativeSensor
from shield.sensors.platform import PlatformNotSupported
from shield.schemas.events import ProcessActivity, ProcessInfo, Activity


def test_windows_native_sensor_platform_enforcement():
    if platform.system() != "Windows":
        with pytest.raises(PlatformNotSupported):
            WindowsNativeSensor()
    else:
        sensor = WindowsNativeSensor(seed_existing=False)
        assert list(sensor.events()) == []


def test_windows_native_sensor_event_injection():
    # Injection test works cross-platform via empty mock snapshot
    sensor = WindowsNativeSensor(snapshot_fn=lambda: [])
    test_event = ProcessActivity(
        device_id="test-win",
        process=ProcessInfo(pid=1234, name="cmd.exe", exe_path="C:\\Windows\\System32\\cmd.exe"),
        activity=Activity(type="process_spawn"),
    )
    sensor.inject_event(test_event)
    events = list(sensor.events())
    assert len(events) == 1
    assert events[0].device_id == "test-win"
    assert sensor.health()["tracked_processes"] == 0


def test_windows_native_sensor_mock_snapshot_detection():
    # Simulates: initial snapshot has PID 100, next snapshot adds PID 200
    state = [(100, 1, "services.exe", "C:\\Windows\\System32\\services.exe")]

    def fake_snapshot():
        return list(state)

    sensor = WindowsNativeSensor(device_id="win-node", seed_existing=True, snapshot_fn=fake_snapshot)
    assert 100 in sensor._seen_pids
    assert sensor.health()["tracked_processes"] == 1

    # No new processes
    assert sensor.scan_processes() == []

    # Spawn new process
    state.append((200, 100, "python.exe", "C:\\Python\\python.exe"))
    new_events = sensor.scan_processes()
    assert len(new_events) == 1
    event = new_events[0]
    assert event.process.pid == 200
    assert event.process.name == "python.exe"
    assert event.process.exe_path == "C:\\Python\\python.exe"
    assert event.process.ppid == 100
    assert event.device_id == "win-node"

    # Verify queue draining
    queued = list(sensor.events())
    assert len(queued) == 1
    assert queued[0].process.pid == 200
    assert list(sensor.events()) == []


@pytest.mark.skipif(platform.system() != "Windows", reason="Requires real Windows kernel for live Toolhelp snapshot")
def test_windows_native_sensor_live_process_discovery():
    sensor = WindowsNativeSensor(device_id="win-live", seed_existing=True)

    # Spawn a real worker process
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(15)"])
    try:
        new_events = sensor.scan_processes()
        matched = [e for e in new_events if e.process.pid == proc.pid]
        assert len(matched) == 1
        event = matched[0]
        assert event.process.pid == proc.pid
        assert "python" in event.process.name.lower()
        assert event.device_id == "win-live"
    finally:
        proc.terminate()
        proc.wait(timeout=5)
