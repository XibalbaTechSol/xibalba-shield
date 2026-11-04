from __future__ import annotations

import platform
import pytest

from shield.sensors.windows import WindowsNativeSensor
from shield.sensors.platform import PlatformNotSupported
from shield.schemas.events import ProcessActivity, ProcessInfo, Activity


def test_windows_native_sensor_platform_enforcement():
    if platform.system() != "Windows":
        with pytest.raises(PlatformNotSupported):
            WindowsNativeSensor()
    else:
        sensor = WindowsNativeSensor()
        assert list(sensor.events()) == []


def test_windows_native_sensor_event_injection_when_on_windows():
    if platform.system() == "Windows":
        sensor = WindowsNativeSensor()
        test_event = ProcessActivity(
            device_id="test-win",
            process=ProcessInfo(pid=1234, ppid=1, uid=0, gid=0, comm="cmd.exe"),
            activity=Activity(action="exec", path="C:\\Windows\\System32\\cmd.exe"),
        )
        sensor.inject_event(test_event)
        events = list(sensor.events())
        assert len(events) == 1
        assert events[0].device_id == "test-win"
