from __future__ import annotations

import platform
import pytest

from shield.sensors.windows import WindowsNativeSensor
from shield.sensors.platform import PlatformNotSupported
from shield.schemas.events import NormalizedEvent


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
        test_event = NormalizedEvent(
            event_id="test-win-event-1",
            timestamp="2026-11-04T00:00:00Z",
            event_type="ProcessActivity",
            source="ETW",
            data={"pid": 1234, "image": "cmd.exe"},
        )
        sensor.inject_event(test_event)
        events = list(sensor.events())
        assert len(events) == 1
        assert events[0].event_id == "test-win-event-1"
