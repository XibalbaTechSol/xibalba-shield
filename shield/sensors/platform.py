"""Platform support boundaries for native sensors."""

from __future__ import annotations

import platform
from dataclasses import dataclass


class PlatformNotSupported(RuntimeError):
    pass


@dataclass(frozen=True)
class NativeSensorPlan:
    platform: str
    status: str
    required_native_source: str
    normalized_events: tuple[str, ...]
    verification_command: str


def require_linux(sensor_name: str) -> None:
    if platform.system() != "Linux":
        raise PlatformNotSupported(f"{sensor_name} is currently implemented only on Linux eBPF")


def windows_support_status() -> dict:
    return native_support_matrix()["Windows"].__dict__


def macos_support_status() -> dict:
    return native_support_matrix()["macOS"].__dict__


def native_support_matrix() -> dict[str, NativeSensorPlan]:
    return {
        "Windows": NativeSensorPlan(
            platform="Windows",
            status="planned",
            required_native_source="ETW/Sysmon/Windows Filtering Platform",
            normalized_events=("ProcessActivity", "FileActivity", "NetworkFlow"),
            verification_command="run platform-native ETW/WFP integration tests on Windows",
        ),
        "macOS": NativeSensorPlan(
            platform="macOS",
            status="planned",
            required_native_source="EndpointSecurity Framework/NetworkExtension",
            normalized_events=("ProcessActivity", "FileActivity", "NetworkFlow"),
            verification_command="run EndpointSecurity/NetworkExtension integration tests on macOS",
        ),
    }


def require_native_platform(target: str) -> None:
    current = platform.system()
    if current != target:
        raise PlatformNotSupported(f"{target} native sensors require {target}; current platform is {current}")
