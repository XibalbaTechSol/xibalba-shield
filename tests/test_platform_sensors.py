from __future__ import annotations

import platform

import pytest

from shield.sensors.platform import (
    PlatformNotSupported,
    macos_support_status,
    native_support_matrix,
    require_native_platform,
    windows_support_status,
)


def test_native_support_matrix_documents_platform_contracts():
    matrix = native_support_matrix()

    assert matrix["Windows"].status == "planned"
    assert "ETW" in matrix["Windows"].required_native_source
    assert "ProcessActivity" in matrix["Windows"].normalized_events
    assert matrix["macOS"].status == "planned"
    assert "EndpointSecurity" in matrix["macOS"].required_native_source


def test_legacy_platform_status_helpers_use_matrix():
    assert windows_support_status()["platform"] == "Windows"
    assert macos_support_status()["platform"] == "macOS"


def test_require_native_platform_rejects_wrong_platform():
    target = "Windows" if platform.system() != "Windows" else "macOS"

    with pytest.raises(PlatformNotSupported):
        require_native_platform(target)
