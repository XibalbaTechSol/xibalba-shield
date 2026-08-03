"""
Tests for the real Linux eBPF sensor (shield/sensors/ebpf/, spec §4.1).

Only one thing is verifiable without root: constructing the sensor as non-root raises the
documented PermissionError rather than some other, less legible failure. Everything else --
including whether the BPF C source is even syntactically valid -- needs root on this machine,
because BCC's `BPF(text=...)` compiles AND loads (creates every declared map) in one call, and
map creation is itself a `bpf()` syscall gated on CAP_BPF
(`kernel.unprivileged_bpf_disabled=2` here). An earlier version of this module claimed
compilation alone was root-free and was wrong -- see `loader.py`'s own corrected docstring.

The root-gated tests self-skip when not root, the same convention `test_integrity_exporter.py`
uses for bcc_middleware reachability: no silent mock, and no failing the whole suite in
ordinary non-root CI/dev either. Run `sudo pytest tests/test_ebpf_sensor.py` to actually
exercise them.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

_BPF_SOURCE = Path(__file__).parent.parent / "shield" / "sensors" / "ebpf" / "process_exec.bpf.c"


def _bcc_available() -> bool:
    try:
        import bcc  # noqa: F401

        return True
    except ImportError:
        return False


pytestmark = pytest.mark.skipif(not _bcc_available(), reason="bcc (python3-bpfcc) not installed")


@pytest.mark.skipif(os.geteuid() != 0, reason="BCC's BPF(text=...) creates BPF maps at construction time, which needs CAP_BPF")
def test_bpf_source_compiles_and_loads():
    """BCC's `BPF(text=...)` compiles AND loads (creates every declared map) in one call --
    there is no root-free way to check just the C source is valid. Run with sudo."""
    from bcc import BPF

    b = BPF(text=_BPF_SOURCE.read_text())
    assert b is not None


def test_construction_without_root_raises_permission_error():
    from shield.sensors.ebpf.loader import LinuxEbpfSensor

    if os.geteuid() == 0:
        pytest.skip("running as root -- this test asserts the non-root failure path specifically")

    with pytest.raises(PermissionError, match="requires root"):
        LinuxEbpfSensor(device_id="test-device")


@pytest.mark.skipif(os.geteuid() != 0, reason="requires root (CAP_BPF) to load/attach the real BPF program")
def test_sensor_observes_a_real_execve():
    """The concrete, no-silent-mock proof: spawn a real subprocess and confirm the sensor's
    perf-buffer callback actually reports ITS pid via a real kernel kprobe -- not a fixture,
    not a synthetic event. Run with `sudo pytest tests/test_ebpf_sensor.py -k real_execve`."""
    import subprocess
    import time

    from shield.sensors.ebpf.loader import LinuxEbpfSensor

    sensor = LinuxEbpfSensor(device_id="test-device", tenant_id="pytest")

    proc = subprocess.Popen(["/usr/bin/true"])
    target_pid = proc.pid
    proc.wait()

    found = False
    deadline = time.time() + 5
    while time.time() < deadline and not found:
        for event in sensor.poll(timeout_ms=500):
            if event.process.pid == target_pid:
                found = True

    assert found, f"never observed real execve for pid {target_pid} within 5s"
