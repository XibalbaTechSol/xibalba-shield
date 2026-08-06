"""
Tests for the three real Linux eBPF sensors (shield/sensors/ebpf/, spec §4.1):
LinuxEbpfSensor (process exec), LinuxFileWriteSensor (file writes), LinuxTcpConnectSensor
(outbound TCP connects).

Only one thing is verifiable without root: constructing a sensor as non-root raises the
documented PermissionError rather than some other, less legible failure. Everything else --
including whether any of the three BPF C sources are even syntactically valid -- needs root
on this machine, because BCC's `BPF(text=...)` compiles AND loads (creates every declared
map) in one call, and map creation is itself a `bpf()` syscall gated on CAP_BPF
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

_EBPF_DIR = Path(__file__).parent.parent / "shield" / "sensors" / "ebpf"
_BPF_SOURCE = _EBPF_DIR / "process_exec.bpf.c"
_FILE_WRITE_SOURCE = _EBPF_DIR / "file_write.bpf.c"
_TCP_CONNECT_SOURCE = _EBPF_DIR / "tcp_connect.bpf.c"


def _bcc_available() -> bool:
    try:
        import bcc  # noqa: F401

        return True
    except ImportError:
        return False


def test_sensitive_path_filter_matches_globs_without_root():
    from shield.sensors.ebpf.loader import _matches_sensitive_path

    assert _matches_sensitive_path("/home/alice/.ssh/id_rsa", ["/home/*/.ssh/*"]) is True
    assert _matches_sensitive_path("/tmp/notes.txt", ["/home/*/.ssh/*"]) is False
    assert _matches_sensitive_path("/tmp/notes.txt", []) is True


def test_tcp_connect_source_avoids_net_sock_header_chain():
    source = _TCP_CONNECT_SOURCE.read_text()
    include_lines = [line.strip() for line in source.splitlines() if line.strip().startswith("#include")]

    assert "#include <net/sock.h>" not in include_lines
    assert "struct shield_sock_common" in source
    assert "skc_daddr" in source
    assert "skc_rcv_saddr" in source
    assert "skc_dport" in source
    assert "skc_num" in source


@pytest.mark.skipif(not _bcc_available(), reason="bcc (python3-bpfcc) not installed")
@pytest.mark.skipif(os.geteuid() != 0, reason="BCC's BPF(text=...) creates BPF maps at construction time, which needs CAP_BPF")
def test_bpf_source_compiles_and_loads():
    """BCC's `BPF(text=...)` compiles AND loads (creates every declared map) in one call --
    there is no root-free way to check just the C source is valid. Run with sudo."""
    from bcc import BPF

    b = BPF(text=_BPF_SOURCE.read_text())
    assert b is not None


@pytest.mark.skipif(not _bcc_available(), reason="bcc (python3-bpfcc) not installed")
@pytest.mark.skipif(os.geteuid() != 0, reason="BCC's BPF(text=...) creates BPF maps at construction time, which needs CAP_BPF")
def test_file_write_bpf_source_compiles_and_loads():
    from bcc import BPF

    b = BPF(text=_FILE_WRITE_SOURCE.read_text())
    assert b is not None


@pytest.mark.skipif(not _bcc_available(), reason="bcc (python3-bpfcc) not installed")
@pytest.mark.skipif(os.geteuid() != 0, reason="BCC's BPF(text=...) creates BPF maps at construction time, which needs CAP_BPF")
def test_tcp_connect_bpf_source_compiles_and_loads():
    from bcc import BPF

    b = BPF(text=_TCP_CONNECT_SOURCE.read_text())
    assert b is not None


@pytest.mark.parametrize("sensor_name", ["LinuxEbpfSensor", "LinuxFileWriteSensor", "LinuxTcpConnectSensor"])
def test_construction_without_root_raises_permission_error(sensor_name):
    import shield.sensors.ebpf.loader as loader_module

    if os.geteuid() == 0:
        pytest.skip("running as root -- this test asserts the non-root failure path specifically")

    sensor_cls = getattr(loader_module, sensor_name)
    with pytest.raises(PermissionError, match="requires root"):
        sensor_cls(device_id="test-device")


@pytest.mark.skipif(not _bcc_available(), reason="bcc (python3-bpfcc) not installed")
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


@pytest.mark.skipif(not _bcc_available(), reason="bcc (python3-bpfcc) not installed")
@pytest.mark.skipif(os.geteuid() != 0, reason="requires root (CAP_BPF) to load/attach the real BPF program")
def test_file_write_sensor_observes_a_real_write_open():
    """Writes a real temp file from THIS test process and confirms the sensor's kprobe+
    kretprobe pair on openat actually reports it -- not a fixture."""
    import tempfile
    import time

    from shield.sensors.ebpf.loader import LinuxFileWriteSensor

    sensor = LinuxFileWriteSensor(device_id="test-device", tenant_id="pytest")
    my_pid = os.getpid()

    with tempfile.NamedTemporaryFile(mode="w", suffix="-pytest-write") as tmp:
        tmp.write("real pytest write\n")
        tmp.flush()
        target_path = tmp.name

        found = False
        deadline = time.time() + 5
        while time.time() < deadline and not found:
            for event in sensor.poll(timeout_ms=500):
                if event.process.pid == my_pid and event.file.path == target_path:
                    found = True

    assert found, f"never observed real write-open of {target_path!r} within 5s"


@pytest.mark.skipif(not _bcc_available(), reason="bcc (python3-bpfcc) not installed")
@pytest.mark.skipif(os.geteuid() != 0, reason="requires root (CAP_BPF) to load/attach the real BPF program")
def test_tcp_connect_sensor_observes_a_real_connect():
    """Connects to a real local TCP listener started by this test (no external service
    dependency) and confirms the sensor's kprobe+kretprobe pair on tcp_v4_connect reports
    it -- not a fixture."""
    import socket as _socket
    import time

    from shield.sensors.ebpf.loader import LinuxTcpConnectSensor

    sensor = LinuxTcpConnectSensor(device_id="test-device", tenant_id="pytest")
    my_pid = os.getpid()

    listener = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listen_port = listener.getsockname()[1]
    client = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
    client.connect(("127.0.0.1", listen_port))

    found = False
    deadline = time.time() + 5
    while time.time() < deadline and not found:
        for event in sensor.poll(timeout_ms=500):
            if event.process.pid == my_pid and event.flow.dst_port == listen_port:
                found = True

    client.close()
    listener.close()
    assert found, f"never observed real connect to port {listen_port} within 5s"
