"""
Linux eBPF sensors — real kernel probes, per spec/xibalba-shield-v1.md §4.1.

Three sensors, each loading its own `.bpf.c` source via BCC (python3-bpfcc, already
installed system-wide — BCC JIT-compiles C source with its own embedded LLVM against the
running kernel's installed headers; no separate `clang` binary is needed):

  - `LinuxEbpfSensor` (`process_exec.bpf.c`) — process-exec, via a kprobe on `execve`.
  - `LinuxFileWriteSensor` (`file_write.bpf.c`) — file writes, via a kprobe+kretprobe pair
    on `openat`, filtered to `O_WRONLY`/`O_RDWR` in-kernel. Not yet filtered by "sensitive
    path" (spec §4.1's own phrasing) — that's config-loadable-filter work (§4.6), unbuilt.
  - `LinuxTcpConnectSensor` (`tcp_connect.bpf.c`) — outbound TCP connects, via a
    kprobe+kretprobe pair on `tcp_v4_connect`. IPv4 only; `tcp_v6_connect` is real,
    separate kernel-side work deferred to keep this file's review surface bounded.

All three normalize into the same `schemas.events` shapes `DevModeSensor` already produces
(`ProcessActivity`/`FileActivity`/`NetworkFlow`), so nothing downstream (agent_core,
policy_engine) needs to know which sensor is live. DNS observation (spec §4.1's other named
target) is NOT built — see the module docstring note in `tcp_connect.bpf.c` for why it's a
separate mechanism (uprobe/UDP-parsing, not a syscall kprobe) rather than an oversight here.

**Verified as of this writing: nothing about this module has been confirmed working.** BCC's
`BPF(text=...)` compiles AND loads (creates every declared map) in one call, and map creation
is itself a `bpf()` syscall gated on `CAP_BPF` — so on this machine
(`kernel.unprivileged_bpf_disabled=2`) there is no way to even confirm any of the three C
sources are syntactically valid without root, let alone that they attach and observe real
events. (An earlier version of this docstring claimed compilation alone was root-free for
`process_exec.bpf.c`; that was wrong — corrected in that file's own comment rather than
silently fixed here too.)

Run `sudo python3 -m shield.sensors.ebpf.loader` (or `sudo pytest tests/test_ebpf_sensor.py`)
to actually verify this module. Until that has been run successfully at least once, treat
every claim in this file as unverified design, not working code — no silent mock, same rule
the rest of this repo follows.
"""

from __future__ import annotations

import os
import socket
import struct
import time
from pathlib import Path
from typing import Iterator

from ...schemas.events import (
    Activity,
    FileActivity,
    FileInfo,
    NetworkFlow,
    NetworkFlowInfo,
    NormalizedEvent,
    ProcessActivity,
    ProcessInfo,
)

_BPF_SOURCE = Path(__file__).with_name("process_exec.bpf.c")
_FILE_WRITE_SOURCE = Path(__file__).with_name("file_write.bpf.c")
_TCP_CONNECT_SOURCE = Path(__file__).with_name("tcp_connect.bpf.c")


def _require_root(class_name: str) -> None:
    if os.geteuid() != 0:
        raise PermissionError(
            f"{class_name} requires root (CAP_BPF) to load its BPF program — "
            "this machine has kernel.unprivileged_bpf_disabled=2, so there is no "
            "non-root path. Run under sudo."
        )


class LinuxEbpfSensor:
    """Structurally satisfies `shield.sensors.base.Sensor` (a `Protocol` — matched by shape,
    not inheritance, the same way `dev_generator.DevModeSensor` does). Real implementation
    backed by a kprobe on `execve`. Requires root to construct
    (the BPF program load happens in `__init__`, not lazily, so a permission failure surfaces
    immediately rather than on first `events()` iteration)."""

    def __init__(self, device_id: str, tenant_id: str = ""):
        _require_root("LinuxEbpfSensor")

        # Imported here, not at module level: importing bcc doesn't itself require root, but
        # every OTHER Sensor implementation in this package has zero runtime dependency on
        # bcc being installed at all, so it shouldn't be an import-time cost for them.
        from bcc import BPF

        self._device_id = device_id
        self._tenant_id = tenant_id
        self._pending: list[ProcessActivity] = []

        self._bpf = BPF(text=_BPF_SOURCE.read_text())
        execve_fnname = self._bpf.get_syscall_fnname("execve")
        self._bpf.attach_kprobe(event=execve_fnname, fn_name="on_execve")
        self._bpf["process_exec_events"].open_perf_buffer(self._on_perf_event)

    def _on_perf_event(self, cpu: int, data, size: int) -> None:  # noqa: ARG002 — perf_buffer callback signature
        rec = self._bpf["process_exec_events"].event(data)
        self._pending.append(
            ProcessActivity(
                device_id=self._device_id,
                tenant_id=self._tenant_id,
                process=ProcessInfo(
                    pid=rec.pid,
                    name=rec.comm.decode("utf-8", errors="replace"),
                    exe_path=rec.filename.decode("utf-8", errors="replace"),
                    ppid=rec.ppid,
                ),
                activity=Activity(type="launch", severity="medium", outcome="success"),
            )
        )

    def poll(self, timeout_ms: int = 1000) -> list[ProcessActivity]:
        """One poll cycle: blocks up to `timeout_ms`, returns whatever real events arrived
        (possibly empty). Separated from `events()` so `self_test()` can drive polling on
        its own deadline instead of an unbounded generator."""
        self._bpf.perf_buffer_poll(timeout=timeout_ms)
        drained, self._pending = self._pending, []
        return drained

    def events(self) -> Iterator[NormalizedEvent]:
        """Blocking generator: polls the perf buffer forever, yielding one normalized event
        per real `execve` call observed on this machine, for as long as the caller keeps
        iterating."""
        while True:
            for event in self.poll():
                yield event


class LinuxFileWriteSensor:
    """Structurally satisfies `Sensor`. Real implementation backed by a kprobe+kretprobe
    pair on `openat`, filtered in-kernel to write-mode opens. Requires root to construct,
    same reasoning as `LinuxEbpfSensor`."""

    def __init__(self, device_id: str, tenant_id: str = ""):
        _require_root("LinuxFileWriteSensor")

        from bcc import BPF

        self._device_id = device_id
        self._tenant_id = tenant_id
        self._pending: list[FileActivity] = []

        self._bpf = BPF(text=_FILE_WRITE_SOURCE.read_text())
        openat_fnname = self._bpf.get_syscall_fnname("openat")
        self._bpf.attach_kprobe(event=openat_fnname, fn_name="syscall__trace_entry_openat")
        self._bpf.attach_kretprobe(event=openat_fnname, fn_name="trace_openat_return")
        self._bpf["file_write_events"].open_perf_buffer(self._on_perf_event)

    def _on_perf_event(self, cpu: int, data, size: int) -> None:  # noqa: ARG002
        rec = self._bpf["file_write_events"].event(data)
        path = rec.filename.decode("utf-8", errors="replace")
        name = path.rsplit("/", 1)[-1] if path else ""
        self._pending.append(
            FileActivity(
                device_id=self._device_id,
                process=ProcessInfo(
                    pid=rec.pid,
                    name=rec.comm.decode("utf-8", errors="replace"),
                    ppid=rec.ppid,
                ),
                file=FileInfo(path=path, name=name),
                activity=Activity(
                    type="write_open",
                    severity="medium",
                    outcome="success" if rec.ret >= 0 else "failure",
                ),
            )
        )

    def poll(self, timeout_ms: int = 1000) -> list[FileActivity]:
        self._bpf.perf_buffer_poll(timeout=timeout_ms)
        drained, self._pending = self._pending, []
        return drained

    def events(self) -> Iterator[NormalizedEvent]:
        while True:
            for event in self.poll():
                yield event


class LinuxTcpConnectSensor:
    """Structurally satisfies `Sensor`. Real implementation backed by a kprobe+kretprobe
    pair on `tcp_v4_connect`. IPv4 only — see `tcp_connect.bpf.c`'s module docstring.
    Requires root to construct, same reasoning as `LinuxEbpfSensor`."""

    def __init__(self, device_id: str, tenant_id: str = ""):
        _require_root("LinuxTcpConnectSensor")

        from bcc import BPF

        self._device_id = device_id
        self._tenant_id = tenant_id
        self._pending: list[NetworkFlow] = []

        self._bpf = BPF(text=_TCP_CONNECT_SOURCE.read_text())
        self._bpf.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect_entry")
        self._bpf.attach_kretprobe(event="tcp_v4_connect", fn_name="trace_connect_v4_return")
        self._bpf["tcp_connect_events"].open_perf_buffer(self._on_perf_event)

    def _on_perf_event(self, cpu: int, data, size: int) -> None:  # noqa: ARG002
        rec = self._bpf["tcp_connect_events"].event(data)
        self._pending.append(
            NetworkFlow(
                device_id=self._device_id,
                process=ProcessInfo(
                    pid=rec.pid,
                    name=rec.comm.decode("utf-8", errors="replace"),
                    ppid=rec.ppid,
                ),
                flow=NetworkFlowInfo(
                    src_ip=socket.inet_ntoa(struct.pack("I", rec.saddr)),
                    src_port=rec.lport,
                    dst_ip=socket.inet_ntoa(struct.pack("I", rec.daddr)),
                    dst_port=rec.dport,
                    protocol="tcp",
                    direction="outbound",
                ),
                activity=Activity(type="connect", severity="medium", outcome="success"),
            )
        )

    def poll(self, timeout_ms: int = 1000) -> list[NetworkFlow]:
        self._bpf.perf_buffer_poll(timeout=timeout_ms)
        drained, self._pending = self._pending, []
        return drained

    def events(self) -> Iterator[NormalizedEvent]:
        while True:
            for event in self.poll():
                yield event


def _poll_until(sensor, seconds: int, matches) -> bool:
    """Shared self-test polling loop: drive `sensor.poll()` until `matches(event)` is True
    for something real it observed, or the deadline passes."""
    deadline = time.time() + seconds
    while time.time() < deadline:
        remaining_ms = max(1, int((deadline - time.time()) * 1000))
        for event in sensor.poll(timeout_ms=min(1000, remaining_ms)):
            if matches(event):
                return True
    return False


def _self_test_process_exec(seconds: int) -> bool:
    """Load LinuxEbpfSensor, spawn a real subprocess, confirm its real exec is observed."""
    import subprocess

    print("[self-test:process_exec] loading (requires root)...")
    sensor = LinuxEbpfSensor(device_id="self-test-device", tenant_id="self-test")
    proc = subprocess.Popen(["/usr/bin/true"])
    target_pid = proc.pid
    proc.wait()
    print(f"[self-test:process_exec] spawned /usr/bin/true (pid {target_pid}), watching for its exec...")

    ok = _poll_until(sensor, seconds, lambda e: e.process.pid == target_pid)
    print(f"[self-test:process_exec] {'PASS' if ok else 'FAIL'} — "
          f"{'observed' if ok else 'never observed'} pid {target_pid}'s real execve.")
    return ok


def _self_test_file_write(seconds: int) -> bool:
    """Load LinuxFileWriteSensor, write a real temp file from THIS process, confirm the
    sensor observes its own real openat(O_WRONLY|...) call."""
    import os as _os
    import tempfile

    print("[self-test:file_write] loading (requires root)...")
    sensor = LinuxFileWriteSensor(device_id="self-test-device", tenant_id="self-test")
    my_pid = _os.getpid()

    with tempfile.NamedTemporaryFile(mode="w", suffix="-shield-self-test") as tmp:
        tmp.write("real self-test write\n")
        tmp.flush()
        target_path = tmp.name
        print(f"[self-test:file_write] wrote {target_path} from this process (pid {my_pid}), watching...")

        ok = _poll_until(sensor, seconds, lambda e: e.process.pid == my_pid and e.file.path == target_path)

    print(f"[self-test:file_write] {'PASS' if ok else 'FAIL'} — "
          f"{'observed' if ok else 'never observed'} this process's real write open of {target_path!r}.")
    return ok


def _self_test_tcp_connect(seconds: int) -> bool:
    """Load LinuxTcpConnectSensor, connect() to a real local TCP listener started by this
    same self-test (no dependency on any external service being up), confirm the sensor
    observes its own real connect."""
    import os as _os

    print("[self-test:tcp_connect] loading (requires root)...")
    sensor = LinuxTcpConnectSensor(device_id="self-test-device", tenant_id="self-test")
    my_pid = _os.getpid()

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listen_port = listener.getsockname()[1]

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print(f"[self-test:tcp_connect] connecting to 127.0.0.1:{listen_port} from this process "
          f"(pid {my_pid}), watching...")
    client.connect(("127.0.0.1", listen_port))

    ok = _poll_until(sensor, seconds, lambda e: e.process.pid == my_pid and e.flow.dst_port == listen_port)

    client.close()
    listener.close()
    print(f"[self-test:tcp_connect] {'PASS' if ok else 'FAIL'} — "
          f"{'observed' if ok else 'never observed'} this process's real connect to port {listen_port}.")
    return ok


def self_test(seconds: int = 5) -> int:
    """Load each real sensor, trigger a real event only it could produce, and confirm it's
    observed — the concrete proof this module's own docstring asks for before anyone should
    trust it. Must be run as root. Prints what each sensor found; returns 0 only if all
    three pass, 1 if any fail."""
    results = {
        "process_exec": _self_test_process_exec(seconds),
        "file_write": _self_test_file_write(seconds),
        "tcp_connect": _self_test_tcp_connect(seconds),
    }
    passed = sum(results.values())
    print(f"\n[self-test] {passed}/{len(results)} sensors passed: "
          + ", ".join(f"{name}={'PASS' if ok else 'FAIL'}" for name, ok in results.items()))
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    import sys

    sys.exit(self_test())
