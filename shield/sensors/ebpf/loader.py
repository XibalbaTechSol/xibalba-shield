"""
Linux eBPF sensor — real kernel probe, per spec/xibalba-shield-v1.md §4.1.

Loads `process_exec.bpf.c` via BCC (python3-bpfcc, already installed system-wide — BCC
JIT-compiles the C source with its own embedded LLVM against the running kernel's installed
headers; no separate `clang` binary is needed). Attaches a kprobe on the `execve` syscall entry
point and reads real `process_exec` events off a BPF perf ring buffer, normalizing them into
`schemas.events.ProcessActivity` — the same shape `DevModeSensor` produces, so nothing
downstream (agent_core, policy_engine) needs to know which sensor is live.

**Verified as of this writing: nothing about this module has been confirmed working.** BCC's
`BPF(text=...)` compiles AND loads (creates every declared map) in one call, and map creation
is itself a `bpf()` syscall gated on `CAP_BPF` — so on this machine
(`kernel.unprivileged_bpf_disabled=2`) there is no way to even confirm the C source is
syntactically valid without root, let alone that it attaches and observes real events. (An
earlier version of this docstring claimed compilation alone was root-free; that was wrong —
corrected in `process_exec.bpf.c`'s own comment rather than silently fixed here too.)

Run `sudo python3 -m shield.sensors.ebpf.loader` (or `sudo pytest tests/test_ebpf_sensor.py`)
to actually verify this module. Until that has been run successfully at least once, treat
every claim in this file as unverified design, not working code — no silent mock, same rule
the rest of this repo follows.
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Iterator

from ...schemas.events import Activity, NormalizedEvent, ProcessActivity, ProcessInfo

_BPF_SOURCE = Path(__file__).with_name("process_exec.bpf.c")


class LinuxEbpfSensor:
    """Structurally satisfies `shield.sensors.base.Sensor` (a `Protocol` — matched by shape,
    not inheritance, the same way `dev_generator.DevModeSensor` does). Real implementation
    backed by a kprobe on `execve`. Requires root to construct
    (the BPF program load happens in `__init__`, not lazily, so a permission failure surfaces
    immediately rather than on first `events()` iteration)."""

    def __init__(self, device_id: str, tenant_id: str = ""):
        if os.geteuid() != 0:
            raise PermissionError(
                "LinuxEbpfSensor requires root (CAP_BPF) to load its BPF program — "
                "this machine has kernel.unprivileged_bpf_disabled=2, so there is no "
                "non-root path. Run under sudo."
            )

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


def self_test(seconds: int = 5) -> int:
    """Load the real sensor, spawn a real subprocess, and confirm the sensor observes its
    real exec — the concrete proof this module's own docstring asks for before anyone should
    trust it. Must be run as root. Prints what it found; returns 0 on success, 1 if the probe
    subprocess's exec was never observed within `seconds`."""
    import subprocess

    print("[self-test] loading LinuxEbpfSensor (requires root)...")
    sensor = LinuxEbpfSensor(device_id="self-test-device", tenant_id="self-test")
    print("[self-test] loaded and attached. Spawning /usr/bin/true as the probe subprocess...")

    proc = subprocess.Popen(["/usr/bin/true"])
    target_pid = proc.pid
    proc.wait()

    found = False
    deadline = time.time() + seconds
    while time.time() < deadline and not found:
        remaining_ms = max(1, int((deadline - time.time()) * 1000))
        for event in sensor.poll(timeout_ms=min(1000, remaining_ms)):
            print(
                f"[self-test] observed real exec: pid={event.process.pid} "
                f"ppid={event.process.ppid} comm={event.process.name!r} "
                f"exe={event.process.exe_path!r}"
            )
            if event.process.pid == target_pid:
                found = True

    if found:
        print(f"[self-test] PASS — observed the probe subprocess's own real execve (pid {target_pid}).")
        return 0
    print(f"[self-test] FAIL — never observed pid {target_pid}'s execve within {seconds}s.")
    return 1


if __name__ == "__main__":
    import sys

    sys.exit(self_test())
