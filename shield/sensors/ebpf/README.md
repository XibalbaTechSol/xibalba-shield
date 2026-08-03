# Linux eBPF sensor — real code written, `[UNVERIFIED]`

Per `spec/xibalba-shield-v1.md` §4.1 in the parent `integrity-latest` repo: eBPF programs on
`process_exec`/`process_exit` tracepoints, file open/write hooks on sensitive paths, and
TCP-connect/DNS hooks, pushing compact records to user space via a ring buffer. Only the
`process_exec` piece is implemented so far.

**Status as of this update:** `process_exec.bpf.c` (a kprobe on the `execve` syscall entry,
using BCC's `get_syscall_fnname` — the same proven approach as BCC's own `execsnoop` tool) and
`loader.py` (the userspace `LinuxEbpfSensor`, implementing the `Sensor` protocol) are both
written and reviewed. **Neither has been confirmed to actually work**, because this machine's
`kernel.unprivileged_bpf_disabled=2` means even checking the C source compiles needs root —
BCC's `BPF(text=...)` compiles *and* loads (creates every declared map) in one call, so there
is no root-free way to validate any of it, not even syntax. (An earlier draft of these files
claimed compilation alone was root-free; that was measured and found wrong, and corrected in
place — see `loader.py`'s own docstring for the record.)

**Before trusting this module in any deployment:**
1. Run `sudo python3 -m shield.sensors.ebpf.loader` (or `sudo pytest tests/test_ebpf_sensor.py
   -v`) from the repo root — see the parent `README.md`'s "Verifying the eBPF sensor" section
   for exact commands and expected output.
2. Confirm it reports a real observed `execve` for a real spawned subprocess, not just that it
   loads without error.
3. Only then wire its output into `shield/agent_core/router.py` in place of
   `shield/sensors/dev_generator.py`, and flip this file's own status line and the parent
   README's status table row 11 from UNVERIFIED to verified — in the same commit, so the
   code's own docstrings and the tracking doc never disagree.

Until all three are true, use `dev_generator.DevModeSensor` for testing the rest of the
pipeline (`agent_core`, `policy_engine`, `integrity_exporter`) — its output matches the same
normalized schemas this sensor will eventually produce, so nothing downstream needs to change
when the real sensor replaces it.

**Not yet built at all, even as an unverified sketch:** file open/write hooks on sensitive
paths, TCP-connect/DNS hooks. Only `process_exec` exists in any form today.
