# Linux eBPF sensors — 2 of 3 VERIFIED, 1 BLOCKED

Per `spec/xibalba-shield-v1.md` §4.1 in the parent `integrity-latest` repo: eBPF programs on
`process_exec`/`process_exit` tracepoints, file open/write hooks on sensitive paths, and
TCP-connect/DNS hooks, pushing compact records to user space via a ring buffer.

**Status as of 2026-08-04:**

| Sensor | File | Status |
|---|---|---|
| Process-exec | `process_exec.bpf.c` | ✅ **VERIFIED.** Observed a real spawned subprocess's real `execve`. |
| File writes | `file_write.bpf.c` | ✅ **VERIFIED.** Observed the test process's own real write-mode `openat`. |
| TCP-connect | `tcp_connect.bpf.c` | 🔴 **BLOCKED.** `#include <net/sock.h>` drags in kernel headers this BCC version can't parse — confirmed a BCC/kernel version-skew problem, not a bug in this file, by reproducing the identical class of failure with BCC's own shipped `tcpconnect-bpfcc` binary. See that file's own comment for the full record. |
| DNS | not built | Needs a uprobe on `getaddrinfo` or UDP:53 parsing — a different mechanism than a syscall kprobe, deliberately not built alongside the other three. |

Reproduce: `sudo python3 -m shield.sensors.ebpf.loader` (or `sudo pytest
tests/test_ebpf_sensor.py -v`) from the repo root — see the parent `README.md`'s "Verifying
the eBPF sensors" section for exact commands and expected output.

**Before wiring the process-exec or file-write sensor into `shield/agent_core/router.py`** in
place of `shield/sensors/dev_generator.py`: nothing else needs to happen — both are verified.
Continue using `DevModeSensor` for anything that needs the TCP-connect sensor's output shape
until that one is unblocked (a newer BCC release, or a hand-verified `struct sock_common`
layout for this kernel — see `tcp_connect.bpf.c`'s own comment for why that wasn't attempted
blind).

If you touch any of these three files, keep this table, `loader.py`'s module docstring, and
each `.bpf.c` file's own comment in agreement — the honesty rule this whole project runs on
means the code's own comments and the tracking docs must never say different things.
