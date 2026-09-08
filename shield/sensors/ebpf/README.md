# Linux eBPF sensors — 3 of 3 VERIFIED on one kernel, matrix not yet frozen

Per `spec/xibalba-shield-v1.md` §4.1 in the parent `integrity-core` repo: eBPF programs on
`process_exec`/`process_exit` tracepoints, file open/write hooks on sensitive paths, and
TCP-connect/DNS hooks, pushing compact records to user space via a ring buffer.

**Status as of 2026-08-31, verified on kernel `7.0.0-30-generic` (Ubuntu 24.04.4 LTS):**

| Sensor | File | Status |
|---|---|---|
| Process-exec | `process_exec.bpf.c` | ✅ **VERIFIED.** Observed a real spawned subprocess's real `execve`. |
| File writes | `file_write.bpf.c` | ✅ **VERIFIED.** Observed the test process's own real write-mode `openat`; optional userspace sensitive-path glob filtering is wired from device config. |
| TCP-connect | `tcp_connect.bpf.c` | ✅ **VERIFIED.** Was blocked by `#include <net/sock.h>` dragging in kernel headers this BCC version couldn't parse (confirmed a BCC/kernel version-skew problem, not a bug in this file, by reproducing the identical failure with BCC's own shipped `tcpconnect-bpfcc` binary). Fixed by copying the socket's known field prefix into a local struct before reading it, rather than reading through the map-loaded pointer directly — newer verifiers reject the latter even inside `bpf_probe_read`. Root-run evidence archived at `artifacts/live-gate/tcp-connect-root.log`. See that file's own comment for the full technical record. |
| DNS | not built | Needs a uprobe on `getaddrinfo` or UDP:53 parsing — a different mechanism than a syscall kprobe, deliberately not built alongside the other three. |

Reproduce: `sudo python3 -m shield.sensors.ebpf.loader` (or `sudo pytest
tests/test_ebpf_sensor.py -v`) from the repo root — see the parent `README.md`'s "Verifying
the eBPF sensors" section for exact commands and expected output. Each sensor also has its
own standalone, pytest-independent root-run script for per-kernel evidence bundles
(`docs/SUPPORTED_MATRIX.md`'s closing procedure): `scripts/verify_process_exec_root.py`,
`scripts/verify_file_write_root.py`, `scripts/verify_tcp_connect_root.py` — all three now
exist (2026-09-05; previously only TCP had one).

Attach failures across all three sensors now raise a typed `SensorAttachError` (`loader.py`)
carrying which stage failed (`bpf_load`/`kprobe`/`kretprobe`/`perf_buffer`) instead of a raw
bcc/libbpf traceback, and each sensor's `lost_events`/`health()` wiring has a real (root-gated)
test confirming the counter is load-bearing, not silently dead code
(`test_lost_events_counter_reflects_bcc_lost_cb`, 2026-09-05). This closes the "measured ...
attach-failure behavior" half of Gate 3's wording for the one kernel already verified here — it
does **not** touch the still-open half: `docs/SUPPORTED_MATRIX.md`'s Ubuntu 22.04/26.04 rows
remain `⬜ not run` and need real per-kernel hardware/VMs to close, not something a code change
in this repo can substitute for.

**Root-run evidence, 2026-09-05, same kernel:** `sudo .venv/bin/python -m pytest
tests/test_ebpf_sensor.py -v` — 11 passed (3 pre-existing non-root-runnable cases skipped as
designed), including all three new `test_lost_events_counter_reflects_bcc_lost_cb` cases. All
three standalone verify scripts (`scripts/verify_{process_exec,file_write,tcp_connect}_root.py`)
independently report `"status": "pass"`, archived at `artifacts/live-gate/{process-exec,
file-write,tcp-connect}-root.log`.

**Before wiring any of the three sensors into `shield/agent_core/router.py`** in place of
`shield/sensors/dev_generator.py`: nothing else needs to happen on this kernel — all three are
verified here. What's still open is the supported-matrix freeze itself
(`docs/PRODUCTION_READINESS_PLAN.md` workstream C, Gate 3): this verification covers exactly
one kernel/distro. A pilot on a different target needs this same root-run evidence reproduced
and archived for that target before any sensor is claimed verified there — carrying this
result over unverified would be exactly the kind of claim this repo's honesty rule forbids.

If you touch any of these three files, keep this table, `loader.py`'s module docstring, and
each `.bpf.c` file's own comment in agreement — the honesty rule this whole project runs on
means the code's own comments and the tracking docs must never say different things.
