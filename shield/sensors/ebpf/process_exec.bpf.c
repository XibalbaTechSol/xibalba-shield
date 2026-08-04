/*
 * Real eBPF program, compiled and loaded by shield/sensors/ebpf/loader.py via BCC (already
 * installed system-wide as python3-bpfcc — BCC JIT-compiles this source with its own embedded
 * LLVM against the running kernel's installed headers, no separate `clang` binary required).
 * Written against spec/xibalba-shield-v1.md §4.1: capture pid/ppid/comm/filename on process
 * exec, push a compact record to user space over a perf ring buffer — no policy logic here,
 * that's the Policy Engine's job (§4.1's own stated reason for the split: a kernel-sensor bug
 * must never become a false-enforcement bug).
 *
 * Attaches as a kprobe on the `execve` syscall entry point (via BCC's `get_syscall_fnname`,
 * which resolves the real kernel symbol across kernel-version/arch syscall-wrapper naming
 * differences), the same proven approach as BCC's own `execsnoop` tool
 * (/usr/sbin/execsnoop-bpfcc, shipped by the `bpfcc-tools` package already installed on this
 * machine) — chosen over `TRACEPOINT_PROBE(sched, sched_process_exec)` because that macro
 * additionally requires BCC to read the tracepoint's format file from tracefs to generate the
 * args struct, one more root-gated step this design avoids.
 *
 * **Correction, recorded rather than silently fixed:** an earlier version of this comment
 * claimed a kprobe-based program could be *compiled* under BCC without root, with only
 * load/attach needing it. Measured, that's false: BCC's `BPF(text=...)` eagerly creates every
 * declared map (here, the `BPF_PERF_OUTPUT` table) as part of construction, and map creation
 * is itself a `bpf()` syscall requiring `CAP_BPF` — so `BPF(text=...)` raises on this machine
 * (`kernel.unprivileged_bpf_disabled=2`) regardless of whether the C source is valid. There is
 * no non-root verification path for this file through BCC's high-level API.
 *
 * **VERIFIED live, 2026-08-04:** `sudo python3 -m shield.sensors.ebpf.loader` observed a real
 * spawned subprocess's real `execve` (pid 395017). See `loader.py`'s module docstring for the
 * full verification record across all three sensors.
 */

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct process_exec_record {
    u32 pid;
    u32 ppid;
    char comm[TASK_COMM_LEN];
    char filename[256];
};

BPF_PERF_OUTPUT(process_exec_events);

int on_execve(struct pt_regs *ctx, const char __user *filename)
{
    struct process_exec_record rec = {};
    struct task_struct *task;

    rec.pid = bpf_get_current_pid_tgid() >> 32;

    task = (struct task_struct *)bpf_get_current_task();
    rec.ppid = task->real_parent->tgid;

    bpf_get_current_comm(&rec.comm, sizeof(rec.comm));
    bpf_probe_read_user_str(&rec.filename, sizeof(rec.filename), filename);

    process_exec_events.perf_submit(ctx, &rec, sizeof(rec));
    return 0;
}
