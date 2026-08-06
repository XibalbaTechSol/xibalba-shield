/*
 * Real eBPF program for shield/sensors/ebpf/loader.py's LinuxFileWriteSensor. Written
 * against spec/xibalba-shield-v1.md §4.1's "file open/write hooks on sensitive paths" --
 * only the write half is built here. Sensitive-path matching is userspace configuration
 * (`DeviceConfig.sensitive_paths`) rather than kernel policy logic.
 *
 * Same proven approach as BCC's own `opensnoop` tool (/usr/sbin/opensnoop-bpfcc, shipped by
 * the already-installed `bpfcc-tools` package): a `syscall__`-prefixed kprobe on `openat`'s
 * entry (BCC's typed-argument syscall-shim convention) paired with a kretprobe to learn
 * whether the open actually succeeded, correlated via a BPF_HASH keyed by thread ID -- the
 * same entry/return correlation pattern process_exec.bpf.c's simpler single-kprobe design
 * doesn't need (execve either replaces the process or fails synchronously; open has a
 * separate, meaningful return value worth capturing).
 *
 * SCOPE: only `openat` is hooked, not the older `open`/`creat` syscalls or `openat2` --
 * openat is what virtually all modern glibc file-opening resolves to, and bounding scope to
 * one syscall keeps this file reviewable. Filters to WRITE opens (O_WRONLY|O_RDWR) directly
 * in the entry probe, before anything is stashed in the hash map, so read-only opens (the
 * overwhelming majority on a real system) cost one branch and nothing else -- matching
 * spec §3's "do the least possible work in kernel space" resource-budget constraint.
 *
 * VERIFIED live, 2026-08-04: `sudo python3 -m shield.sensors.ebpf.loader` observed the test
 * process's own real write-mode open of a real temp file. See loader.py's module docstring
 * for the full verification record across all three sensors.
 */

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fcntl.h>

struct file_write_record {
    u32 pid;
    u32 ppid;
    char comm[TASK_COMM_LEN];
    char filename[256];
    int flags;
    int ret;
};

struct val_t {
    char comm[TASK_COMM_LEN];
    u32 ppid;
    const char *filename;
    int flags;
};

BPF_HASH(open_args, u64, struct val_t);
BPF_PERF_OUTPUT(file_write_events);

int syscall__trace_entry_openat(struct pt_regs *ctx, int dfd, const char __user *filename, int flags)
{
    if ((flags & (O_WRONLY | O_RDWR)) == 0)
        return 0;  // read-only open -- not what this sensor exists to capture

    u64 id = bpf_get_current_pid_tgid();
    struct val_t val = {};
    struct task_struct *task;

    bpf_get_current_comm(&val.comm, sizeof(val.comm));
    task = (struct task_struct *)bpf_get_current_task();
    val.ppid = task->real_parent->tgid;
    val.filename = filename;
    val.flags = flags;

    open_args.update(&id, &val);
    return 0;
}

int trace_openat_return(struct pt_regs *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    struct val_t *valp = open_args.lookup(&id);
    if (valp == 0)
        return 0;  // no matching entry -- either a read-only open we skipped, or missed

    struct file_write_record rec = {};
    rec.pid = id >> 32;
    rec.ppid = valp->ppid;
    rec.flags = valp->flags;
    rec.ret = PT_REGS_RC(ctx);
    __builtin_memcpy(&rec.comm, valp->comm, sizeof(rec.comm));
    bpf_probe_read_user_str(&rec.filename, sizeof(rec.filename), (void *)valp->filename);

    file_write_events.perf_submit(ctx, &rec, sizeof(rec));
    open_args.delete(&id);
    return 0;
}
