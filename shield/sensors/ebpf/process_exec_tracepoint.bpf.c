/* Kernel-compatible process execution probe.
 *
 * Some kernels do not expose a traceable sys_execve kprobe even though the
 * sched_process_exec tracepoint is present.  Keep the same compact record as
 * process_exec.bpf.c so the userspace normalizer remains unchanged.
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

TRACEPOINT_PROBE(sched, sched_process_exec)
{
    struct process_exec_record rec = {};
    struct task_struct *task;

    rec.pid = args->pid;
    task = (struct task_struct *)bpf_get_current_task();
    rec.ppid = task->real_parent->tgid;
    bpf_get_current_comm(&rec.comm, sizeof(rec.comm));
    /* This kernel's BCC tracepoint layout does not expose the dynamic
     * filename field as a typed member.  Userspace recovers argv[0] from
     * /proc/<pid>/cmdline, exactly as the kprobe path does when its bounded
     * user-string read is empty. */
    process_exec_events.perf_submit(args, &rec, sizeof(rec));
    return 0;
}
