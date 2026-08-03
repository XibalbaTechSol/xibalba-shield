/*
 * [PLANNED] — NEVER COMPILED, NEVER LOADED, NEVER VERIFIED BY THE BPF VERIFIER.
 * See ./README.md before treating anything in this file as working. Written against
 * spec/xibalba-shield-v1.md §4.1's tracepoint shape as a design sketch to build against.
 *
 * Intended: attach to sched_process_exec, capture pid/ppid/comm/filename, push a compact
 * record through a BPF ring buffer to user space (shield/sensors/linux, not yet written
 * either — the ring-buffer consumer that would read this doesn't exist yet).
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct process_exec_record {
	__u32 pid;
	__u32 ppid;
	char comm[16];
	char filename[256];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20); /* 1 MiB — within the 90 MB RSS budget (spec §3) */
} process_exec_ringbuf SEC(".maps");

SEC("tp_btf/sched_process_exec")
int handle_process_exec(struct bpf_raw_tracepoint_args *ctx)
{
	struct process_exec_record *rec;

	rec = bpf_ringbuf_reserve(&process_exec_ringbuf, sizeof(*rec), 0);
	if (!rec)
		return 0;

	rec->pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&rec->comm, sizeof(rec->comm));
	/* ppid and filename extraction from ctx intentionally left unfinished here — this
	 * file has never been built against a real kernel/BTF, so completing the argument
	 * unpacking without being able to verify it against the actual tracepoint signature
	 * would be guessing, not implementing. See README.md. */

	bpf_ringbuf_submit(rec, 0);
	return 0;
}

char _license[] SEC("license") = "GPL";
