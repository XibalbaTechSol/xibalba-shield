/*
 * Real eBPF program for shield/sensors/ebpf/loader.py's LinuxTcpConnectSensor. Written
 * against spec/xibalba-shield-v1.md §4.1's "TCP-connect/DNS hooks" -- only TCP-connect is
 * built here; DNS resolution observation is a separate, unbuilt piece (see loader.py's
 * module docstring for why: DNS is typically observed via a uprobe on libc's getaddrinfo or
 * by parsing UDP:53 payloads, a different and more involved mechanism than a syscall kprobe,
 * and building it un-reviewed alongside this file would risk shipping it wrong).
 *
 * Same proven approach as BCC's own `tcpconnect` tool (/usr/sbin/tcpconnect-bpfcc, shipped
 * by the already-installed `bpfcc-tools` package): a kprobe on `tcp_v4_connect`'s entry
 * stashes the `struct sock *` being connected, a kretprobe on the same function reads the
 * now-populated socket fields (source/dest address, dest port) once the connect call
 * actually returns.
 *
 * SCOPE: IPv4 only. `tcp_v6_connect` is a real, separate kernel function BCC's own tool
 * hooks in parallel with a near-identical second code path -- deferring it here rather
 * than doubling this file's size and review surface for a first cut; spec §3 doesn't
 * require IPv6 for v1.
 *
 * **Updated, 2026-08-06:** `#include <net/sock.h>` previously pulled in a kernel header chain
 * that BCC 0.29.1 could not parse on this host. The needed leading `struct sock_common`
 * layout was verified against this kernel's BTF:
 *
 *   bpftool btf dump file /sys/kernel/btf/vmlinux format c
 *
 * BTF shows `struct sock` starts with `struct sock_common __sk_common`, and the fields used
 * below (`skc_daddr`, `skc_rcv_saddr`, `skc_dport`, `skc_num`) are in the first three unions
 * of `struct sock_common`. The minimal mirror below intentionally models only that prefix.
 * This removed the known compile blocker, but newer verifiers still rejected the resulting
 * program: forming a field address directly from `skp` (the pointer loaded from the BPF map)
 * is treated as scalar-pointer arithmetic and rejected before `bpf_probe_read` even runs, so
 * the fix below (2026-08-31) reads the whole known prefix into a local struct first via
 * `bpf_probe_read(&common, sizeof(common), skp)`, then reads fields from that local copy.
 * Root-run evidence: `sudo python3 scripts/verify_tcp_connect_root.py` observed a real
 * localhost TCP connect on kernel `7.0.0-30-generic`, archived at
 * `artifacts/live-gate/tcp-connect-root.log`. That evidence covers this one kernel only —
 * see `shield/sensors/ebpf/README.md` for what a broader supported-matrix claim still needs.
 */

#include <uapi/linux/ptrace.h>
#include <bcc/proto.h>
#include <linux/sched.h>
#include <linux/types.h>

struct shield_sock_common {
    union {
        struct {
            __be32 skc_daddr;
            __be32 skc_rcv_saddr;
        };
    };
    union {
        unsigned int skc_hash;
        __u16 skc_u16hashes[2];
    };
    union {
        struct {
            __be16 skc_dport;
            __u16 skc_num;
        };
    };
};

struct sock {
    struct shield_sock_common __sk_common;
};

struct tcp_connect_record {
    u32 pid;
    u32 ppid;
    char comm[TASK_COMM_LEN];
    u32 saddr;
    u32 daddr;
    u16 lport;
    u16 dport;
};

BPF_HASH(currsock, u64, struct sock *);
BPF_PERF_OUTPUT(tcp_connect_events);

int trace_connect_entry(struct pt_regs *ctx, struct sock *sk)
{
    u64 id = bpf_get_current_pid_tgid();
    currsock.update(&id, &sk);
    return 0;
}

int trace_connect_v4_return(struct pt_regs *ctx)
{
    int ret = PT_REGS_RC(ctx);
    u64 id = bpf_get_current_pid_tgid();

    struct sock **skpp = currsock.lookup(&id);
    if (skpp == 0)
        return 0;  // missed entry

    if (ret != 0) {
        // connect() didn't succeed in sending a SYN -- socket fields may be unpopulated
        currsock.delete(&id);
        return 0;
    }

    struct sock *skp = *skpp;
    struct tcp_connect_record rec = {};
    struct task_struct *task;

    rec.pid = id >> 32;
    task = (struct task_struct *)bpf_get_current_task();
    rec.ppid = task->real_parent->tgid;
    bpf_get_current_comm(&rec.comm, sizeof(rec.comm));
    // Do not form field addresses from `skp` directly. On newer kernels the
    // verifier treats the pointer loaded from the map as a scalar, so even a
    // bpf_probe_read(&skp->__sk_common.field, ...) is rejected before the
    // helper runs. Copy the known socket prefix first, then read locals.
    struct shield_sock_common common = {};
    if (bpf_probe_read(&common, sizeof(common), skp) != 0) {
        currsock.delete(&id);
        return 0;
    }
    rec.saddr = common.skc_rcv_saddr;
    rec.daddr = common.skc_daddr;
    // skc_num is already host-byte-order (unlike skc_dport, which needs ntohs) --
    // same asymmetry BCC's own tcpconnect reference handles the identical way.
    rec.lport = common.skc_num;
    rec.dport = ntohs(common.skc_dport);

    tcp_connect_events.perf_submit(ctx, &rec, sizeof(rec));
    currsock.delete(&id);
    return 0;
}
