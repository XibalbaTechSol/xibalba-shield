# Linux eBPF sensor — `[PLANNED]`, not built

Per `spec/xibalba-shield-v1.md` §4.1 in the parent `integrity-latest` repo: eBPF programs on
`process_exec`/`process_exit` tracepoints, file open/write hooks on sensitive paths, and
TCP-connect/DNS hooks, pushing compact records to user space via a ring buffer.

**Status as of this scaffold: nothing here is loaded, built, or tested.** `process_exec.bpf.c`
in this directory is real eBPF C source written against the intended tracepoint shape — it has
never been compiled, verified by the kernel's BPF verifier, or loaded, because doing so needs
`CAP_BPF`/root and a matching kernel/BTF toolchain that the environment this was authored in did
not have available. Treat it as a design sketch to build against, the same way
`integrity-latest`'s `UltraPlonkVerifier.sol` is an explicit "will be replaced wholesale, not
edited" placeholder that reverts until the real thing lands — this file is that same honesty
pattern, not a working sensor with a caveat.

**Before trusting this module in any deployment:**
1. Compile against a real kernel/BTF (`clang -target bpf`, `libbpf`), with root/`CAP_BPF`.
2. Verify it actually loads and the ring-buffer consumer receives real events on real
   `process_exec` activity — not just that it compiles.
3. Only then wire its output into `shield/agent_core/router.py` in place of
   `shield/sensors/dev_generator.py`.

Until all three are true, use `dev_generator.DevModeSensor` for testing the rest of the
pipeline (`agent_core`, `policy_engine`, `integrity_exporter`) — its output matches the same
normalized schemas this sensor will eventually produce, so nothing downstream needs to change
when the real sensor replaces it.
