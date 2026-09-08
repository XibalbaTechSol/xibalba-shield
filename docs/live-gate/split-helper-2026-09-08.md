# Split-helper live gate — 2026-09-08

## Result

PASS on the local Ubuntu host running kernel `7.0.0-31-generic`.

- `xibalba-shield-ebpf-helper.service`: active/enabled; root-owned BCC probe and Unix socket.
- `xibalba-shield.service`: active/enabled; non-root endpoint process consuming the socket.
- Helper uses the `sched_process_exec` tracepoint fallback because this kernel rejects `sys_execve` as non-traceable.
- Main service has only `CAP_KILL` for cross-UID containment; BPF capabilities remain in the helper.
- `scripts/validate_local_containment.sh`: `containment=CONFIRMED_SIGSTOP` after a service restart.
- `scripts/verify_process_exec_root.py`: `status: pass`, observed a real spawned `/usr/bin/true` exec.
- Focused bridge/CLI tests: `31 passed`.

## Boundaries

This is local kernel/runtime evidence, not a reboot or multi-kernel production qualification. A reboot test was intentionally skipped. The helper still needs a supported-kernel matrix and deployment-specific assurance before making a production security claim.

## Control-plane and socket repair evidence

The local endpoint was switched to the dedicated development mTLS listener at
`https://127.0.0.1:8443` using the generated CA, server certificate, and client certificate.
The runtime-status publisher, policy path, and remediation worker now use the configured
verified client context. A post-restart backend readback accepted fresh status, and the
remediation worker successfully claimed its authenticated queue request over mTLS.

The first restart exposed a service-unit ownership bug: both units declared the same
`RuntimeDirectory=xibalba-shield`. Endpoint cleanup removed the helper's socket pathname even
though the helper process still had its listening descriptor. The endpoint unit now requires and
starts after the helper and leaves runtime-directory ownership to the helper alone. After the
unit fix and coordinated restart, the live status reported:

- `sensors.attached=true`, `attach_mode=privileged-helper`;
- a fresh `last_event_at` from a real process event and `lost_events=0`;
- OPA healthy, backend evidence queue depth `0`, and exporter failures `0`;
- no endpoint failures after the restart window.

This remains local development evidence. The CA and credentials must be replaced by deployment-
managed trust material before production use.
