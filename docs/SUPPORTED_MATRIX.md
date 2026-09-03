# Shield Supported OS/Kernel Matrix

**Status:** Frozen for the Linux track, provisional entries pending root-run evidence.
**Updated:** 2026-09-03
**Owning gate:** `docs/PRODUCTION_READINESS_PLAN.md` Gate 1 (scope and threat model) and Gate 3
(sensor coverage). This document *is* the "published supported OS/kernel matrix" those gates
require — do not restate it elsewhere; link here instead.

## What "supported" means here

A row in this table is `verified` only when `scripts/verify_tcp_connect_root.py`,
`sudo pytest tests/test_ebpf_sensor.py -v`, and a fresh run of
`shield local-run --profile <target vertical>` have all been executed as root **on that exact
kernel/distro**, with output archived under `artifacts/live-gate/`. Nothing here is "probably
fine because it's close to a verified kernel" — this repo's own rule is that a field-offset or
verifier-behavior assumption must be checked against the specific target, not carried over
(see `tcp_connect.bpf.c`'s header comment for why that rule exists: a wrong assumption produces
plausible-looking but silently wrong data, which is worse than an honest gap).

## Linux track

| Distro | Kernel | Process-exec | File-write | TCP-connect | Evidence |
|---|---|---|---|---|---|
| Ubuntu 24.04 LTS | `7.0.0-30-generic` | ✅ verified | ✅ verified | ✅ verified | `artifacts/live-gate/tcp-connect-root.log` (2026-08-31); process/file verified 2026-08-04, re-confirm alongside next TCP re-run |
| Ubuntu 22.04 LTS | TBD | ⬜ not run | ⬜ not run | ⬜ not run | none yet |
| Ubuntu 26.04 LTS | TBD | ⬜ not run | ⬜ not run | ⬜ not run | none yet |

Scope of this freeze: the three currently-in-standard-support Ubuntu LTS releases (22.04, 24.04,
26.04). Non-LTS Ubuntu releases, other distros (Debian, RHEL/Rocky, Amazon Linux, etc.), and
kernel versions outside the distro-shipped default are explicitly **out of scope** unless a real
pilot target requires one — add a row and gate it through the same verified/not-run process
rather than assuming coverage.

### Closing a `⬜ not run` row

1. Provision the target distro (VM, container with a real kernel — not a chroot that shares the
   host kernel — or bare metal).
2. Install the pinned BCC/kernel-headers stack for that distro; note the exact package versions
   in the evidence log, since BCC/kernel skew is the class of bug that blocked TCP-connect
   before (see `shield/sensors/ebpf/README.md`).
3. `sudo python3 -m shield.sensors.ebpf.loader` and `sudo pytest tests/test_ebpf_sensor.py -v`.
4. `sudo python3 scripts/verify_tcp_connect_root.py`, archive the JSON output under
   `artifacts/live-gate/tcp-connect-root-<distro>-<kernel>.log`.
5. Update this table's row to `✅ verified` with a link to the archived evidence — never flip a
   row to verified without an archived artifact backing it, matching how the 24.04 row is cited.
6. Update `shield/sensors/ebpf/README.md`'s status table if the per-file record needs it too —
   keep both in agreement, per that file's own closing rule.

## Windows track

**Status: not started, not scaffolded to real behavior.** `shield/sensors/windows.py` exists
today as an honestly-labeled outline (`WindowsNativeSensor._initialize_etw`/`_initialize_wfp`
are `TODO: ...; pass`, `events()` yields nothing) and `shield/sensors/platform.py`'s
`native_support_matrix()` already reports Windows as `"planned"` — this file does not change
that status, it records why closing it is a separate, larger workstream from the Linux matrix
freeze above, not an entry that can be "frozen" alongside it:

- No Windows host is available in this development environment to write against, compile, or
  run ETW/WFP code — the same category of constraint that blocked TCP-connect verification
  until a real root-capable Linux host was used, except here there is no fallback host at all
  yet. Writing native ETW/WFP integration code blind, with no way to compile or test it, is
  exactly the "plausible-looking but wrong" risk this repo's rules exist to prevent — it would
  not be honest to mark this file more "real" without that capability.
- Real scope, for whoever picks this up: ETW process/file events via `StartTrace`/`OpenTrace`
  (Advapi32, likely through `pywin32` or a TDH-based consumer rather than hand-rolled ctypes,
  given TDH's manifest-based event parsing is what makes ETW records structurally reliable
  rather than guessed), and network-flow visibility via either WFP callouts (requires a signed
  kernel-mode driver and a real code-signing certificate — a packaging/ops dependency, not just
  code) or, as a lighter first cut, ETW's own network provider events if they cover the needed
  fields without a driver.
- **Recommended before writing any Windows sensor code:** get access to a real Windows dev/test
  host (VM is fine) so the same "write it, verify it as root/admin, archive the evidence"
  discipline used for the Linux sensors applies here too, rather than producing another
  `tcp_connect.bpf.c`-style blocked-until-verified file with no path to closing it locally.

## macOS track

Same status as Windows (`"planned"` in `native_support_matrix()`), out of scope for this freeze
and not requested — not expanded here.
