---
title: Sensor Model
acronyms: [eBPF]
created: 2026-08-12
updated: 2026-08-12
type: concept
tags: [sensors, infrastructure]
confidence: high
source_files:
  - shield/sensors/base.py
  - shield/sensors/dev_generator.py
  - shield/sensors/linux_sensor.py
  - shield/sensors/windows.py
  - shield/sensors/macos.py
---

## Table of contents

- [Overview](#overview)
- [DevModeSensor — real code, synthetic data, never claimed as telemetry](#devmodesensor-real-code-synthetic-data-never-claimed-as-telemetry)
- [Linux eBPF sensors — two verified, one blocked](#linux-ebpf-sensors-two-verified-one-blocked)
- [Windows/macOS — honest interface-boundary stubs](#windows-macos-honest-interface-boundary-stubs)
- [Related pages](#related-pages)

## Overview

`shield/sensors/base.py` defines the `Sensor` protocol every sensor implementation satisfies:

```python
class Sensor(Protocol):
    def events(self) -> Iterator[NormalizedEvent]: ...
```

A sensor yields already-normalized events (`shield/schemas/events.py`) and owns no policy logic
and makes no enforcement decisions — that split exists so a sensor bug can never itself become a
false-enforcement bug, matching [Event Router](event-router.md)'s own "kept deliberately dumb"
posture.

## `DevModeSensor` — real code, synthetic data, never claimed as telemetry

`shield/sensors/dev_generator.py`'s `DevModeSensor` is a real, working sensor implementation used
to exercise [Event Router](event-router.md), [Policy Engine](policy-engine.md), and
[Integrity Exporter](integrity-exporter.md) end to end before/without a real kernel sensor. Every
event it produces is fabricated from small hardcoded sample pools:

```python
_SAMPLE_PROCESSES = [
    ("python.exe", "python", 1000, "powershell.exe"),
    ("shadow_ai_tool.exe", "shadow_ai_tool", 1000, "explorer.exe"),
    ("ollama-serve", "ollama-serve", 1, "systemd"),
]
_SAMPLE_AGENTS = ["copilot-agent", "unregistered-llm-tool", "customer-support-bot"]
```

`exe_path` and similar fields are fabricated strings, never real observations of the host
machine. This module's docstring is explicit that pointing it at production policy decisions and
mistaking its output for real telemetry would be exactly the kind of silent-mock claim this
project's ground rules forbid.

## Linux eBPF sensors — two verified, one blocked

`shield/sensors/linux_sensor.py` and `shield/sensors/ebpf/` are real Linux kprobe/kretprobe
implementations, not stubs:

| Probe | Status |
|---|---|
| Process execution | Historically live-verified — a kprobe on `execve` observed a real spawned subprocess as root. |
| File write-open | Historically live-verified — a kprobe/kretprobe on `openat` observed a real write-mode open; filters write-mode opens in-kernel and sensitive paths in userspace. |
| TCP connect | Live-verified as root on Ubuntu 24.04 LTS. Uses a BTF-checked minimal socket-prefix mirror to avoid the old `net/sock.h` BCC header compile failure, copied into a local struct before field reads (newer verifiers reject reading fields directly off the map-loaded pointer). See `docs/SUPPORTED_MATRIX.md` for which other kernels still need this evidence. |

No eBPF sensor in this repo should be marked verified unless it was loaded as root and observed a
real event on the target kernel — "historically live-verified" specifically means that
verification happened at some point in the past, not that it is re-checked on every change.

## Windows/macOS — honest interface-boundary stubs

`shield/sensors/windows.py`'s `WindowsNativeSensor` and `shield/sensors/macos.py`'s
`MacOSNativeSensor` both satisfy the `Sensor` protocol structurally but are documented TODOs, not
implementations:

```python
def _initialize_etw(self) -> None:
    """Initialize ETW trace sessions for Process and File events."""
    # TODO: Implement pywintrace or direct CFFI calls to Advapi32.dll (StartTrace)
    pass
```

Windows targets ETW (Event Tracing for Windows) for process/file and WFP (Windows Filtering
Platform) for network; macOS targets the EndpointSecurity framework (`libEndpointSecurity`) for
process/file and NetworkExtension for network flows. Both `events()` methods `yield from []` —
they produce no events at all. Neither claims to be more than an outline; both are marked
`[PLANNED]`.

## Related pages

- [Event Router](event-router.md) — the consumer of every sensor's event stream
- [Policy Engine](policy-engine.md) — where sensor events get evaluated
