# Xibalba Shield

Endpoint agent for AI-agent discovery, constraint, and Integrity-backed evidence — device and
network security, separate from the HIPAA/healthcare vertical (which stays in
[`integrity-latest`](https://github.com/XibalbaTechSol/integrity-latest)).

**Full technical specification:** [`spec/xibalba-shield-v1.md`](https://github.com/XibalbaTechSol/integrity-latest/blob/main/spec/xibalba-shield-v1.md)
in the parent repo. **Repo-split decision and rationale:**
[`spec/integrity-protocol-v0.4.md`](https://github.com/XibalbaTechSol/integrity-latest/blob/main/spec/integrity-protocol-v0.4.md)
§14.1.

Xibalba Shield discovers AI agents and tools running on a device, constrains what they can do,
and produces cryptographic evidence of every consequential decision by feeding signed telemetry
into Integrity Protocol. Shield is the sensor and enforcer; Integrity Protocol is the scorer and
archive — neither subsumes the other. See the spec's §1 for the full statement of that boundary.

## Status against the spec

| Module | Spec § | Status |
|---|---|---|
| Event schemas | §5 | **Real** — exact shapes, no field renaming |
| Policy rule schema | §7 | **Real** |
| Policy Engine | §4.3 | **Real** — table-driven, first-match, zero cloud round-trip |
| Agent Core (registry, router) | §4.2 | **Real** |
| Integrity Exporter | §4.5 | **Real** — real `integrity-sdk` BCC signing + telemetry, no mock |
| One guardrail hook (tool execution) | §4.4 | **Real** — one of five hook points, per the spec's own build order |
| CLI (`shield status`, `shield events`) | §4.6 | **Real** |
| Linux sensor — dev/test generator | §4.1 | **Real**, explicitly synthetic — never claims to be real telemetry |
| Linux sensor — real eBPF probe | §4.1 | **`[PLANNED]`** — see `shield/sensors/ebpf/README.md` |
| Windows/macOS sensors | §4.1 | **`[PLANNED]`** — post-Linux per spec §3 |
| Network sensor | §9 | **`[PLANNED]`** — deferred past v1 per spec §9 |
| Configuration/update module | §4.6 | **`[PLANNED]`** |

No silent mocks: every row above is either real and tested, or explicitly marked `[PLANNED]`
with a stated reason, matching `integrity-latest`'s own ground rule.

## Quickstart (dev mode — no real sensor required)

```bash
uv venv .venv && uv pip install -e ".[dev]"
uv run pytest
```

```python
from shield.agent_core import AgentRegistry, DeviceContext, EventLog, EventRouter
from shield.integrity_exporter import IntegrityExporter
from shield.policy_engine import PolicyEngine
from shield.sensors import DevModeSensor

device = DeviceContext(device_id="dev-1", tenant_id="local-dev", device_role="workstation")
router = EventRouter(
    device=device,
    registry=AgentRegistry(),
    policy_engine=PolicyEngine(rules=[]),  # load real rules per spec §7 for actual policy
    exporter=IntegrityExporter(bcc_middleware_url="http://localhost:8000"),
    event_log=EventLog(path=...),
)
for event in DevModeSensor(device_id="dev-1").events():
    router.handle(event)
```

## Dependency direction

`xibalba-shield` depends on `integrity-sdk` one-way, imported exactly as any third-party agent
runtime would — no privileged API. `integrity-latest` has, and must always have, zero
dependency on this repo in either direction.
