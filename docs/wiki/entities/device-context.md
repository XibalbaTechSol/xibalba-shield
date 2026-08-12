---
title: Device Context & Agent Registry
acronyms: []
created: 2026-08-12
updated: 2026-08-12
type: entity
tags: [infrastructure, enforcement]
confidence: high
source_files:
  - shield/agent_core/registry.py
  - shield/policy_engine/engine.py
---

## Table of contents

- [Overview](#overview)
- [AgentRegistry](#agentregistry)
- [How the policy engine reads this](#how-the-policy-engine-reads-this)
- [Related pages](#related-pages)

## Overview

`shield/agent_core/registry.py` defines two small dataclasses/classes that live for the lifetime
of the single long-lived agent-core process on each device, and together form the evaluation
context every [Policy Engine](../concepts/policy-engine.md) call and
[Event Router](../concepts/event-router.md) decision reads from:

- **`DeviceContext`** — per-device identity: `device_id`, `tenant_id`, `os`, `device_role`. A
  frozen dataclass, constructed once at `shield run` startup from `DeviceConfig`
  (`shield/config/loader.py`) and never mutated.
- **`AgentRegistry`** — per-agent registration state, and Shield's shadow-AI-discovery mechanism.
  An agent with no entry in the registry is, by definition, unregistered.

This page merges what would otherwise be two very thin pages: `AgentRegistry`'s entire distinct
surface is five small methods on a `dict`-backed registry, and its facts are inseparable from the
same module and the same "registered" evaluation-context concept `DeviceContext` feeds — keeping
them on one canonical page avoids the schema's no-duplication problem two overlapping stubs would
create.

## `AgentRegistry`

```python
class AgentRegistry:
    def register(self, agent_id, name, *, owner_user_id="", purpose="") -> RegisteredAgent: ...
    def touch(self, agent_id) -> None: ...
    def is_registered(self, agent_id) -> bool: ...
    def registered_ids(self) -> frozenset[str]: ...
    def all_agents(self) -> list[RegisteredAgent]: ...
```

Thread-safe (a `threading.Lock` guards the internal dict) because sensor callbacks and the CLI's
`shield status` read path can touch it concurrently. `register()` records a new
`RegisteredAgent(agent_id, name, owner_user_id, purpose, first_seen, last_seen)`, or refreshes
`last_seen` if the agent already exists. `touch()` deliberately does **not** register an unknown
agent — it only refreshes `last_seen` for an agent already present. That distinction is what lets
the policy engine's `agent` condition group's `registered: false` matching actually mean
something: an agent that has only ever been `touch()`-ed by
[Event Router](../concepts/event-router.md) (which calls `registry.touch(event.agent.agent_id)`
for every `AgentEvent`) without ever being explicitly `register()`-ed stays unregistered.

## How the policy engine reads this

`EventRouter._context()` builds an `EvaluationContext` with
`registered_agent_ids=self.registry.registered_ids()` on every call, which
[Policy Engine](../concepts/policy-engine.md) receives as part of `ctx` in the OPA input. The
`agent` condition group named in `shield/schemas/policy_rule.py` (registration state, agent ID,
owner, workload metadata) is intended to match against exactly this registry state — though see
policy-engine.md's documented drift section for the caveat that the current OPA-delegated
evaluator doesn't consult the JSON rule bundles' condition groups directly.

## Related pages

- [Event Router](../concepts/event-router.md) — calls `registry.touch()` and builds
  `EvaluationContext` from this registry every `handle()` call
- [Policy Engine](../concepts/policy-engine.md) — the `agent` condition group this registry
  backs
