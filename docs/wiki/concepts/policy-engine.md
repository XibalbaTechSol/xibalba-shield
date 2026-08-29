---
title: Policy Engine
acronyms: [OPA]
created: 2026-08-12
updated: 2026-08-22
type: concept
tags: [enforcement, infrastructure]
confidence: medium
source_files:
  - shield/policy_engine/engine.py
  - shield/config/loader.py
  - shield/config/hot_reload.py
  - shield/schemas/policy_rule.py
  - shield/agent_core/slm_backend.py
---

## Table of contents

- [Overview](#overview)
- [What evaluate() actually does](#what-evaluate-actually-does)
- [Local profile-supervised OPA smoke runs](#local-profile-supervised-opa-smoke-runs)
- [Combined-condition regression coverage](#combined-condition-regression-coverage)
- [Documented drift vs. README.md and CLAUDE.md — now corrected](#documented-drift-vs-readme-md-and-claude-md-now-corrected)
- [Interface shape reused by Tier 2](#interface-shape-reused-by-tier-2)
- [Related pages](#related-pages)

## Overview

`PolicyEngine.evaluate(event, ctx) -> PolicyDecision` (`shield/policy_engine/engine.py`) is Tier 1
of the [SLM Cascade Tiers](slm-cascade-tiers.md) architecture — the deterministic decision every
event passes through first. Every evaluation produces a `PolicyDecision`; there is no
"unmatched, so nothing happened" outcome. This page documents what the engine actually does
today, which is **not** what the repository's own README.md and CLAUDE.md still describe (see
[Documented drift](#documented-drift-vs-readme-md-and-claude-md-now-corrected) below) — that gap
was the reason
this page's confidence is `medium` rather than `high`.

## What `evaluate()` actually does

```python
class PolicyEngine:
    def __init__(self, opa_url: str = "http://localhost:8181",
                 opa_package_path: str = "/v1/data/shield/policy", *,
                 policy_version: str = "", policy_hash: str = ""):
        ...

    def evaluate(self, event: NormalizedEvent, ctx: EvaluationContext) -> PolicyDecision:
        opa_input = {"event": asdict(event), "ctx": {...}}
        opa_decision = asyncio.run(opa_evaluate(
            opa_url=self.opa_url, opa_package_path=self.opa_package_path,
            opa_timeout_seconds=2.0, opa_input=opa_input,
        ))
        ...
```

`PolicyEngine.evaluate()` serializes the event and evaluation context and sends them to a local
Open Policy Agent (OPA) sidecar via `integrity_sdk.policy.opa_client.evaluate` — the same OPA
REST client `bcc_middleware` uses in the parent `integrity-core` repo. It does not itself walk
any rule list, match any condition, or implement first-match semantics. OPA's response
(`raw_result`, expected to carry `action`/`message`/`rule_id`/`name`/`version` fields) is
translated directly into a `PolicyDecision`. If OPA says `allow == False` but supplies no
specific `action`, the engine coerces that to `action = "deny"` rather than defaulting to
`log_only`.

**Fail-closed on OPA unavailability.** If the OPA sidecar cannot be reached, returns a non-200,
or returns a malformed body, `integrity_sdk.policy.opa_client.evaluate` raises
`OPAUnavailableError`. The engine catches this and returns:

```python
PolicyDecision(
    rule=RuleRef(rule_id="_opa_unavailable", name="OPA Unavailable", version="0"),
    decision=Decision(action="deny", reason=f"OPA unavailable: {exc}", severity="high"),
)
```

This means "local/offline, zero cloud round-trip" still holds — OPA runs as a local sidecar, not
a cloud service — but "no network dependency" does not: every event denies if the local OPA
process is down or unreachable. That is a real operational fact for anyone running `shield run`.

## Local profile-supervised OPA smoke runs

For local smoke integration, `shield local-run --profile PROFILE` supports exactly three explicit
profiles: `smb`, `professional-services`, and `regulated`. It starts exactly one corresponding Rego
file from `policies/rego/`, binds OPA to a dedicated loopback port, waits for a profile-specific rule
probe, and fails if OPA exits early or returns an incompatible policy shape. The selected Rego file's
SHA-256 hash is carried into `PolicyRef` metadata and printed at startup. The child process is
terminated and force-killed on context exit if necessary.

This command is local runtime hardening and smoke integration, not production process supervision,
Windows lifecycle proof, external Integrity export, or deployment readiness. The three shared-package
Rego files must be checked and loaded individually; loading all three together creates duplicate-default
conflicts under `shield.policy`.


`shield/schemas/policy_rule.py` defines a real, still-used `PolicyRule` dataclass shape — ordered
JSON rule bundles, condition groups `process`/`agent`/`file`/`flow`/`context`/`activity`, actions
`allow`/`deny`/`contain`/`log_only`/`escalate`, first-match-wins by list order. `policies/defaults/`
ships three real bundles in this shape (`smb.json`, `professional-services.json`,
`regulated.json`), and `shield/config/loader.py`'s `load_policy_bundle()` parses them into
`PolicyRule` objects, computes a `sha256` bundle hash, and enforces `trusted_policy_hashes` pins.
`shield/config/hot_reload.py`'s `PolicyHotReloader` re-parses the file on a changed mtime and
updates `policy_engine.policy_version`/`policy_hash` — but its own comment states the current
reality plainly:

```python
# We no longer set self._policy_engine.rules, OPA handles rule logic.
self._policy_engine.policy_version = bundle.version
self._policy_engine.policy_hash = bundle.hash
```

So today, the JSON rule bundle's `conditions`/`actions` content is used only for **authoring,
schema validation (`shield validate`), and hash pinning** — never consulted by
`PolicyEngine.evaluate()` to decide anything. `PolicyEngine` never receives the parsed
`PolicyRule` list at all; `shield/cli.py`'s `run` command constructs it with only
`policy_version=`/`policy_hash=` strings.

**Partially closed, 2026-08-13: all three default packs now have Rego translations.**
`policies/rego/smb.rego`, `professional-services.rego`, and `regulated.rego` are interpreter-backed
translations under the shared `shield.policy` package. SMB precedence and absent-agent registration
handling are regression-tested. Each vertical must still be loaded as an isolated OPA profile;
loading all three together would create duplicate default-rule conflicts.

## Combined-condition regression coverage

`tests/test_policy_engine.py` now includes a real-OPA, table-driven regression for the
professional-services profile using normalized `AgentEvent` inputs. The cases deliberately combine
agent, context, and activity fields on each event and verify the policy engine's public
`evaluate()` interface preserves the Rego profile's ordered evidence:

- an unregistered agent wins before the same event's unapproved endpoint and client-data context;
- once the agent is registered, the unapproved endpoint denial wins before client-data escalation;
- once the agent is registered and the endpoint is approved, the client-data context reaches the
  escalation rule.

This is regression coverage for the existing professional-services Rego translation and the
OPA-backed `PolicyEngine.evaluate()` adapter. It does not add a policy-language feature, a network
credential dependency, or a mocked OPA decision path.

## Documented drift vs. README.md and CLAUDE.md — now corrected

`README.md`'s status table and "Policy Model" section, `CLAUDE.md`'s repository-layout comment,
and `IMPLEMENTATION_PLAN.md`'s test-count entry were all corrected 2026-08-12 to describe this
OPA-backed reality (they previously read "table-driven, first-match, local/offline," describing
the pre-2026-08-07 in-process matcher). Git history shows the OPA migration landed in commit
`f86c0f0` ("Replace integrity_exporter with OTel telemetry, move policy evaluation to OPA") and
has not been reverted. `tests/test_policy_engine.py` mocks `opa_evaluate` directly, confirming
this is the intended, tested current behavior, not an accidental regression.

## Interface shape reused by Tier 2

`PolicyEngine.evaluate(event, ctx) -> PolicyDecision`'s exact signature is also the interface
`shield/agent_core/slm_backend.py`'s `SlmBackend` protocol implements — a Tier-2 backend is a
drop-in escalation path with the same call shape, not a parallel decision system. See
[SLM Cascade Tiers](slm-cascade-tiers.md).

## Related pages

- [Event Router](event-router.md) — calls `evaluate()` as step 2 of `handle()`
- [SLM Cascade Tiers](slm-cascade-tiers.md) — Tier 1's place in the 3-tier cascade
- [Guardrail Hooks](guardrail-hooks.md) — `guard_retrieval`/`guard_model_routing` depend on the
  `context` condition group existing in the rule schema
- [Enforcement Pipeline](../architecture/enforcement-pipeline.md)
