---
title: Configurable Advisory Inference
acronyms: [Jev, LLM, SLM]
created: 2026-10-04
updated: 2026-10-06
type: concept
tags: [enforcement, compliance, slm, infrastructure]
confidence: high
source_files:
  - shield/policy_engine/inference.py
  - shield/policy_engine/jev_shadow.py
  - shield/backend/settings.py
  - shield/backend/api.py
  - shield/cli.py
  - tests/test_jev_failure_modes.py
---

# Configurable Advisory Inference

Shield can run bounded inference after deterministic policy evaluation. The provider annotates an
already-made policy decision; it cannot authorize, deny, contain, sign, or delay enforcement. The
runtime path is defined by [`Event Router`](event-router.md) and remains separate from the
[`Policy Engine`](policy-engine.md).

## Table of contents

- [Provider choices](#provider-choices)
- [Settings contract](#settings-contract)
- [Runtime and evidence](#runtime-and-evidence)
- [Failure boundary](#failure-boundary)
  - [Why a failure happened: reasoncode](#why-a-failure-happened-reasoncode)
- [Reading the trace back: integrity and reason codes](#reading-the-trace-back-integrity-and-reason-codes)

## Provider choices

`build_inference_provider(settings)` supports these provider identifiers:

| Provider | Implementation | Endpoint | Purpose |
|---|---|---|---|
| `disabled` | none | no | Keep advisory inference off. |
| `jev` | `FixtureJevProvider` | no | Deterministic offline Jev-compatible analysis for local tests and demos. |
| `local_classifier` | `LocalClassifierProvider` | no | Bounded local risk classification from event metadata. |
| `lila` | `HttpInferenceProvider` | yes | JSON adapter for a Lila-compatible local or HTTPS service. |
| `llm` | `HttpInferenceProvider(openai_compatible=True)` | yes | OpenAI-compatible chat-completions adapter with JSON output mode. |

Remote credentials are not stored in tenant settings. The HTTP adapter reads the optional
`SHIELD_INFERENCE_API_KEY` host environment variable and sends only the redacted
`DecisionEnvelope.body()`.

## Settings contract

The backend validates these tenant-scoped fields:

- `inferenceEnabled`, `inferenceProvider`, and `inferenceMode` (`shadow` only);
- `inferenceModel`, `inferenceEndpoint`, `inferencePromptProfile`, and `inferenceSecretRef`;
- `inferenceTimeoutMs` (50–5000), `inferenceMaxTokens` (32–4096), and
  `inferenceTemperature` (0–1);
- strict `inferenceRedactionMode`;
- `inferenceFailureMode` (`continue_with_policy` or `mark_unavailable`); and
- `inferenceEventClasses`, a bounded list of event classes to analyze.

Endpoints must use HTTP(S); non-loopback HTTP endpoints are rejected and must use HTTPS. Secret
settings are references beginning with `secret://`, never raw credentials.

## Runtime and evidence

`JevShadowAnalyzer` runs after the router has a `PolicyDecision`. It creates a parent-linked
`DecisionEnvelope` with tenant, agent, trace, invocation, policy, event-class, severity, and
provider metadata. `JsonlDecisionTraceSink` writes the redacted envelope and `JevAnalysis` to the
local trace handoff consumed by the authenticated `/api/shield/decision-trace` endpoint.

The advisory contains provider status, risk category, transition probabilities, escalation advice,
and the observed event hash. The trace explicitly records `causal_claim: false`; probabilities
describe observational correlation and are not proof of reasoning or causality. See
[`Compliance Evidence Trail`](../queries/compliance-evidence-trail.md) and the Integrity
[`DecisionTrace contract`](../../../../integrity-core/docs/EXECUTION_PLAN.md#shared-sdk-contracts-c8-c11)
for the cross-product evidence boundary.

## Failure boundary

Provider exceptions become an unavailable advisory. Events outside the configured class scope are
skipped. The deterministic Shield/OPA/BCC result and normal evidence path remain unchanged when a
provider is disabled, unavailable, malformed, contradictory, or slow.

That last sentence is **proven differentially**, not asserted: `tests/test_jev_failure_modes.py`
routes the same event through a real OPA and a real signed `smb` pack once with a healthy provider
and once per failure mode, and requires the `PolicyDecision` to be identical, for both a genuine
Rego *deny* and a `log_only` baseline (a test that only ever saw "allow" could not tell a preserved
decision from one never made). The HTTP providers are driven against a real local HTTP server, so
timeouts and refused connections are real.

### Why a failure happened: `reason_code`

"Unavailable" alone does not tell an operator whether the provider is down, slow, mis-keyed, or
returning garbage. Every failed advisory carries a stable `reason_code`, in the log line and in the
stored advisory row (`advisory.reason_code`, `null` for a healthy one). The analyzer classifies the
exception's **type** only; neither the exception message nor any response body is logged, because
provider-returned content must not reach a log line.

| `reason_code` | `status` | Meaning |
|---|---|---|
| `ADVISORY_PROVIDER_TIMEOUT` | `unavailable` | No answer within `inferenceTimeoutMs`. |
| `ADVISORY_PROVIDER_UNREACHABLE` | `unavailable` | Connection refused, DNS failure, network down. |
| `ADVISORY_PROVIDER_HTTP_ERROR` | `unavailable` | The server answered with an HTTP error (401 bad key, 500...). |
| `ADVISORY_PROVIDER_MALFORMED_RESPONSE` | `unavailable` | Not JSON, wrong shape, or an ill-typed field. |
| `ADVISORY_PROVIDER_OUTPUT_REJECTED` | `unavailable` | Well-formed, but refused by `DecisionTrace`'s own validation (a probability outside 0..1, more than 32 entries). |
| `ADVISORY_PROVIDER_ERROR` | `unavailable` | Anything else the provider raised. |
| `ADVISORY_OBSERVED_HASH_MISMATCH` | `rejected` | The advice was about a *different* event than the one analyzed. |

`rejected` is used only for the hash mismatch: the advice arrived, so it is not unavailable, but it is
not advice about this event, and recording it as `available` would put a false link in the evidence
trail ("every advisory projection links to the observed event hash"). No link at all is not a
contradicting one, so an advisory with no `observed_event_hash` is left alone. Mapping
`ADVISORY_PROVIDER_OUTPUT_REJECTED` onto `rejected` instead of `unavailable` would arguably be more
precise, but it would change what existing consumers see for those cases, so it is left as an option.

Two stricter behaviours came out of this. A provider that returns the wrong *type* is now an
unavailable advisory (it used to raise in the sink and lose the record). And `recommended_escalation`
must be a real boolean: `bool("false")` is `True`, so a model that quotes its JSON booleans used to
turn "do not escalate" into "escalate", with status `available` and nothing to suggest trouble.

`reason_code` lives on `ShieldJevAnalysis`, a Shield-local subclass of the SDK's `JevAnalysis`,
because `JevAnalysis` has no reason field and belongs to `integrity-core`; adding one there would be
a cross-package schema change. Consumers read it with `getattr(analysis, "reason_code", None)`.

## Reading the trace back: integrity and reason codes

`shield/backend/api.py`'s `_read_decision_trace` verifies a tenant's most recent trace before the
dashboard shows it. `valid` is `false` for any integrity problem, and `reason_code` names the
**first** one found:

| `reason_code` | Meaning |
|---|---|
| `TRACE_UNREADABLE` | The file could not be read or parsed. |
| `TRACE_LINK_BROKEN` | An event's parent is not the event before it: a row was removed, or a parent pointer edited. |
| `TRACE_NAMESPACE_MISMATCH` | An event belongs to a different tenant, agent or trace than the trace it sits in. |
| `TRACE_HASH_MISMATCH` | An event's stored hash is not the hash of its own envelope: the envelope was rewritten. |
| `TRACE_INVALID` | A row is structurally malformed. |

Hashes are **recomputed** from each envelope and compared with the stored ones. This once trusted the
stored hashes, so rewriting only the *final* event left nothing after it to disagree with and the
latest decision could be flipped while the trace still read as valid; a rewrite anywhere earlier was
caught. Tenant isolation was already correct (two tenants sharing one trace id never see each other's
events) and is now pinned by a test.

**A window is not damage.** Only the last 50 lines are read, so a long-running device's trace starts
mid-chain. That used to be reported as `valid: false` forever once a trace passed 50 events, a false
alarm that would have made every code above a cry-wolf label. A window is now verified as a
*segment* (hashes, links and namespaces among its own events) and returned with `truncated: true`;
its `root` and `proofs` are omitted, because a Merkle root over part of a chain is not the trace's
root.

**Known limit.** Removing events from either end of a trace, or from a window's edge, leaves a
shorter chain that is still internally consistent, so it cannot be detected from this file alone.
Pinning the root externally closes that (integrity-core B4's evidence anchor). Not built here: a
display of `reason_code` or `truncated` in the dashboard (the API returns both; the UI ignores
unknown keys).
