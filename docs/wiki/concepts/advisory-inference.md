---
title: Configurable Advisory Inference
acronyms: [Jev, LLM, SLM]
created: 2026-10-04
updated: 2026-10-04
type: concept
tags: [enforcement, compliance, slm, infrastructure]
confidence: high
source_files:
  - shield/policy_engine/inference.py
  - shield/policy_engine/jev_shadow.py
  - shield/backend/settings.py
  - shield/cli.py
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
