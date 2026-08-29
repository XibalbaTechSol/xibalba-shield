# A2A local-to-cloud escalation schema — go/no-go proposal

**Status:** built and tested, authorized as scoped (option 1: fail-closed default). Chose
fail-closed over fail-open per this repo's own inherited posture from `bcc_middleware`
("any failure to positively confirm 'allowed' denies the request") and this router's
real-time enforcement stance — irreducible uncertainty about a potentially dangerous action
is treated as dangerous, not waved through.

Added: `Decision.tier` (`"tier1"|"tier2"|"tier2_unresolved"`, `shield/schemas/events.py`),
`EscalationRequest`/`EscalationResponse` schemas (defined, not yet consumed — no Tier 3
exists), and the actual fail-closed fallback in `shield/agent_core/router.py`'s `handle()`:
any decision still `escalate` after Tier 1 (and Tier 2, if configured) — whether because no
Tier 2 was configured, Tier 2 raised, or Tier 2 itself remained uncertain — is rewritten to
`contain` with reason `A2A_UNRESOLVED_ESCALATION`, never reaching export as a bare unresolved
`escalate`. Two pre-existing tests that asserted the OLD unresolved-`escalate` behavior
(`test_router_keeps_tier1_decision_when_no_slm_backend_configured`,
`test_router_falls_back_to_tier1_decision_when_slm_backend_raises`) were renamed and updated
to assert the new, correct fail-closed behavior — they were asserting the exact gap this
proposal closes. New: `test_router_tags_tier2_on_slm_revised_decision`,
`test_router_fails_closed_when_tier2_itself_remains_uncertain`. Full suite green: 137
passed, 9 skipped (up from 135/9 before this change).

Written after reading `shield/agent_core/router.py`'s `handle()`,
`shield/agent_core/slm_backend.py`'s `SlmBackend` protocol, and
`shield/schemas/{policy_rule,events}.py`'s `Action`/`Decision`/`PolicyDecision` definitions
(2026-08-18).

## Why this slice, and why now

`docs/archive/2026-08/IMPLEMENTATION_PLAN.md`'s Hybrid Cascading Architecture section lists,
unchecked and with no code yet: "Define structured Agent-to-Agent (A2A) communication schema for local-to-cloud
escalations" and "Implement Tier 3 Cloud Frontier fallback for ambiguous/low-confidence SLM
decisions." Most other open items in this repo's plan are hard-blocked by this environment
specifically — TCP-sensor verification needs root, Windows/macOS sensors need those platforms,
live eBPF/exporter re-verification needs a running Integrity stack. The A2A schema item is not
blocked by any of that; it's pure design-and-wiring work against code that already exists.

## The gap, verified today

Tier 1 → Tier 2 escalation is real and already wired: `Action` (`schemas/policy_rule.py`) is
`Literal["allow", "deny", "contain", "log_only", "escalate"]`, and `router.py`'s `handle()`
calls `self.slm_backend.evaluate(...)` exactly when the Tier-1 `PolicyEngine` returns
`"escalate"` and a backend is configured. That part works and is tested.

**What doesn't exist: anywhere for a Tier-2 `"escalate"` to go.** When `SlmBackend.evaluate()`
itself returns `"escalate"` — meaning the local SLM is *still* not confident — `router.py` has
no Tier 3 to call. The decision object simply carries `action == "escalate"` forward: it fails
the `action == "contain"` check a few lines later (so `ActionBroker` never touches it), fails the
implicit "acted on" bar every other terminal action gets, and flows straight into guardrail hooks
and export exactly as any other decision would — logged and exported as `"escalate"`, with no
disposition ever actually applied to the event. This is a real, silent no-decision outcome, not
a crash and not an explicit denial — the kind of gap this repo's own "no silent mocks" rule is
about naming rather than leaving implicit.

Separately, `PolicyDecision`/`Decision` (`schemas/events.py`) carry no field recording *which
tier* produced the final action, and no confidence value. `router.py` logs the Tier-1→Tier-2
transition (`logger.info("Tier-2 SLM revised decision...")`) but doesn't persist it on the
decision object itself — so a SIEM export, an audit query, or a dashboard reading `PolicyDecision`
records after the fact cannot distinguish "Tier 1 resolved this confidently" from "Tier 2 revised
it" from "Tier 2 was asked and remains uncertain."

## What this is NOT

- **Not** Tier 3 itself. No cloud model, no cloud API integration, no network call to any
  frontier-model provider. That needs its own provider/cost/latency/data-handling decisions this
  proposal does not make.
- **Not** a change to Tier 1 or the real `ActionBroker`/containment path — untouched.
- **Not** a fix to the Llama-vs-Qwen model-naming inconsistency flagged elsewhere in the plan —
  unrelated, separate, smaller cleanup item.
- **Not** the "add cloud-fallback latency and decision metrics to burn-in reporting" item — that
  depends on Tier 3 existing and is explicitly out of scope until it does.

## Scope: the slice itself

- A structured `EscalationRequest`/`EscalationResponse` schema (new dataclasses in
  `shield/schemas/`, same module discipline as `policy_rule.py`/`events.py` — canonical, no
  ad-hoc dict shapes). `EscalationRequest` carries the normalized event, the Tier-1 and Tier-2
  decisions that led here (not just the final one — an auditor needs the trail, not just the
  outcome), and a reason string. `EscalationResponse` mirrors `PolicyDecision`'s shape closely
  enough that a future Tier-3 backend is a drop-in `evaluate()`-shaped call, the same
  `SlmBackend` protocol convention Tier 2 already established.
- A `tier` field added to `Decision` or `PolicyDecision` (design choice to resolve during
  implementation, not here) recording which tier actually produced the final action —
  `"tier1"`/`"tier2"`/`"tier2_unresolved"` — so every exported decision is self-describing rather
  than requiring log correlation to reconstruct.
- **A defined, explicit terminal disposition for a Tier-2 `"escalate"` when no Tier 3 is
  configured** — this is the real, immediately-shippable value of this slice even before any
  cloud tier exists. Per this repo's own convention ("fail-open/fail-closed postures are stated
  explicitly per module"), pick one and say so in the module docstring: e.g. an unresolved
  escalation with no Tier 3 configured falls back to `"contain"` (fail-closed — treat
  irreducible uncertainty as dangerous) or to `"log_only"` with a distinct flagged status
  (fail-open — never block on an unconfigured tier). This is a real security posture decision,
  not a default to pick casually.
- Tests: an escalate-with-no-tier-3-configured event resolves to the chosen explicit fallback,
  not to a silently-forwarded `"escalate"`; the `tier` field is populated correctly across all
  three paths (Tier-1-resolved, Tier-2-revised, Tier-2-still-uncertain); a stub `Tier3Backend`
  Protocol conformance test (no real implementation, just proving the interface shape a future
  cloud backend would satisfy).

## Explicitly deferred — not attempted here

- The actual Tier 3 cloud call, provider choice, auth, latency budget, and data-minimization
  policy for what leaves the device.
- Burn-in reporting metrics for cloud-fallback latency/decisions.
- Any change to how Tier 1 or Tier 2 make their own decisions — this slice only defines what
  happens *after* Tier 2 hands back `"escalate"` with nowhere to go.

## Acceptance criteria

- Real tests, passing, proving: (a) the new schemas round-trip through `to_dict()`-style
  serialization the same way `PolicyDecision` already does; (b) a Tier-2-still-uncertain event
  resolves to the explicitly chosen fallback disposition, never a bare unresolved `"escalate"`
  reaching export; (c) the `tier` provenance field is correct for all three resolution paths.
- `docs/archive/2026-08/IMPLEMENTATION_PLAN.md`'s A2A schema checkbox updated to reflect exactly what's closed —
  schema + fallback disposition — and the Tier 3 implementation checkbox stays unchecked,
  explicitly not implied closed by this slice.
- The chosen fail-open/fail-closed fallback posture is stated in the module docstring, matching
  this repo's existing per-module convention, not left to be inferred from behavior.
- `.venv/bin/python -m pytest` clean at the current baseline plus new tests, no regression.

## Real risks

- **The fallback-disposition choice is the one genuinely consequential decision in this slice.**
  Fail-closed (contain-on-unresolved-escalate) risks false-positive containment of legitimate
  agent activity purely because Tier 2 was uncertain. Fail-open (log-only-on-unresolved-escalate)
  risks exactly the failure mode Tier 2 was introduced to catch — a genuinely dangerous action
  that neither tier could confidently resolve sails through. This should not be decided silently
  inside an implementation PR; it belongs in this proposal's decision below.
- Adding a `tier` field to `PolicyDecision`/`Decision` touches a schema `integrity_exporter`
  and SIEM/SOAR adapters both consume — check `siem.py`'s field mapping and any BCC-commitment
  interaction before landing, so an additive field doesn't silently break a downstream consumer
  expecting an exact field set.
- Low blast radius otherwise: no OS-level enforcement change, no new external dependency, no
  network call added by this slice specifically (Tier 3 itself is deferred).

## Decision needed

1. **Authorize as scoped above, fail-closed default** — unresolved Tier-2 escalation without a
   configured Tier 3 falls back to `contain`.
2. **Authorize as scoped above, fail-open default** — falls back to `log_only` with a distinct
   flagged/unresolved status.
3. **Authorize with changes** — different schema shape, or defer the fallback-disposition
   decision itself to a follow-up once real Tier-2 escalation-rate data exists from a pilot.
4. **Not yet** — stay at proposal stage; revisit later.
