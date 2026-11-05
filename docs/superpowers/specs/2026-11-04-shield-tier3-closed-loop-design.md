# Shield Tier 3: Cloud Adjudication and the Closed Enforcement Loop

**Status:** design, approved conversationally 2026-11-04. Not implemented.
**Scope:** `xibalba-shield`. Completes the A2A Hybrid Cascading Architecture's deferred third tier
and closes the detect → reason → act → generalize loop.

---

## 1. Purpose

Shield detects and contains dangerous agent behaviour on a device in milliseconds using
deterministic rules (Tier 1) and a local small language model (Tier 2). Both tiers judge a single
event in isolation, and neither learns: a threat contained on one device teaches the fleet nothing.

This design adds **Tier 3** — a cloud frontier model that reasons over what the local tiers
found — and closes the loop by letting confirmed detections become **policy**, so that seeing a
threat once anywhere makes the fleet resistant to that *class* of threat.

### 1.1 The goal, stated honestly

The operator ask was "a closed loop should make the system immune to security threats." Immunity
is not an achievable or defensible engineering target, and designing toward it produces claims that
fail a customer audit. This design instead targets properties that can be measured and proven:

| Property | Target |
|---|---|
| Mean time to contain (local, Tier 1/2) | unchanged — single-digit ms, never regressed by Tier 3 |
| Mean time to adjudicate (Tier 3) | seconds, off the blocking path |
| False-positive release latency | bounded, automatic |
| Class-level coverage after one sighting | fleet-wide, via canary-promoted Rego |
| Evidence | every autonomous action carries a signed, chained receipt |

"Immune" is replaced by: *nothing is contained without a reversible, evidenced decision, and no
confirmed threat class recurs undetected.*

---

## 2. What already exists

This is not greenfield. The seam is cut and the contract is written.

| Piece | Location | State |
|---|---|---|
| Tier 1, deterministic | `shield/policy_engine/` → local OPA sidecar, Rego packs in `policies/rego/` | real, shipping |
| Tier 2, local SLM | `shield/slm_backend.py`, Qwen2.5-0.5B | real, shipping |
| Tier 2 dispatch hook | `shield/agent_core/router.py` — fires only when Tier 1 returns `escalate` | real |
| **Tier 3 dispatch point** | `router.py` — unresolved `escalate` currently **fails closed to contain** (`A2A_UNRESOLVED_ESCALATION`) | **the seam** |
| **Tier 3 data contract** | `shield/schemas/events.py` — `EscalationRequest`, `EscalationResponse` | **written, unimplemented** |
| Containment actuator | `shield/agent_core/action_broker.py` — `freeze()` (SIGSTOP), `kill_process()`, `block_flow()` | real |
| **Reversal actuator** | `action_broker.py` — `resume()` (SIGCONT) | **real; this is what makes auto-release possible** |
| Signed receipts | `shield/gate_receipts.py` over `integrity_sdk.core.receipt_writer` — chained + checkpointed | real |
| Durable export retry | `shield/integrity_exporter/spool.py` — SQLite retry queue | real |
| Shadow-inference precedent | `shield/policy_engine/jev_shadow.py` (`JevShadowAnalyzer`) — classifies, never decides | real |
| Rego bundle integrity | `shield/opa_local.py` — allowlisting + SHA-256 identity binding | real |

`EscalationRequest` already carries the **full decision trail** (`event`, `tier1_decision`,
`tier2_decision`, `reason`), and `EscalationResponse` is deliberately shaped so a Tier 3 backend is
a drop-in `evaluate()`-shaped call, matching the `SlmBackend` protocol
(`evaluate(event, ctx) -> PolicyDecision`). This design implements against those shapes rather than
inventing new ones.

---

## 3. Non-goals and rejected designs

**3.1 Tier 3 must never sit on the blocking enforcement path.** `router.py`'s `handle()` calls
`ActionBroker.contain()` *first*, before any export, precisely because a real BCC commitment costs
200–700ms and must not delay a SIGSTOP. A cloud frontier model costs 1–10s. Putting it in-path
would make Shield slower than the threat. **Tier 3 therefore adjudicates after local containment
has already happened.**

**3.2 The cloud never reaches into a device.** All actuation stays local, through `ActionBroker`.
Tier 3 returns a verdict; the local agent applies it. This keeps per-device blast-radius limits
enforceable locally and means a compromised or confused cloud cannot directly drive endpoints.

**3.3 Cloud unreachability must never cause fleet-scale action.** Unreachable Tier 3 degrades to
exactly today's behaviour — local fail-closed per event. It never escalates to fleet-wide
containment (an internet blip must not contain the fleet) and never becomes a fleet-wide free pass.

**3.4 Tier 3 does not compute AIS.** Per the inherited cross-repo rule, AIS is computed only in
`integrity-oracle/scoring-core`. `ais_impact` remains a hint.

**3.5 No silent mocks.** Any unimplemented portion states so in its own docstring.

---

## 4. Architecture

```
event
  │
  ├─ Tier 1  OPA/Rego (deterministic, ms)
  │     allow/deny/contain  ──────────────────────────────► ActionBroker (local, immediate)
  │     escalate │
  │              ▼
  ├─ Tier 2  local SLM (ms–100s of ms)
  │     allow/deny/contain ──────────────────────────────► ActionBroker (local, immediate)
  │     escalate │  (still uncertain)
  │              ▼
  │        FAIL CLOSED → contain NOW (unchanged, local, ms)
  │              │
  │              │  …containment has already happened. Only now:
  │              ▼
  └─ Tier 3  cloud frontier adjudication (1–10s, OFF-PATH)
           │
           ├─ verdict: false positive ──► ActionBroker.resume()      (narrowing, auto)
           ├─ verdict: confirmed      ──► keep contained + escalate evidence
           └─ generalize ─────────────► candidate Rego rule
                                             │
                                             ▼
                                   corpus replay check (deterministic)
                                             │
                                             ▼
                                   canary cohort → fleet, auto-rollback
```

### 4.1 `Tier3Backend` protocol

Mirrors `SlmBackend` so the router's dispatch stays uniform:

```python
class Tier3Backend(Protocol):
    def adjudicate(self, request: EscalationRequest) -> EscalationResponse: ...
```

Deliberately *not* named `evaluate()`: the call happens post-containment and may return a
release, so the semantics differ from the two in-path tiers. Separate name, separate contract,
no accidental substitution into an in-path slot.

### 4.2 Where it attaches in `router.py`

The existing fail-closed block stays exactly as it is — containment still happens first. Tier 3 is
dispatched *after* the `ActionBroker` call, on the same best-effort footing as the OTel span and
the BCC commitment (both already independent, post-containment, best-effort paths). A Tier 3 that
raises, times out, or is unconfigured leaves the local decision standing, logged — the same posture
`router.py` already applies when the Tier 2 backend raises.

Dispatch is asynchronous: `handle()` must not block on it. Verdicts arrive later and are applied by
the adjudication consumer (§4.3).

### 4.3 Adjudication consumer

A local component that receives `EscalationResponse`s and applies them:

- **release** → `ActionBroker.resume(pid)`, if and only if the release invariants (§5) hold
- **confirm** → no actuation (already contained); emit evidence, feed the rule generaliser
- **rule candidate** → hand to the promotion pipeline (§6)

Reuses `integrity_exporter/spool.py`'s durable-SQLite-retry pattern, so a verdict is not lost to a
restart. **Fail-closed:** a verdict that cannot be durably recorded is not applied.

---

## 5. Safety invariants for autonomous action

The operator chose full autonomy, including contain. These are the engineering requirements that
make autonomous enforcement operable — not a dilution of that choice. Each is testable.

**I1 — Narrowing-only autonomy on live processes.** Tier 3 may autonomously *release* (narrow) and
may autonomously *confirm*. It may also contain (per the autonomy decision), but only via a rule
that passed §6's gates, never as an unreviewed one-off command against an arbitrary device.

**I2 — Reversibility.** Every autonomous action maps to an inverse (`freeze`↔`resume`, rule
install↔rollback). An action with no inverse is not autonomous.

**I3 — Kill switch.** A single local control disables all Tier 3 actuation, leaving Tiers 1/2
untouched. Must be settable without network access and without a redeploy. The existing
`--enforcement-mode observe|enforce` precedent applies: Tier 3 gets its own independent switch, so
observe-mode Tier 3 can run against live enforce-mode Tiers 1/2.

**I4 — Blast-radius caps, enforced locally.** Per-device and per-fleet ceilings on autonomous
actions per time window. Exceeding a ceiling trips to observe-only and raises an operator alert.
A cloud that starts emitting mass verdicts cannot act on more than the cap.

**I5 — No prompt-sourced authority.** Tier 3 receives **typed, length-bounded, structured**
evidence — never free text spliced into a prompt. Process names, paths, and tool inputs are
attacker-controlled; `gate_receipts.py` already carries a tool-input *digest* rather than the
input, and Tier 3 inherits that discipline. A verdict's *action* is parsed from an enum, never from
model prose.

**I6 — Unreachability posture.** Stated per §3.3. Tested with a healthy-but-slow stub, not only an
unreachable one, so a timeout shorter than the dependency's latency is caught as structural.

**I7 — Evidence or it did not happen.** Every autonomous action emits a signed, chained receipt
before the action is reported complete.

---

## 6. Rule generalisation and promotion (the loop closure)

This is what makes the loop *closed* rather than merely reactive.

1. **Candidate authoring.** For a confirmed detection, Tier 3 proposes a Rego rule targeting the
   observed *class*. Emitted into the vertical's isolated OPA package, never a shared default.
   (Shield's 2026-10-24 incident was duplicate OPA default rules causing 400s. Autonomous rule
   authoring would make that failure class routine, so package isolation is mandatory, not stylistic.)
2. **Deterministic corpus replay — the key gate.** Before promotion, the candidate is replayed
   against the stored event corpus. If it would have contained known-good activity, it is rejected.
   This is a cheap deterministic check on a non-deterministic author, and it is the single highest-value
   safety mechanism in this design.
3. **Syntactic and integrity validation.** Bundle compiles; SHA-256 identity bound per
   `opa_local.py`'s existing allowlisting.
4. **Canary cohort.** Promoted to a small device cohort first. Health signals: OPA error rate,
   decision latency, containment rate delta.
5. **Auto-rollback.** Any canary health regression rolls the bundle back automatically and freezes
   further promotion pending an operator.
6. **Fleet promotion.** Only on a clean canary window.

Promotion state is durable and auditable: which rule, authored from which event, which replay
result, which canary window, who/what promoted it.

---

## 7. Failure postures (per repo convention)

| Component | Posture | Rationale |
|---|---|---|
| Tier 3 dispatch | fail-open *to the local decision* | local tiers already decided and acted; cloud is additive |
| Unresolved `escalate` (no Tier 3) | fail-closed → contain | unchanged from today |
| Adjudication consumer, cannot persist | fail-closed → do not apply | an unrecorded autonomous action is unauditable |
| Release path | fail-closed → stay contained | a failed release leaves the safe state |
| Rule promotion | fail-closed → do not promote | unproven policy does not ship |
| Receipt write failure | fail-closed → action not reported complete | matches `gate_receipts.py` strict default |

---

## 8. Testing strategy

- **Every check must be proven able to fail.** A conformance test that passes before the feature
  exists measured nothing. Each invariant in §5 gets a mutation proof: break the guard, watch the
  test fail, restore. Recorded in the PR.
- **Corpus replay** tested with a rule that is deliberately too broad — it must be rejected.
- **Canary rollback** tested by injecting an OPA error-rate regression.
- **I5** tested with an event whose process name is an injection payload; the verdict's action must
  still parse from the enum and the payload must not reach a prompt as instructions.
- **I6** tested with a healthy-but-slow stub.
- **Latency regression guard:** Tier 1/2 containment latency measured with Tier 3 enabled and
  disabled; Tier 3 must not move it.
- No test may depend on a live frontier model: the backend is a protocol, tests use real local
  fakes that honour the contract, and the single integration test against a real provider is
  marked and skippable (matching the existing `bcc_middleware` integration-test convention).

---

## 9. Open questions

1. **Which cloud model, and hosted where?** Affects latency budget, cost per adjudication, and
   whether evidence leaves the tenant boundary. Unresolved.
2. **Cost ceiling per device per day.** Adjudication is per-escalation; a noisy device could be a
   cost-amplification vector. Needs a budget cap, which `hermes_analyst.py` already has a precedent
   for (`outcome='unanalysed_budget'`).
3. **Does evidence leaving the device need tenant consent?** Likely contractual, not technical.
4. **Fleet-wide promotion authority** currently has no durable multi-tenant control plane to live
   in — today's backend is free-tier with SQLite on an ephemeral disk, so promotion state would not
   survive a redeploy. §6 steps 4–6 are blocked on that until it exists.

---

## 10. Sequencing

**Phase A1 — shadow.** Implement `Tier3Backend` + the dispatch + the consumer, actuation disabled.
Record every verdict and its agreement with Tier 1/2. Follows the `jev_shadow.py` precedent exactly.
Exit criterion: measured agreement and false-positive rate on real traffic.

**Phase A2 — live release.** Enable autonomous release (narrowing) under §5's invariants.
Exit criterion: bounded release latency, zero unevidenced actions.

**Phase C1 — rule authoring, proposal-only.** Generalise confirmed detections into candidate Rego;
run replay + validation; do not promote. Exit criterion: candidate quality measured against replay.

**Phase C2 — canary promotion + auto-rollback.** Requires the durable control plane (§9.4).

**Phase C3 — fleet promotion.** Full loop closed.

Each phase is independently shippable and independently revertible. A1 and A2 need no new
infrastructure; C2 onward does.

---

## 11. Decisions recorded

- Approach **C** (local actuation + cloud-authored policy with canary promotion), sequenced A → C.
- Autonomy level: **full, including contain**, chosen with the risks stated.
- Rejected: Tier 3 in the blocking path; cloud reaching into devices; designing toward "immunity".

### 11.1 One interpretation that needs explicit confirmation

"Full autonomy including contain" was chosen. §3.2 and invariant I1 together route autonomous
*contain* through the §6 rule pipeline (replay-checked, canary-promoted) rather than letting Tier 3
issue an ad-hoc "contain PID 4242 on device X" command straight to an endpoint.

This is a narrower reading than the words strictly allow, and it is called out here rather than
buried because it is a real constraint on the chosen autonomy level. The reasoning: an unreviewed
remote contain command is precisely the fleet-wide enforcement weapon that §3.2 exists to prevent,
and it has no deterministic gate in front of it — a single bad verdict or one successful prompt
injection becomes immediate containment on a named machine.

Autonomy is preserved in substance: no human approves anything in the loop. The difference is that
autonomous containment is expressed as *policy that was replay-validated and canaried* rather than
as a direct remote command.

**If direct ad-hoc remote contain is wanted as well, say so and it becomes an explicit additional
component** — with its own rate cap, its own kill switch, and its own receipt type. It is a
deliberate design decision, not an oversight, and it is reversible either way.
