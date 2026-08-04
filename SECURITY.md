# Security Posture & Threat Model

This document translates `spec/xibalba-shield-v1.md` §6 (Privacy and HIPAA Posture) and §13
(What This Product Is Not) — both design-intent documents in the parent `integrity-latest`
repo — into a statement of what **this repo's code, as it exists today**, actually enforces.
Where the two disagree, this file is describing implementation reality; the spec is describing
design intent. Neither replaces the other.

**Ground rule, same as everywhere else in this repo: no silent mocks.** A security document
that overstates what's enforced is worse than no document at all — it tells an operator to
trust a control that isn't there. Every claim below is checked against the actual module it
describes, not against what the spec says the module should eventually do. Cross-check against
`README.md`'s status table before deploying against anything real; that table is the source of
truth for what's `[PLANNED]` vs. built vs. verified, and it changes faster than this file will.

---

## 1. Default posture: allow, not deny

**Shield ships default-allow, not default-deny.** `PolicyEngine.evaluate()`
(`shield/policy_engine/engine.py`) returns `action="allow", reason="no policy rule matched"`
for any event that doesn't match a configured rule. Out of the box, with no rules loaded,
Shield **observes and evidences everything and blocks nothing.** Enforcement only exists for
whatever you explicitly write a `deny` rule for (`spec/xibalba-shield-v1.md` §7's policy rule
format). This is a deliberate design choice, not a bug — a device-security agent that silently
started blocking things nobody configured would be its own kind of silent-mock — but it means
**an unconfigured or under-configured deployment is a visibility tool, not a control.** Don't
represent it as the latter to a customer or an auditor without a real rule set behind it.

## 2. Guardrail hooks fail open on their own bugs

Each of the six guardrail hooks (`shield/guardrail_hooks/*.py`) raises its own typed exception
(`ToolCallDenied`, etc.) when the Policy Engine's decision isn't `allow`/`log_only` — that's the
intended block path, and it's real. Separately, `EventRouter.handle()`
(`shield/agent_core/router.py`) wraps every hook invocation in a bare `except Exception` that
logs and continues rather than propagating:

```python
try:
    hook(event, decision)
except Exception:  # noqa: BLE001
    # A guardrail hook must never take down the router...
    logger.exception("guardrail hook raised; continuing")
```

**This means a bug in a hook — not a policy decision, an actual crash — does not block the
action it was evaluating.** The event still proceeds. This mirrors `pretool_gate.py`'s "a gate
bug must not brick the session" posture in the parent repo, and the tradeoff is the same one
that posture makes: availability over strict enforcement when the enforcement code itself is
broken. If your threat model requires "an internal bug in the enforcement path blocks the
action," this code does not provide that — it provides the opposite, deliberately.

## 3. Evidence export failing never rolls back an enforcement decision

`EventRouter.handle()` makes the local enforcement decision (Policy Engine + guardrail hooks)
*before* calling `IntegrityExporter.export_event`/`export_decision`. If the export call fails —
network down, `bcc_middleware` unreachable, oracle registration missing (see README row 5) — the
decision that already happened is not undone:

```python
try:
    self.exporter.export_event(event)
    self.exporter.export_decision(decision)
except Exception:  # noqa: BLE001
    # Evidence export failing must never roll back an already-made enforcement decision...
```

**Practical consequence:** a deny that happened locally is real and took effect even if it never
reaches Integrity Protocol's Merkle anchor. Conversely, **an allow that happened locally is real
even if no cryptographic evidence of it ever gets produced.** Don't assume "it's in the
tamper-evident log" for any decision made while the exporter was down — see §5 below for what
that actually means for auditability.

## 4. The local decision log is a diagnostics convenience, not evidence

`shield/agent_core/eventlog.py`'s `EventLog` is a plain, append-only, **unsigned** JSONL file on
local disk — exactly what backs `shield status`/`shield events --recent`. It has no tamper
protection, no integrity hash chain, and no access control beyond the filesystem's own. Its
entire design goal, stated in its own docstring, is that "a security product an admin cannot
explain in one command is a security product they will disable during an incident" — it exists
so a human can `tail`/`grep` it during an incident, not so it can stand up as forensic evidence
on its own.

**Cryptographic tamper-evidence exists only for decisions that successfully reach
`bcc_middleware`** via the exporter (BCC-signed commitment, Merkle-anchored — see README row 5
and `integrity-latest`'s own `docs/INTERFACE_CONTRACT.md`). A decision that only ever made it
into the local `EventLog` — because `--no-exporter` was passed, or export failed (§3) — carries
no cryptographic guarantee against tampering or deletion. An attacker with write access to the
log file can edit or truncate it with no detection mechanism in this repo.

## 5. What a root-level attacker on the same device can do

Shield's eBPF sensors and its own process run as root (or with equivalent capabilities) to load
BPF programs and observe kernel events — see `shield/sensors/ebpf/loader.py` and the
`PermissionError` both real sensors raise when not run as root (README row 7, `test_cli.py`).
**Anything that runs as root on the same machine can defeat Shield entirely**: kill the agent
process, unload its BPF programs, corrupt or delete the local `EventLog` (§4), edit the local
policy rules file the hot-reloader watches (`shield/config/hot_reload.py` — it protects against
a *malformed* edit by keeping the last-known-good rule set, not against a *malicious* one that
parses cleanly and simply removes the deny rules), or block outbound network traffic to prevent
any evidence from ever reaching Integrity Protocol. **There is no self-tamper-protection, no
process-integrity attestation, and no anti-debugging/anti-unload mechanism anywhere in this
codebase.** This is a real, unmitigated gap relative to what an EDR/XDR product typically
claims — consistent with `spec/xibalba-shield-v1.md` §13's own statement that Shield is "not a
full replacement for existing EDR/XDR in a v1 scope."

## 6. Behavioral telemetry only — content is never inspected

Matching spec §6's governing principle: the two verified eBPF sensors (process-exec, file-write)
observe *that* a process executed or *that* a file was opened for writing — never the content of
the file, the arguments beyond what the kernel exposes at the syscall boundary, or any
higher-level semantic meaning. The `output` guardrail hook (`shield/guardrail_hooks/output.py`)
gates on a caller-supplied `risk_level`/`categories` classification but **does not itself
classify anything** — no content-inspection or DLP capability exists in this repo. §6's
PHI-tagging/guardrail-content-classifier mechanism is `[PLANNED]` (README row 13); until it's
built, Shield **cannot detect what a message or file *says*, only that an agent touched it.**
Don't represent Shield as a DLP or content-classification control to anyone until that row moves
off `[PLANNED]`.

## 7. What's actually enforced today vs. observed vs. not built at all

Cross-reference against README's numbered status table; the short version, security-relevant
framing:

| Capability | State |
|---|---|
| Deny a matched process-exec or file-write event via policy rule | **Real, enforceable** — both sensors verified, Policy Engine + `EventLog` real |
| Deny a matched TCP-connect event | **Not possible** — sensor blocked at compile time (README row 10), no network-layer enforcement exists yet |
| Gate an application-level tool call / prompt / model route / output before it happens | **Real, but opt-in instrumentation** — the six guardrail hooks only fire if the calling agent runtime actually invokes them; Shield cannot force an uninstrumented agent runtime through a hook it never calls |
| Detect a semantic/physical gap after an action (expected vs. actual state) | **Real, detection only** — `verify_post_action` can only flag, never block, since the action already happened by the time it runs (§4.4, row 6) |
| Produce cryptographically verifiable evidence of a decision | **Real, but conditional** — only for decisions whose export succeeds (§3, §4) against a live, reachable `bcc_middleware` |
| Resist a co-located root-level attacker | **Not built** — see §5 |
| Classify or inspect content (PHI, DLP, prompt content) | **Not built** — see §6 |
| Windows/macOS coverage | **Not built** — Linux-only (README row 11) |

---

## Reporting a vulnerability

This is a pre-alpha research repository (see `pyproject.toml`'s `Development Status ::
2 - Pre-Alpha` classifier) with no production deployments and no pilot customers yet (README
row 16). If you find a security issue, open an issue in this repository or contact Xibalba
Solutions directly rather than filing a public disclosure against a system nothing depends on
yet.
