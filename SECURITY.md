# Security Posture & Threat Model

This document translates `spec/xibalba-shield-v1.md` §6 (Privacy and HIPAA Posture) and §13
(What This Product Is Not) — both design-intent documents in the parent `integrity-core`
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

## 4. The local decision log can be tamper-evident, but not self-protecting

`shield/agent_core/eventlog.py`'s `EventLog` is local JSONL on disk — exactly what backs
`shield status`/`shield events --recent`. When `shield run --log-integrity-key PATH` is set,
each row carries an HMAC-backed hash-chain entry and `shield verify-log --integrity-key PATH`
detects edited rows, continuity breaks, and wrong-key verification. Without that key option,
the log remains plain diagnostic JSONL for backward compatibility.

**Cryptographic tamper-evidence exists only for decisions that successfully reach
`bcc_middleware`** via the exporter (BCC-signed commitment, Merkle-anchored — see README and
`integrity-core`'s own `docs/INTERFACE_CONTRACT.md`). A locally HMAC-chained decision is
tamper-evident only as long as the key and log are protected by the host. It is useful for
pilot operations, not a replacement for off-device evidence.

## 5. What a root-level attacker on the same device can do

Shield's eBPF sensors and its own process run as root (or with equivalent capabilities) to load
BPF programs and observe kernel events — see `shield/sensors/ebpf/loader.py` and the
`PermissionError` both real sensors raise when not run as root (README row 7, `test_cli.py`).
**Anything that runs as root on the same machine can defeat Shield entirely**: kill the agent
process, unload its BPF programs, steal the log HMAC key, corrupt or delete the local
`EventLog` (§4), edit the local
policy rules file the hot-reloader watches (`shield/config/hot_reload.py` — it protects against
a *malformed* edit by keeping the last-known-good rule set, not against a *malicious* one that
parses cleanly and simply removes the deny rules), or block outbound network traffic to prevent
any evidence from ever reaching Integrity Protocol. **There is no self-tamper-protection, no
process-integrity attestation, and no anti-debugging/anti-unload mechanism anywhere in this
codebase.** This is a real, unmitigated gap relative to what an EDR/XDR product typically
claims — consistent with `spec/xibalba-shield-v1.md` §13's own statement that Shield is "not a
full replacement for existing EDR/XDR in a v1 scope."

## 6. Behavioral telemetry and metadata DLP only

Matching spec §6's governing principle: the two verified eBPF sensors (process-exec, file-write)
observe *that* a process executed or *that* a file was opened for writing — never the content of
the file, the arguments beyond what the kernel exposes at the syscall boundary, or any
higher-level semantic meaning. `shield/content_classifier.py` classifies metadata only:
caller-supplied category labels, file paths, data-source names, and model endpoint names. It
does not read prompt text, output text, files, documents, PHI, secrets, or credentials. Don't
represent Shield as deep DLP/content inspection; represent it as metadata DLP plus enforcement
on labels and context.

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
| Classify metadata for DLP labels | **Real** — no raw-content inspection; see §6 |
| Windows/macOS coverage | **Native sensors not built** — Linux-only telemetry; platform boundaries documented |

---

## Reporting a vulnerability

This is a pre-alpha research repository (see `pyproject.toml`'s `Development Status ::
2 - Pre-Alpha` classifier) with no production deployments and no pilot customers yet (README
row 16). If you find a security issue, open an issue in this repository or contact Xibalba
Solutions directly rather than filing a public disclosure against a system nothing depends on
yet.
