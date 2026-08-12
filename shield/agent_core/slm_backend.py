"""
Tier-2 SLM backend interface — the "Hybrid Cascading Architecture (A2A)" section of README.md
and SPECIFICATION.md §3.4/§3.4.1.

Why this exists: `slm_training/app.py` already has real, working, grammar-constrained Qwen2.5-0.5B
inference, but as a standalone Flask demo disconnected from `shield/` — nothing under `shield/`
imports `llama_cpp`/`qwen`/`slm_training`, and the demo does its own SIGKILL-only containment
(`os.killpg`), bypassing `agent_core/action_broker.py`'s real `ActionBroker` (SIGSTOP/SIGCONT/
cgroup-freeze) entirely. This module is the actual integration point: an `SlmBackend` protocol
matching `PolicyEngine.evaluate()`'s exact signature (so a Tier-2 backend is a drop-in escalation
path, not a parallel decision system), a `SimulatedSlmBackend` for testing/CI without a real
model on disk, and a `LocalSlmBackend` that wraps the real Qwen inference — with any resulting
`contain` decision still routed through the real `ActionBroker` by `EventRouter`, never through
the demo's own containment logic.

No production Tier-2 rollout is claimed here. This gives operators and developers a way to
exercise the Tier-2 escalation path end-to-end (`shield run --slm-backend simulated|local`)
without requiring a fine-tuned, production-grade model — which this project cannot build alone
(see README.md's "Community: help build Tier 2" section). `--slm-backend none` (the default)
preserves today's behavior exactly: no Tier-2 call is ever made.
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from typing import Protocol

from ..policy_engine.engine import EvaluationContext
from ..schemas.events import Decision, EventRef, NormalizedEvent, PolicyDecision, RuleRef

logger = logging.getLogger("shield.agent_core.slm_backend")


class SlmBackend(Protocol):
    """Same call shape as `PolicyEngine.evaluate()` — a Tier-2 backend is swapped in only for
    events Tier 1 already flagged `escalate`; it is never the first evaluator an event sees."""

    def evaluate(self, event: NormalizedEvent, ctx: EvaluationContext) -> PolicyDecision: ...


def _process_command_line(event: NormalizedEvent) -> str | None:
    """Best-effort extraction of a process's exe_path + cmdline for text-pattern matching.
    Only ProcessActivity/FileActivity/NetworkFlow carry a `process` field — AgentEvent doesn't,
    and falls through to the caller's own fallback (see each backend's `evaluate()`)."""
    process = getattr(event, "process", None)
    if process is None:
        return None
    parts = [getattr(process, "exe_path", "") or "", getattr(process, "cmdline", "") or ""]
    text = " ".join(p for p in parts if p)
    return text or None


class SimulatedSlmBackend:
    """NOT a real model. A deterministic keyword-pattern mapper mirroring the labeled malicious/
    benign command patterns already used to generate `slm_training/generate_dataset.py`'s SFT
    dataset — the same oracle that dataset's labels came from, made callable instead of only
    emitting static JSONL. This exists so the Tier-2 escalation path is exercisable in tests and
    CI without a real model on disk.

    Every decision this backend produces is labeled synthetic directly in its `reason` field, so
    it can never be read back as a real model verdict — mirrors `sensors/dev_generator.py`'s own
    "NOT real, explicitly labeled" convention for synthetic telemetry."""

    # Mirrors slm_training/generate_dataset.py's labeled malicious command indicators
    # (ransomware, data exfil, reverse shells, priv-esc/theft, container escape, wipers).
    _CONTAIN_INDICATORS: tuple[str, ...] = (
        "nc -l", "netcat -l", "/dev/tcp/", "openssl enc", "gpg --encrypt",
        "curl -x post", "wget --post", "cat /etc/shadow", ".ssh/id_rsa",
        "rm -rf", "dd if=/dev/zero", "mount -t cgroup",
    )
    # Mirrors slm_training/generate_dataset.py's labeled benign command patterns.
    _ALLOW_INDICATORS: tuple[str, ...] = (
        "sleep ", "ping ", "python3 -c", "md5sum /dev/urandom", "git commit",
        "ls -la", "cat /var/log", "npm install",
    )

    def evaluate(self, event: NormalizedEvent, ctx: EvaluationContext) -> PolicyDecision:
        event_id = f"evt-slm-sim-{uuid.uuid4().hex[:12]}"
        text = (_process_command_line(event) or "").lower()

        action = "log_only"
        reason = "no known synthetic pattern matched"
        for indicator in self._CONTAIN_INDICATORS:
            if indicator in text:
                action, reason = "contain", f"matched known-malicious synthetic pattern: {indicator!r}"
                break
        else:
            for indicator in self._ALLOW_INDICATORS:
                if indicator in text:
                    action, reason = "allow", f"matched known-benign synthetic pattern: {indicator!r}"
                    break

        return PolicyDecision(
            device_id=ctx.device_id,
            event_ref=EventRef(klass=event.klass, event_id=event_id),
            rule=RuleRef(
                rule_id="_simulated_slm",
                name="Simulated Tier-2 SLM (synthetic, not a real model)",
                version="0",
            ),
            decision=Decision(
                action=action,
                reason=f"[SIMULATED SLM -- deterministic pattern match, not a real model] {reason}",
                severity="high" if action == "contain" else "low",
            ),
        )


# Same system prompt and JSON-schema grammar slm_training/app.py's /api/simulate route uses,
# duplicated here (not imported) so LocalSlmBackend's output is directly comparable to the demo's.
_LOCAL_SLM_SYSTEM_PROMPT = """You are Xibalba Tier 2 Security Agent (SLM).
Analyze the following endpoint telemetry.
Output valid JSON only. You must provide your step-by-step reasoning FIRST, then your action.

Rules:
1. CONTAIN if the process executes reverse shells (nc, netcat), ransomware (openssl enc, find ... openssl), wipes logs (rm -rf), reads sensitive files (shadow, .ssh), or exfiltrates data (curl, wget).
2. ALLOW benign operations like sleep, ping, or safe scripts.

Examples:
Input: [Process Exec] /usr/bin/nc nc -lvnp 9999 (PID: 123)
Output: {"reasoning": "The 'nc -lvnp' command is opening a listening port, which is a classic reverse shell indicator.", "action": "CONTAIN"}

Input: [Process Exec] /usr/bin/find find /tmp -type f -exec openssl enc -aes-256 (PID: 124)
Output: {"reasoning": "The find command is iterating over files and passing them to openssl for encryption, which perfectly matches ransomware behavior.", "action": "CONTAIN"}
"""

_LOCAL_SLM_RESPONSE_FORMAT = {
    "type": "json_object",
    "schema": {
        "type": "object",
        "properties": {
            "reasoning": {"type": "string"},
            "action": {"type": "string", "enum": ["ALLOW", "CONTAIN", "ESCALATE"]},
        },
        "required": ["reasoning", "action"],
    },
}

_LOCAL_SLM_ACTION_MAP = {"ALLOW": "allow", "CONTAIN": "contain", "ESCALATE": "escalate"}


class LocalSlmBackend:
    """Thin wrapper around real grammar-constrained Qwen2.5-0.5B inference.

    Deliberately does NOT `import slm_training.app` — that module has import-time side effects
    (starts a Flask app, requires root and loads a real eBPF sensor, calls `os._exit(1)` on
    failure) that make it unsafe to import as a library dependency of `shield/`. This class
    re-implements only the inference call (same system prompt, same JSON-schema-constrained
    `response_format`, same model file the demo's `/api/simulate` route uses), so its output is
    directly comparable to the demo's without inheriting its process-management side effects.

    `llama-cpp-python` and the model file are optional — neither is a hard dependency of
    `shield/`'s core package (see `pyproject.toml`; `slm_training/` manages its own). Construction
    raises `RuntimeError` with an actionable message if either is missing, rather than failing at
    import time for every caller who never asked for this backend."""

    def __init__(self, model_path: str | None = None):
        try:
            from llama_cpp import Llama
        except ImportError as exc:
            raise RuntimeError(
                "LocalSlmBackend requires the optional 'llama-cpp-python' package "
                "('pip install llama-cpp-python') -- it is not a hard dependency of shield/."
            ) from exc

        default_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            "slm_training", "models", "qwen2.5-0.5b-instruct-q4_k_m.gguf",
        )
        path = model_path or default_path
        if not os.path.isfile(path):
            raise RuntimeError(
                f"LocalSlmBackend model file not found at {path!r}. Download the model into "
                f"slm_training/models/, or pass an explicit model_path."
            )
        self._llm = Llama(model_path=path, n_ctx=2048, verbose=False)

    def evaluate(self, event: NormalizedEvent, ctx: EvaluationContext) -> PolicyDecision:
        event_id = f"evt-slm-local-{uuid.uuid4().hex[:12]}"
        text = _process_command_line(event) or json.dumps(event.to_dict())

        response = self._llm.create_chat_completion(
            messages=[
                {"role": "system", "content": _LOCAL_SLM_SYSTEM_PROMPT},
                {"role": "user", "content": text},
            ],
            response_format=_LOCAL_SLM_RESPONSE_FORMAT,
            temperature=0.1,
        )
        raw = json.loads(response["choices"][0]["message"]["content"])
        action = _LOCAL_SLM_ACTION_MAP.get(raw.get("action"), "escalate")

        return PolicyDecision(
            device_id=ctx.device_id,
            event_ref=EventRef(klass=event.klass, event_id=event_id),
            rule=RuleRef(rule_id="_local_slm", name="Local Tier-2 SLM (Qwen2.5-0.5B)", version="0"),
            decision=Decision(
                action=action,
                reason=str(raw.get("reasoning", "")),
                severity="high" if action == "contain" else "medium" if action == "escalate" else "low",
            ),
        )


def build_slm_backend(name: str) -> SlmBackend | None:
    """CLI-facing factory for `--slm-backend {none,simulated,local}`. Raises RuntimeError (with
    an actionable message, via LocalSlmBackend's own constructor) rather than silently falling
    back to another backend if `local` was explicitly requested but its dependencies are missing
    — a silent fallback here would misrepresent which tier actually evaluated an event."""
    if name == "none":
        return None
    if name == "simulated":
        return SimulatedSlmBackend()
    if name == "local":
        return LocalSlmBackend()
    raise ValueError(f"unknown slm backend {name!r} -- expected one of: none, simulated, local")
