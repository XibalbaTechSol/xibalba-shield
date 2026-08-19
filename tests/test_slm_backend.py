from __future__ import annotations

import pytest

from shield.agent_core.registry import AgentRegistry, DeviceContext
from shield.agent_core.router import EventRouter
from shield.agent_core.slm_backend import (
    LocalSlmBackend,
    SimulatedSlmBackend,
    build_slm_backend,
)
from shield.policy_engine.engine import EvaluationContext, PolicyEngine
from shield.schemas.events import Activity, ProcessActivity, ProcessInfo

from unittest.mock import AsyncMock, patch

from integrity_sdk.policy.opa_client import OPADecision


@pytest.fixture(autouse=True)
def mock_opa():
    # Same convention as test_agent_core.py -- PolicyEngine delegates to a real OPA REST
    # client; these tests exercise slm_backend.py, not OPA itself, so a fixed OPA response
    # keeps Tier 1 deterministic without needing a live OPA server.
    with patch("shield.policy_engine.engine.opa_evaluate", new_callable=AsyncMock) as mock_eval:
        mock_eval.return_value = OPADecision(allow=True, raw_result={"action": "allow"})
        yield mock_eval


def _ctx() -> EvaluationContext:
    return EvaluationContext(tenant_id="t", device_role="workstation", device_id="dev-1")


def _process_event(cmdline: str) -> ProcessActivity:
    return ProcessActivity(
        device_id="dev-1",
        process=ProcessInfo(pid=4242, name="proc", exe_path="/usr/bin/sh", cmdline=cmdline),
        activity=Activity(type="process_exec"),
    )


def _router(**kwargs):
    device = DeviceContext(device_id="dev-1", tenant_id="t", device_role="workstation")
    return EventRouter(
        device=device,
        registry=kwargs.get("registry", AgentRegistry()),
        policy_engine=kwargs.get("policy_engine", PolicyEngine()),
        exporter=kwargs.get("exporter"),
        action_broker=kwargs.get("action_broker"),
        guardrail_hooks=kwargs.get("guardrail_hooks", ()),
        event_log=kwargs.get("event_log"),
        slm_backend=kwargs.get("slm_backend"),
    )


def _force_action(engine, action):
    """Same helper as test_agent_core.py: wraps a real PolicyEngine.evaluate so tests can
    exercise a specific decision.action without a policy rule file that produces it."""
    original = engine.evaluate

    def _evaluate(event, context):
        decision = original(event, context)
        decision.decision.action = action
        return decision

    engine.evaluate = _evaluate
    return engine


# --- SimulatedSlmBackend: decision mapping ----------------------------------------------

def test_simulated_backend_contains_known_malicious_pattern():
    backend = SimulatedSlmBackend()
    event = _process_event("nc -lvnp 9999")
    decision = backend.evaluate(event, _ctx())
    assert decision.decision.action == "contain"
    assert "SIMULATED SLM" in decision.decision.reason
    assert decision.rule.rule_id == "_simulated_slm"


def test_simulated_backend_allows_known_benign_pattern():
    backend = SimulatedSlmBackend()
    event = _process_event("sleep 300")
    decision = backend.evaluate(event, _ctx())
    assert decision.decision.action == "allow"
    assert "SIMULATED SLM" in decision.decision.reason


def test_simulated_backend_logs_only_unknown_pattern():
    backend = SimulatedSlmBackend()
    event = _process_event("some-completely-unrecognized-binary --flag")
    decision = backend.evaluate(event, _ctx())
    assert decision.decision.action == "log_only"


def test_simulated_backend_never_mistaken_for_a_real_model():
    # Every single decision this backend can produce must self-label as synthetic --
    # this is the property the whole class exists to guarantee.
    backend = SimulatedSlmBackend()
    for cmdline in ("nc -lvnp 9999", "sleep 300", "unrecognized-thing"):
        decision = backend.evaluate(_process_event(cmdline), _ctx())
        assert "SIMULATED SLM" in decision.decision.reason


# --- build_slm_backend factory -----------------------------------------------------------

def test_build_slm_backend_none_returns_none():
    assert build_slm_backend("none") is None


def test_build_slm_backend_simulated_returns_simulated_instance():
    assert isinstance(build_slm_backend("simulated"), SimulatedSlmBackend)


def test_build_slm_backend_rejects_unknown_name():
    with pytest.raises(ValueError):
        build_slm_backend("not-a-real-backend")


def test_local_slm_backend_raises_actionable_error_without_llama_cpp():
    # Real behavior, not mocked: llama-cpp-python is not installed in this environment
    # (it's an optional dependency slm_training/ manages separately, not shield/'s core
    # package) -- constructing LocalSlmBackend must fail loudly and specifically, not with
    # a bare ImportError a caller has to go decode.
    pytest.importorskip("llama_cpp", reason="only meaningful when llama-cpp-python is ABSENT")


def test_local_slm_backend_missing_dependency_message():
    try:
        import llama_cpp  # noqa: F401
    except ImportError:
        with pytest.raises(RuntimeError, match="llama-cpp-python"):
            LocalSlmBackend()
    else:
        pytest.skip("llama-cpp-python is installed in this environment; nothing to assert here")


# --- Router integration: Tier-2 escalation wiring -----------------------------------------

def test_router_calls_slm_backend_only_on_escalate_decisions():
    engine = _force_action(PolicyEngine(), "allow")
    backend = SimulatedSlmBackend()
    called = []
    original_evaluate = backend.evaluate

    def _tracking_evaluate(event, ctx):
        called.append(True)
        return original_evaluate(event, ctx)

    backend.evaluate = _tracking_evaluate

    router = _router(policy_engine=engine, slm_backend=backend)
    router.handle(_process_event("sleep 300"))

    assert not called, "SLM backend must not be called when Tier 1 already decided 'allow'"


def test_router_revises_escalate_decision_using_slm_backend():
    engine = _force_action(PolicyEngine(), "escalate")
    backend = SimulatedSlmBackend()

    router = _router(policy_engine=engine, slm_backend=backend)
    decision = router.handle(_process_event("nc -lvnp 9999"))

    assert decision.decision.action == "contain"
    assert decision.rule.rule_id == "_simulated_slm"


def test_router_fails_closed_to_contain_when_no_slm_backend_configured():
    """docs/design/2026-08-18-a2a-escalation-schema-proposal.md: Tier 1's `escalate` with no
    Tier 2 configured (and no Tier 3 -- none exists) must not reach export as a bare,
    unresolved `escalate` -- that was a real, silent no-decision outcome. Fails closed to
    `contain` instead, tagged with the A2A_UNRESOLVED_ESCALATION reason."""
    engine = _force_action(PolicyEngine(), "escalate")
    router = _router(policy_engine=engine, slm_backend=None)
    decision = router.handle(_process_event("nc -lvnp 9999"))
    assert decision.decision.action == "contain"
    assert decision.decision.tier == "tier1"
    assert "A2A_UNRESOLVED_ESCALATION" in decision.decision.reason


def test_router_fails_closed_to_contain_when_slm_backend_raises():
    engine = _force_action(PolicyEngine(), "escalate")

    class _RaisingBackend:
        def evaluate(self, event, ctx):
            raise RuntimeError("simulated Tier-2 failure")

    router = _router(policy_engine=engine, slm_backend=_RaisingBackend())
    decision = router.handle(_process_event("nc -lvnp 9999"))

    # A broken Tier-2 backend must never take down the router or silently vanish the
    # Tier-1 decision it was supposed to refine -- and the still-unresolved `escalate` that
    # results must still fail closed to `contain`, not reach export unresolved.
    assert decision.decision.action == "contain"
    assert decision.decision.tier == "tier1"
    assert "A2A_UNRESOLVED_ESCALATION" in decision.decision.reason


def test_router_tags_tier2_on_slm_revised_decision():
    engine = _force_action(PolicyEngine(), "escalate")
    backend = SimulatedSlmBackend()

    router = _router(policy_engine=engine, slm_backend=backend)
    decision = router.handle(_process_event("nc -lvnp 9999"))

    assert decision.decision.tier == "tier2"


def test_router_fails_closed_when_tier2_itself_remains_uncertain():
    """docs/design/2026-08-18-a2a-escalation-schema-proposal.md: Tier 2 consulted and STILL
    uncertain (returns its own `escalate`, not an exception) -- the genuinely-uncertain case
    the fallback exists for, distinct from Tier 2 being unavailable/broken."""
    from shield.schemas.events import Decision as _Decision, EventRef as _EventRef, PolicyDecision as _PolicyDecision, RuleRef as _RuleRef

    engine = _force_action(PolicyEngine(), "escalate")

    class _StillUncertainBackend:
        def evaluate(self, event, ctx):
            return _PolicyDecision(
                device_id=ctx.device_id,
                event_ref=_EventRef(klass=event.klass, event_id="evt-tier2-uncertain"),
                rule=_RuleRef(rule_id="_still_uncertain_slm", name="_still_uncertain_slm", version=""),
                decision=_Decision(action="escalate", reason="Tier 2 remains uncertain", severity="medium"),
            )

    router = _router(policy_engine=engine, slm_backend=_StillUncertainBackend())
    decision = router.handle(_process_event("nc -lvnp 9999"))

    assert decision.decision.action == "contain"
    assert decision.decision.tier == "tier2_unresolved"
    assert "A2A_UNRESOLVED_ESCALATION" in decision.decision.reason
