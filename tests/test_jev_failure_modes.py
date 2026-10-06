"""A7: Jev/advisory failure modes must never change enforcement, and must say why.

docs/EXECUTION_PLAN.md A7, second open item: "A provider outage, malformed response, tenant
mismatch and tamper test preserve local enforcement and produce an operator-readable reason
code." Two claims in one sentence, tested separately:

1. **Enforcement is preserved.** Proven differentially rather than by asserting one outcome: the
   same event is routed once with a healthy provider and once per failure mode, and the
   PolicyDecision must be identical. Run against a real OPA and a real signed pack, with both a
   *deny* (an unregistered agent, by a genuine Rego rule) and a *log_only* baseline -- a test that
   only ever saw "allow" could not tell a preserved decision from one that was never made. The
   existing outage test in test_jev_shadow.py runs against a fake OPA and so cannot.
2. **The failure says why.** An advisory that is merely "unavailable" does not tell an operator
   whether the provider is down, slow, mis-keyed, or returning garbage. Each failure carries a
   stable reason code, in the log line and in the stored advisory.

The HTTP providers are driven against a real local HTTP server (real sockets, real timeouts),
not a patched urlopen. Provider *response content* is never logged: every scenario plants a marker
in the body and asserts it cannot appear in the logs.
"""

from __future__ import annotations

import json
import logging
import os
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from integrity_sdk.core.decision_trace import JevAnalysis

from shield.agent_core.registry import AgentRegistry, DeviceContext
from shield.agent_core.router import EventRouter
from shield.backend import api
from shield.opa_local import supervised_opa
from shield.policy_engine import PolicyEngine
from shield.policy_engine.inference import HttpInferenceProvider, InferenceConfig
from shield.policy_engine.jev_shadow import JevShadowAnalyzer, JsonlDecisionTraceSink
from shield.schemas.events import (
    AgentActivity,
    AgentContext,
    AgentEvent,
    AgentInfo,
    Decision,
    EventRef,
    PolicyDecision,
    PolicyRef,
    RuleRef,
)

# Planted in provider output. Provider-returned content must never reach a log line.
SECRET = "SECRET-PROVIDER-CONTENT-do-not-log"


# ------------------------------------------------------------------------------ fixtures


@pytest.fixture(scope="module")
def engine():
    """One real supervised OPA and signed `smb` pack for the whole module."""
    with supervised_opa("smb") as (opa_url, pack):
        yield PolicyEngine(opa_url=opa_url, pack=pack)


def _event() -> AgentEvent:
    return AgentEvent(
        device_id="dev-1",
        agent=AgentInfo(agent_id="agent-1", name="Agent One"),
        context=AgentContext(tools_called=["shell"]),
        activity=AgentActivity(type="tool_execution"),
    )


def _route(engine, provider, *, registered: bool, sink=None):
    """Route one event through a real router, returning (decision, advisories)."""
    registry = AgentRegistry()
    if registered:
        registry.register("agent-1", "Agent One")
    captured: list = []

    def collect(envelope, analysis):
        captured.append((envelope, analysis))
        if sink is not None:
            sink(envelope, analysis)

    analyzer = JevShadowAnalyzer(tenant_id="tenant-1", agent_id="agent-1", provider=provider, sink=collect)
    router = EventRouter(
        device=DeviceContext(device_id="dev-1", tenant_id="tenant-1", device_role="workstation"),
        registry=registry, policy_engine=engine, jev_analyzer=analyzer,
    )
    return router.handle(_event()), captured


def _fingerprint(decision: PolicyDecision) -> tuple:
    """Everything about the enforcement outcome, minus the per-call uuid/timestamp noise."""
    return (
        decision.decision.action, decision.rule.rule_id, decision.decision.reason,
        decision.policy.hash, decision.policy.version, decision.decision.tier,
        decision.event_ref.klass,
    )


class _AdvisoryServer:
    """A real HTTP server on a real socket, standing in for a remote inference endpoint."""

    def __init__(self, *, status: int = 200, body: bytes = b"{}", delay: float = 0.0):
        self.status, self.body, self.delay = status, body, delay
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802 -- stdlib hook name
                self.rfile.read(int(self.headers.get("Content-Length") or 0))
                if outer.delay:
                    time.sleep(outer.delay)
                try:
                    self.send_response(outer.status)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(outer.body)))
                    self.end_headers()
                    self.wfile.write(outer.body)
                except (BrokenPipeError, ConnectionResetError):
                    pass  # the client gave up (that is the timeout scenario)

            def log_message(self, *_args):  # keep test output quiet
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}/v1"
        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *_exc):
        self.httpd.shutdown()
        self.httpd.server_close()


def _http_provider(url: str, *, openai: bool = False, timeout_ms: int = 1500) -> HttpInferenceProvider:
    config = InferenceConfig(
        enabled=True, provider="llm" if openai else "lila", model="m", endpoint=url, timeout_ms=timeout_ms,
    )
    return HttpInferenceProvider(config, provider_id="llm:m" if openai else "lila", openai_compatible=openai)


def _closed_port_url() -> str:
    """A localhost URL that nothing is listening on (bind, note the port, release it)."""
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return f"http://127.0.0.1:{port}/v1"


class _Raises:
    provider_id = "jev.raises"

    def __init__(self, exc: Exception):
        self.exc = exc

    def analyze(self, _envelope):
        raise self.exc


class _Returns:
    provider_id = "jev.returns"

    def __init__(self, value):
        self.value = value

    def analyze(self, _envelope):
        return self.value


def _ok_body(**overrides) -> bytes:
    body = {"risk_category": "low", "recommended_escalation": False,
            "transition_probabilities": {"continue": 0.9, "escalate": 0.1}}
    body.update(overrides)
    return json.dumps(body).encode()


def _openai_body(content) -> bytes:
    return json.dumps({"choices": [{"message": {"content": content}}]}).encode()


# Each scenario: id, a callable building (context manager, provider), the expected reason code.
def _scenarios():
    def raising(exc):
        return lambda: (_NullContext(), _Raises(exc))

    def served(body: bytes, *, status: int = 200, openai: bool = False, delay: float = 0.0, timeout_ms: int = 1500):
        def build():
            server = _AdvisoryServer(status=status, body=body, delay=delay)
            return server, _http_provider(server.url, openai=openai, timeout_ms=timeout_ms)
        return build

    def refused():
        return _NullContext(), _http_provider(_closed_port_url())

    return [
        ("raises-timeout", raising(TimeoutError("local provider timeout")), "ADVISORY_PROVIDER_TIMEOUT"),
        ("raises-unexpected", raising(RuntimeError(f"boom {SECRET}")), "ADVISORY_PROVIDER_ERROR"),
        ("connection-refused", refused, "ADVISORY_PROVIDER_UNREACHABLE"),
        ("slow-endpoint-times-out", served(_ok_body(), delay=0.8, timeout_ms=100), "ADVISORY_PROVIDER_TIMEOUT"),
        ("http-500", served(f"<html>{SECRET}</html>".encode(), status=500), "ADVISORY_PROVIDER_HTTP_ERROR"),
        ("http-401", served(b'{"error":"bad key"}', status=401), "ADVISORY_PROVIDER_HTTP_ERROR"),
        ("body-not-json", served(f"not json {SECRET}".encode()), "ADVISORY_PROVIDER_MALFORMED_RESPONSE"),
        ("body-is-a-list", served(json.dumps([SECRET]).encode()), "ADVISORY_PROVIDER_MALFORMED_RESPONSE"),
        ("body-is-a-string", served(json.dumps(SECRET).encode()), "ADVISORY_PROVIDER_MALFORMED_RESPONSE"),
        ("probability-non-numeric", served(_ok_body(transition_probabilities={"continue": SECRET})),
         "ADVISORY_PROVIDER_MALFORMED_RESPONSE"),
        ("probabilities-not-an-object", served(_ok_body(transition_probabilities=[SECRET])),
         "ADVISORY_PROVIDER_MALFORMED_RESPONSE"),
        ("escalation-is-a-string", served(_ok_body(recommended_escalation="false")),
         "ADVISORY_PROVIDER_MALFORMED_RESPONSE"),
        ("probability-out-of-range", served(_ok_body(transition_probabilities={"continue": 2.0})),
         "ADVISORY_PROVIDER_OUTPUT_REJECTED"),
        ("too-many-probabilities", served(_ok_body(transition_probabilities={f"s{i}": 0.01 for i in range(40)})),
         "ADVISORY_PROVIDER_OUTPUT_REJECTED"),
        ("openai-content-not-json", served(_openai_body(f"definitely not json {SECRET}"), openai=True),
         "ADVISORY_PROVIDER_MALFORMED_RESPONSE"),
        ("openai-no-choices", served(json.dumps({"choices": []}).encode(), openai=True),
         "ADVISORY_PROVIDER_MALFORMED_RESPONSE"),
        ("provider-returns-wrong-type", lambda: (_NullContext(), _Returns({"status": "available"})),
         "ADVISORY_PROVIDER_MALFORMED_RESPONSE"),
        ("provider-returns-none", lambda: (_NullContext(), _Returns(None)),
         "ADVISORY_PROVIDER_MALFORMED_RESPONSE"),
    ]


class _NullContext:
    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False


SCENARIOS = _scenarios()


# ------------------------------------------------------------ 1. enforcement is preserved


@pytest.mark.parametrize("registered,expected_action", [(False, "deny"), (True, "log_only")])
@pytest.mark.parametrize("scenario_id,build,_code", SCENARIOS, ids=[s[0] for s in SCENARIOS])
def test_no_provider_failure_changes_the_enforcement_decision(
    engine, scenario_id, build, _code, registered, expected_action
):
    """Differential: the same event, healthy provider vs this failure, must decide identically.

    `registered=False` is a genuine Rego deny; `registered=True` is the pack's log_only default.
    Both are checked because a failure that only ever coincided with "allow" proves nothing.
    """
    baseline, _ = _route(engine, None, registered=registered)  # FixtureJevProvider: healthy
    assert baseline.decision.action == expected_action, "baseline is not the case this test intends"

    context, provider = build()
    with context:
        under_failure, advisories = _route(engine, provider, registered=registered)

    assert _fingerprint(under_failure) == _fingerprint(baseline), (
        f"{scenario_id}: a provider failure altered the enforcement decision"
    )
    assert len(advisories) == 1, "the advisory trace record must still be written on failure"


def test_a_healthy_provider_still_records_an_available_advisory(engine):
    """The control for the whole module: without it, 'unavailable' everywhere would pass."""
    _, advisories = _route(engine, None, registered=True)
    assert advisories[0][1].status == "available"


# ------------------------------------------------------ 2. the failure says why, safely


@pytest.mark.parametrize("scenario_id,build,expected_code", SCENARIOS, ids=[s[0] for s in SCENARIOS])
def test_each_failure_carries_a_stable_operator_readable_reason_code(
    engine, scenario_id, build, expected_code, caplog
):
    context, provider = build()
    with caplog.at_level(logging.WARNING, logger="shield.policy_engine.jev_shadow"):
        with context:
            _, advisories = _route(engine, provider, registered=True)

    analysis = advisories[0][1]
    assert analysis.status == "unavailable", f"{scenario_id}: a failure must not read as available"
    assert getattr(analysis, "reason_code", None) == expected_code, scenario_id

    logged = "\n".join(record.getMessage() for record in caplog.records)
    assert expected_code in logged, f"{scenario_id}: the reason code never reached the operator's log"
    assert SECRET not in logged, f"{scenario_id}: provider-returned content leaked into a log line"


def test_reason_code_reaches_the_stored_advisory_row(engine, tmp_path):
    path = tmp_path / "trace.jsonl"
    _route(engine, _Raises(TimeoutError("slow")), registered=True, sink=JsonlDecisionTraceSink(path))
    (row,) = [json.loads(line) for line in path.read_text().splitlines()]
    assert row["advisory"]["status"] == "unavailable"
    assert row["advisory"]["reason_code"] == "ADVISORY_PROVIDER_TIMEOUT"
    assert row["advisory"]["causal_claim"] is False


def test_a_healthy_advisory_row_has_no_reason_code(engine, tmp_path):
    path = tmp_path / "trace.jsonl"
    _route(engine, None, registered=True, sink=JsonlDecisionTraceSink(path))
    (row,) = [json.loads(line) for line in path.read_text().splitlines()]
    assert row["advisory"]["status"] == "available"
    assert row["advisory"]["reason_code"] is None


# --------------------------------------------------- 3. a mismatched advisory is rejected


def test_an_advisory_about_a_different_event_is_rejected_not_recorded_as_available(engine):
    """"Every advisory projection links to the observed event hash." A provider (buggy,
    replayed, or hostile) that answers about some OTHER event used to be stored as `available`
    with that wrong link, which is a false statement in the evidence trail."""
    liar = _Returns(JevAnalysis("jev.liar", "available", "low", {"continue": 0.9, "escalate": 0.1},
                                False, "0x" + "ee" * 32))
    baseline, _ = _route(engine, None, registered=False)
    decision, advisories = _route(engine, liar, registered=False)

    envelope, analysis = advisories[0]
    assert analysis.status == "rejected"
    assert analysis.reason_code == "ADVISORY_OBSERVED_HASH_MISMATCH"
    assert analysis.observed_event_hash != "0x" + "ee" * 32, "the bogus link must not be recorded"
    assert _fingerprint(decision) == _fingerprint(baseline)


def test_an_advisory_with_no_observed_hash_is_not_treated_as_a_mismatch(engine):
    """Absence of a link is not a *contradicting* link; only a positive mismatch is rejected."""
    silent = _Returns(JevAnalysis("jev.silent", "available", "low", {"continue": 1.0}, False, None))
    _, advisories = _route(engine, silent, registered=True)
    assert advisories[0][1].status == "available"


# --------------------------------------------- 4. escalation must be a real boolean, always


def test_the_string_false_is_not_silently_coerced_into_a_recommendation_to_escalate(engine):
    """`bool("false")` is True. A model that quotes its JSON booleans used to turn 'do not
    escalate' into 'escalate' on the operator's screen, with status `available` and nothing to
    suggest anything was wrong."""
    with _AdvisoryServer(body=_ok_body(recommended_escalation="false")) as server:
        _, advisories = _route(engine, _http_provider(server.url), registered=True)
    analysis = advisories[0][1]
    assert analysis.recommended_escalation is False
    assert analysis.status == "unavailable", "an ill-typed field is a malformed response, not advice"


def test_real_booleans_are_still_honoured(engine):
    for value in (True, False):
        with _AdvisoryServer(body=_ok_body(recommended_escalation=value)) as server:
            _, advisories = _route(engine, _http_provider(server.url), registered=True)
        assert advisories[0][1].status == "available"
        assert advisories[0][1].recommended_escalation is value


# ------------------------------------- 5. the operator-facing trace reader: tenant and tamper


def _write_trace(path: Path, tenant: str, events: int, *, agent: str = "agent-1") -> None:
    analyzer = JevShadowAnalyzer(tenant_id=tenant, agent_id=agent, sink=JsonlDecisionTraceSink(path))
    for index in range(events):
        decision = PolicyDecision(
            device_id="dev-1", event_ref=EventRef(klass="agent_event", event_id=f"{tenant}-evt-{index}"),
            rule=RuleRef(rule_id="r1", name="n", version="1"), policy=PolicyRef(version="1", hash="sha256:" + "ab" * 32),
            decision=Decision(action="allow", reason="ok"),
        )
        analyzer.analyze(_event(), decision)


def _rows(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines()]


def _rewrite(path: Path, rows: list[dict]) -> None:
    path.write_text("\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n")


@pytest.fixture
def trace_path(tmp_path, monkeypatch):
    path = tmp_path / "decision-trace.jsonl"
    monkeypatch.setenv("SHIELD_DECISION_TRACE_PATH", str(path))
    return path


def test_an_untampered_trace_is_valid_with_no_reason_code(trace_path):
    _write_trace(trace_path, "tenant-a", 3)
    result = api._read_decision_trace("tenant-a")
    assert result["valid"] is True
    assert result.get("reason_code") is None
    assert len(result["events"]) == 3


def test_rewriting_only_the_last_event_is_detected(trace_path):
    """The gap the probe found: stored hashes were trusted, so a rewrite of the final event had
    nothing after it to disagree with and the reader called the trace valid. Flipping the most
    recent decision is the tamper most worth catching."""
    _write_trace(trace_path, "tenant-a", 3)
    rows = _rows(trace_path)
    rows[-1]["envelope"]["policy_decision"] = "deny"
    _rewrite(trace_path, rows)
    result = api._read_decision_trace("tenant-a")
    assert result["valid"] is False
    assert result["reason_code"] == "TRACE_HASH_MISMATCH"


def test_rewriting_an_earlier_event_is_detected(trace_path):
    _write_trace(trace_path, "tenant-a", 3)
    rows = _rows(trace_path)
    rows[0]["envelope"]["policy_decision"] = "deny"
    _rewrite(trace_path, rows)
    result = api._read_decision_trace("tenant-a")
    assert result["valid"] is False
    assert result["reason_code"] == "TRACE_HASH_MISMATCH"


def test_altering_a_stored_hash_without_the_envelope_is_detected(trace_path):
    _write_trace(trace_path, "tenant-a", 2)
    rows = _rows(trace_path)
    rows[-1]["event_hash"] = "0x" + "11" * 32
    _rewrite(trace_path, rows)
    assert api._read_decision_trace("tenant-a")["valid"] is False


def test_deleting_a_middle_event_breaks_the_chain(trace_path):
    _write_trace(trace_path, "tenant-a", 3)
    rows = _rows(trace_path)
    del rows[1]
    _rewrite(trace_path, rows)
    result = api._read_decision_trace("tenant-a")
    assert result["valid"] is False
    assert result["reason_code"] == "TRACE_LINK_BROKEN"


def test_an_unreadable_trace_file_is_reported_not_raised(trace_path):
    trace_path.write_text("this is not json\n")
    result = api._read_decision_trace("tenant-a")
    assert result["valid"] is False
    assert result["reason_code"] == "TRACE_UNREADABLE"
    assert result["events"] == []


def test_two_tenants_sharing_one_trace_id_never_see_each_others_events(trace_path):
    """Tenant mismatch: both tenants emit onto the same device, hence the same trace id, and
    their rows are interleaved in one file. Each must see only its own, each chain valid."""
    _write_trace(trace_path, "tenant-a", 2)
    _write_trace(trace_path, "tenant-b", 3)
    a = api._read_decision_trace("tenant-a")
    b = api._read_decision_trace("tenant-b")
    assert [event["tenant_id"] for event in a["events"]] == ["tenant-a"] * 2
    assert [event["tenant_id"] for event in b["events"]] == ["tenant-b"] * 3
    assert a["valid"] is True and b["valid"] is True
    assert not ({e["event_id"] for e in a["events"]} & {e["event_id"] for e in b["events"]})
    assert api._read_decision_trace("tenant-c")["events"] == []


def _forged_row(source_row: dict, **envelope_overrides) -> dict:
    """A row whose hashes are all CORRECTLY recomputed, so only the namespace can give it away.

    A crude edit (change a field, leave the stored hash) is caught by the hash check first and
    would mask the namespace check entirely. An attacker who can recompute a hash is exactly the
    one the namespace check exists for.
    """
    from integrity_sdk.core.decision_trace import DecisionEnvelope

    body = dict(source_row["envelope"])
    body.pop("envelope_version", None)
    body.update(envelope_overrides)
    forged = DecisionEnvelope(**body)
    row = json.loads(json.dumps(source_row))
    row.update(event_id=forged.event_id, event_hash=forged.event_hash,
               parent_event_hash=forged.parent_event_hash, envelope=forged.body())
    return row


def test_a_consistently_forged_row_from_another_tenant_is_rejected_as_a_namespace_splice(trace_path):
    """The row says tenant-a; the envelope inside it (hashes recomputed to match) says tenant-b."""
    _write_trace(trace_path, "tenant-a", 2)
    rows = _rows(trace_path)
    forged = _forged_row(rows[-1], tenant_id="tenant-b")
    forged["tenant_id"] = "tenant-a"  # the lie: filed under tenant-a
    _rewrite(trace_path, rows[:-1] + [forged])
    result = api._read_decision_trace("tenant-a")
    assert result["valid"] is False
    assert result["reason_code"] == "TRACE_NAMESPACE_MISMATCH"


def test_a_consistently_forged_row_from_another_agent_is_rejected_as_a_namespace_splice(trace_path):
    _write_trace(trace_path, "tenant-a", 2)
    rows = _rows(trace_path)
    forged = _forged_row(rows[-1], agent_id="agent-2", event_id="tenant-a-evt-spliced")
    forged["agent_id"] = "agent-1"
    _rewrite(trace_path, rows[:-1] + [forged])
    result = api._read_decision_trace("tenant-a")
    assert result["valid"] is False
    assert result["reason_code"] == "TRACE_NAMESPACE_MISMATCH"


def test_a_crude_cross_tenant_edit_is_still_caught_by_one_check_or_the_other(trace_path):
    _write_trace(trace_path, "tenant-a", 2)
    rows = _rows(trace_path)
    rows[-1]["envelope"]["tenant_id"] = "tenant-b"  # stored hash left stale
    _rewrite(trace_path, rows)
    result = api._read_decision_trace("tenant-a")
    assert result["valid"] is False
    assert result["reason_code"] in {"TRACE_NAMESPACE_MISMATCH", "TRACE_HASH_MISMATCH"}


def test_a_malformed_row_is_reported_as_invalid_not_raised(trace_path):
    _write_trace(trace_path, "tenant-a", 2)
    rows = _rows(trace_path)
    del rows[-1]["envelope"]
    _rewrite(trace_path, rows)
    result = api._read_decision_trace("tenant-a")
    assert result["valid"] is False
    assert result["reason_code"] == "TRACE_INVALID"


def test_a_non_object_json_line_is_reported_not_raised(trace_path):
    """`json.loads("[1]")` is a list; calling .get on it used to raise out of the API handler."""
    trace_path.write_text("[1, 2, 3]\n")
    result = api._read_decision_trace("tenant-a")
    assert result["valid"] is False
    assert result["reason_code"] == "TRACE_UNREADABLE"


# --- a window is not damage ------------------------------------------------------------------


@pytest.mark.parametrize("count", [3, 49, 50])
def test_a_trace_within_the_window_is_complete_and_has_a_root(trace_path, count):
    _write_trace(trace_path, "tenant-a", count)
    result = api._read_decision_trace("tenant-a")
    assert result["valid"] is True
    assert result["truncated"] is False
    assert result["root"] is not None
    assert len(result["events"]) == count


@pytest.mark.parametrize("count", [51, 60, 120])
def test_a_healthy_trace_longer_than_the_window_is_not_reported_invalid(trace_path, count):
    """The false alarm found while building this: past `limit` events the window starts mid-chain,
    and the old check demanded a genesis parent, so a healthy long-running device showed an
    invalid trace forever. A reason code on that would have been a cry-wolf label."""
    _write_trace(trace_path, "tenant-a", count)
    result = api._read_decision_trace("tenant-a")
    assert result["valid"] is True
    assert result["reason_code"] is None
    assert result["truncated"] is True, "the window's partial view must be disclosed, not hidden"
    assert len(result["events"]) == 50
    assert result["root"] is None, "a root over part of a chain would not be the trace's root"


def test_tampering_is_still_detected_inside_a_truncated_window(trace_path):
    _write_trace(trace_path, "tenant-a", 60)
    rows = _rows(trace_path)
    rows[-1]["envelope"]["policy_decision"] = "deny"
    _rewrite(trace_path, rows)
    result = api._read_decision_trace("tenant-a")
    assert result["truncated"] is True
    assert result["valid"] is False
    assert result["reason_code"] == "TRACE_HASH_MISMATCH"


def test_a_broken_link_is_still_detected_inside_a_truncated_window(trace_path):
    _write_trace(trace_path, "tenant-a", 60)
    rows = _rows(trace_path)
    del rows[40]
    _rewrite(trace_path, rows)
    result = api._read_decision_trace("tenant-a")
    assert result["valid"] is False
    assert result["reason_code"] == "TRACE_LINK_BROKEN"
