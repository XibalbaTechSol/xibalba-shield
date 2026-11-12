"""Tests for the gate's zone mask and the sensor-silence fault (`shield/gate_zone.py`).

What these pin, in the order the feature can go wrong:

1. **Off is inert.** No provider call, no new response key, no new receipt content.
2. **The mask only removes permission.** Every zone x class cell in enforce; a pack deny stays a
   deny in every zone; an unknown tool is `execute`, never `read`.
3. **Shadow never blocks** but says what it would have done.
4. **Sensor silence demotes**, a fresh sensor does not, a gate that never had a sensor is left
   alone, and a missing/unreadable status file counts as silent once a sensor is expected.
5. **Receipts** carry the zone and class and still verify with the SDK's own `verify_log`.

Mutation-checked: see the PR description for the mutations run against these tests.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import textwrap
import threading
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from integrity_sdk.core.receipts import verify_log
from integrity_sdk.did import Keypair

from shield.config import ConfigError, DeviceConfig, load_device_config
from shield.gate_daemon import GateRequest, GateServer, evaluate_pre_tool_use
from shield.gate_receipts import CHECKPOINTS_FILENAME, RECEIPTS_FILENAME, GateReceiptWriter
from shield.gate_zone import (
    DEFAULT_TOOL_CLASSES,
    REASON_ZONE_RESTRICTED,
    GateZoneSettings,
    SensorSilenceZoneProvider,
    StaticZoneProvider,
    ZoneMask,
    ZoneReading,
    build_zone_mask,
    classify_tool,
    register_zone_provider,
)
from shield.policy_engine.engine import DecisionBasis, EvaluationContext
from shield.schemas.events import Decision, EventRef, PolicyDecision, PolicyRef, RuleRef
from shield.sensor_status import read_sensor_status, write_sensor_status
from shield.watchdog import Watchdog

_DIGEST = "ab" * 32
_PACK_HASH = "sha256:" + "cd" * 32
_REPO_ROOT = Path(__file__).resolve().parents[1]
_NOW = 1_800_000_000.0

#: One representative tool per class. `Deploy` is in no map, so it must classify as `execute`.
_TOOL_FOR_CLASS = {"read": "Read", "draft": "Edit", "execute": "Bash", "escalate": "AskHuman"}
_ESCALATE_MAP = {"AskHuman": "escalate"}


# ------------------------------------------------------------------------------ helpers


def _decision(action: str = "allow", *, reason: str = "because", rule_id: str = "rule-1") -> PolicyDecision:
    return PolicyDecision(
        device_id="dev-1", event_ref=EventRef(klass="agent_event", event_id="evt-1"),
        rule=RuleRef(rule_id=rule_id, name="A rule", version="1"),
        policy=PolicyRef(version="1.2.3", hash=_PACK_HASH),
        decision=Decision(action=action, reason=reason),
        invocation_id="11111111-1111-4111-8111-111111111111",
    )


def _evaluator(action: str = "allow"):
    return lambda _event, _ctx: _decision(action)


def _basis_evaluator(action: str = "allow", decision: str = "permit", reason_code: str = "ALLOWED"):
    def evaluate(_event, _ctx):
        return _decision(action), DecisionBasis(decision, reason_code, ("C-1",), _PACK_HASH, "agent_event")
    return evaluate


def _ctx() -> EvaluationContext:
    return EvaluationContext(tenant_id="t", device_role="r", device_id="dev-1")


def _request(tool_name: str = "Bash", agent_id: str = "agent-1") -> GateRequest:
    return GateRequest(agent_id=agent_id, tool_name=tool_name, tool_input_sha256=_DIGEST)


def _mask(zone: str, mode: str = "enforce", **kwargs) -> ZoneMask:
    kwargs.setdefault("tool_classes", _ESCALATE_MAP)
    return ZoneMask(mode=mode, provider=StaticZoneProvider(zone), **kwargs)


def _ask(tool_name: str = "Bash", *, zone_mask=None, action: str = "allow", enforcement_mode="enforce", **kwargs):
    return evaluate_pre_tool_use(
        _request(tool_name), evaluator=_evaluator(action), ctx=_ctx(), device_id="dev-1",
        enforcement_mode=enforcement_mode, zone_mask=zone_mask, **kwargs,
    )


@pytest.fixture
def keys():
    return Keypair.generate(), os.urandom(32)


def _writer(tmp_path: Path, keys) -> GateReceiptWriter:
    signer, hmac_key = keys
    return GateReceiptWriter(tmp_path / "receipts", signer=signer, hmac_key=hmac_key, log_id="shield-gate:dev-1")


def _verified_receipts(tmp_path: Path, signer_key: str) -> list[dict]:
    """Verify what is on disk with the SDK's verifier (not code from this repo) and return it."""
    base = tmp_path / "receipts"
    receipts = [json.loads(line) for line in (base / RECEIPTS_FILENAME).read_bytes().splitlines()]
    checkpoints_path = base / CHECKPOINTS_FILENAME
    checkpoints = (
        [json.loads(line) for line in checkpoints_path.read_bytes().splitlines()] if checkpoints_path.exists() else []
    )
    verify_log(receipts, trusted_signers=[signer_key], checkpoint=checkpoints[-1] if checkpoints else None)
    return receipts


def _status_file(tmp_path: Path, *, age: float = 0.0, sensors: dict | None = None) -> Path:
    path = tmp_path / "sensor-status.json"
    write_sensor_status(path, {"attached": True} if sensors is None else sensors, now=_NOW - age)
    return path


def _silence(inner_zone: str = "green", *, status_path, **kwargs) -> SensorSilenceZoneProvider:
    kwargs.setdefault("clock", lambda: _NOW)
    return SensorSilenceZoneProvider(StaticZoneProvider(inner_zone), status_path=status_path, **kwargs)


# ---------------------------------------------------------------------- classification


@pytest.mark.parametrize(("tool", "expected"), [
    ("Read", "read"), ("Glob", "read"), ("Grep", "read"),
    ("Write", "draft"), ("Edit", "draft"), ("NotebookEdit", "draft"),
    ("Bash", "execute"),
])
def test_the_default_map_classifies_the_common_agent_tools(tool, expected):
    assert classify_tool(tool) == expected


@pytest.mark.parametrize("tool", ["Deploy", "mcp__anything__run", "read", "READ", "", "Read "])
def test_a_tool_not_in_the_map_is_execute_never_read(tool):
    """Unknown means "could do anything", so it gets the most restricted ordinary class. Matching is
    exact: a different spelling of a known tool is a different, unknown tool."""
    assert classify_tool(tool) == "execute"


def test_the_map_is_configurable_and_overlays_the_defaults():
    mask = _mask("yellow", tool_classes={"Bash": "read", "AskHuman": "escalate"})
    assert mask.classify("Bash") == "read"
    assert mask.classify("Edit") == "draft"  # defaults survive an overlay
    assert mask.classify("Deploy") == "execute"
    assert dict(DEFAULT_TOOL_CLASSES)["Bash"] == "execute"  # and the overlay did not edit the defaults


def test_an_unknown_action_class_in_the_map_is_a_configuration_error():
    with pytest.raises(ValueError, match="action class"):
        _mask("green", tool_classes={"Bash": "admin"})


# ------------------------------------------------------------------- the mask, in enforce

_MATRIX = {
    "green": {"read": "allow", "draft": "allow", "execute": "allow", "escalate": "allow"},
    "yellow": {"read": "allow", "draft": "allow", "execute": "deny", "escalate": "allow"},
    "red": {"read": "allow", "draft": "deny", "execute": "deny", "escalate": "allow"},
}


@pytest.mark.parametrize(("zone", "action_class", "expected"), [
    (zone, action_class, expected) for zone, row in _MATRIX.items() for action_class, expected in row.items()
])
def test_each_zone_permits_exactly_its_classes_in_enforce(zone, action_class, expected):
    response = _ask(_TOOL_FOR_CLASS[action_class], zone_mask=_mask(zone))
    assert response["decision"] == expected
    assert response["zone_mask"]["zone"] == zone
    assert response["zone_mask"]["action_class"] == action_class
    assert response["zone_mask"]["restricted"] is (expected == "deny")
    assert response["zone_mask"]["applied"] is (expected == "deny")
    if expected == "deny":
        assert response["action"] == "deny" and response["enforced"] is True
        assert response["reason"].startswith(REASON_ZONE_RESTRICTED)
        assert zone in response["reason"] and action_class in response["reason"]
    else:
        assert (response["action"], response["reason"], response["rule_id"]) == ("allow", "because", "rule-1")


@pytest.mark.parametrize("zone", ["green", "yellow", "red"])
@pytest.mark.parametrize("pack_action", ["deny", "contain", "escalate"])
@pytest.mark.parametrize("tool", ["Read", "Bash", "AskHuman"])
def test_a_call_the_pack_denies_stays_denied_in_every_zone(zone, pack_action, tool):
    """The mask can only remove permission. It must never turn a pack denial into an allow -- not
    in green, not for a `read`, and not for an always-permitted `escalate` class -- and it must not
    rewrite the pack's own reason either."""
    response = _ask(tool, zone_mask=_mask(zone), action=pack_action)
    assert response["decision"] == "deny"
    assert (response["action"], response["reason"], response["rule_id"]) == (pack_action, "because", "rule-1")
    assert response["zone_mask"]["applied"] is False


def test_the_mask_does_not_change_what_the_pack_is_asked():
    """An additional check, not a change to pack evaluation: the evaluator sees the same event and
    context with the mask on as with it off."""
    seen = []

    def evaluator(event, ctx):
        seen.append((event.agent.agent_id, list(event.context.tools_called), event.activity.type, ctx))
        return _decision("allow")

    ctx = _ctx()
    for mask in (None, _mask("red")):
        evaluate_pre_tool_use(_request("Bash"), evaluator=evaluator, ctx=ctx, device_id="dev-1", zone_mask=mask)
    assert seen[0] == seen[1]


def test_log_only_is_a_permit_the_mask_still_restricts():
    response = _ask("Bash", zone_mask=_mask("red"), action="log_only")
    assert response["decision"] == "deny" and response["zone_mask"]["applied"] is True


def test_an_unknown_tool_is_restricted_like_execute():
    assert _ask("Deploy", zone_mask=_mask("yellow"))["decision"] == "deny"
    assert _ask("Deploy", zone_mask=_mask("yellow"))["zone_mask"]["action_class"] == "execute"


def test_observe_enforcement_mode_still_never_blocks_but_reports_the_restriction():
    """`--enforcement-mode observe` is the gate-wide "never block" switch and outranks the mask."""
    response = _ask("Bash", zone_mask=_mask("red"), enforcement_mode="observe")
    assert response["decision"] == "allow" and response["enforced"] is False
    assert response["action"] == "deny" and response["reason"].startswith(REASON_ZONE_RESTRICTED)


# ------------------------------------------------------------------------- unknown zones


def test_an_unknown_zone_is_treated_as_yellow_by_default():
    mask = _mask("unknown")
    assert _ask("Bash", zone_mask=mask)["decision"] == "deny"
    response = _ask("Edit", zone_mask=mask)
    assert response["decision"] == "allow"
    assert response["zone_mask"]["zone"] == "yellow" and response["zone_mask"]["source"] == "unknown_default"


def test_what_an_unknown_zone_means_is_configurable():
    assert _ask("Edit", zone_mask=_mask("unknown", unknown_zone="red"))["decision"] == "deny"
    assert _ask("Bash", zone_mask=_mask("unknown", unknown_zone="green"))["decision"] == "allow"


@pytest.mark.parametrize("bad", ["purple", "", None, 7, "GREEN"])
def test_a_provider_answer_that_is_not_a_zone_is_unknown_not_green(bad):
    response = _ask("Bash", zone_mask=ZoneMask(mode="enforce", provider=lambda _agent: bad))
    assert response["decision"] == "deny" and response["zone_mask"]["zone"] == "yellow"


def test_a_provider_that_raises_is_unknown_and_does_not_break_the_gate():
    def provider(_agent):
        raise RuntimeError("scorer exploded")

    response = _ask("Bash", zone_mask=ZoneMask(mode="enforce", provider=provider))
    assert response["decision"] == "deny"
    assert response["zone_mask"]["source"] == "provider_error"
    assert _ask("Read", zone_mask=ZoneMask(mode="enforce", provider=provider))["decision"] == "allow"


def test_the_static_provider_can_zone_agents_individually():
    provider = StaticZoneProvider("green", per_agent={"agent-bad": "red"})
    mask = ZoneMask(mode="enforce", provider=provider)
    ask = lambda agent: evaluate_pre_tool_use(  # noqa: E731
        _request("Bash", agent_id=agent), evaluator=_evaluator(), ctx=_ctx(), device_id="dev-1", zone_mask=mask)
    assert ask("agent-1")["decision"] == "allow"
    assert ask("agent-bad")["decision"] == "deny"


# --------------------------------------------------------------------------------- modes


def test_off_is_inert_same_bytes_and_no_provider_call():
    calls = []

    def provider(agent_id):
        calls.append(agent_id)
        return "red"

    baseline = _ask("Bash")  # no zone mask at all: today's call
    off = _ask("Bash", zone_mask=ZoneMask(mode="off", provider=provider))
    assert json.dumps(off) == json.dumps(baseline)
    assert "zone_mask" not in off
    assert set(off) == {"v", "decision", "checked", "action", "enforced", "reason", "rule_id", "policy_version",
                        "policy_hash", "invocation_id", "receipt", "receipt_status"}
    assert calls == []


def test_off_adds_nothing_to_a_receipt(tmp_path, keys):
    writer = _writer(tmp_path, keys)
    provider = Mock(return_value="red")
    response = _ask("Bash", zone_mask=ZoneMask(mode="off", provider=provider),
                    basis_evaluator=_basis_evaluator(), receipts=writer)
    writer.close()
    receipt = _verified_receipts(tmp_path, writer.signer_key)[0]
    assert (receipt["decision"], receipt["reason_code"], receipt["controls"]) == ("permit", "ALLOWED", ["C-1"])
    assert "zone_mask" not in response and response["decision"] == "allow"
    provider.assert_not_called()


def test_off_builds_no_mask_at_all():
    """The default settings produce no mask object, so the daemon cannot consult a provider."""
    assert GateZoneSettings().mode == "off"
    assert build_zone_mask(GateZoneSettings()) is None
    assert build_zone_mask(GateZoneSettings(mode="off", zone="red")) is None


def test_shadow_records_the_would_be_restriction_but_allows(caplog):
    with caplog.at_level("INFO", logger="shield.gate_daemon"):
        response = _ask("Bash", zone_mask=_mask("red", mode="shadow"))
    assert response["decision"] == "allow" and response["action"] == "allow"
    assert (response["reason"], response["rule_id"]) == ("because", "rule-1")
    assert response["zone_mask"] == {
        "mode": "shadow", "zone": "red", "action_class": "execute", "restricted": True, "applied": False,
        "source": "provider", "sensor": None,
    }
    assert any("would restrict" in record.getMessage() for record in caplog.records)


def test_an_unknown_mode_is_a_configuration_error():
    with pytest.raises(ValueError, match="zone mode"):
        ZoneMask(mode="audit", provider=StaticZoneProvider("green"))


# ------------------------------------------------------------------------ sensor silence


def test_a_fresh_healthy_sensor_does_not_demote(tmp_path):
    provider = _silence("green", status_path=_status_file(tmp_path, age=5))
    reading = provider("agent-1")
    assert (reading.zone, reading.ceiling, reading.sensor) == ("green", None, "fresh")
    assert _ask("Bash", zone_mask=ZoneMask(mode="enforce", provider=provider))["decision"] == "allow"


def test_a_stale_sensor_demotes_to_red_by_default(tmp_path):
    provider = _silence("green", status_path=_status_file(tmp_path, age=61), max_age_seconds=60)
    response = _ask("Edit", zone_mask=ZoneMask(mode="enforce", provider=provider))
    assert response["decision"] == "deny"
    assert response["zone_mask"]["zone"] == "red"
    assert response["zone_mask"]["source"] == "sensor_silent" and response["zone_mask"]["sensor"] == "stale"
    assert _ask("Read", zone_mask=ZoneMask(mode="enforce", provider=provider))["decision"] == "allow"


def test_the_staleness_threshold_is_configurable(tmp_path):
    path = _status_file(tmp_path, age=61)
    assert _silence(status_path=path, max_age_seconds=60).sensor_state() == "stale"
    assert _silence(status_path=path, max_age_seconds=120).sensor_state() == "fresh"


def test_demotion_can_be_configured_to_yellow(tmp_path):
    provider = _silence("green", status_path=_status_file(tmp_path, age=600), demote_to="yellow")
    mask = ZoneMask(mode="enforce", provider=provider)
    assert _ask("Edit", zone_mask=mask)["decision"] == "allow"
    response = _ask("Bash", zone_mask=mask)
    assert response["decision"] == "deny" and response["zone_mask"]["zone"] == "yellow"


def test_demotion_only_ever_demotes(tmp_path):
    """Silence configured to demote to yellow must not lift an agent that is already red."""
    provider = _silence("red", status_path=_status_file(tmp_path, age=600), demote_to="yellow")
    response = _ask("Edit", zone_mask=ZoneMask(mode="enforce", provider=provider))
    assert response["decision"] == "deny" and response["zone_mask"]["zone"] == "red"


def test_silence_demotes_an_agent_whose_zone_is_unknown_too(tmp_path):
    provider = _silence("unknown", status_path=_status_file(tmp_path, age=600))
    response = _ask("Edit", zone_mask=ZoneMask(mode="enforce", provider=provider, unknown_zone="green"))
    assert response["decision"] == "deny" and response["zone_mask"]["zone"] == "red"


def test_a_gate_that_never_had_a_sensor_is_not_demoted(tmp_path):
    """No status file configured is "this gate runs standalone", which is a different fact from "the
    sensor went quiet" and is reported as such."""
    provider = _silence("green", status_path=None)
    assert provider.sensor_state() == "not_configured"
    response = _ask("Bash", zone_mask=ZoneMask(mode="enforce", provider=provider))
    assert response["decision"] == "allow"
    assert response["zone_mask"]["sensor"] == "not_configured" and response["zone_mask"]["source"] == "provider"


def test_a_missing_status_file_counts_as_silent_when_a_sensor_is_expected(tmp_path):
    provider = _silence("green", status_path=tmp_path / "never-written.json")
    assert provider.sensor_state() == "missing"
    response = _ask("Bash", zone_mask=ZoneMask(mode="enforce", provider=provider))
    assert response["decision"] == "deny" and response["zone_mask"]["source"] == "sensor_silent"


@pytest.mark.parametrize("content", [
    b"", b"not json", b"[]", b'{"v": 1}', b'{"v": 1, "written_at": "yesterday", "sensors": {"attached": true}}',
    b'{"v": 1, "written_at": true, "sensors": {"attached": true}}',
    b'{"v": 1, "written_at": 1800000000.0, "sensors": "fine"}', b"\xff\xfe\x00",
    b'{"v": 1, "written_at": NaN, "sensors": {"attached": true}}',
    b'{"v": 1, "written_at": -Infinity, "sensors": {"attached": true}}',
    b'{"v": 2, "written_at": 1800000000.0, "sensors": {"attached": true}}',
])
def test_an_unreadable_status_file_counts_as_silent_not_healthy(tmp_path, content):
    path = tmp_path / "sensor-status.json"
    path.write_bytes(content)
    provider = _silence("green", status_path=path)
    assert provider.sensor_state() == "unreadable"
    assert _ask("Bash", zone_mask=ZoneMask(mode="enforce", provider=provider))["decision"] == "deny"


def test_a_status_path_that_cannot_be_opened_counts_as_silent(tmp_path):
    directory = tmp_path / "is-a-directory"
    directory.mkdir()
    assert _silence(status_path=directory).sensor_state() == "unreadable"


def test_a_timestamp_from_the_future_is_not_fresh_forever(tmp_path):
    """Otherwise one write of a far-future `written_at` would keep a dead sensor "fresh" for good."""
    path = _status_file(tmp_path, age=-3600)
    assert _silence(status_path=path).sensor_state() == "unreadable"
    assert _silence(status_path=_status_file(tmp_path, age=-1)).sensor_state() == "fresh"  # small clock skew is fine


@pytest.mark.parametrize("sensors", [
    {"attached": False}, {"attached": False, "error": "detached"}, {"attached": True, "error": "boom"},
    {"attached": "yes"}, {},
])
def test_a_sensor_that_reports_unhealthy_demotes_even_when_the_file_is_fresh(tmp_path, sensors):
    provider = _silence("green", status_path=_status_file(tmp_path, sensors=sensors))
    assert provider.sensor_state() == "unhealthy"
    response = _ask("Bash", zone_mask=ZoneMask(mode="enforce", provider=provider))
    assert response["decision"] == "deny" and response["zone_mask"]["sensor"] == "unhealthy"


def test_when_seen_excuses_a_file_that_never_existed_but_not_one_that_vanished(tmp_path):
    path = tmp_path / "sensor-status.json"
    provider = _silence("green", status_path=path, expect="when-seen")
    assert provider.sensor_state() == "never_seen"
    assert provider("agent-1").ceiling is None

    write_sensor_status(path, {"attached": True}, now=_NOW)
    assert provider.sensor_state() == "fresh"

    path.unlink()
    assert provider.sensor_state() == "missing"
    assert provider("agent-1").ceiling == "red"


def test_when_seen_does_not_excuse_an_unreadable_file(tmp_path):
    path = tmp_path / "sensor-status.json"
    path.write_bytes(b"garbage")
    assert _silence(status_path=path, expect="when-seen").sensor_state() == "unreadable"


@pytest.mark.parametrize("kwargs", [
    {"demote_to": "green"}, {"demote_to": "unknown"}, {"expect": "sometimes"}, {"max_age_seconds": 0},
    {"max_age_seconds": -5},
])
def test_silence_settings_are_validated(tmp_path, kwargs):
    with pytest.raises(ValueError):
        _silence(status_path=tmp_path / "s.json", **kwargs)


def test_shadow_mode_reports_a_silence_demotion_without_blocking(tmp_path):
    provider = _silence("green", status_path=tmp_path / "absent.json")
    response = _ask("Bash", zone_mask=ZoneMask(mode="shadow", provider=provider))
    assert response["decision"] == "allow"
    assert response["zone_mask"]["restricted"] is True and response["zone_mask"]["sensor"] == "missing"


# ------------------------------------------------ the signal's other end: the watchdog


def _watchdog(sensor, **kwargs) -> Watchdog:
    policy_engine = Mock()
    policy_engine.health_status.return_value = {"healthy": True}
    return Watchdog(
        interval=1.0, device_config=DeviceConfig(device_id="dev-1", tenant_id="tenant-1"),
        policy_engine=policy_engine, reloader=None, opa_supervisor=None, exporter=None, sensor=sensor, **kwargs,
    )


@patch("shield.watchdog.publish_runtime_status")
def test_the_watchdog_writes_what_the_gate_reads(_publish, tmp_path):
    path = tmp_path / "run" / "sensor-status.json"
    sensor = Mock()
    sensor.health.return_value = {"attached": True, "lost_events": 0, "last_event_at": None}
    _watchdog(sensor, sensor_status_file=path).tick()

    status = read_sensor_status(path)
    assert status["sensors"] == {"attached": True, "lost_events": 0, "last_event_at": None}
    assert (path.stat().st_mode & 0o777) == 0o600
    assert SensorSilenceZoneProvider(StaticZoneProvider("green"), status_path=path).sensor_state() == "fresh"
    assert list(path.parent.iterdir()) == [path]  # the temp file used for the atomic replace is gone


@patch("shield.watchdog.publish_runtime_status")
def test_a_sensor_whose_health_check_raises_is_written_as_unhealthy(_publish, tmp_path):
    path = tmp_path / "sensor-status.json"
    sensor = Mock()
    sensor.health.side_effect = RuntimeError("perf buffer gone")
    _watchdog(sensor, sensor_status_file=path).tick()
    assert SensorSilenceZoneProvider(StaticZoneProvider("green"), status_path=path).sensor_state() == "unhealthy"


@patch("shield.watchdog.publish_runtime_status")
def test_the_watchdog_writes_no_status_file_unless_asked(mock_publish, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    sensor = Mock()
    sensor.health.return_value = {"attached": True}
    _watchdog(sensor).tick()
    assert list(tmp_path.iterdir()) == []
    mock_publish.assert_called_once()


@patch("shield.watchdog.publish_runtime_status")
def test_a_status_file_that_cannot_be_written_does_not_stop_the_tick(mock_publish, tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("x")
    sensor = Mock()
    sensor.health.return_value = {"attached": True}
    _watchdog(sensor, sensor_status_file=blocker / "under-a-file" / "s.json").tick()
    mock_publish.assert_called_once()


# ------------------------------------------------------------------------------ receipts


def test_a_restricted_call_is_recorded_with_its_zone_and_class_and_the_log_verifies(tmp_path, keys):
    writer = _writer(tmp_path, keys)
    response = _ask("Bash", zone_mask=_mask("yellow"), basis_evaluator=_basis_evaluator(), receipts=writer)
    allowed = _ask("Edit", zone_mask=_mask("yellow"), basis_evaluator=_basis_evaluator(), receipts=writer)
    writer.close()

    assert response["decision"] == "deny" and response["receipt_status"] == "recorded"
    receipts = _verified_receipts(tmp_path, writer.signer_key)
    assert (receipts[0]["decision"], receipts[0]["reason_code"], receipts[0]["mode"]) == (
        "deny", "AIS_ZONE_RESTRICTED", "enforce")
    assert receipts[0]["controls"] == [
        "C-1", "ais_zone:yellow", "ais_action_class:execute", "ais_zone_source:provider"]
    assert response["receipt"]["hash"]  # and the response points at that receipt

    assert allowed["decision"] == "allow"
    assert (receipts[1]["decision"], receipts[1]["reason_code"]) == ("permit", "ALLOWED")
    assert receipts[1]["controls"] == ["C-1", "ais_zone:yellow", "ais_action_class:draft", "ais_zone_source:provider"]


def test_a_shadow_receipt_keeps_the_real_verdict_and_tags_the_would_be_restriction(tmp_path, keys):
    writer = _writer(tmp_path, keys)
    response = _ask("Bash", zone_mask=_mask("red", mode="shadow"), basis_evaluator=_basis_evaluator(),
                    receipts=writer)
    writer.close()
    receipt = _verified_receipts(tmp_path, writer.signer_key)[0]
    assert response["decision"] == "allow"
    assert (receipt["decision"], receipt["reason_code"], receipt["mode"]) == ("permit", "ALLOWED", "enforce")
    assert receipt["controls"] == [
        "C-1", "ais_zone:red", "ais_action_class:execute", "ais_zone_source:provider", "ais_zone_mask:shadow_restricted"]


def test_a_pack_deny_keeps_its_own_reason_code_in_the_receipt(tmp_path, keys):
    writer = _writer(tmp_path, keys)
    _ask("Bash", zone_mask=_mask("red"), action="deny",
         basis_evaluator=_basis_evaluator("deny", "deny", "PACK_SAID_NO"), receipts=writer)
    writer.close()
    receipt = _verified_receipts(tmp_path, writer.signer_key)[0]
    assert (receipt["decision"], receipt["reason_code"]) == ("deny", "PACK_SAID_NO")
    assert "ais_zone:red" in receipt["controls"] and "ais_zone_mask:shadow_restricted" not in receipt["controls"]


def test_a_silence_demotion_is_named_in_the_receipt(tmp_path, keys):
    writer = _writer(tmp_path, keys)
    provider = _silence("green", status_path=tmp_path / "absent.json")
    _ask("Bash", zone_mask=ZoneMask(mode="enforce", provider=provider),
         basis_evaluator=_basis_evaluator(), receipts=writer)
    writer.close()
    receipt = _verified_receipts(tmp_path, writer.signer_key)[0]
    assert receipt["reason_code"] == "AIS_ZONE_RESTRICTED"
    assert receipt["controls"] == ["C-1", "ais_zone:red", "ais_action_class:execute", "ais_zone_source:sensor_silent"]


def test_an_observe_mode_restriction_is_a_shadow_receipt_of_the_deny(tmp_path, keys):
    writer = _writer(tmp_path, keys)
    response = _ask("Bash", zone_mask=_mask("red"), enforcement_mode="observe",
                    basis_evaluator=_basis_evaluator(), receipts=writer)
    writer.close()
    receipt = _verified_receipts(tmp_path, writer.signer_key)[0]
    assert response["decision"] == "allow"
    assert (receipt["decision"], receipt["reason_code"], receipt["mode"]) == ("deny", "AIS_ZONE_RESTRICTED", "shadow")


# ---------------------------------------------------------------- over the real socket


def test_the_daemon_applies_the_mask_over_a_real_socket(tmp_path):
    path = tmp_path / "gate.sock"
    server = GateServer(path, evaluator=_evaluator(), ctx=_ctx(), device_id="dev-1", zone_mask=_mask("yellow"))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def ask(tool_name: str) -> dict:
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(10)
        try:
            client.connect(str(path))
            client.sendall(json.dumps({"v": 1, "agent_id": "agent-1", "tool_name": tool_name}).encode() + b"\n")
            return json.loads(client.makefile("rb").readline())
        finally:
            client.close()

    try:
        denied, allowed = ask("Bash"), ask("Write")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    assert denied["decision"] == "deny" and denied["reason"].startswith("AIS_ZONE_RESTRICTED")
    assert allowed["decision"] == "allow" and allowed["zone_mask"]["action_class"] == "draft"


# ------------------------------------------------------------- settings, loader and CLI


def test_settings_build_the_static_provider_inside_the_silence_wrapper(tmp_path):
    settings = GateZoneSettings(mode="enforce", zone="green", agent_zones={"agent-bad": "red"},
                                tool_classes={"Deploy": "read"}, sensor_status_file=str(tmp_path / "absent.json"))
    mask = build_zone_mask(settings)
    assessment = mask.assess("agent-1", "Deploy")
    assert (assessment.zone, assessment.action_class, assessment.sensor) == ("red", "read", "missing")

    standalone = build_zone_mask(GateZoneSettings(mode="enforce", zone="green", agent_zones={"agent-bad": "red"}))
    assert standalone.assess("agent-1", "Bash").zone == "green"
    assert standalone.assess("agent-1", "Bash").sensor == "not_configured"
    assert standalone.assess("agent-bad", "Bash").zone == "red"


def test_a_later_provider_plugs_in_by_name_without_touching_the_gate():
    """The seam: a scorer registers a factory under a name, and settings select it."""
    register_zone_provider("test-scorer", lambda settings: (lambda agent_id: "red" if agent_id == "x" else "green"))
    mask = build_zone_mask(GateZoneSettings(mode="enforce", provider="test-scorer"))
    assert mask.assess("x", "Read").zone == "red" and mask.assess("y", "Read").zone == "green"
    with pytest.raises(ValueError, match="unknown zone provider"):
        build_zone_mask(GateZoneSettings(mode="enforce", provider="nope"))


def test_a_provider_can_be_named_by_import_path():
    mask = build_zone_mask(GateZoneSettings(mode="enforce", provider="tests.zone_provider_fixture:make_provider"))
    assert mask.assess("anyone", "Read").zone == "yellow"


@pytest.mark.parametrize("doc", [
    {"mode": "audit"}, {"zone": "purple"}, {"agent_zones": {"a": "blue"}}, {"agent_zones": ["a"]},
    {"unknown_as": "unknown"}, {"tool_classes": {"Bash": "admin"}}, {"sensor_demote_to": "green"},
    {"sensor_expect": "never"}, {"sensor_max_age_seconds": 0}, {"sensor_max_age_seconds": "60"},
    {"sensor_max_age_seconds": True}, {"surprise": 1}, {"sensor_status_file": 5},
])
def test_bad_settings_are_refused_by_name(doc):
    with pytest.raises(ValueError):
        GateZoneSettings.from_mapping(doc)


def test_the_device_config_loader_carries_gate_zone_and_defaults_to_off(tmp_path):
    path = tmp_path / "device.json"
    path.write_text(json.dumps({"device_id": "dev-1"}))
    assert load_device_config(path).gate_zone == {}
    assert GateZoneSettings.from_mapping(load_device_config(path).gate_zone).mode == "off"

    path.write_text(json.dumps({"device_id": "dev-1", "gate_zone": {
        "mode": "shadow", "zone": "yellow", "sensor_status_file": "/run/shield/sensor-status.json"}}))
    settings = GateZoneSettings.from_mapping(load_device_config(path).gate_zone)
    assert (settings.mode, settings.zone, settings.sensor_status_file) == (
        "shadow", "yellow", "/run/shield/sensor-status.json")


def test_the_device_config_loader_refuses_a_bad_gate_zone_naming_the_file(tmp_path):
    path = tmp_path / "device.json"
    path.write_text(json.dumps({"device_id": "dev-1", "gate_zone": {"mode": "audit"}}))
    with pytest.raises(ConfigError, match="gate_zone") as excinfo:
        load_device_config(path)
    assert str(path) in str(excinfo.value)


def _cli(*argv: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "shield.cli", "gate-daemon", "--device-id", "dev-1",
         "--pack-dir", "/nonexistent", *argv],
        cwd=_REPO_ROOT, capture_output=True, text=True, timeout=60,
    )


@pytest.mark.parametrize("argv", [
    ("--zone", "red"), ("--zone-agent", "a=red"), ("--zone-sensor-status-file", "/tmp/x"),
    ("--zone-tool-class", "Bash=read"), ("--zone-mode", "off", "--zone", "red"),
])
def test_cli_refuses_zone_options_that_would_silently_do_nothing(argv):
    result = _cli(*argv)
    assert result.returncode == 2 and "--zone-mode" in result.stderr


@pytest.mark.parametrize("argv", [
    ("--zone-mode", "enforce", "--zone-agent", "no-equals"),
    ("--zone-mode", "enforce", "--zone-agent", "a=purple"),
    ("--zone-mode", "enforce", "--zone-tool-class", "Bash=admin"),
    ("--zone-mode", "enforce", "--zone-sensor-max-age", "0"),
    ("--zone-mode", "enforce", "--zone-provider", "nope"),
])
def test_cli_refuses_malformed_zone_options(argv):
    result = _cli(*argv)
    assert result.returncode == 2 and "shield gate-daemon:" in result.stderr


_CLI_PROBE = textwrap.dedent(
    """
    import json, sys
    import shield.cli as cli

    class FakePack:
        manifest = {"name": "t", "version": "1"}
        pack_hash = "sha256:" + "ab" * 32

    class FakeEngine:
        def __init__(self, *args, **kwargs):
            pass

    captured = {}
    cli.resolve_pack = lambda *args, **kwargs: FakePack()
    cli.PolicyEngine = FakeEngine
    cli.serve_forever = lambda socket_path, **kwargs: captured.update(kwargs)

    code = cli.main(["gate-daemon", "--register-agent", "a", *sys.argv[1:]])
    mask = captured.get("zone_mask")
    out = {"code": code, "has_key": "zone_mask" in captured, "mask": None}
    if mask is not None:
        bash, edit = mask.assess("a", "Bash"), mask.assess("b", "Edit")
        out["mask"] = {"mode": mask.mode, "a_bash": [bash.zone, bash.action_class, bash.sensor, bash.restricted],
                       "b_edit": [edit.zone, edit.action_class, edit.restricted]}
    print(json.dumps(out))
    """
)


def _probe(*argv: str) -> tuple[dict, str]:
    result = subprocess.run([sys.executable, "-c", _CLI_PROBE, *argv], cwd=_REPO_ROOT, capture_output=True,
                            text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout.strip().splitlines()[-1]), result.stderr


def test_cli_passes_no_mask_by_default():
    outcome, stderr = _probe("--device-id", "dev-1")
    assert outcome == {"code": 0, "has_key": True, "mask": None}
    assert "zone" not in stderr  # the startup banner is unchanged when the feature is off


def test_cli_wires_the_flags_into_the_mask(tmp_path):
    outcome, stderr = _probe(
        "--device-id", "dev-1", "--zone-mode", "enforce", "--zone", "green", "--zone-agent", "b=red",
        "--zone-tool-class", "Bash=draft", "--zone-sensor-status-file", str(tmp_path / "absent.json"),
        "--zone-sensor-demote-to", "yellow",
    )
    assert outcome["mask"] == {"mode": "enforce", "a_bash": ["yellow", "draft", "missing", False],
                               "b_edit": ["red", "draft", True]}
    assert "zone mask enforce" in stderr


def test_cli_flags_override_the_device_config(tmp_path):
    config = tmp_path / "device.json"
    config.write_text(json.dumps({"device_id": "dev-1", "gate_zone": {"mode": "enforce", "zone": "red"}}))
    from_config, _ = _probe("--device-config", str(config))
    assert from_config["mask"]["mode"] == "enforce" and from_config["mask"]["a_bash"][0] == "red"

    overridden, _ = _probe("--device-config", str(config), "--zone-mode", "shadow", "--zone", "yellow")
    assert overridden["mask"]["mode"] == "shadow" and overridden["mask"]["a_bash"][0] == "yellow"

    switched_off, _ = _probe("--device-config", str(config), "--zone-mode", "off")
    assert switched_off["mask"] is None


def test_shield_run_has_the_sensor_status_file_option():
    out = subprocess.run([sys.executable, "-m", "shield.cli", "run", "--help"], cwd=_REPO_ROOT,
                         capture_output=True, text=True, timeout=60).stdout
    assert "--sensor-status-file" in out
