"""The `ais` zone provider: the gate's own receipts set its agents' zones (the AIS loop closed at L0).

Every loop test here runs the real path: `evaluate_pre_tool_use` -> SDK `GateReceiptWriter` on disk ->
`integrity_sdk.core.ais_local` tailing that file -> `ZoneMask` -> the next decision.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from integrity_sdk.did import Keypair

from shield.cli import _gate_zone_mask
from shield.config import DeviceConfig
from shield.gate_daemon import GateRequest, evaluate_pre_tool_use
from shield.gate_receipts import RECEIPTS_FILENAME, GateReceiptWriter
from shield.gate_zone import (
    REASON_ZONE_RESTRICTED,
    SOURCE_AIS_COLD_START,
    SOURCE_AIS_LOCAL,
    AisReceiptZoneProvider,
    GateZoneSettings,
    build_zone_mask,
)
from shield.policy_engine.engine import DecisionBasis, EvaluationContext
from shield.schemas.events import PolicyDecision

_DIGEST = "ab" * 32
_PACK_HASH = "sha256:" + "cd" * 32
AGENT = "agent-1"


def _real_decision(action: str) -> PolicyDecision:
    # Built the same way tests/test_gate_zone.py builds one, so the gate sees a normal pack answer.
    from tests.test_gate_zone import _decision as build

    return build(action)


def _pack(action: str):
    decision, reason = ("permit", "ALLOWED") if action == "allow" else ("deny", "PACK_SAID_NO")

    def evaluate(_event, _ctx):
        return _real_decision(action), DecisionBasis(decision, reason, ("C-1",), _PACK_HASH, "agent_event")
    return evaluate


class Gate:
    """One gate daemon's decision path with real receipts and the ais provider."""

    def __init__(self, tmp_path: Path, *, mode: str = "enforce", **ais) -> None:
        signer, hmac_key = Keypair.generate(), os.urandom(32)
        self.dir = tmp_path / "receipts"
        self.writer = GateReceiptWriter(self.dir, signer=signer, hmac_key=hmac_key, log_id="shield-gate:dev-1")
        ais = {"default_tier": 3, "window_size": 50, "min_observations": 10, **ais}
        self.mask = build_zone_mask(GateZoneSettings(
            mode=mode, provider="ais", receipts_file=str(self.dir / RECEIPTS_FILENAME), ais=ais,
            tool_classes={"AskHuman": "escalate"},
        ))

    def ask(self, tool: str, pack: str = "allow") -> dict:
        return evaluate_pre_tool_use(
            GateRequest(agent_id=AGENT, tool_name=tool, tool_input_sha256=_DIGEST),
            evaluator=lambda _e, _c: _real_decision(pack), basis_evaluator=_pack(pack),
            ctx=EvaluationContext(tenant_id="t", device_role="r", device_id="dev-1"), device_id="dev-1",
            enforcement_mode="enforce", zone_mask=self.mask, receipts=self.writer,
        )

    def zone(self, tool: str = "Read") -> str:
        return self.mask.assess(AGENT, tool).zone

    def close(self) -> None:
        self.writer.close()


@pytest.fixture
def gate(tmp_path):
    g = Gate(tmp_path)
    yield g
    g.close()


def _denied_by_mask(response: dict) -> bool:
    return response.get("zone_mask", {}).get("applied") is True


# ------------------------------------------------------------------------------ the loop


def test_cold_start_is_unknown_then_the_score_takes_over(gate):
    first = gate.mask.assess(AGENT, "Bash")
    assert (first.zone, first.source) == ("yellow", SOURCE_AIS_COLD_START)  # unknown_as, not a computed red
    for _ in range(10):
        gate.ask("Read")
    reading = gate.mask.assess(AGENT, "Bash")
    assert (reading.zone, reading.source, reading.restricted) == ("green", SOURCE_AIS_LOCAL, False)


def test_pack_violations_turn_the_zone_red_and_the_mask_then_blocks_execute(gate):
    for _ in range(37):
        gate.ask("Read")
    assert gate.zone() == "green"
    for _ in range(13):  # 13 of 50 = S_C 740 < 750 at tier 3
        gate.ask("Bash", pack="deny")
    assert gate.zone() == "red"

    response = gate.ask("Bash")  # the pack permits this call; the zone does not
    assert _denied_by_mask(response)
    assert gate.ask("Read").get("zone_mask", {}).get("applied") is False
    assert gate.ask("AskHuman").get("zone_mask", {}).get("applied") is False  # escalate is always allowed


def test_red_is_not_self_sustaining_and_recovers_through_permitted_actions(gate):
    # The violations come first, so they are the oldest decisions in the window and leave it first.
    for _ in range(13):
        gate.ask("Bash", pack="deny")
    for _ in range(37):
        gate.ask("Read")
    assert gate.zone() == "red"  # 13 of 50 violations: S_C 740 < 750
    # Hammering execute while red: every attempt is denied by the mask, and none of it may count.
    # (If it counted, the window would be 50 violations and recovery would take ~46 reads, not 9.)
    for _ in range(200):
        assert _denied_by_mask(gate.ask("Bash"))
    assert gate.zone() == "red"
    # Reads are what red permits; each one pushes the oldest violation out of the window.
    seen = []
    for _ in range(9):
        gate.ask("Read")
        seen.append(gate.zone())
    # 1-2 reads: still 12-11 violations (red/yellow boundary at 12); then yellow; green only at <= 4
    # violations (recovery 920), i.e. after the 9th read -- hysteresis, not the plain 900 line.
    assert seen[-1] == "green" and seen[-2] == "yellow" and "yellow" in seen[:3]
    assert not _denied_by_mask(gate.ask("Bash"))


def test_receipts_say_the_zone_came_from_the_local_score(gate):
    for _ in range(10):
        gate.ask("Read")
    gate.ask("Bash")
    last = json.loads((gate.dir / RECEIPTS_FILENAME).read_text().splitlines()[-1])
    assert f"ais_zone_source:{SOURCE_AIS_LOCAL}" in last["controls"]
    assert "ais_zone:green" in last["controls"]


def test_tier_comes_from_configuration(tmp_path):
    g = Gate(tmp_path, default_tier=0, min_observations=1)
    try:
        g.ask("Read")
        score = g.mask.assess(AGENT, "Read")
        assert score.zone == "green"  # per-tier policy: tier 0's ceiling of 300 is green (>= 270)
    finally:
        g.close()


def test_a_scorer_failure_is_unknown_not_open():
    def broken(_agent_id):
        raise RuntimeError("scorer exploded")
    from shield.gate_zone import ZoneMask

    mask = ZoneMask(mode="enforce", provider=AisReceiptZoneProvider(broken))
    assessment = mask.assess(AGENT, "Bash")
    assert assessment.zone == "yellow" and assessment.restricted


# ------------------------------------------------------------------------------ settings


@pytest.mark.parametrize("document,message", [
    ({"mode": "enforce", "provider": "static", "ais": {"default_tier": 3}}, "only read by the 'ais'"),
    ({"mode": "enforce", "provider": "ais", "ais": {"default_tier": 3, "tier": 2}}, "unknown field"),
    ({"mode": "enforce", "provider": "ais", "receipts_file": ""}, "receipts_file"),
])
def test_settings_refuse_misconfiguration(document, message):
    with pytest.raises(ValueError, match=message):
        GateZoneSettings.from_mapping(document)


@pytest.mark.parametrize("settings,message", [
    (GateZoneSettings(mode="enforce", provider="ais", ais={"default_tier": 3}), "--receipt-dir"),
    (GateZoneSettings(mode="enforce", provider="ais", receipts_file="/tmp/r.jsonl"), "default_tier"),
    (GateZoneSettings(mode="enforce", provider="ais", receipts_file="/tmp/r.jsonl", ais={"default_tier": 7}), "tier"),
    (GateZoneSettings(mode="enforce", provider="ais", receipts_file="/tmp/r.jsonl",
                      ais={"default_tier": 3, "zone_policy": {"mode": "nonsense"}}), "polic|mode"),
])
def test_building_the_ais_provider_refuses_what_it_cannot_honour(settings, message):
    with pytest.raises(ValueError, match=message):
        build_zone_mask(settings)


# ------------------------------------------------------------------------------ cli


def _args(**overrides) -> SimpleNamespace:
    return SimpleNamespace(**overrides)


def test_cli_points_the_ais_provider_at_this_gates_receipts(tmp_path):
    mask = _gate_zone_mask(_args(zone_mode="enforce", zone_provider="ais", zone_ais_tier=2,
                                 zone_ais_agent_tiers=["b=0"], zone_ais_min_observations=1,
                                 receipt_dir=tmp_path), DeviceConfig(device_id="dev-1"))
    provider = mask._provider._inner  # the silence wrapper holds the ais provider
    source = provider._source
    assert source._tail.path == tmp_path / RECEIPTS_FILENAME
    assert source._settings.default_tier == 2 and source._settings.agent_tiers == {"b": 0}


def test_cli_refuses_the_ais_provider_without_receipts():
    with pytest.raises(ValueError, match="--receipt-dir"):
        _gate_zone_mask(_args(zone_mode="enforce", zone_provider="ais", zone_ais_tier=3),
                        DeviceConfig(device_id="dev-1"))


def test_cli_refuses_ais_options_while_the_mask_is_off(tmp_path):
    with pytest.raises(ValueError, match="--zone-mode"):
        _gate_zone_mask(_args(zone_provider="ais", zone_ais_tier=3, receipt_dir=tmp_path),
                        DeviceConfig(device_id="dev-1"))
    # And with no provider named, ais options are refused for the static provider they cannot affect.
    with pytest.raises(ValueError, match="only read by the 'ais'"):
        _gate_zone_mask(_args(zone_ais_tier=3, receipt_dir=tmp_path), DeviceConfig(device_id="dev-1"))


def test_cli_rejects_a_malformed_agent_tier(tmp_path):
    with pytest.raises(ValueError, match="AGENT=TIER"):
        _gate_zone_mask(_args(zone_mode="enforce", zone_provider="ais", zone_ais_tier=3,
                              zone_ais_agent_tiers=["b=high"], receipt_dir=tmp_path), DeviceConfig(device_id="dev-1"))
