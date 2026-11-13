"""Paid zone enforcement: a signed, expiring entitlement turns `enforce` on; anything else is shadow.

Design: docs/superpowers/specs/2026-11-12-shield-plans-metering-design.md §1 (billing is never in the
decision path) and §6 (entitlement on the device). Every gate test here goes through
`build_zone_mask` -> `evaluate_pre_tool_use` -> a real `GateReceiptWriter`, so what is asserted is
what a running daemon does and what its receipt records.
"""

from __future__ import annotations

import base64
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from integrity_sdk.did import Keypair

from shield.cli import _gate_zone_mask
from shield.config import DeviceConfig
from shield.entitlement import (
    STATUS_BAD_SIGNATURE,
    STATUS_EXPIRED,
    STATUS_MALFORMED,
    STATUS_MISSING,
    STATUS_NOT_YET_VALID,
    STATUS_OK,
    STATUS_PLAN,
    STATUS_WRONG_DEVICE,
    EntitlementGate,
    sign_entitlement,
    verify_entitlement,
)
from shield.gate_daemon import GateRequest, evaluate_pre_tool_use
from shield.gate_receipts import RECEIPTS_FILENAME, GateReceiptWriter
from shield.gate_zone import GateZoneSettings, ZoneMask, build_zone_mask
from tests.test_gate_zone_ais import _DIGEST, _pack, _real_decision

from shield.policy_engine.engine import EvaluationContext

TENANT, DEVICE, AGENT = "t-1", "dev-1", "agent-1"
NOW = datetime(2026, 11, 13, 12, 0, tzinfo=timezone.utc)
BACKEND = Keypair.generate()
BACKEND_KEY = base64.b64encode(BACKEND.public_bytes()).decode("ascii")


def _entitlement(**overrides):
    fields = dict(tenant_id=TENANT, device_id=DEVICE, plan="pro", zone_enforce=True,
                  issued_at=NOW - timedelta(days=1), not_after=NOW + timedelta(days=30), keypair=BACKEND)
    fields.update(overrides)
    return sign_entitlement(**fields)


def _verify(document, *, keys=(BACKEND_KEY,), now=NOW, tenant=TENANT, device=DEVICE):
    return verify_entitlement(document, trusted_keys=keys, tenant_id=tenant, device_id=device, now=now)


# --------------------------------------------------------------------------- verification


def test_a_valid_entitlement_for_this_device_is_ok():
    assert _verify(_entitlement()) == STATUS_OK


def test_a_plan_without_zone_enforcement_is_plan():
    assert _verify(_entitlement(plan="free", zone_enforce=False)) == STATUS_PLAN


def test_expiry_is_exclusive_of_not_after():
    document = _entitlement(not_after=NOW)
    assert _verify(document, now=NOW - timedelta(seconds=1)) == STATUS_OK
    assert _verify(document, now=NOW) == STATUS_EXPIRED


def test_issued_beyond_the_clock_skew_is_not_yet_valid():
    assert _verify(_entitlement(issued_at=NOW + timedelta(seconds=299),
                                not_after=NOW + timedelta(days=1))) == STATUS_OK
    assert _verify(_entitlement(issued_at=NOW + timedelta(seconds=301),
                                not_after=NOW + timedelta(days=1))) == STATUS_NOT_YET_VALID


@pytest.mark.parametrize("tenant, device", [("t-other", DEVICE), (TENANT, "dev-other")])
def test_an_entitlement_for_another_tenant_or_device_is_refused(tenant, device):
    assert _verify(_entitlement(), tenant=tenant, device=device) == STATUS_WRONG_DEVICE


@pytest.mark.parametrize("field, value", [
    ("plan", "team"), ("zone_enforce", False), ("not_after", (NOW + timedelta(days=3650)).isoformat()),
    ("device_id", "dev-2"),
])
def test_any_edited_claim_breaks_the_signature(field, value):
    document = {**_entitlement(), field: value}
    assert _verify(document, device=document["device_id"]) == STATUS_BAD_SIGNATURE


def test_a_signer_that_is_not_trusted_is_refused_even_when_its_signature_is_valid():
    assert _verify(_entitlement(keypair=Keypair.generate())) == STATUS_BAD_SIGNATURE


def test_no_trusted_keys_trusts_nothing():
    assert _verify(_entitlement(), keys=()) == STATUS_BAD_SIGNATURE


@pytest.mark.parametrize("document", [
    None, [], "x", {}, {**_entitlement(), "extra": 1},
    {**_entitlement(), "zone_enforce": "yes"},
    {**_entitlement(), "schema": "xibalba.shield.entitlement.v0"},
    {**_entitlement(), "not_after": "tomorrow"},
    {**_entitlement(), "signature": "%%%"},
])
def test_malformed_documents_are_malformed_never_an_exception(document):
    assert _verify(document) == STATUS_MALFORMED


# --------------------------------------------------------------------------- the file gate


def test_the_gate_reports_missing_without_a_path_or_file(tmp_path):
    assert EntitlementGate(None, trusted_keys=[BACKEND_KEY], tenant_id=TENANT, device_id=DEVICE).status() \
        == STATUS_MISSING
    assert EntitlementGate(tmp_path / "nope.json", trusted_keys=[BACKEND_KEY], tenant_id=TENANT,
                           device_id=DEVICE).status() == STATUS_MISSING


def test_the_gate_picks_up_a_refreshed_file_and_a_lapse_without_restarting(tmp_path):
    path = tmp_path / "entitlement.json"
    clock = [NOW.timestamp()]
    gate = EntitlementGate(path, trusted_keys=[BACKEND_KEY], tenant_id=TENANT, device_id=DEVICE,
                           clock=lambda: clock[0])
    path.write_text(json.dumps(_entitlement(plan="free", zone_enforce=False)))
    assert gate.status() == STATUS_PLAN
    path.write_text(json.dumps(_entitlement(not_after=NOW + timedelta(hours=1))))
    os.utime(path, ns=(1, 1))  # a different mtime even on filesystems with coarse timestamps
    assert gate.status() == STATUS_OK
    clock[0] += 3601  # same file, time passes
    assert gate.status() == STATUS_EXPIRED


def test_the_gate_reports_garbage_as_malformed(tmp_path):
    path = tmp_path / "entitlement.json"
    path.write_text("{not json")
    assert EntitlementGate(path, trusted_keys=[BACKEND_KEY], tenant_id=TENANT, device_id=DEVICE).status() \
        == STATUS_MALFORMED


# --------------------------------------------------------------------------- the gate decision


class _Gate:
    """A gate daemon's decision path: static red zone, real receipts, a mask from `build_zone_mask`."""

    def __init__(self, tmp_path: Path, *, mode: str = "enforce", entitlement=None, provider_zone="red"):
        self.dir = tmp_path / "receipts"
        self.writer = GateReceiptWriter(self.dir, signer=Keypair.generate(), hmac_key=os.urandom(32),
                                        log_id="shield-gate:dev-1")
        settings = {"mode": mode, "zone": provider_zone, "entitlement_keys": [BACKEND_KEY]}
        if entitlement is not None:
            path = tmp_path / "entitlement.json"
            path.write_text(json.dumps(entitlement))
            settings["entitlement_file"] = str(path)
        self.mask = build_zone_mask(GateZoneSettings.from_mapping(settings), tenant_id=TENANT, device_id=DEVICE)

    def ask(self, tool: str = "Bash", pack: str = "allow") -> dict:
        return evaluate_pre_tool_use(
            GateRequest(agent_id=AGENT, tool_name=tool, tool_input_sha256=_DIGEST),
            evaluator=lambda _e, _c: _real_decision(pack), basis_evaluator=_pack(pack),
            ctx=EvaluationContext(tenant_id=TENANT, device_role="r", device_id=DEVICE), device_id=DEVICE,
            enforcement_mode="enforce", zone_mask=self.mask, receipts=self.writer,
        )

    def last_receipt(self) -> dict:
        self.writer.close()
        lines = (self.dir / RECEIPTS_FILENAME).read_text().splitlines()
        return json.loads(lines[-1])


def _now_entitlement(**overrides):
    now = datetime.now(timezone.utc)
    return _entitlement(issued_at=now - timedelta(minutes=1), not_after=now + timedelta(days=30), **overrides)


def test_enforce_with_a_valid_entitlement_blocks_and_says_so(tmp_path):
    gate = _Gate(tmp_path, entitlement=_now_entitlement())
    response = gate.ask("Bash")
    assert response["decision"] == "deny" and response["zone_mask"]["applied"] is True
    assert response["zone_mask"]["mode"] == "enforce" and response["zone_mask"]["entitlement"] == STATUS_OK
    assert "ais_zone_entitlement:ok" in gate.last_receipt()["controls"]


@pytest.mark.parametrize("entitlement, status", [
    (None, STATUS_MISSING),
    ("expired", STATUS_EXPIRED),
    ("free", STATUS_PLAN),
    ("untrusted", STATUS_BAD_SIGNATURE),
])
def test_enforce_without_a_valid_entitlement_runs_as_shadow_and_never_blocks(tmp_path, entitlement, status):
    now = datetime.now(timezone.utc)
    document = {
        None: None,
        "expired": _entitlement(issued_at=now - timedelta(days=40), not_after=now - timedelta(days=1)),
        "free": _now_entitlement(plan="free", zone_enforce=False),
        "untrusted": _now_entitlement(keypair=Keypair.generate()),
    }[entitlement]
    gate = _Gate(tmp_path, entitlement=document)
    response = gate.ask("Bash")
    # The red zone would restrict `execute`; without the entitlement the call still goes through.
    assert response["decision"] == "allow" and response["action"] == "allow"
    assert response["zone_mask"]["mode"] == "shadow" and response["zone_mask"]["requested_mode"] == "enforce"
    assert response["zone_mask"]["applied"] is False and response["zone_mask"]["entitlement"] == status
    controls = gate.last_receipt()["controls"]
    assert f"ais_zone_entitlement:{status}" in controls and "ais_zone_mask:shadow_restricted" in controls


def test_a_pack_denial_still_stands_when_the_entitlement_is_missing(tmp_path):
    # Licensing only decides whether the *mask* may block; the pack's own verdict is untouched.
    response = _Gate(tmp_path).ask("Bash", pack="deny")
    assert response["decision"] == "deny" and response["zone_mask"]["applied"] is False


@pytest.mark.parametrize("mode", ["shadow"])
def test_shadow_never_consults_the_entitlement(tmp_path, mode):
    gate = _Gate(tmp_path, mode=mode)
    response = gate.ask("Bash")
    assert response["zone_mask"]["entitlement"] is None
    assert not any(c.startswith("ais_zone_entitlement:") for c in gate.last_receipt()["controls"])


def test_billing_is_never_in_the_decision_path(tmp_path):
    """§1: provider broken, entitlement expired, no backend anywhere -> the pack answers and a receipt
    is written. Remove the downgrade, or add anything that fails the call, and this fails."""
    now = datetime.now(timezone.utc)
    expired = _entitlement(issued_at=now - timedelta(days=40), not_after=now - timedelta(days=1))
    path = tmp_path / "entitlement.json"
    path.write_text(json.dumps(expired))

    def broken_provider(_agent):
        raise RuntimeError("scorer unavailable")

    mask = ZoneMask(mode="enforce", provider=broken_provider, unknown_zone="red",
                    entitlement=EntitlementGate(path, trusted_keys=[BACKEND_KEY], tenant_id=TENANT,
                                                device_id=DEVICE).status)
    writer = GateReceiptWriter(tmp_path / "r", signer=Keypair.generate(), hmac_key=os.urandom(32),
                               log_id="shield-gate:dev-1")
    response = evaluate_pre_tool_use(
        GateRequest(agent_id=AGENT, tool_name="Bash", tool_input_sha256=_DIGEST),
        evaluator=lambda _e, _c: _real_decision("allow"), basis_evaluator=_pack("allow"),
        ctx=EvaluationContext(tenant_id=TENANT, device_role="r", device_id=DEVICE), device_id=DEVICE,
        enforcement_mode="enforce", zone_mask=mask, receipts=writer,
    )
    writer.close()
    assert response["decision"] == "allow"
    receipts = (tmp_path / "r" / RECEIPTS_FILENAME).read_text().splitlines()
    assert len(receipts) == 1 and json.loads(receipts[0])["decision"] == "permit"


def test_an_entitlement_callable_that_raises_is_shadow_not_a_crash():
    def explode():
        raise OSError("disk gone")

    mask = ZoneMask(mode="enforce", provider=lambda _a: "red", entitlement=explode)
    assert mask.effective_mode() == ("shadow", STATUS_MALFORMED)


# --------------------------------------------------------------------------- CLI


def test_cli_flags_reach_the_entitlement_gate(tmp_path):
    path = tmp_path / "entitlement.json"
    path.write_text(json.dumps(_now_entitlement()))
    mask = _gate_zone_mask(SimpleNamespace(
        zone_mode="enforce", zone="red", zone_entitlement_file=path, zone_entitlement_keys=[BACKEND_KEY],
    ), DeviceConfig(device_id=DEVICE, tenant_id=TENANT))
    assert mask.effective_mode() == ("enforce", STATUS_OK)


def test_cli_enforce_without_entitlement_flags_is_shadow():
    mask = _gate_zone_mask(SimpleNamespace(zone_mode="enforce", zone="red"),
                           DeviceConfig(device_id=DEVICE, tenant_id=TENANT))
    assert mask.effective_mode() == ("shadow", STATUS_MISSING)


def test_cli_refuses_entitlement_keys_while_the_mask_is_off():
    with pytest.raises(ValueError, match="zone mask is off"):
        _gate_zone_mask(SimpleNamespace(zone_entitlement_keys=[BACKEND_KEY]),
                        DeviceConfig(device_id=DEVICE, tenant_id=TENANT))
