"""Backend usage ledger (plans & metering design §3; §8 tests 4 and 5).

Reports are built from a real SDK receipt log by the shipped device code (`shield.gate_usage`),
and the contract tests upload them through the shipped `UsageUploader` to the real handler, so
the device and backend halves are checked against each other rather than against a fake.
"""

from __future__ import annotations

import json
import os
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest
from integrity_sdk.did import Keypair, fingerprint_for_pubkey, public_key_multibase

from shield.backend.api import make_handler
from shield.backend.store import ShieldStore
from shield.backend.usage_ledger import UsageRejected
from shield.gate_receipts import GateReceiptWriter
from shield.gate_usage import UsageUploader, build_reports, load_cursor, save_cursor

ADMIN = "admin-token-for-usage-tests"
TENANT, DEVICE, OTHER = "tenant-u", "dev-u1", "dev-u2"
EXCLUDED = "AIS_ZONE_RESTRICTED"


def did_of(keypair: Keypair) -> str:
    return f"did:integrity:{fingerprint_for_pubkey(keypair.public_bytes())}"


class Gate:
    """A real gate receipt log that checkpoints every `every` receipts."""

    def __init__(self, directory: Path, *, signer: Keypair, log_id: str, every: int = 3):
        self.dir, self.signer = directory, signer
        self.key = public_key_multibase(signer.public_bytes())
        self.writer = GateReceiptWriter(directory, signer=signer, hmac_key=os.urandom(32), log_id=log_id, checkpoint_every=every)

    def decide(self, n: int, *, reason: str = "INTEGRITY_RULE_MATCH", decision: str = "permit") -> "Gate":
        for _ in range(n):
            self.writer.record(agent_did="did:key:agent", device_id=DEVICE, tool_name="Bash", tool_input_sha256=None,
                               event_class="tool_call", pack_hash="0x" + "ab" * 32, decision=decision, reason_code=reason,
                               mode="enforce")
        return self

    def bodies(self, *, tenant: str = TENANT, device: str = DEVICE) -> list[dict]:
        return [r.body(tenant_id=tenant, device_id=device) for r in build_reports(self.dir, {}, trusted_signers=[self.key])]


@pytest.fixture
def backend(tmp_path):
    store = ShieldStore(tmp_path / "backend.sqlite3")
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(store=store, admin_token=ADMIN))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_address[1]}"
    yield store, url
    server.shutdown()
    server.server_close()
    store.close()


def enroll(store: ShieldStore, url: str, device: str = DEVICE, *, signer: Keypair | None) -> str:
    token = store.enroll_device(tenant_id=TENANT, device_id=device, base_url=url).device_token
    if signer is not None:
        store.bind_integrity_agent(tenant_id=TENANT, device_id=device, agent_id=did_of(signer), registration_status="registered")
    return token


def post(url: str, body: dict, token: str) -> tuple[int, dict]:
    request = urllib.request.Request(url + "/api/shield/usage", data=json.dumps(body).encode(), method="POST",
                                     headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}")


def summary(url: str, period: str | None = None, token: str = ADMIN) -> tuple[int, dict]:
    query = f"?tenant_id={TENANT}" + (f"&period={period}" if period else "")
    request = urllib.request.Request(url + "/api/shield/usage" + query, headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}")


def uploader(url: str, token: str, device: str = DEVICE) -> UsageUploader:
    return UsageUploader(url, TENANT, device, token, auth_header=lambda: f"Bearer {token}")


# -- contract: the shipped uploader against the real handler ---------------------------------

def test_uploader_reports_land_in_the_ledger_and_a_replay_is_a_no_op(backend, tmp_path):
    store, url = backend
    signer = Keypair.generate()
    token = enroll(store, url, signer=signer)
    gate = Gate(tmp_path / "gate", signer=signer, log_id="shield-gate:a").decide(5).decide(2, reason=EXCLUDED, decision="deny")
    reports = build_reports(gate.dir, load_cursor(gate.dir), trusted_signers=[gate.key])
    assert [(r.seq_from, r.seq_to) for r in reports] == [(0, 2), (3, 5)]

    outcome = uploader(url, token).upload(gate.dir, reports)
    assert (outcome.acknowledged, outcome.rejected, outcome.retry_later) == (2, None, False)
    assert load_cursor(gate.dir) == {"shield-gate:a": 6}

    _, usage = summary(url)
    assert usage["totals"] == {"billable": 5, "excluded_mask": 1, "excluded_fault": 0}
    assert usage["gaps"] == []

    # A device that lost its cursor resends the same ranges: acknowledged, nothing double-counted.
    save_cursor(gate.dir, {})
    again = uploader(url, token).upload(gate.dir, build_reports(gate.dir, {}, trusted_signers=[gate.key]))
    assert (again.acknowledged, again.rejected) == (2, None)
    assert summary(url)[1]["totals"]["billable"] == 5


def test_uploader_stops_without_advancing_when_the_device_has_no_registered_key(backend, tmp_path):
    store, url = backend
    token = enroll(store, url, signer=None)
    gate = Gate(tmp_path / "gate", signer=Keypair.generate(), log_id="shield-gate:a").decide(3)
    outcome = uploader(url, token).upload(gate.dir, build_reports(gate.dir, {}, trusted_signers=[gate.key]))
    assert outcome.acknowledged == 0 and outcome.rejected and "403" in outcome.rejected
    assert "no registered signing identity" in outcome.rejected
    assert load_cursor(gate.dir) == {}


# -- §8 test 4: ledger idempotency ------------------------------------------------------------

def test_changed_body_for_a_stored_range_is_409(backend, tmp_path):
    store, url = backend
    signer = Keypair.generate()
    token = enroll(store, url, signer=signer)
    first = Gate(tmp_path / "gate", signer=signer, log_id="shield-gate:a").decide(3).bodies()[0]
    assert post(url, first, token)[0] == 201
    # Same signed checkpoint, split shifted from billable to excluded: the checkpoint still verifies
    # (it does not cover the split, design §3.4), so only the ledger can catch it.
    shifted = json.loads(json.dumps(first))
    shifted["counts"]["billable"] -= 1
    shifted["counts"]["excluded_mask"] += 1
    status, payload = post(url, shifted, token)
    assert status == 409 and "different report" in payload["error"]


def test_overlapping_range_is_refused(backend, tmp_path):
    store, url = backend
    signer = Keypair.generate()
    token = enroll(store, url, signer=signer)
    gate = Gate(tmp_path / "gate", signer=signer, log_id="shield-gate:a", every=3).decide(6)
    first, second = gate.bodies()
    assert post(url, second, token)[0] == 201           # [3..5]
    overlapping = dict(second, seq_from=2, counts={"billable": 4, "excluded_mask": 0, "excluded_fault": 0})
    status, payload = post(url, overlapping, token)    # [2..5] intersects [3..5]
    assert status == 409 and "overlaps" in payload["error"]
    assert post(url, first, token)[0] == 201            # [0..2] touches but does not overlap


def test_gap_is_flagged_not_invented_and_closes_when_filled(backend, tmp_path):
    store, url = backend
    signer = Keypair.generate()
    token = enroll(store, url, signer=signer)
    first, second, third = Gate(tmp_path / "gate", signer=signer, log_id="shield-gate:a").decide(9).bodies()
    assert post(url, first, token)[0] == 201
    assert post(url, third, token)[0] == 201
    _, usage = summary(url)
    assert usage["totals"]["billable"] == 6             # nothing invented for the hole
    assert usage["gaps"] == [{"log_id": "shield-gate:a", "device_id": DEVICE, "seq_from": 3, "seq_to": 5}]
    assert post(url, second, token)[0] == 201
    _, usage = summary(url)
    assert usage["gaps"] == [] and usage["totals"]["billable"] == 9


def test_first_range_starting_above_zero_is_a_gap(backend, tmp_path):
    store, url = backend
    signer = Keypair.generate()
    token = enroll(store, url, signer=signer)
    _, second = Gate(tmp_path / "gate", signer=signer, log_id="shield-gate:a").decide(6).bodies()
    assert post(url, second, token)[0] == 201
    assert summary(url)[1]["gaps"] == [{"log_id": "shield-gate:a", "device_id": DEVICE, "seq_from": 0, "seq_to": 2}]


def test_reinstall_is_a_new_log_and_adds_to_the_total(backend, tmp_path):
    store, url = backend
    signer = Keypair.generate()
    token = enroll(store, url, signer=signer)
    old = Gate(tmp_path / "old", signer=signer, log_id="shield-gate:old").decide(3).bodies()[0]
    new = Gate(tmp_path / "new", signer=signer, log_id="shield-gate:new").decide(3).bodies()[0]
    assert (old["seq_from"], new["seq_from"]) == (0, 0)
    assert post(url, old, token)[0] == 201 and post(url, new, token)[0] == 201
    _, usage = summary(url)
    assert usage["totals"]["billable"] == 6 and usage["devices"][0]["reports"] == 2


# -- §8 test 5: arithmetic and signatures --------------------------------------------------------

@pytest.fixture
def one_report(backend, tmp_path):
    store, url = backend
    signer = Keypair.generate()
    token = enroll(store, url, signer=signer)
    body = Gate(tmp_path / "gate", signer=signer, log_id="shield-gate:a").decide(3).bodies()[0]
    return store, url, token, body


def mutated(body: dict, **changes) -> dict:
    copy = json.loads(json.dumps(body))
    for path, value in changes.items():
        target = copy
        *parents, leaf = path.split("__")
        for parent in parents:
            target = target[parent]
        target[leaf] = value
    return copy


@pytest.mark.parametrize("changes, fragment", [
    ({"counts__billable": 2}, "sum"),
    ({"seq_to": 3, "counts__billable": 4}, "tree_size"),
    ({"checkpoint__log_id": "shield-gate:other"}, "log_id"),
    ({"checkpoint__root": "0x" + "00" * 32}, "does not verify"),
    ({"seq_from": True}, "integer"),
    ({"counts__billable": -1, "counts__excluded_mask": 4}, "negative"),
    ({"schema": "xibalba.shield.usage-report.v0"}, "schema"),
])
def test_malformed_or_forged_reports_are_400(one_report, changes, fragment):
    _, url, token, body = one_report
    status, payload = post(url, mutated(body, **changes), token)
    assert status == 400 and fragment in payload["error"]


def test_extra_fields_are_refused(one_report):
    _, url, token, body = one_report
    assert post(url, dict(body, billable_override=0), token)[0] == 400


def test_checkpoint_signed_by_another_key_is_403(backend, tmp_path):
    store, url = backend
    token = enroll(store, url, signer=Keypair.generate())
    forged = Gate(tmp_path / "gate", signer=Keypair.generate(), log_id="shield-gate:a").decide(3).bodies()[0]
    status, payload = post(url, forged, token)
    assert status == 403 and "registered key" in payload["error"]


def test_a_device_cannot_report_another_devices_log(backend, tmp_path):
    store, url = backend
    victim_key = Keypair.generate()
    enroll(store, url, DEVICE, signer=victim_key)
    attacker_token = enroll(store, url, OTHER, signer=Keypair.generate())
    stolen = Gate(tmp_path / "gate", signer=victim_key, log_id="shield-gate:a").decide(3).bodies(device=OTHER)
    status, _ = post(url, stolen[0], attacker_token)
    assert status == 403
    status, _ = post(url, dict(stolen[0], device_id=DEVICE), attacker_token)  # claims the victim's id
    assert status == 401


def test_store_refuses_a_body_for_a_different_device_than_authenticated(backend, tmp_path):
    # Two devices bound to one key (a cloned install) is the case where the signature alone cannot
    # tell them apart; the body must still speak only for the device that authenticated.
    store, url = backend
    shared = Keypair.generate()
    enroll(store, url, DEVICE, signer=shared)
    enroll(store, url, OTHER, signer=shared)
    body = Gate(tmp_path / "gate", signer=shared, log_id="shield-gate:a").decide(3).bodies()[0]
    with pytest.raises(UsageRejected) as raised:
        store.usage.record(body, tenant_id=TENANT, device_id=OTHER)
    assert raised.value.status == 403 and "its own usage" in str(raised.value)


def test_unauthenticated_report_is_401(one_report):
    _, url, _, body = one_report
    assert post(url, body, "wrong-token")[0] == 401


# -- reading ----------------------------------------------------------------------------------

def test_synthetic_devices_are_not_counted(backend, tmp_path):
    store, url = backend
    signer = Keypair.generate()
    token = enroll(store, url, signer=signer)
    assert post(url, Gate(tmp_path / "gate", signer=signer, log_id="shield-gate:a").decide(3).bodies()[0], token)[0] == 201
    store._conn.execute("UPDATE devices SET synthetic=1 WHERE tenant_id=? AND device_id=?", (TENANT, DEVICE))
    store._conn.commit()
    assert summary(url)[1]["totals"] == {"billable": 0, "excluded_mask": 0, "excluded_fault": 0}


def test_usage_is_attributed_to_the_period_it_was_received(one_report):
    store, url, token, body = one_report
    store.usage._clock = lambda: "2026-10-31T23:59:59Z"
    assert post(url, body, token)[0] == 201
    assert summary(url, "2026-10")[1]["totals"]["billable"] == 3
    assert summary(url, "2026-11")[1]["totals"]["billable"] == 0


def test_summary_requires_admin_and_a_valid_period(one_report):
    _, url, token, _ = one_report
    assert summary(url, token=token)[0] in (401, 403)
    assert summary(url, "2026-1")[0] == 400
