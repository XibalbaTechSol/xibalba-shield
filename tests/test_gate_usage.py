"""Usage reports from real gate receipts (plans & metering design §3; device side of §8 tests 4-5)."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from integrity_sdk.billing import BILLABLE, EXCLUDED_FAULT, EXCLUDED_MASK
from integrity_sdk.core.ais_local import REASON_ZONE_RESTRICTED
from integrity_sdk.did import Keypair, public_key_multibase

from shield.gate_receipts import (
    CHECKPOINTS_FILENAME,
    RECEIPTS_FILENAME,
    GateReceiptWriter,
)
from shield.gate_usage import (
    CURSOR_FILENAME,
    REPORT_SCHEMA,
    USAGE_PATH,
    UsageReportError,
    UsageUploader,
    build_reports,
    load_cursor,
    run,
    save_cursor,
)

TENANT, DEVICE = "tenant-a", "dev-1"


class Gate:
    """A real SDK receipt writer, checkpointing every `every` receipts."""

    def __init__(self, directory: Path, *, every: int = 3, log_id: str = "shield-gate:dev-1", signer=None):
        self.dir = directory
        self.signer = signer or Keypair.generate()
        self.key = public_key_multibase(self.signer.public_bytes())
        self.writer = GateReceiptWriter(directory, signer=self.signer, hmac_key=os.urandom(32),
                                        log_id=log_id, checkpoint_every=every)

    def decide(self, n: int = 1, *, decision: str = "permit", reason: str = "INTEGRITY_RULE_MATCH") -> None:
        for _ in range(n):
            self.writer.record(agent_did="did:key:agent", device_id=DEVICE, tool_name="Bash", tool_input_sha256=None, event_class="tool_call",
                               pack_hash="0x" + "ab" * 32, decision=decision, reason_code=reason, mode="enforce")

    def close(self) -> None:
        self.writer.close()


def reports(gate: Gate):
    return build_reports(gate.dir, load_cursor(gate.dir), trusted_signers=[gate.key])


def checkpoint_sizes(directory: Path) -> list[int]:
    return [json.loads(line)["tree_size"] for line in (directory / CHECKPOINTS_FILENAME).read_text().splitlines()]


class FakeBackend:
    def __init__(self, statuses=None):
        self.statuses = list(statuses or [])
        self.bodies: list[dict] = []
        self.urls: list[str] = []

    def __call__(self, url, body, headers):
        self.urls.append(url)
        self.bodies.append(json.loads(body))
        status = self.statuses.pop(0) if self.statuses else 200
        if isinstance(status, Exception):
            raise status
        return status, "{}"


def uploader(backend) -> UsageUploader:
    return UsageUploader("https://shield.example/", TENANT, DEVICE, "tok", transport=backend, auth_header=lambda: "Bearer t")


# ---------------------------------------------------------------- building


def test_each_report_ends_exactly_on_a_signed_checkpoint(tmp_path):
    gate = Gate(tmp_path, every=3)
    gate.decide(7)  # checkpoints at 3 and 6; receipt 7 is not yet covered
    got = reports(gate)
    assert [(r.seq_from, r.seq_to) for r in got] == [(0, 2), (3, 5)]
    assert [r.checkpoint["tree_size"] for r in got] == [3, 6]
    assert all(r.checkpoint["tree_size"] == r.seq_to + 1 for r in got)


def test_nothing_past_the_last_checkpoint_is_reported(tmp_path):
    gate = Gate(tmp_path, every=5)
    gate.decide(4)
    assert reports(gate) == []
    gate.decide(1)
    assert [(r.seq_from, r.seq_to) for r in reports(gate)] == [(0, 4)]


def test_clean_close_checkpoint_makes_the_tail_reportable_once(tmp_path):
    gate = Gate(tmp_path, every=3)
    gate.decide(4)
    gate.close()  # final checkpoint at 4
    assert [(r.seq_from, r.seq_to) for r in reports(gate)] == [(0, 2), (3, 3)]


def test_counts_sum_to_the_range_and_exclude_mask_denials_and_gate_faults(tmp_path):
    gate = Gate(tmp_path, every=6)
    gate.decide(2, decision="permit")
    gate.decide(1, decision="deny", reason="INTEGRITY_NO_MATCH")
    gate.decide(1, decision="deny", reason=REASON_ZONE_RESTRICTED)
    gate.decide(1, decision="deny", reason="INTEGRITY_EVALUATOR_ERROR")
    gate.decide(1, decision="deny", reason="INTEGRITY_NO_PACK")
    (report,) = reports(gate)
    assert report.counts == {BILLABLE: 3, EXCLUDED_MASK: 1, EXCLUDED_FAULT: 2}
    assert sum(report.counts.values()) == report.seq_to - report.seq_from + 1


def test_report_body_is_the_design_schema(tmp_path):
    gate = Gate(tmp_path, every=2)
    gate.decide(2)
    (report,) = reports(gate)
    body = report.body(tenant_id=TENANT, device_id=DEVICE)
    assert set(body) == {"schema", "tenant_id", "device_id", "log_id", "seq_from", "seq_to", "counts", "checkpoint"}
    assert body["schema"] == REPORT_SCHEMA
    assert body["checkpoint"]["signature"] and body["checkpoint"]["log_id"] == body["log_id"]


def test_a_tampered_receipt_is_refused(tmp_path):
    gate = Gate(tmp_path, every=3)
    gate.decide(3)
    path = tmp_path / RECEIPTS_FILENAME
    lines = path.read_text().splitlines()
    row = json.loads(lines[1])
    row["reason_code"] = REASON_ZONE_RESTRICTED  # reclassify a billable call as a mask denial
    lines[1] = json.dumps(row)
    path.write_text("\n".join(lines) + "\n")
    with pytest.raises(UsageReportError, match="does not verify"):
        reports(gate)


def test_a_log_signed_by_another_key_is_refused(tmp_path):
    gate = Gate(tmp_path, every=2)
    gate.decide(2)
    other = public_key_multibase(Keypair.generate().public_bytes())
    with pytest.raises(UsageReportError):
        build_reports(tmp_path, {}, trusted_signers=[other])


def test_a_signing_key_is_required(tmp_path):
    gate = Gate(tmp_path, every=2)
    gate.decide(2)
    with pytest.raises(UsageReportError, match="trusted receipt signer"):
        build_reports(tmp_path, {}, trusted_signers=[])


def test_a_torn_final_line_is_ignored_and_left_in_place(tmp_path):
    gate = Gate(tmp_path, every=2)
    gate.decide(2)
    path = tmp_path / RECEIPTS_FILENAME
    with path.open("ab") as handle:
        handle.write(b'{"partial":')
    before = path.read_bytes()
    assert [(r.seq_from, r.seq_to) for r in reports(gate)] == [(0, 1)]
    assert path.read_bytes() == before, "the reporter must never repair the writer's files"


def test_a_cursor_beyond_the_log_is_refused_not_silently_reset(tmp_path):
    gate = Gate(tmp_path, every=2)
    gate.decide(2)
    with pytest.raises(UsageReportError, match="truncated or replaced"):
        build_reports(tmp_path, {gate.writer.log_id: 10}, trusted_signers=[gate.key])


# ---------------------------------------------------------------- cursor


def test_cursor_round_trips_atomically(tmp_path):
    save_cursor(tmp_path, {"a": 3, "b": 9})
    assert load_cursor(tmp_path) == {"a": 3, "b": 9}
    assert [p.name for p in tmp_path.iterdir()] == [CURSOR_FILENAME]


def test_a_corrupt_cursor_is_an_error(tmp_path):
    (tmp_path / CURSOR_FILENAME).write_text("{not json")
    with pytest.raises(UsageReportError):
        load_cursor(tmp_path)


def test_a_second_pass_after_acknowledgement_emits_nothing(tmp_path):
    gate = Gate(tmp_path, every=3)
    gate.decide(6)
    backend = FakeBackend()
    up = uploader(backend)
    assert up.upload(tmp_path, reports(gate)).acknowledged == 2
    assert reports(gate) == []
    gate.decide(3)
    assert [(r.seq_from, r.seq_to) for r in reports(gate)] == [(6, 8)]


def test_a_reinstall_with_a_new_log_id_starts_from_zero(tmp_path):
    old = Gate(tmp_path / "old", every=2, log_id="shield-gate:old")
    old.decide(4)
    uploader(FakeBackend()).upload(old.dir, reports(old))
    cursor = load_cursor(old.dir)
    assert cursor == {"shield-gate:old": 4}

    new_dir = tmp_path / "new"
    new = Gate(new_dir, every=2, log_id="shield-gate:new", signer=old.signer)
    new.decide(2)
    save_cursor(new_dir, cursor)  # the cursor survived the reinstall
    got = build_reports(new_dir, load_cursor(new_dir), trusted_signers=[new.key])
    assert [(r.log_id, r.seq_from, r.seq_to) for r in got] == [("shield-gate:new", 0, 1)]


# ---------------------------------------------------------------- uploading


def test_upload_posts_each_report_in_order_and_advances_on_2xx(tmp_path):
    gate = Gate(tmp_path, every=2)
    gate.decide(4)
    backend = FakeBackend([200, 201])
    outcome = uploader(backend).upload(tmp_path, reports(gate))
    assert (outcome.acknowledged, outcome.retry_later, outcome.rejected) == (2, False, None)
    assert backend.urls == ["https://shield.example" + USAGE_PATH] * 2
    assert [b["seq_from"] for b in backend.bodies] == [0, 2]
    assert all(b["tenant_id"] == TENANT and b["device_id"] == DEVICE for b in backend.bodies)
    assert load_cursor(tmp_path) == {gate.writer.log_id: 4}


@pytest.mark.parametrize("failure", [404, 500, 503, 429, OSError("connection refused")])
def test_unreachable_or_undeployed_backend_does_not_advance_and_asks_for_retry(tmp_path, failure):
    gate = Gate(tmp_path, every=2)
    gate.decide(4)
    outcome = uploader(FakeBackend([failure])).upload(tmp_path, reports(gate))
    assert outcome.retry_later and outcome.acknowledged == 0 and outcome.rejected is None
    assert load_cursor(tmp_path) == {}
    assert len(reports(gate)) == 2, "both ranges are still pending"


def test_a_failure_mid_batch_keeps_the_acknowledged_prefix(tmp_path):
    gate = Gate(tmp_path, every=2)
    gate.decide(6)
    outcome = uploader(FakeBackend([200, 503])).upload(tmp_path, reports(gate))
    assert outcome.acknowledged == 1 and outcome.retry_later
    assert load_cursor(tmp_path) == {gate.writer.log_id: 2}
    assert [(r.seq_from, r.seq_to) for r in reports(gate)] == [(2, 3), (4, 5)]


@pytest.mark.parametrize("status", [400, 401, 403, 409, 422])
def test_a_refused_range_stops_without_advancing(tmp_path, status):
    gate = Gate(tmp_path, every=2)
    gate.decide(4)
    backend = FakeBackend([status])
    outcome = uploader(backend).upload(tmp_path, reports(gate))
    assert outcome.rejected and outcome.rejected.startswith(f"HTTP {status}")
    assert len(backend.bodies) == 1, "later ranges are not sent past a refusal"
    assert load_cursor(tmp_path) == {}


def test_run_once_exit_codes(tmp_path):
    gate = Gate(tmp_path, every=2)
    gate.decide(2)
    assert run(tmp_path, uploader(FakeBackend([503])), trusted_signers=[gate.key], once=True) == 3
    assert run(tmp_path, uploader(FakeBackend([400])), trusted_signers=[gate.key], once=True) == 1
    assert run(tmp_path, uploader(FakeBackend([200])), trusted_signers=[gate.key], once=True) == 0
    assert run(tmp_path, uploader(FakeBackend()), trusted_signers=[gate.key], once=True) == 0  # nothing pending


def test_run_backs_off_on_retry_and_does_not_spin(tmp_path):
    gate = Gate(tmp_path, every=2)
    gate.decide(2)
    slept: list[float] = []

    class Stop(Exception):
        pass

    def sleep(seconds):
        slept.append(seconds)
        if len(slept) == 3:
            raise Stop

    with pytest.raises(Stop):
        run(tmp_path, uploader(FakeBackend([503, 503, 503])), trusted_signers=[gate.key],
            sleep=sleep, delays=iter([5.0, 10.0, 20.0]))
    assert slept == [5.0, 10.0, 20.0]


def test_the_cli_dry_run_prints_pending_reports_without_network(tmp_path, capsys):
    from shield.cli import main

    gate = Gate(tmp_path / "r", every=2)
    gate.decide(3)
    key = tmp_path / "key.pem"
    key.write_bytes(gate.signer.private_pem())
    key.chmod(0o600)
    assert main(["usage-report", "--receipt-dir", str(gate.dir), "--receipt-key", str(key), "--dry-run"]) == 0
    printed = json.loads(capsys.readouterr().out)
    assert [(r["seq_from"], r["seq_to"]) for r in printed] == [(0, 1)]
    assert not (gate.dir / CURSOR_FILENAME).exists()
