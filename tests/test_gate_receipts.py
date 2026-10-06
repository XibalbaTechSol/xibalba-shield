"""Tests for the gate daemon's signed, chained receipts (docs/EXECUTION_PLAN.md B2).

Three layers, on purpose:

1. `GateReceiptWriter` on its own: chain, checkpoints, restart, and every way a log can be
   damaged. Receipts are verified with the SDK's own `verify_log`, never with code written here,
   so these tests cannot agree with a bug in the writer by sharing it.
2. The daemon over a real Unix socket with stub evaluators: wire contract, observe mode,
   write failures, strict mode.
3. The daemon over a real socket against a real supervised OPA and a real signed pack, because a
   receipt that only ever recorded a stub's verdict would prove nothing about what the pack said.

Regression tests were mutation-checked: each was run against the code with the guard it covers
removed, to confirm it fails there.
"""

from __future__ import annotations

import json
import logging
import os
import signal
import socket
import subprocess
import sys
import textwrap
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from integrity_sdk.core.receipts import ReceiptError, receipt_hash, verify_log
from integrity_sdk.did import Keypair, public_key_multibase

import shield.gate_receipts as gate_receipts
from shield.gate_daemon import GateServer, evaluate_pre_tool_use, GateRequest
from shield.gate_receipts import (
    CHECKPOINTS_FILENAME,
    RECEIPTS_FILENAME,
    GateReceiptWriter,
    ReceiptSetupError,
    ReceiptWriteError,
    default_log_id,
    load_hmac_key,
    load_signer,
)
from shield.opa_local import supervised_opa
from shield.policy_engine.engine import (
    NO_PACK_HASH,
    DecisionBasis,
    EvaluationContext,
    PolicyEngine,
)
from shield.schemas.events import Decision, EventRef, PolicyDecision, PolicyRef, RuleRef

_DIGEST = "ab" * 32
_PACK_HASH = "sha256:" + "cd" * 32
_LOG_ID = "shield-gate:dev-1"
_REPO_ROOT = Path(__file__).resolve().parents[1]


# ------------------------------------------------------------------------------ helpers


@pytest.fixture
def keys():
    return Keypair.generate(), os.urandom(32)


def _writer(tmp_path: Path, keys, **overrides) -> GateReceiptWriter:
    signer, hmac_key = keys
    kwargs = dict(signer=signer, hmac_key=hmac_key, log_id=_LOG_ID)
    kwargs.update(overrides)
    return GateReceiptWriter(tmp_path / "receipts", **kwargs)


def _record(writer: GateReceiptWriter, index: int = 0, **overrides):
    kwargs = dict(
        agent_did=f"did:key:agent-{index}", device_id="dev-1", tool_name="Bash",
        tool_input_sha256=_DIGEST, event_class="agent_event", pack_hash=_PACK_HASH,
        decision="permit", reason_code="ALLOWED", mode="enforce", controls=("C-1",),
    )
    kwargs.update(overrides)
    return writer.record(**kwargs)


def _lines(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_bytes().splitlines()]


def _logs(tmp_path: Path) -> tuple[list[dict], list[dict]]:
    base = tmp_path / "receipts"
    return _lines(base / RECEIPTS_FILENAME), _lines(base / CHECKPOINTS_FILENAME)


def _verify(tmp_path: Path, signer_key: str) -> list[dict]:
    """Verify exactly what is on disk, the way an auditor would, and return the receipts."""
    receipts, checkpoints = _logs(tmp_path)
    verify_log(receipts, trusted_signers=[signer_key], checkpoint=checkpoints[-1] if checkpoints else None)
    return receipts


# ----------------------------------------------------------------- writer: chain & privacy


def test_receipts_form_a_chain_that_verifies_offline(tmp_path, keys):
    writer = _writer(tmp_path, keys)
    refs = [_record(writer, i) for i in range(5)]
    writer.close()
    receipts = _verify(tmp_path, writer.signer_key)
    assert [r["seq"] for r in receipts] == [0, 1, 2, 3, 4]
    assert [ref.seq for ref in refs] == [0, 1, 2, 3, 4]
    # The hash the caller is told about is the hash of the receipt that is on disk.
    assert [ref.hash for ref in refs] == [receipt_hash(r) for r in receipts]


def test_the_device_and_tool_are_hmac_hidden_but_the_agent_is_named(tmp_path, keys):
    writer = _writer(tmp_path, keys)
    _record(writer, 7, device_id="serial-MRN-0042", tool_name="SecretToolName")
    writer.close()
    raw = (tmp_path / "receipts" / RECEIPTS_FILENAME).read_bytes()
    assert b"serial-MRN-0042" not in raw and b"SecretToolName" not in raw
    assert raw.count(b"hmac-sha256:") == 2
    assert b"did:key:agent-7" in raw  # the agent DID is an identifier by design


def test_the_default_log_id_keeps_the_device_id_out_of_the_file(tmp_path, keys):
    """`log_id` is stored in every receipt in the clear. Deriving it from the raw device id put
    that id in the file the HMAC identifiers exist to keep it out of; only a live run against the
    real file showed it, because the other privacy test used a fixed log id."""
    signer, hmac_key = keys
    log_id = default_log_id(hmac_key, "serial-MRN-0042")
    assert "serial-MRN-0042" not in log_id
    assert log_id == default_log_id(hmac_key, "serial-MRN-0042")  # stable, or resume would refuse
    assert log_id != default_log_id(hmac_key, "serial-MRN-0043")
    assert log_id != default_log_id(os.urandom(32), "serial-MRN-0042")
    writer = GateReceiptWriter(tmp_path / "receipts", signer=signer, hmac_key=hmac_key, log_id=log_id)
    _record(writer, device_id="serial-MRN-0042")
    writer.close()
    assert b"serial-MRN-0042" not in (tmp_path / "receipts" / RECEIPTS_FILENAME).read_bytes()
    assert b"serial-MRN-0042" not in (tmp_path / "receipts" / CHECKPOINTS_FILENAME).read_bytes()


def test_the_action_identifier_binds_the_input_digest(tmp_path, keys):
    writer = _writer(tmp_path, keys)
    _record(writer, tool_input_sha256="11" * 32)
    _record(writer, tool_input_sha256="22" * 32)
    _record(writer, tool_input_sha256=None)
    receipts, _ = _logs(tmp_path)
    assert len({r["action_hmac"] for r in receipts}) == 3
    assert len({r["device_id_hmac"] for r in receipts}) == 1


def test_the_log_directory_and_files_are_private_to_the_owner(tmp_path, keys):
    writer = _writer(tmp_path, keys)
    _record(writer)
    writer.close()
    base = tmp_path / "receipts"
    assert (base.stat().st_mode & 0o777) == 0o700
    for name in (RECEIPTS_FILENAME, CHECKPOINTS_FILENAME):
        assert ((base / name).stat().st_mode & 0o777) == 0o600


# -------------------------------------------------------------- writer: restart, checkpoints


def test_a_restart_continues_the_same_chain(tmp_path, keys):
    first = _writer(tmp_path, keys)
    for i in range(3):
        _record(first, i)
    first.close()
    second = _writer(tmp_path, keys)
    assert second.receipt_count == 3
    ref = _record(second, 3)
    second.close()
    assert ref.seq == 3
    assert [r["seq"] for r in _verify(tmp_path, second.signer_key)] == [0, 1, 2, 3]


def test_checkpoints_are_periodic_signed_and_referenced_by_later_receipts(tmp_path, keys):
    writer = _writer(tmp_path, keys, checkpoint_every=3)
    for i in range(7):
        _record(writer, i)
    receipts, checkpoints = _logs(tmp_path)
    assert [c["tree_size"] for c in checkpoints] == [3, 6]
    assert receipts[3]["checkpoint_reference"]["tree_size"] == 3
    assert receipts[6]["checkpoint_reference"]["tree_size"] == 6
    assert receipts[2]["checkpoint_reference"] is None
    writer.close()
    # A clean stop commits to everything recorded, including the receipts after the last cadence.
    _, checkpoints = _logs(tmp_path)
    assert [c["tree_size"] for c in checkpoints] == [3, 6, 7]
    _verify(tmp_path, writer.signer_key)


def test_close_is_idempotent_and_stops_further_records(tmp_path, keys):
    writer = _writer(tmp_path, keys)
    _record(writer)
    writer.close()
    writer.close()
    with pytest.raises(ReceiptWriteError):
        _record(writer)
    assert len(_logs(tmp_path)[0]) == 1


def test_concurrent_requests_cannot_fork_the_chain(tmp_path, keys):
    """The daemon is a threaded server. Without one lock around build-write-advance, two threads
    read the same head and sign two receipts with one seq and one prev_hash."""
    writer = _writer(tmp_path, keys, checkpoint_every=50)
    errors: list[BaseException] = []

    def worker(base: int) -> None:
        try:
            for i in range(25):
                _record(writer, base * 100 + i)
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    writer.close()
    assert not errors
    receipts = _verify(tmp_path, writer.signer_key)
    assert [r["seq"] for r in receipts] == list(range(200))


# ------------------------------------------------------ writer: damage and refusing to start


def test_a_torn_final_line_is_discarded_and_the_chain_continues(tmp_path, keys, caplog):
    """A crash mid-write leaves a last line with no newline. The daemon answers only after the
    newline and fsync, so that record was never acknowledged; losing it loses nothing anyone saw."""
    first = _writer(tmp_path, keys)
    for i in range(3):
        _record(first, i)
    first.close()
    path = tmp_path / "receipts" / RECEIPTS_FILENAME
    path.write_bytes(path.read_bytes() + b'{"receipt_version":"integrity.receipt/1","seq":3,"pre')
    with caplog.at_level(logging.WARNING, logger="shield.gate_receipts"):
        second = _writer(tmp_path, keys)
    assert "incomplete line" in caplog.text
    assert second.receipt_count == 3
    assert path.read_bytes().endswith(b"\n")
    assert _record(second, 3).seq == 3
    second.close()
    assert [r["seq"] for r in _verify(tmp_path, second.signer_key)] == [0, 1, 2, 3]


def test_a_complete_but_corrupt_line_refuses_to_start(tmp_path, keys):
    first = _writer(tmp_path, keys)
    _record(first)
    first.close()
    path = tmp_path / "receipts" / RECEIPTS_FILENAME
    path.write_bytes(path.read_bytes() + b"this is not json\n")
    with pytest.raises(ReceiptSetupError, match="not valid JSON"):
        _writer(tmp_path, keys)


def test_editing_a_recorded_decision_refuses_to_start(tmp_path, keys):
    first = _writer(tmp_path, keys)
    for i in range(3):
        _record(first, i, decision="deny", reason_code="DENIED")
    first.close()
    path = tmp_path / "receipts" / RECEIPTS_FILENAME
    rows = _lines(path)
    rows[1]["decision"] = "permit"  # flip a recorded deny into a permit
    path.write_bytes(b"".join(json.dumps(r, sort_keys=True).encode() + b"\n" for r in rows))
    with pytest.raises(ReceiptSetupError, match="BAD_SIGNATURE"):
        _writer(tmp_path, keys)


def test_removing_the_tail_after_a_checkpoint_refuses_to_start(tmp_path, keys):
    """A bare hash chain cannot show tail truncation; a checkpoint is what does."""
    first = _writer(tmp_path, keys)
    for i in range(5):
        _record(first, i)
    first.checkpoint()
    first.close()
    path = tmp_path / "receipts" / RECEIPTS_FILENAME
    path.write_bytes(b"".join(line + b"\n" for line in path.read_bytes().splitlines()[:3]))
    with pytest.raises(ReceiptSetupError, match="TRUNCATED"):
        _writer(tmp_path, keys)


def test_a_different_signing_key_refuses_to_extend_the_log(tmp_path, keys):
    first = _writer(tmp_path, keys)
    _record(first)
    first.close()
    with pytest.raises(ReceiptSetupError, match="UNTRUSTED_SIGNER"):
        _writer(tmp_path, (Keypair.generate(), keys[1]))


def test_a_log_belonging_to_another_device_refuses_to_start(tmp_path, keys):
    """`ReceiptLog.resume` verifies against whatever log id the receipts carry; without this check
    a daemon configured for one device would resume, and extend, another device's log."""
    first = _writer(tmp_path, keys, log_id="shield-gate:other-device")
    _record(first)
    first.close()
    with pytest.raises(ReceiptSetupError, match="shield-gate:other-device"):
        _writer(tmp_path, keys)


# --------------------------------------------------------------- writer: write failures


def _failing_write(monkeypatch, writer: GateReceiptWriter, *, partial: int = 0):
    """Make the next write to the receipt file fail, optionally after writing `partial` bytes."""
    real_write = os.write
    state = {"armed": True}

    def write(fd, data):
        if state["armed"] and fd == writer._receipts_fd:
            state["armed"] = False
            if partial:
                real_write(fd, bytes(data[:partial]))
            raise OSError(28, "No space left on device")
        return real_write(fd, data)

    monkeypatch.setattr(gate_receipts.os, "write", write)


def test_a_failed_write_does_not_advance_the_chain(tmp_path, keys, monkeypatch):
    writer = _writer(tmp_path, keys)
    _record(writer, 0)
    _failing_write(monkeypatch, writer)
    with pytest.raises(ReceiptWriteError, match="No space left"):
        _record(writer, 1)
    assert writer.receipt_count == 1
    assert _record(writer, 2).seq == 1  # still contiguous: the failed receipt left no hole
    writer.close()
    assert [r["seq"] for r in _verify(tmp_path, writer.signer_key)] == [0, 1]


def test_a_partial_write_is_rolled_back_off_the_disk(tmp_path, keys, monkeypatch):
    """Bytes that landed before the error must not stay: the next append would follow them."""
    writer = _writer(tmp_path, keys)
    _record(writer, 0)
    _failing_write(monkeypatch, writer, partial=17)
    with pytest.raises(ReceiptWriteError):
        _record(writer, 1)
    _record(writer, 2)
    writer.close()
    assert all(line.startswith(b"{") for line in (tmp_path / "receipts" / RECEIPTS_FILENAME).read_bytes().splitlines())
    reopened = _writer(tmp_path, keys)  # resume re-verifies the whole file
    assert reopened.receipt_count == 2
    reopened.close()


def test_a_write_that_cannot_be_rolled_back_disables_the_writer(tmp_path, keys, monkeypatch):
    writer = _writer(tmp_path, keys)
    _record(writer, 0)
    _failing_write(monkeypatch, writer, partial=17)

    def broken_truncate(*_args):
        raise OSError(5, "Input/output error")

    monkeypatch.setattr(gate_receipts.os, "ftruncate", broken_truncate)
    with pytest.raises(ReceiptWriteError):
        _record(writer, 1)
    with pytest.raises(ReceiptWriteError, match="disabled"):
        _record(writer, 2)


# ------------------------------------------------------------------------- key hygiene


def test_key_files_must_be_private_and_long_enough(tmp_path):
    hmac_path = tmp_path / "hmac.key"
    hmac_path.write_bytes(os.urandom(32))
    hmac_path.chmod(0o644)
    with pytest.raises(ReceiptSetupError, match="chmod 600"):
        load_hmac_key(hmac_path)
    hmac_path.chmod(0o600)
    assert len(load_hmac_key(hmac_path)) == 32

    short = tmp_path / "short.key"
    short.write_bytes(b"x" * 16)
    short.chmod(0o600)
    with pytest.raises(ReceiptSetupError, match="at least 32"):
        load_hmac_key(short)

    pem = tmp_path / "signer.pem"
    pem.write_bytes(b"not a pem")
    pem.chmod(0o600)
    with pytest.raises(ReceiptSetupError, match="Ed25519 PEM"):
        load_signer(pem)
    with pytest.raises(ReceiptSetupError, match="cannot read"):
        load_signer(tmp_path / "missing.pem")


def test_a_short_hmac_key_is_refused_by_the_writer_itself(tmp_path):
    with pytest.raises(ReceiptSetupError, match="at least 32"):
        GateReceiptWriter(tmp_path / "r", signer=Keypair.generate(), hmac_key=b"short", log_id=_LOG_ID)


# ----------------------------------------------------------- daemon: stub evaluators, wire


def _decision(action: str = "allow") -> PolicyDecision:
    return PolicyDecision(
        device_id="dev-1", event_ref=EventRef(klass="agent_event", event_id="evt-1"),
        rule=RuleRef(rule_id="rule-1", name="A rule", version="1"),
        policy=PolicyRef(version="1.2.3", hash=_PACK_HASH),
        decision=Decision(action=action, reason="because"),
    )


def _basis(decision: str = "permit", reason_code: str = "ALLOWED", controls=("C-1",)) -> DecisionBasis:
    return DecisionBasis(decision, reason_code, tuple(controls), _PACK_HASH, "agent_event")


def _basis_evaluator(action: str = "allow", **basis_kwargs):
    def evaluate(_event, _ctx):
        return _decision(action), _basis(**basis_kwargs)
    return evaluate


def _ctx(**kwargs) -> EvaluationContext:
    return EvaluationContext(tenant_id="t", device_role="r", device_id="dev-1", **kwargs)


class _Running:
    """A GateServer on a real socket, with receipts, in a background thread."""

    def __init__(self, tmp_path: Path, *, basis_evaluator, writer, mode="enforce", strict=False, ctx=None):
        self.path = tmp_path / "gate.sock"
        self.server = GateServer(
            self.path, evaluator=lambda e, c: basis_evaluator(e, c)[0], ctx=ctx or _ctx(),
            device_id="dev-1", enforcement_mode=mode, basis_evaluator=basis_evaluator,
            receipts=writer, strict_receipts=strict,
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_exc):
        self.server.shutdown()
        self.server.server_close()  # also closes the writer, which writes the final checkpoint
        self.thread.join(timeout=5)

    def ask(self, request: dict | str) -> dict:
        raw = request if isinstance(request, str) else json.dumps(request)
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(10)
        try:
            client.connect(str(self.path))
            client.sendall(raw.encode() + b"\n")
            line = client.makefile("rb").readline()
        finally:
            client.close()
        assert line
        return json.loads(line)


def _req(**overrides) -> dict:
    payload = {"v": 1, "event": "pre_tool_use", "agent_id": "agent-1", "tool_name": "Bash",
               "tool_input_sha256": _DIGEST}
    payload.update(overrides)
    return payload


def test_the_response_names_the_receipt_and_it_is_the_one_on_disk(tmp_path, keys):
    writer = _writer(tmp_path, keys)
    with _Running(tmp_path, basis_evaluator=_basis_evaluator(), writer=writer) as server:
        response = server.ask(_req())
    assert response["receipt_status"] == "recorded"
    assert response["receipt"]["seq"] == 0
    receipts = _verify(tmp_path, writer.signer_key)
    assert response["receipt"]["hash"] == receipt_hash(receipts[0])
    assert receipts[0]["agent_did"] == "agent-1"
    assert receipts[0]["mode"] == "enforce" and receipts[0]["decision"] == "permit"
    assert receipts[0]["pack_hash"] == _PACK_HASH


def test_a_receipt_is_written_before_the_answer_is_sent(tmp_path, keys):
    """The caller must never be told about a receipt that is not on disk yet."""
    writer = _writer(tmp_path, keys)
    with _Running(tmp_path, basis_evaluator=_basis_evaluator(), writer=writer) as server:
        response = server.ask(_req())
        # No close, no sleep: the file already holds what the response promised.
        on_disk = _lines(tmp_path / "receipts" / RECEIPTS_FILENAME)
    assert receipt_hash(on_disk[response["receipt"]["seq"]]) == response["receipt"]["hash"]


def test_observe_mode_allows_but_the_receipt_records_the_verdict_it_would_have_enforced(tmp_path, keys):
    writer = _writer(tmp_path, keys)
    evaluator = _basis_evaluator("deny", decision="deny", reason_code="DENIED")
    with _Running(tmp_path, basis_evaluator=evaluator, writer=writer, mode="observe") as server:
        response = server.ask(_req())
    assert response["decision"] == "allow" and response["enforced"] is False
    receipt = _verify(tmp_path, writer.signer_key)[0]
    assert receipt["mode"] == "shadow"
    assert receipt["decision"] == "deny" and receipt["reason_code"] == "DENIED"


def test_an_evaluator_that_raises_is_recorded_as_a_deny_with_no_pack(tmp_path, keys):
    writer = _writer(tmp_path, keys)

    def raising(_event, _ctx):
        raise RuntimeError("engine blew up")

    with _Running(tmp_path, basis_evaluator=raising, writer=writer) as server:
        response = server.ask(_req())
    assert response["decision"] == "deny"
    receipt = _verify(tmp_path, writer.signer_key)[0]
    assert (receipt["decision"], receipt["reason_code"]) == ("deny", "INTEGRITY_EVALUATOR_ERROR")
    assert receipt["pack_hash"] == NO_PACK_HASH


def test_a_malformed_request_is_refused_and_leaves_no_receipt(tmp_path, keys):
    writer = _writer(tmp_path, keys)
    with _Running(tmp_path, basis_evaluator=_basis_evaluator(), writer=writer) as server:
        response = server.ask("this is not json")
    assert response["decision"] == "deny"
    assert response["receipt"] is None and response["receipt_status"] == "skipped"
    assert _logs(tmp_path)[0] == []


def test_without_receipts_the_response_says_disabled_not_nothing(tmp_path):
    response = evaluate_pre_tool_use(
        GateRequest(agent_id="a", tool_name="Bash", tool_input_sha256=_DIGEST),
        evaluator=lambda e, c: _decision("allow"), ctx=_ctx(), device_id="dev-1",
    )
    assert response["receipt"] is None and response["receipt_status"] == "disabled"


def test_receipts_without_a_basis_evaluator_is_a_configuration_error(tmp_path, keys):
    with pytest.raises(ValueError, match="basis_evaluator"):
        evaluate_pre_tool_use(
            GateRequest(agent_id="a", tool_name="Bash"), evaluator=lambda e, c: _decision(),
            ctx=_ctx(), device_id="dev-1", receipts=_writer(tmp_path, keys),
        )
    with pytest.raises(ValueError, match="basis_evaluator"):
        GateServer(tmp_path / "x.sock", evaluator=lambda e, c: _decision(), ctx=_ctx(),
                   device_id="dev-1", receipts=_writer(tmp_path, keys))


def _break_writes(monkeypatch, writer):
    """Every write to the receipt file fails from now on."""
    real_write = os.write

    def write(fd, data):
        if fd == writer._receipts_fd:
            raise OSError(5, "Input/output error")
        return real_write(fd, data)

    monkeypatch.setattr(gate_receipts.os, "write", write)


def test_a_receipt_that_cannot_be_written_leaves_the_decision_standing_and_says_so(tmp_path, keys, monkeypatch, caplog):
    writer = _writer(tmp_path, keys)
    _break_writes(monkeypatch, writer)
    with caplog.at_level(logging.ERROR, logger="shield.gate_daemon"):
        with _Running(tmp_path, basis_evaluator=_basis_evaluator(), writer=writer) as server:
            response = server.ask(_req())
    assert response["decision"] == "allow", "an audit failure must not become a policy decision by default"
    assert response["receipt"] is None and response["receipt_status"] == "failed"
    assert "receipt NOT recorded" in caplog.text


def test_strict_mode_denies_a_call_whose_receipt_cannot_be_written(tmp_path, keys, monkeypatch):
    writer = _writer(tmp_path, keys)
    _break_writes(monkeypatch, writer)
    with _Running(tmp_path, basis_evaluator=_basis_evaluator(), writer=writer, strict=True) as server:
        response = server.ask(_req())
    assert response["decision"] == "deny" and response["enforced"] is True
    assert response["rule_id"] == "_receipt_unavailable"
    assert response["receipt_status"] == "failed"


def test_strict_mode_never_blocks_in_observe_mode(tmp_path, keys, monkeypatch):
    writer = _writer(tmp_path, keys)
    _break_writes(monkeypatch, writer)
    with _Running(tmp_path, basis_evaluator=_basis_evaluator(), writer=writer, mode="observe", strict=True) as server:
        response = server.ask(_req())
    assert response["decision"] == "allow"
    assert response["receipt_status"] == "failed"


# --------------------------------------------------------- engine: the decision basis


def test_evaluate_with_basis_matches_evaluate_and_records_the_final_verdict(monkeypatch):
    """The local risk gate can harden a verdict after the pack answered. The receipt must record
    that final verdict: `permit` for a call the gate then contained would be a false statement."""
    from shield.policy_engine import engine as engine_module
    from shield.schemas.events import AgentActivity, AgentContext, AgentEvent, AgentInfo

    event = AgentEvent(
        device_id="dev-1", agent=AgentInfo(agent_id="agent-1", name="agent-1", type="llm_tool"),
        context=AgentContext(tools_called=["Bash"]), activity=AgentActivity(type="tool_execution", risk_level="low"),
    )
    ctx = _ctx(registered_agent_ids=frozenset({"agent-1"}))
    with supervised_opa("smb") as (opa_url, pack):
        engine = PolicyEngine(opa_url=opa_url, pack=pack)
        decision, basis = engine.evaluate_with_basis(event, ctx)
        assert decision.decision.action == "log_only" == engine.evaluate(event, ctx).decision.action
        assert (basis.decision, basis.reason_code) == ("log_only", "INTEGRITY_NO_MATCH")
        assert basis.pack_hash == pack.pack_hash and basis.event_class == "agent_event"

        # Now let the local risk gate contain an otherwise permissive result.
        monkeypatch.setattr(engine_module, "assess_event", lambda _event: SimpleNamespace(
            suggested_action="contain", signals=[SimpleNamespace(reason="synthetic evidence")],
            confidence=1.0, human_required=False, score=99,
        ))
        contained, basis = engine.evaluate_with_basis(event, ctx)
    assert contained.decision.action == "contain"
    assert (basis.decision, basis.reason_code) == ("deny", "INTEGRITY_LOCAL_RISK_CONTAIN")
    assert basis.controls == ()


# --------------------------------------------------------------- real OPA, real pack


def _engine_server(tmp_path, keys, opa_url, pack, ctx, *, writer_kwargs=None, **kwargs):
    writer = _writer(tmp_path, keys, **(writer_kwargs or {}))
    engine = PolicyEngine(opa_url=opa_url, pack=pack)
    return writer, _Running(tmp_path, basis_evaluator=engine.evaluate_with_basis, writer=writer, ctx=ctx, **kwargs)


def test_a_real_rego_deny_is_recorded_with_the_packs_own_reason_code(tmp_path, keys):
    with supervised_opa("smb") as (opa_url, pack):
        writer, server = _engine_server(tmp_path, keys, opa_url, pack, _ctx())  # nobody registered
        with server:
            response = server.ask(_req())
    assert response["decision"] == "deny" and response["receipt_status"] == "recorded"
    receipt = _verify(tmp_path, writer.signer_key)[0]
    assert (receipt["decision"], receipt["reason_code"]) == ("deny", "SMB_DENY_UNREGISTERED_AGENT")
    assert receipt["pack_hash"] == pack.pack_hash == response["policy_hash"]
    assert receipt["event_class"] == "agent_event"
    assert receipt["mode"] == "enforce"


def test_pack_defaults_are_recorded_as_no_match_under_both_postures(tmp_path, keys):
    """A registered agent's unmatched call: smb's agent_event default is log_only, regulated's is
    deny. Both go through the real daemon, so the receipts show the pack mattering."""
    results = {}
    for profile in ("smb", "regulated"):
        directory = tmp_path / profile
        directory.mkdir()
        ctx = _ctx(registered_agent_ids=frozenset({"agent-1"}))
        with supervised_opa(profile) as (opa_url, pack):
            writer, server = _engine_server(directory, keys, opa_url, pack, ctx)
            with server:
                server.ask(_req())
        results[profile] = _verify(directory, writer.signer_key)[0]
    assert (results["smb"]["decision"], results["smb"]["reason_code"]) == ("log_only", "INTEGRITY_NO_MATCH")
    assert (results["regulated"]["decision"], results["regulated"]["reason_code"]) == ("deny", "INTEGRITY_NO_MATCH")
    assert results["smb"]["pack_hash"] != results["regulated"]["pack_hash"]


def test_many_real_requests_produce_one_verifiable_chain_and_a_final_checkpoint(tmp_path, keys):
    with supervised_opa("smb") as (opa_url, pack):
        writer, server = _engine_server(tmp_path, keys, opa_url, pack, _ctx(),
                                        writer_kwargs={"checkpoint_every": 4})
        with server:
            seqs = [server.ask(_req(tool_input_sha256=f"{n:064x}"))["receipt"]["seq"] for n in range(10)]
    assert seqs == list(range(10))
    receipts, checkpoints = _logs(tmp_path)
    assert [c["tree_size"] for c in checkpoints] == [4, 8, 10]
    verify_log(receipts, trusted_signers=[writer.signer_key], checkpoint=checkpoints[-1])


# ------------------------------------------------- process lifecycle, fresh interpreter
#
# Subprocesses on purpose: SIGTERM and SIGKILL need a process that can actually be killed, and
# a crash is the one condition no in-process test can produce honestly.

_DAEMON_SCRIPT = textwrap.dedent(
    """
    import sys
    from pathlib import Path
    from types import SimpleNamespace
    from integrity_sdk.did import Keypair
    from shield.gate_daemon import serve_forever
    from shield.gate_receipts import GateReceiptWriter
    from shield.policy_engine.engine import DecisionBasis, EvaluationContext
    from shield.schemas.events import Decision, EventRef, PolicyDecision, PolicyRef, RuleRef

    sock, receipt_dir, key_pem, hmac_path = sys.argv[1:5]
    writer = GateReceiptWriter(receipt_dir, signer=Keypair.from_pem(Path(key_pem).read_bytes()),
                               hmac_key=Path(hmac_path).read_bytes(), log_id="shield-gate:dev-1",
                               checkpoint_every=1000)

    class Engine:
        def evaluate(self, event, ctx):
            return self.evaluate_with_basis(event, ctx)[0]

        def evaluate_with_basis(self, event, ctx):
            decision = PolicyDecision(
                device_id="dev-1", event_ref=EventRef(klass="agent_event", event_id="e"),
                rule=RuleRef(rule_id="r", name="r", version="1"),
                policy=PolicyRef(version="1", hash="sha256:" + "cd" * 32),
                decision=Decision(action="allow", reason="ok"))
            return decision, DecisionBasis("permit", "ALLOWED", (), "sha256:" + "cd" * 32, "agent_event")

    serve_forever(Path(sock), engine=Engine(), ctx=EvaluationContext(device_id="dev-1"),
                  device_id="dev-1", receipts=writer)
    """
)


def _start_daemon(tmp_path: Path, keys) -> tuple[subprocess.Popen, Path, str]:
    signer, hmac_key = keys
    key_pem = tmp_path / "signer.pem"
    if not key_pem.exists():
        # `Keypair.private_pem` is the inverse of the `from_pem` the daemon uses.
        key_pem.write_bytes(signer.private_pem())
        key_pem.chmod(0o600)
        (tmp_path / "hmac.key").write_bytes(hmac_key)
        (tmp_path / "hmac.key").chmod(0o600)
    sock = tmp_path / "g.sock"
    proc = subprocess.Popen(
        [sys.executable, "-c", _DAEMON_SCRIPT, str(sock), str(tmp_path / "receipts"),
         str(key_pem), str(tmp_path / "hmac.key")],
        cwd=_REPO_ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    deadline = time.monotonic() + 20
    while not sock.exists():
        assert proc.poll() is None, f"daemon exited early: {proc.stderr.read()}"
        assert time.monotonic() < deadline, "socket never appeared"
        time.sleep(0.05)
    return proc, sock, key_pem.name


def _ask(sock: Path, request: dict) -> dict:
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(10)
    try:
        client.connect(str(sock))
        client.sendall(json.dumps(request).encode() + b"\n")
        return json.loads(client.makefile("rb").readline())
    finally:
        client.close()


def test_a_clean_stop_writes_a_final_checkpoint_that_verifies(tmp_path, keys):
    proc, sock, _ = _start_daemon(tmp_path, keys)
    try:
        for n in range(3):
            assert _ask(sock, _req(tool_input_sha256=f"{n:064x}"))["receipt_status"] == "recorded"
        proc.send_signal(signal.SIGTERM)
        assert proc.wait(timeout=15) == 0
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)
    receipts, checkpoints = _logs(tmp_path)
    assert [c["tree_size"] for c in checkpoints] == [3], "a clean stop must commit to everything recorded"
    verify_log(receipts, trusted_signers=[public_key_multibase(keys[0].public_bytes())],
               checkpoint=checkpoints[-1])


def test_a_hard_crash_leaves_a_log_the_next_start_resumes_and_extends(tmp_path, keys):
    """SIGKILL skips every `finally`: no final checkpoint, no socket cleanup. Whatever was
    acknowledged must still be on disk, verifiable, and extendable by the next daemon."""
    proc, sock, _ = _start_daemon(tmp_path, keys)
    try:
        acknowledged = [_ask(sock, _req(tool_input_sha256=f"{n:064x}"))["receipt"] for n in range(5)]
        proc.kill()
        proc.wait(timeout=5)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)
    receipts, checkpoints = _logs(tmp_path)
    assert checkpoints == [], "a hard crash never reaches the shutdown checkpoint"
    assert [receipt_hash(r) for r in receipts] == [ref["hash"] for ref in acknowledged]

    sock.unlink()  # SIGKILL leaves the socket file behind; remove_stale_socket handles that on start
    signer_key = public_key_multibase(keys[0].public_bytes())
    proc, sock, _ = _start_daemon(tmp_path, keys)
    try:
        assert _ask(sock, _req(tool_input_sha256="ee" * 32))["receipt"]["seq"] == 5
        proc.send_signal(signal.SIGTERM)
        assert proc.wait(timeout=15) == 0
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)
    receipts, checkpoints = _logs(tmp_path)
    verify_log(receipts, trusted_signers=[signer_key], checkpoint=checkpoints[-1])
    assert [r["seq"] for r in receipts] == [0, 1, 2, 3, 4, 5]


# ---------------------------------------------------------------------- CLI validation


def _cli(*argv: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "shield.cli", "gate-daemon", "--device-id", "dev-1",
         "--pack-dir", "/nonexistent", *argv],
        cwd=_REPO_ROOT, capture_output=True, text=True, timeout=60,
    )


def test_cli_refuses_strict_receipts_without_a_receipt_dir():
    result = _cli("--strict-receipts")
    assert result.returncode == 2 and "--strict-receipts needs --receipt-dir" in result.stderr


def test_cli_refuses_a_receipt_dir_without_both_keys(tmp_path):
    result = _cli("--receipt-dir", str(tmp_path / "r"))
    assert result.returncode == 2
    assert "--receipt-hmac-key-file" in result.stderr


def test_cli_refuses_an_unverifiable_log_before_touching_the_policy_pack(tmp_path, keys):
    """Receipt setup runs first, so a log that fails verification stops the daemon without
    waiting for (or depending on) an OPA install -- the pack path here does not even exist."""
    # Seeded with the log id the CLI will derive for `--device-id dev-1`, so the only thing wrong
    # with this log, from the daemon's side, is that a different key now signs.
    first = _writer(tmp_path, keys, log_id=default_log_id(keys[1], "dev-1"))
    _record(first)
    first.close()
    key_pem, hmac_key = tmp_path / "other.pem", tmp_path / "hmac.key"
    key_pem.write_bytes(Keypair.generate().private_pem())
    key_pem.chmod(0o600)
    hmac_key.write_bytes(keys[1])
    hmac_key.chmod(0o600)
    result = _cli("--receipt-dir", str(tmp_path / "receipts"), "--receipt-key", str(key_pem),
                  "--receipt-hmac-key-file", str(hmac_key))
    assert result.returncode == 1
    assert "UNTRUSTED_SIGNER" in result.stderr and "refusing to extend" in result.stderr
