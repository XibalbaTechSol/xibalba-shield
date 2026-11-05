"""Tests for the commissioning-ladder instrumentation: router latency capture and the
operator resume path. Real ActionBroker, real subprocess, real signals -- the only injected
piece is a recording sink, because that is the seam the router itself exposes."""
from __future__ import annotations

import os
import signal
import subprocess
import sys
import time

import pytest

from shield.agent_core.action_broker import ActionBroker
from shield.agent_core.registry import AgentRegistry, DeviceContext
from shield.agent_core.router import EventRouter
from shield.cli import main as shield_main
from shield.policy_engine import PolicyEngine
from shield.schemas.events import (
    Activity, EnforcementOutcome, ProcessActivity, ProcessInfo,
)

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX signals")


def _router(broker, sink):
    engine = PolicyEngine()
    original = engine.evaluate

    def always_contain(event, context):
        decision = original(event, context)
        decision.decision.action = "contain"
        return decision

    engine.evaluate = always_contain
    return EventRouter(
        device=DeviceContext(device_id="dev-1", tenant_id="t", device_role="workstation"),
        registry=AgentRegistry(), policy_engine=engine,
        action_broker=broker, enforcement_outcome_sink=sink,
    )


def _event(pid):
    return ProcessActivity(
        device_id="dev-1", process=ProcessInfo(pid=pid, name="sleep"), activity=Activity(type="launch"),
    )


@posix_only
def test_completed_freeze_records_a_real_monotonic_latency():
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    outcomes: list[EnforcementOutcome] = []
    try:
        _router(ActionBroker(), outcomes.append).handle(_event(child.pid))
        assert len(outcomes) == 1 and outcomes[0].completed
        # Positive, finite, and small: a frozen sleep process, not a fabricated constant.
        assert outcomes[0].handle_to_contain_ms is not None
        assert 0 < outcomes[0].handle_to_contain_ms < 5000
        assert outcomes[0].to_dict()["handle_to_contain_ms"] == outcomes[0].handle_to_contain_ms
    finally:
        os.kill(child.pid, signal.SIGCONT)
        child.kill()
        child.wait()


def test_failed_freeze_reports_no_latency_rather_than_a_fast_one():
    class Raising:
        def contain(self, pid, **kw):
            raise ProcessLookupError(f"no such process: {pid}")

    outcomes: list[EnforcementOutcome] = []
    _router(Raising(), outcomes.append).handle(_event(4242))
    assert outcomes[0].completed is False
    assert outcomes[0].handle_to_contain_ms is None


@posix_only
def test_shield_resume_really_continues_a_frozen_process(capsys, tmp_path):
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    try:
        ActionBroker().freeze(child.pid)
        deadline = time.monotonic() + 5
        state = ""
        while time.monotonic() < deadline:
            with open(f"/proc/{child.pid}/stat") as fh:
                state = fh.read().rsplit(")", 1)[1].split()[0]
            if state == "T":
                break
            time.sleep(0.02)
        assert state == "T", "child should be stopped before resume"

        assert shield_main(["resume", "--pid", str(child.pid), "--outcome-log", str(tmp_path / "o.jsonl")]) == 0
        # Without --device-config the resume still happens but says it is not recorded.
        assert "backend was not told" in capsys.readouterr().err

        with open(f"/proc/{child.pid}/stat") as fh:
            assert fh.read().rsplit(")", 1)[1].split()[0] != "T"
    finally:
        child.kill()
        child.wait()


def test_shield_resume_reports_a_missing_process(capsys, tmp_path):
    assert shield_main(["resume", "--pid", "999999", "--outcome-log", str(tmp_path / "o.jsonl")]) == 1
    assert "could not resume" in capsys.readouterr().err


# ---- end to end: freeze -> `shield resume` -> backend metrics ---------------------------------

import json
import threading
import urllib.request
from http.server import ThreadingHTTPServer

from shield.backend.api import make_handler
from shield.backend.store import ShieldStore

_ADMIN = "e2e-admin-token"


def _http(url, *, method="GET", body=None, token=_ADMIN):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        "Accept": "application/json", "Content-Type": "application/json", "Authorization": f"Bearer {token}",
    })
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read().decode())


@posix_only
def test_resume_is_recorded_and_counts_toward_false_freeze_rate(tmp_path):
    store = ShieldStore(tmp_path / "s.sqlite3")
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(store=store, admin_token=_ADMIN))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_port}"
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    try:
        token = _http(f"{base}/api/shield/enroll", method="POST",
                      body={"tenant_id": "t", "device_id": "dev-1"})["device_token"]
        # The freeze, recorded the way `shield run` records it (a completed outcome with latency).
        _http(f"{base}/api/shield/enforcement-outcomes", method="POST", token=token, body={
            "tenant_id": "t", "device_id": "dev-1",
            "outcome": {"event_id": "evt-freeze", "device_id": "dev-1", "action": "freeze",
                        "completed": True, "handle_to_contain_ms": 3.2},
        })
        ActionBroker().freeze(child.pid)

        cfg = tmp_path / "device.json"
        cfg.write_text(json.dumps({
            "backend_url": base, "device_id": "dev-1", "device_role": "workstation",
            "device_token": token, "tenant_id": "t", "feature_flags": {},
            "sensitive_paths": [], "trusted_policy_hashes": [],
        }))
        assert shield_main(["resume", "--pid", str(child.pid), "--event-id", "evt-freeze",
                            "--device-config", str(cfg), "--outcome-log", str(tmp_path / "o.jsonl")]) == 0

        m = _http(f"{base}/api/shield/commissioning-metrics?tenant_id=t&device_id=dev-1")
        assert m["false_freeze"]["linked_resumes"] == 1
        assert m["false_freeze"]["rate"] == 1.0  # 1 reversed of 1 completed freeze
        assert m["handle_to_contain_ms"]["p50"] == 3.2
    finally:
        server.shutdown()
        store.close()
        child.kill()
        child.wait()


# ---- local outcome log: what the device-side app reads ----------------------------------------

import json as _json
import stat

from shield.agent_core.outcome_log import LocalOutcomeLog, fan_out


def test_local_outcome_log_appends_json_lines_with_private_permissions(tmp_path):
    log = LocalOutcomeLog(tmp_path / "sub" / "outcomes.jsonl")
    assert log.append({"event_id": "e1", "pid": 4242, "action": "freeze", "completed": True})
    assert log.append({"event_id": "e2", "pid": None, "action": "contain", "completed": False})
    lines = (tmp_path / "sub" / "outcomes.jsonl").read_text().splitlines()
    assert [_json.loads(l)["event_id"] for l in lines] == ["e1", "e2"]
    if sys.platform != "win32":
        # Outcomes name processes on the device: file 0600, directory 0700.
        assert stat.S_IMODE((tmp_path / "sub" / "outcomes.jsonl").stat().st_mode) == 0o600
        assert stat.S_IMODE((tmp_path / "sub").stat().st_mode) == 0o700


def test_local_outcome_log_rotates_to_one_bounded_backup(tmp_path):
    path = tmp_path / "outcomes.jsonl"
    log = LocalOutcomeLog(path, max_bytes=200)
    for i in range(30):
        log.append({"event_id": f"e{i}", "padding": "x" * 40})
    assert path.exists() and path.with_name("outcomes.jsonl.1").exists()
    assert not path.with_name("outcomes.jsonl.2").exists()  # one backup, never an unbounded series
    assert path.stat().st_size < 600  # the live file restarted; it did not grow without bound


def test_local_outcome_log_never_raises_on_a_write_failure(tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("x")  # a FILE where the directory should be -> mkdir/open must fail
    assert LocalOutcomeLog(blocker / "outcomes.jsonl").append({"event_id": "e"}) is False


def test_fan_out_isolates_a_failing_sink():
    got: list = []

    def boom(_):
        raise RuntimeError("backend down")

    fan_out(boom, got.append)("outcome")
    assert got == ["outcome"]  # the backend failing did not stop the local record


@posix_only
def test_router_freeze_lands_in_the_local_log_with_its_pid(tmp_path):
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    log = LocalOutcomeLog(tmp_path / "outcomes.jsonl")
    try:
        _router(ActionBroker(), fan_out(log)).handle(_event(child.pid))
        rec = _json.loads((tmp_path / "outcomes.jsonl").read_text().splitlines()[0])
        assert rec["pid"] == child.pid
        assert rec["action"] == "freeze" and rec["completed"] is True
        assert rec["handle_to_contain_ms"] is not None
    finally:
        os.kill(child.pid, signal.SIGCONT)
        child.kill()
        child.wait()


@posix_only
def test_resume_is_recorded_locally_even_with_no_backend(tmp_path, capsys):
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    out = tmp_path / "o.jsonl"
    try:
        ActionBroker().freeze(child.pid)
        assert shield_main(["resume", "--pid", str(child.pid), "--event-id", "evt-1", "--outcome-log", str(out)]) == 0
        rec = _json.loads(out.read_text().splitlines()[0])
        assert (rec["action"], rec["pid"], rec["resumes_event_id"]) == ("resume", child.pid, "evt-1")
    finally:
        child.kill()
        child.wait()
