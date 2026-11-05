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
def test_shield_resume_really_continues_a_frozen_process(capsys):
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

        assert shield_main(["resume", "--pid", str(child.pid)]) == 0
        # Without --device-config the resume still happens but says it is not recorded.
        assert "not recorded" in capsys.readouterr().err

        with open(f"/proc/{child.pid}/stat") as fh:
            assert fh.read().rsplit(")", 1)[1].split()[0] != "T"
    finally:
        child.kill()
        child.wait()


def test_shield_resume_reports_a_missing_process(capsys):
    assert shield_main(["resume", "--pid", "999999"]) == 1
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
                            "--device-config", str(cfg)]) == 0

        m = _http(f"{base}/api/shield/commissioning-metrics?tenant_id=t&device_id=dev-1")
        assert m["false_freeze"]["linked_resumes"] == 1
        assert m["false_freeze"]["rate"] == 1.0  # 1 reversed of 1 completed freeze
        assert m["handle_to_contain_ms"]["p50"] == 3.2
    finally:
        server.shutdown()
        store.close()
        child.kill()
        child.wait()
