from shield.agent_core.tier3_safety import BoundedAdjudicationStore, Tier3DispatchGate, process_identity_matches, verified_resume
from shield.schemas.events import Decision, EscalationResponse, ProcessInfo


def _response():
    return EscalationResponse(decision=Decision(action="contain"))


def test_store_is_bounded_and_evicts_oldest():
    store = BoundedAdjudicationStore(max_records=2)
    for _ in range(3):
        store.record(_response())
    assert len(store.snapshot()) == 2


def test_dispatch_gate_limits_inflight():
    gate = Tier3DispatchGate(max_inflight=1, max_per_window=10)
    assert gate.acquire()
    assert not gate.acquire()
    gate.release()
    assert gate.acquire()
    gate.release()


def test_dispatch_gate_limits_window():
    gate = Tier3DispatchGate(max_inflight=2, max_per_window=1, window_seconds=60)
    assert gate.acquire()
    gate.release()
    assert not gate.acquire()


def test_pid_identity_requires_start_or_cgroup_and_matches():
    expected = ProcessInfo(pid=42, name="x", start_time=100, cgroup_id=7)
    assert process_identity_matches(expected, ProcessInfo(pid=42, name="other", start_time=100, cgroup_id=7))
    assert not process_identity_matches(expected, ProcessInfo(pid=42, name="x", start_time=101, cgroup_id=7))
    assert not process_identity_matches(ProcessInfo(pid=42, name="x"), ProcessInfo(pid=42, name="x"))


def test_verified_resume_refuses_pid_reuse():
    class Broker:
        def resume(self, pid): raise AssertionError("must not resume")
    expected = ProcessInfo(pid=42, name="x", start_time=100)
    try:
        verified_resume(Broker(), expected, lambda pid: ProcessInfo(pid=pid, name="new", start_time=101))
    except RuntimeError as exc:
        assert "identity" in str(exc)
    else:
        raise AssertionError("PID reuse was not rejected")
