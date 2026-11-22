from shield.agent_core.tier3_consumer import Tier3Consumer
from shield.schemas.events import Decision, EscalationResponse

def response(verdict="release", pid=4242, identity="start-time-111"):
    r = EscalationResponse(Decision("contain"), verdict=verdict)
    r.pid, r.pid_identity = pid, identity
    return r

class Broker:
    def __init__(self, fail=False): self.calls=[]; self.fail=fail
    def resume(self, pid):
        if self.fail: raise RuntimeError("resume unavailable")
        self.calls.append(("resume", pid))

def consumer(tmp_path, broker, identity=lambda pid: "start-time-111"):
    return Tier3Consumer(tmp_path / "db", mode="enforce", action_broker=broker, pid_identity=identity)

def test_release_resumes_contained_process(tmp_path):
    b=Broker(); out=consumer(tmp_path,b).apply(response())
    assert out.applied and b.calls == [("resume",4242)]

def test_recycled_pid_is_not_resumed(tmp_path):
    b=Broker(); out=consumer(tmp_path,b,lambda pid: "start-time-999").apply(response())
    assert not out.applied and out.reason == "pid_identity_mismatch" and b.calls == []

def test_exited_pid_is_not_resumed(tmp_path):
    out=consumer(tmp_path,Broker(),lambda pid: None).apply(response())
    assert not out.applied and out.reason == "pid_gone"

def test_confirm_and_uncertain_leave_contained(tmp_path):
    b=Broker()
    assert not consumer(tmp_path,b).apply(response("confirm")).applied
    assert not consumer(tmp_path,b).apply(response("uncertain")).applied
    assert b.calls == []

def test_resume_failure_leaves_contained(tmp_path):
    out=consumer(tmp_path,Broker(fail=True)).apply(response())
    assert not out.applied and out.reason.startswith("resume_failed")
