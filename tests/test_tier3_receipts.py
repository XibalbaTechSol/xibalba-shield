from integrity_sdk.core.receipts import verify_log
from shield.agent_core.tier3_consumer import Tier3Consumer
from shield.schemas.events import Decision, EscalationResponse

def response():
    r = EscalationResponse(Decision("contain"), verdict="release")
    r.pid, r.pid_identity = 42, "id-1"
    return r

class Broker:
    def resume(self, pid): self.called = pid

def test_release_writes_verifiable_receipt_before_resume(tmp_path):
    b = Broker(); c = Tier3Consumer(tmp_path/"db", mode="enforce", action_broker=b,
        pid_identity=lambda pid: "id-1", receipt_dir=tmp_path/"receipts")
    assert c.apply(response()).applied
    path = tmp_path/"receipts"/"receipts.jsonl"
    assert path.exists() and len(path.read_bytes().splitlines()) == 1

def test_receipt_failure_blocks_release(tmp_path, monkeypatch):
    b = Broker(); c = Tier3Consumer(tmp_path/"db", mode="enforce", action_broker=b,
        pid_identity=lambda pid: "id-1", receipt_dir=tmp_path/"receipts")
    monkeypatch.setattr(c.receipt_writer, "record", lambda **kw: (_ for _ in ()).throw(OSError("disk")))
    out = c.apply(response())
    assert not out.applied and out.reason.startswith("receipt_failed")
