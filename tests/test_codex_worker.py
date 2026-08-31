import json

from scripts.codex_worker import process_once


class Agent:
    def analyze_event(self, event, *, policy_action=""):
        return type("Result", (), {"source": "test", "classification": "unknown", "confidence": 0.1, "rationale": "review", "recommended_test": "inspect"})()


def test_worker_claims_spool_and_writes_advisory_result(tmp_path):
    inbox = tmp_path / "inbox"
    outbox = tmp_path / "outbox"
    inbox.mkdir()
    (inbox / "event.json").write_text(json.dumps({"event": {"class": "process_activity"}, "policy_action": "escalate"}))

    assert process_once(inbox, outbox, agent=Agent()) == 1
    result = json.loads((outbox / "event.result.json").read_text())
    assert result["enforcement"] == "advisory_only"
    assert not list(inbox.iterdir())
