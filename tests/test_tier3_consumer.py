from shield.agent_core.tier3_consumer import Tier3Consumer
from shield.schemas.events import Decision, EscalationResponse


def response(verdict="release", action="contain"):
    return EscalationResponse(Decision(action), verdict=verdict)


def test_shadow_records_release_but_never_actuates(tmp_path):
    calls = []
    broker = type("Broker", (), {"resume": lambda self, pid: calls.append(pid)})()
    out = Tier3Consumer(tmp_path / "tier3.db", action_broker=broker).apply(response())
    assert not out.applied and calls == []


def test_records_survive_restart(tmp_path):
    p = tmp_path / "tier3.db"
    Tier3Consumer(p).apply(response("confirm"))
    assert Tier3Consumer(p).recorded_count() == 1


def test_unwritable_store_is_fail_closed(tmp_path):
    p = tmp_path / "missing" / "tier3.db"
    p.parent.write_text("not a directory")
    try:
        Tier3Consumer(p)
    except OSError:
        return
    raise AssertionError("unwritable store was accepted")


def test_release_disagreement_is_recorded(tmp_path):
    out = Tier3Consumer(tmp_path / "tier3.db").apply(response("release"))
    assert out.disagreed_with_local
