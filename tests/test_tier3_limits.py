from concurrent.futures import ThreadPoolExecutor
from shield.agent_core.tier3_consumer import Tier3Consumer
from shield.schemas.events import Decision, EscalationResponse

def resp(): return EscalationResponse(Decision("contain"), verdict="release")

def test_kill_switch_disables_actuation_but_records(tmp_path):
    flag = tmp_path / "disable"; flag.touch()
    out = Tier3Consumer(tmp_path / "db", mode="enforce", action_broker=object(), disabled_flag_path=flag).apply(resp())
    assert not out.applied and out.reason == "tier3_disabled"

def test_cap_refuses_after_window_limit(tmp_path):
    c = Tier3Consumer(tmp_path / "db", mode="enforce", action_broker=object(), max_actions_per_window=2)
    results = [c.apply(resp()) for _ in range(4)]
    assert [r.reason for r in results] == ["release requires verified process identity"] * 2 + ["tier3_action_cap"] * 2
    assert c.tripped

def test_concurrent_verdicts_do_not_exceed_cap(tmp_path):
    c = Tier3Consumer(tmp_path / "db", mode="enforce", action_broker=object(), max_actions_per_window=3)
    with ThreadPoolExecutor(max_workers=16) as ex:
        results = list(ex.map(lambda _: c.apply(resp()), range(32)))
    assert sum(r.reason == "release requires verified process identity" for r in results) == 3
