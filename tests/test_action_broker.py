from __future__ import annotations

import signal

import pytest

from shield.agent_core.action_broker import ActionBroker


def test_containment_freezes_with_sigstop_and_can_resume():
    calls = []
    broker = ActionBroker(kill=lambda pid, sig: calls.append((pid, sig)))

    frozen = broker.contain(4242)
    resumed = broker.resume(4242)

    assert frozen.method == "SIGSTOP"
    assert resumed.method == "SIGCONT"
    assert calls == [(4242, signal.SIGSTOP), (4242, signal.SIGCONT)]


def test_timeout_escalation_sends_sigkill_only_after_wait():
    calls = []
    clock = iter([10.0, 10.0, 11.0])
    sleeps = []
    broker = ActionBroker(
        kill=lambda pid, sig: calls.append((pid, sig)),
        monotonic=lambda: next(clock),
        sleep=lambda seconds: sleeps.append(seconds),
    )

    result = broker.contain(4242, timeout_seconds=1.0)

    assert result.escalated is True
    assert result.method == "SIGKILL"
    assert sleeps == [1.0]
    assert calls == [(4242, signal.SIGSTOP), (4242, signal.SIGKILL)]


def test_freeze_resume_then_escalate_preserves_signal_order():
    calls = []
    clock = iter([20.0, 20.0, 21.0])
    broker = ActionBroker(
        kill=lambda pid, sig: calls.append((pid, sig)),
        monotonic=lambda: next(clock),
        sleep=lambda _seconds: None,
    )

    broker.freeze(4242)
    broker.resume(4242)
    broker.escalate_to_kill(4242, timeout_seconds=1.0)

    assert calls == [
        (4242, signal.SIGSTOP),
        (4242, signal.SIGCONT),
        (4242, signal.SIGKILL),
    ]


def test_cgroup_freeze_and_resume_use_cgroup_freeze_file(tmp_path):
    cgroup = tmp_path / "agent.scope"
    cgroup.mkdir()
    freeze_file = cgroup / "cgroup.freeze"
    freeze_file.write_text("0\n", encoding="ascii")
    broker = ActionBroker()

    frozen = broker.freeze(4242, cgroup_path=cgroup)
    assert frozen.method == "cgroup.freeze"
    assert freeze_file.read_text(encoding="ascii") == "1\n"

    broker.resume(4242, cgroup_path=cgroup)
    assert freeze_file.read_text(encoding="ascii") == "0\n"


@pytest.mark.parametrize("pid", [0, 1, -3, True])
def test_broker_rejects_unsafe_pid(pid):
    with pytest.raises(ValueError, match="greater than 1"):
        ActionBroker().freeze(pid)
