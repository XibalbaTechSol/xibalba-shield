from __future__ import annotations

import signal

import pytest

from shield.agent_core.action_broker import ActionBroker
from shield.agent_core.readiness import ProductionReadiness
from shield.agent_core.responders import ResponderDisabled


def _passed_readiness() -> ProductionReadiness:
    return ProductionReadiness.from_mapping({
        "policy_signature_verified": True,
        "agent_identity_verified": True,
        "kernel_probe_verified": True,
        "audit_receipt_verified": True,
        "rollback_verified": True,
        "operator_approval": True,
        "kill_runtime_tested": True,
        "cgroup_runtime_tested": True,
        "network_runtime_tested": True,
    })


def test_containment_freezes_with_sigstop_and_can_resume():
    calls = []
    broker = ActionBroker(enable_destructive=True, readiness=_passed_readiness(), kill=lambda pid, sig: calls.append((pid, sig)))

    frozen = broker.contain(4242)
    resumed = broker.resume(4242)

    assert frozen.method == "SIGSTOP"
    assert resumed.method == "SIGCONT"
    assert calls == [(4242, signal.SIGSTOP), (4242, signal.SIGCONT)]


def test_responder_interface_keeps_unverified_actions_disabled():
    broker = ActionBroker()
    assert broker.capabilities.freeze_process is True
    assert broker.capabilities.kill_process is False
    assert broker.capabilities.freeze_cgroup is False
    assert broker.capabilities.block_flow is False
    with pytest.raises(ResponderDisabled, match="kill_process"):
        broker.kill_process(4242)
    with pytest.raises(ResponderDisabled, match="freeze_cgroup"):
        broker.freeze_cgroup("/sys/fs/cgroup/example", pid=4242)
    with pytest.raises(ResponderDisabled, match="block_flow"):
        broker.block_flow({"dst_ip": "127.0.0.1", "dst_port": 1})


def test_timeout_escalation_sends_sigkill_only_after_wait():
    calls = []
    clock = iter([10.0, 10.0, 11.0])
    sleeps = []
    broker = ActionBroker(
        enable_destructive=True,
        readiness=_passed_readiness(),
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
        enable_destructive=True,
        readiness=_passed_readiness(),
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
    broker = ActionBroker(enable_cgroup=True, readiness=_passed_readiness())

    frozen = broker.freeze(4242, cgroup_path=cgroup)
    assert frozen.method == "cgroup.freeze"
    assert freeze_file.read_text(encoding="ascii") == "1\n"

    broker.resume(4242, cgroup_path=cgroup)
    assert freeze_file.read_text(encoding="ascii") == "0\n"


@pytest.mark.parametrize("pid", [0, 1, -3, True])
def test_broker_rejects_unsafe_pid(pid):
    with pytest.raises(ValueError, match="greater than 1"):
        ActionBroker().freeze(pid)


def test_destructive_flag_cannot_bypass_readiness_gate():
    broker = ActionBroker(enable_destructive=True)
    assert broker.capabilities.kill_process is False
    with pytest.raises(ResponderDisabled, match="every production readiness proof"):
        broker.kill_process(4242)


def test_passed_readiness_enables_kill_responder():
    calls = []
    broker = ActionBroker(enable_destructive=True, readiness=_passed_readiness(), kill=lambda pid, sig: calls.append((pid, sig)))
    result = broker.kill_process(4242)
    assert result.method == "SIGKILL"
    assert calls == [(4242, signal.SIGKILL)]


def test_passed_readiness_enables_validated_network_adapter():
    flows = []
    broker = ActionBroker(
        enable_network=True,
        readiness=_passed_readiness(),
        block_network=lambda flow: flows.append(flow) or "test-firewall",
    )
    flow = {"protocol": "tcp", "dst_ip": "192.0.2.8", "dst_port": 443, "pid": 4242}
    result = broker.block_flow(flow)
    assert result.method == "test-firewall"
    assert result.action == "block_flow"
    assert flows == [flow]


def test_network_flag_cannot_bypass_readiness_gate():
    broker = ActionBroker(enable_network=True, block_network=lambda _flow: "test-firewall")
    assert broker.capabilities.block_flow is False
    with pytest.raises(ResponderDisabled, match="every production readiness proof"):
        broker.block_flow({"protocol": "tcp", "dst_ip": "192.0.2.8", "dst_port": 443})
