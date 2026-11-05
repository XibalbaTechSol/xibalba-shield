"""Tests for the protected-process interlock.

All identity tests run against a fake /proc tree under tmp_path (injected via `proc_root`), so
they are deterministic, need no root, and exercise the REAL guard code -- the interlock is never
mocked out. One test at the bottom uses the live /proc to prove the real kernel interface works.
"""
from __future__ import annotations

import os
import signal
import sys
from pathlib import Path

import pytest

from shield.agent_core.action_broker import ActionBroker
from shield.agent_core.protected_processes import (
    ProtectedProcessError,
    ProtectedProcessGuard,
)
from shield.agent_core.readiness import ProductionReadiness

SELF_PID, PARENT_PID, GRANDPARENT_PID = 5000, 4000, 3000


def _add_proc(root: Path, pid: int, exe: str | None, ppid: int = 1) -> None:
    """Create /proc/<pid>/{stat,exe}. exe=None omits the symlink (kernel thread / unreadable)."""
    d = root / str(pid)
    d.mkdir(parents=True)
    # comm deliberately contains a space and ')' to prove the stat parser splits on the LAST ')'.
    (d / "stat").write_text(f"{pid} (we ird) name) S {ppid} 0 0 0\n")
    if exe is not None:
        os.symlink(exe, d / "exe")  # dangling target is fine: readlink does not follow it


@pytest.fixture
def proc(tmp_path: Path) -> Path:
    root = tmp_path / "proc"
    root.mkdir()
    _add_proc(root, GRANDPARENT_PID, "/usr/lib/systemd/systemd", ppid=1)
    _add_proc(root, PARENT_PID, "/usr/bin/bash", ppid=GRANDPARENT_PID)
    _add_proc(root, SELF_PID, "/opt/shield/bin/shield", ppid=PARENT_PID)
    return root


def _guard(proc: Path, **kw) -> ProtectedProcessGuard:
    return ProtectedProcessGuard(
        proc_root=proc, getpid=lambda: SELF_PID, getppid=lambda: PARENT_PID, **kw
    )


def test_self_and_ancestors_are_protected(proc):
    g = _guard(proc)
    for pid in (SELF_PID, PARENT_PID, GRANDPARENT_PID):
        assert g.check(pid).protected, pid


def test_system_binary_in_trusted_dir_is_protected(proc):
    _add_proc(proc, 700, "/usr/sbin/sshd")
    assert _guard(proc).check(700).protected


def test_name_spoof_from_untrusted_dir_is_NOT_protected(proc):
    """Malware copying itself to /tmp/sshd must not gain immunity from containment."""
    _add_proc(proc, 701, "/tmp/sshd")
    assert not _guard(proc).check(701).protected


def test_ordinary_process_is_not_protected(proc):
    _add_proc(proc, 702, "/usr/bin/python3")
    assert not _guard(proc).check(702).protected


def test_unreadable_identity_fails_closed(proc):
    _add_proc(proc, 703, None)  # exists, exe unreadable (kernel thread / EACCES / zombie)
    v = _guard(proc).check(703)
    assert v.protected and "fail closed" in v.reason


def test_nonexistent_pid_is_not_protected(proc):
    assert not _guard(proc).check(99999).protected  # the signal itself will raise ProcessLookupError


def test_explicit_extra_pid_is_protected(proc):
    _add_proc(proc, 704, "/usr/bin/python3")
    assert _guard(proc, extra_pids=frozenset({704})).check(704).protected


def test_deleted_binary_suffix_is_handled(proc):
    _add_proc(proc, 705, "/usr/sbin/sshd (deleted)")
    assert _guard(proc).check(705).protected


def test_cgroup_with_protected_member_is_refused(proc, tmp_path):
    _add_proc(proc, 706, "/usr/bin/python3")
    _add_proc(proc, 707, "/usr/sbin/sshd")
    cg = tmp_path / "cg"; cg.mkdir()
    (cg / "cgroup.procs").write_text("706\n707\n")
    with pytest.raises(ProtectedProcessError):
        _guard(proc).assert_cgroup_allowed(cg)


def test_cgroup_with_unreadable_membership_fails_closed(proc, tmp_path):
    cg = tmp_path / "cg"; cg.mkdir()  # no cgroup.procs
    with pytest.raises(ProtectedProcessError, match="fail closed"):
        _guard(proc).assert_cgroup_allowed(cg)


def test_cgroup_of_ordinary_members_is_allowed(proc, tmp_path):
    _add_proc(proc, 708, "/usr/bin/python3")
    cg = tmp_path / "cg"; cg.mkdir()
    (cg / "cgroup.procs").write_text("708\n")
    _guard(proc).assert_cgroup_allowed(cg)


# ---- broker integration: the interlock is enforced at the actuator ------------------------

def _broker(proc: Path, sent: list, **kw) -> ActionBroker:
    ready = ProductionReadiness.from_mapping({k: True for k in (
        "policy_signature_verified", "agent_identity_verified", "kernel_probe_verified",
        "audit_receipt_verified", "rollback_verified", "operator_approval",
        "kill_runtime_tested", "cgroup_runtime_tested", "network_runtime_tested")})
    return ActionBroker(kill=lambda pid, sig: sent.append((pid, sig)), guard=_guard(proc),
                        readiness=ready, **kw)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signals")
def test_broker_refuses_freeze_kill_and_escalate_on_protected_pid_and_sends_no_signal(proc):
    _add_proc(proc, 800, "/usr/sbin/sshd")
    sent: list = []
    b = _broker(proc, sent, enable_destructive=True, sleep=lambda s: None)
    with pytest.raises(ProtectedProcessError):
        b.freeze(800)
    with pytest.raises(ProtectedProcessError):
        b.contain(800)
    with pytest.raises(ProtectedProcessError):
        b.kill_process(800)
    with pytest.raises(ProtectedProcessError):
        b.escalate_to_kill(800, timeout_seconds=0)
    assert sent == []  # the interlock fired BEFORE any signal left the process


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signals")
def test_broker_still_contains_ordinary_process(proc):
    _add_proc(proc, 801, "/usr/bin/python3")
    sent: list = []
    _broker(proc, sent).contain(801)
    assert sent == [(801, signal.SIGSTOP)]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signals")
def test_resume_is_never_blocked_so_recovery_always_works(proc):
    _add_proc(proc, 802, "/usr/sbin/sshd")  # even a protected pid can be un-frozen
    sent: list = []
    _broker(proc, sent).resume(802)
    assert sent == [(802, signal.SIGCONT)]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signals")
def test_cgroup_freeze_refused_when_member_protected(proc, tmp_path):
    _add_proc(proc, 803, "/usr/sbin/sshd")
    cg = tmp_path / "cg"; cg.mkdir()
    (cg / "cgroup.freeze").write_text("0\n"); (cg / "cgroup.procs").write_text("803\n")
    b = _broker(proc, [], enable_cgroup=True)
    with pytest.raises(ProtectedProcessError):
        b.freeze_cgroup(cg)
    assert (cg / "cgroup.freeze").read_text() == "0\n"  # never written


@pytest.mark.skipif(not Path("/proc/self/exe").exists(), reason="needs live Linux /proc")
def test_live_proc_protects_this_very_process_and_pid1_chain():
    g = ProtectedProcessGuard()
    assert g.check(os.getpid()).protected
    assert g.check(os.getppid()).protected
