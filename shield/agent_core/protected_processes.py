"""Protected-process interlock for the Agent Core actuators.

Control-theory framing (see https://en.wikipedia.org/wiki/Control_theory): ActionBroker is the
*actuator* of Shield's closed loop. An actuator with unbounded authority is a plant hazard --
a false-positive "contain" aimed at sshd, systemd, the OPA sidecar, or Shield itself does not
just misfire, it removes the operator's ability to recover the machine (or blinds the sensor
that closes the loop). Real plants solve this with a hardware interlock, independent of the
controller's decision logic (cf. https://en.wikipedia.org/wiki/Interlock_(engineering)).
This module is that interlock.

Placement: the check runs INSIDE ActionBroker's freeze / kill / escalate / cgroup paths, not in
the router or policy layer, so no caller (router, gate daemon, CLI, future Tier 3) can route
around it. A refusal raises ProtectedProcessError; router.py already treats any broker
exception as a failed containment, logs it, and records EnforcementOutcome(completed=False).

Identity is established from /proc/<pid>/exe (the resolved executable path), NOT /proc/<pid>/comm
or argv[0]: a process can rename itself with prctl(PR_SET_NAME) or rewrite argv, so a name-only
allowlist would let malware declare itself uncontainable. A name match only counts if the
binary also lives under a trusted system directory an unprivileged attacker cannot write to.

Fail posture (stated per the repo convention): FAIL CLOSED for protection.
  * Process exists but its exe cannot be read (kernel thread, zombie, EACCES) -> treated as
    protected. Cost: Shield cannot contain a process whose identity it cannot establish.
    Benefit: an unverifiable target is never frozen. A process we cannot read is usually one
    we could not signal anyway (EPERM), so the practical false-refusal rate is low.
  * Process does not exist (no /proc/<pid>) -> not protected; the signal itself will fail with
    ProcessLookupError, which the router records.
  * No /proc at all (Windows, macOS) -> only the pid-based protections (self, ancestors, pid 1,
    explicit pids) apply. Name-based protection is [PLANNED] for those platforms; this is
    stated here rather than implied.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable


class ProtectedProcessError(PermissionError):
    """Raised when a containment action targets a process the interlock protects."""


# Executable basenames whose loss breaks recovery or the sensing loop itself.
# `opa` is the Tier 1 policy sidecar: freezing it makes every decision time out.
DEFAULT_PROTECTED_EXE_NAMES: frozenset[str] = frozenset(
    {
        "systemd", "systemd-journald", "systemd-logind", "systemd-udevd", "init",
        "sshd", "dbus-daemon", "dbus-broker", "login", "agetty", "udevd",
        "containerd", "dockerd", "runc", "kubelet",
        "opa", "shield", "shield-backend",
    }
)

# A name match is honored only when the resolved binary lives here. These directories are
# root-writable only on a sane system, so an unprivileged attacker cannot plant a binary that
# qualifies. (Shield's own venv is covered separately by the self/ancestor pid rule.)
DEFAULT_TRUSTED_EXE_PREFIXES: tuple[str, ...] = (
    "/usr/sbin/", "/usr/bin/", "/usr/lib/systemd/", "/usr/libexec/",
    "/sbin/", "/bin/", "/lib/systemd/", "/opt/shield/", "/usr/local/sbin/",
)


@dataclass(frozen=True)
class ProtectionVerdict:
    protected: bool
    reason: str = ""


@dataclass
class ProtectedProcessGuard:
    """Decide whether a pid may be touched by a containment action.

    Parameters are injectable (proc_root, getpid, getppid) so tests run deterministically
    against a fake /proc tree instead of mocking the interlock away.
    """

    extra_pids: frozenset[int] = field(default_factory=frozenset)
    exe_names: frozenset[str] = DEFAULT_PROTECTED_EXE_NAMES
    trusted_prefixes: tuple[str, ...] = DEFAULT_TRUSTED_EXE_PREFIXES
    proc_root: Path = Path("/proc")
    getpid: "callable" = os.getpid  # type: ignore[assignment]
    getppid: "callable" = os.getppid  # type: ignore[assignment]

    # -- /proc helpers ----------------------------------------------------------------------
    def _proc_dir(self, pid: int) -> Path:
        return self.proc_root / str(pid)

    def _ppid_of(self, pid: int) -> int | None:
        """Parent pid from /proc/<pid>/stat. Field 4, after the ')' that closes comm (comm may
        itself contain spaces and parens, so split on the LAST ')')."""
        try:
            stat = (self._proc_dir(pid) / "stat").read_text()
            return int(stat.rsplit(")", 1)[1].split()[1])
        except (OSError, ValueError, IndexError):
            return None

    def _ancestors(self) -> set[int]:
        """Shield's own pid plus every ancestor up to pid 1 (bounded to defeat a cyclic tree)."""
        chain = {self.getpid(), self.getppid()}
        cur, hops = self.getppid(), 0
        while cur and cur > 1 and hops < 64:
            nxt = self._ppid_of(cur)
            if nxt is None or nxt in chain:
                break
            chain.add(nxt)
            cur, hops = nxt, hops + 1
        return chain

    def _exe_of(self, pid: int) -> str | None:
        try:
            return os.path.realpath(os.readlink(self._proc_dir(pid) / "exe"))
        except OSError:
            return None

    # -- public API -------------------------------------------------------------------------
    def check(self, pid: int) -> ProtectionVerdict:
        """Return the verdict for one pid. Pure query; never signals anything."""
        if pid <= 1:
            return ProtectionVerdict(True, f"pid {pid} is init / reserved")
        if pid in self.extra_pids:
            return ProtectionVerdict(True, f"pid {pid} is explicitly protected")
        if pid in self._ancestors():
            return ProtectionVerdict(True, f"pid {pid} is Shield or one of its ancestors")

        if not self.proc_root.is_dir():
            # No /proc (non-Linux): name protection unavailable -- documented, not implied.
            return ProtectionVerdict(False)
        if not self._proc_dir(pid).exists():
            return ProtectionVerdict(False)  # gone; the signal will report ProcessLookupError

        exe = self._exe_of(pid)
        if exe is None:
            return ProtectionVerdict(True, f"pid {pid} identity unreadable (fail closed)")
        # Linux appends " (deleted)" when the binary was unlinked after exec.
        base = os.path.basename(exe.removesuffix(" (deleted)"))
        if base in self.exe_names and exe.startswith(self.trusted_prefixes):
            return ProtectionVerdict(True, f"pid {pid} runs protected system binary {exe}")
        return ProtectionVerdict(False)

    def assert_allowed(self, pid: int) -> None:
        verdict = self.check(pid)
        if verdict.protected:
            raise ProtectedProcessError(f"refusing to act on protected process: {verdict.reason}")

    def assert_cgroup_allowed(self, cgroup_path: str | os.PathLike[str]) -> None:
        """A cgroup freeze hits every member, so every member must be unprotected.

        If cgroup.procs cannot be read the freeze is refused (fail closed): freezing a group
        whose membership is unknown is exactly the hazard this interlock exists to prevent.
        """
        procs = Path(cgroup_path) / "cgroup.procs"
        try:
            members: Iterable[int] = [int(x) for x in procs.read_text().split()]
        except (OSError, ValueError) as exc:
            raise ProtectedProcessError(f"cgroup membership unreadable ({exc}); refusing (fail closed)") from exc
        for member in members:
            self.assert_allowed(member)


__all__ = [
    "DEFAULT_PROTECTED_EXE_NAMES", "DEFAULT_TRUSTED_EXE_PREFIXES",
    "ProtectedProcessError", "ProtectedProcessGuard", "ProtectionVerdict",
]
