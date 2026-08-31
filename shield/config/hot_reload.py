"""
Policy hot-reload — spec/xibalba-shield-v1.md §4.6's "safe auto-update for ... policy
bundles," scoped down to what's actually buildable without a real distribution server (see
`loader.py`'s module docstring for why the cloud-API/signed-update half stays `[PLANNED]`):
reloading a LOCAL rules file that changed on disk, without restarting the process.
**Safety property this exists for:** a bad edit to a policy file (a JSON syntax error, one
malformed rule) must never zero out or crash a live enforcement engine. `PolicyHotReloader`
only swaps in a new rule set after `load_policy_rules` parses it successfully end to end —
on any failure, the engine keeps running on its last-known-good rules, and the failure is
logged, never silently swallowed or raised into whatever's calling `check_and_reload()`
(likely a periodic timer in `agent_core`, per spec §4.2 — a hot-reload check failing must
not be able to take down the router any more than a guardrail hook or an export failure can,
matching `router.py`'s own stated posture).
Deliberately mtime-based polling, not a filesystem-event watcher (inotify etc.): one `stat()`
call per check is cheap enough to run on any reasonable interval without a new dependency,
and matches spec §3's "do the least possible work" resource philosophy better than holding an
open inotify watch for a file that changes rarely.
"""
from __future__ import annotations
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from ..policy_engine import PolicyEngine
from .loader import ConfigError, load_policy_bundle
logger = logging.getLogger("shield.config.hot_reload")
@dataclass(frozen=True)
class PolicyReloadStatus:
    """Operator-visible state for the policy lifecycle."""
    healthy: bool
    active_policy_version: str
    active_policy_hash: str
    last_attempt_at: str | None
    last_success_at: str | None
    last_error: str | None
class PolicyHotReloader:
    """Wraps a live `PolicyEngine` and the rules file it should track. Call
    `check_and_reload()` periodically (a timer, a CLI command, a test) — it does nothing
    expensive between changes (one `stat()`) and only touches `policy_engine.rules` when a
    real, successfully-parsed change is available."""
    def __init__(
        self,
        policy_engine: PolicyEngine,
        rules_path: Path | str,
        *,
        trusted_policy_hashes: list[str] | None = None,
        reject_downgrades: bool = False,
    ):
        self._policy_engine = policy_engine
        self._rules_path = Path(rules_path)
        self._trusted_policy_hashes = set(trusted_policy_hashes or [])
        self._reject_downgrades = reject_downgrades
        self._active_revision: int | None = None
        self._last_mtime: float | None = None
        self._healthy = False
        self._last_attempt_at: str | None = None
        self._last_success_at: str | None = None
        self._last_error: str | None = None
    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    def status(self) -> PolicyReloadStatus:
        """Return a snapshot suitable for health endpoints and operator telemetry."""
        return PolicyReloadStatus(
            healthy=self._healthy,
            active_policy_version=self._policy_engine.policy_version,
            active_policy_hash=self._policy_engine.policy_hash,
            last_attempt_at=self._last_attempt_at,
            last_success_at=self._last_success_at,
            last_error=self._last_error,
        )
    def check_and_reload(self) -> bool:
        """Returns True if the engine's rules were actually replaced, False otherwise
        (unchanged file, missing/unreadable file, or a parse failure) — every False path is
        logged with the specific reason, so "nothing happened" and "something is broken and
        stuck on old rules" are distinguishable in the log rather than both being silence."""
        self._last_attempt_at = self._now()
        try:
            mtime = self._rules_path.stat().st_mtime
        except OSError as exc:
            self._healthy = False
            self._last_error = f"cannot stat policy bundle: {exc}"
            logger.warning("policy hot-reload: cannot stat %s (%r) -- keeping current rules", self._rules_path, exc)
            return False
        if mtime == self._last_mtime:
            return False
        try:
            bundle = load_policy_bundle(self._rules_path)
        except ConfigError as exc:
            self._healthy = False
            self._last_error = str(exc)
            logger.error(
                "policy hot-reload: %s failed to parse (%s) -- keeping current rules, NOT "
                "zeroing them out", self._rules_path, exc,
            )
            return False
        if self._trusted_policy_hashes and bundle.hash not in self._trusted_policy_hashes:
            self._healthy = False
            self._last_error = f"policy hash {bundle.hash} is not trusted"
            logger.error(
                "policy hot-reload: %s hash %s is not trusted -- keeping current rules",
                self._rules_path,
                bundle.hash,
            )
            return False
        if self._reject_downgrades and self._active_revision is not None:
            if bundle.revision is None or bundle.revision < self._active_revision:
                self._healthy = False
                self._last_error = (
                    f"policy revision {bundle.revision!r} is lower than active revision "
                    f"{self._active_revision}"
                )
                logger.error("policy hot-reload: %s -- keeping current rules", self._last_error)
                return False
        # We no longer set self._policy_engine.rules, OPA handles rule logic.
        self._policy_engine.policy_version = bundle.version
        self._policy_engine.policy_hash = bundle.hash
        self._active_revision = bundle.revision if bundle.revision is not None else self._active_revision
        self._last_mtime = mtime
        self._healthy = True
        self._last_success_at = self._last_attempt_at
        self._last_error = None
        logger.info(
            "policy hot-reload: %s reloaded, %d rule(s), policy_hash=%s",
            self._rules_path,
            len(bundle.rules),
            bundle.hash,
        )
        return True
