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
from pathlib import Path

from ..policy_engine import PolicyEngine
from .loader import ConfigError, load_policy_bundle

logger = logging.getLogger("shield.config.hot_reload")


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
    ):
        self._policy_engine = policy_engine
        self._rules_path = Path(rules_path)
        self._trusted_policy_hashes = set(trusted_policy_hashes or [])
        self._last_mtime: float | None = None

    def check_and_reload(self) -> bool:
        """Returns True if the engine's rules were actually replaced, False otherwise
        (unchanged file, missing/unreadable file, or a parse failure) — every False path is
        logged with the specific reason, so "nothing happened" and "something is broken and
        stuck on old rules" are distinguishable in the log rather than both being silence."""
        try:
            mtime = self._rules_path.stat().st_mtime
        except OSError as exc:
            logger.warning("policy hot-reload: cannot stat %s (%r) -- keeping current rules", self._rules_path, exc)
            return False

        if mtime == self._last_mtime:
            return False

        try:
            bundle = load_policy_bundle(self._rules_path)
        except ConfigError as exc:
            logger.error(
                "policy hot-reload: %s failed to parse (%s) -- keeping current rules, NOT "
                "zeroing them out", self._rules_path, exc,
            )
            return False
        if self._trusted_policy_hashes and bundle.hash not in self._trusted_policy_hashes:
            logger.error(
                "policy hot-reload: %s hash %s is not trusted -- keeping current rules",
                self._rules_path,
                bundle.hash,
            )
            return False

        self._policy_engine.rules = bundle.rules
        self._policy_engine.policy_version = bundle.version
        self._policy_engine.policy_hash = bundle.hash
        self._last_mtime = mtime
        logger.info(
            "policy hot-reload: %s reloaded, %d rule(s), policy_hash=%s",
            self._rules_path,
            len(bundle.rules),
            bundle.hash,
        )
        return True
