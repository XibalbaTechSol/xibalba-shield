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

Real rollback (`rollback_to`) is distinct from the passive "keep last-known-good on parse
failure" behavior above: it's an explicit operator action, restoring a specific previously
active bundle from a bounded local history, deliberately bypassing the downgrade check --
that check exists to stop an accidental/malicious revision regression during normal
operation, not to stop an operator who has decided a rollback is exactly what they want.
"""
from __future__ import annotations
import json
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
    signed: bool = False
    expires_at: str | None = None


@dataclass(frozen=True)
class PolicyHistoryEntry:
    hash: str
    policy_version: str
    revision: int | None
    loaded_at: str


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
        trusted_signing_keys: list[str] | None = None,
        require_signed_policy: bool = False,
        history_dir: Path | str | None = None,
        history_limit: int = 5,
    ):
        self._policy_engine = policy_engine
        self._rules_path = Path(rules_path)
        self._trusted_policy_hashes = set(trusted_policy_hashes or [])
        self._reject_downgrades = reject_downgrades
        self._trusted_signing_keys = list(trusted_signing_keys or [])
        self._require_signed_policy = require_signed_policy
        self._history_dir = Path(history_dir) if history_dir is not None else self._rules_path.parent / "history"
        self._history_limit = history_limit
        self._active_revision: int | None = None
        self._last_mtime: float | None = None
        self._healthy = False
        self._last_attempt_at: str | None = None
        self._last_success_at: str | None = None
        self._last_error: str | None = None
        self._signed = False
        self._expires_at: str | None = None

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
            signed=self._signed,
            expires_at=self._expires_at,
        )

    def _expiry_passed(self) -> bool:
        if not self._expires_at:
            return False
        try:
            expiry = datetime.fromisoformat(self._expires_at.replace("Z", "+00:00"))
        except ValueError:
            return False
        return expiry <= datetime.now(timezone.utc)

    def check_and_reload(self) -> bool:
        """Returns True if the engine's rules were actually replaced, False otherwise
        (unchanged file, missing/unreadable file, a parse failure, or an expired active
        bundle) — every False path is logged with the specific reason, so "nothing
        happened" and "something is broken and stuck on old rules" are distinguishable in
        the log rather than both being silence."""
        self._last_attempt_at = self._now()

        # Expiry is re-checked every call, independent of the mtime shortcut below: an
        # unchanged-but-now-expired bundle must stop being reported healthy without
        # needing a new file write to trigger the mtime check that would otherwise be
        # the only thing that ever re-examines an already-loaded bundle.
        if self._expiry_passed():
            self._healthy = False
            self._last_error = f"active policy expired at {self._expires_at}"
            logger.error("policy hot-reload: %s -- keeping current rules loaded but reporting unhealthy", self._last_error)
            return False

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
            bundle = load_policy_bundle(
                self._rules_path,
                trusted_signing_keys=self._trusted_signing_keys,
                require_signed_policy=self._require_signed_policy,
            )
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
        self._apply(bundle, mtime)
        self._record_history(bundle)
        logger.info(
            "policy hot-reload: %s reloaded, %d rule(s), policy_hash=%s",
            self._rules_path,
            len(bundle.rules),
            bundle.hash,
        )
        return True

    def _apply(self, bundle, mtime: float | None) -> None:
        # We no longer set self._policy_engine.rules, OPA handles rule logic.
        self._policy_engine.policy_version = bundle.version
        self._policy_engine.policy_hash = bundle.hash
        self._active_revision = bundle.revision if bundle.revision is not None else self._active_revision
        if mtime is not None:
            self._last_mtime = mtime
        self._healthy = True
        self._last_success_at = self._last_attempt_at
        self._last_error = None
        self._signed = bundle.signed
        self._expires_at = bundle.expires_at

    def _record_history(self, bundle) -> None:
        """Best-effort: a history-write failure must never fail the reload it's
        recording, matching this module's overall fail-soft-on-secondary-concerns
        posture (see the module docstring's safety property)."""
        try:
            self._history_dir.mkdir(parents=True, exist_ok=True)
            digest = bundle.hash.removeprefix("sha256:")
            entry_path = self._history_dir / f"{digest}.json"
            if not entry_path.exists():
                entry_path.write_bytes(self._rules_path.read_bytes())

            index_path = self._history_dir / "index.json"
            try:
                index = json.loads(index_path.read_text()) if index_path.exists() else []
            except (OSError, json.JSONDecodeError):
                index = []
            index = [e for e in index if e.get("hash") != bundle.hash]
            index.append({
                "hash": bundle.hash,
                "policy_version": bundle.version,
                "revision": bundle.revision,
                "loaded_at": self._last_success_at,
            })
            index = index[-self._history_limit:]
            index_path.write_text(json.dumps(index, indent=2))

            kept_hashes = {e["hash"].removeprefix("sha256:") for e in index}
            for stale in self._history_dir.glob("*.json"):
                if stale.name != "index.json" and stale.stem not in kept_hashes:
                    stale.unlink(missing_ok=True)
        except OSError as exc:
            logger.warning("policy hot-reload: failed to record history for %s: %r", bundle.hash, exc)

    def history(self) -> list[PolicyHistoryEntry]:
        """Newest first. Empty if no reload has ever succeeded (or history is
        disabled/unwritable) -- this reads back exactly what `_record_history` wrote,
        so it reflects the same bounded retention `rollback_to` can act on."""
        index_path = self._history_dir / "index.json"
        if not index_path.exists():
            return []
        try:
            index = json.loads(index_path.read_text())
        except (OSError, json.JSONDecodeError):
            return []
        return [
            PolicyHistoryEntry(hash=e["hash"], policy_version=e.get("policy_version", ""), revision=e.get("revision"), loaded_at=e.get("loaded_at", ""))
            for e in reversed(index)
        ]

    def rollback_to(self, target_hash: str) -> bool:
        """Restore a specific previously-active bundle from local history. Returns
        False (does not raise) if `target_hash` isn't in the retained history --
        bounded retention is a real limit an operator needs to see plainly, not a
        silent no-op. Deliberately bypasses the downgrade check: rollback IS an
        intentional revision regression, the exact thing that check exists to catch
        when it's accidental."""
        digest = target_hash.removeprefix("sha256:")
        entry_path = self._history_dir / f"{digest}.json"
        if not entry_path.exists():
            logger.error("policy rollback: hash %s is not in retained history at %s", target_hash, self._history_dir)
            return False
        try:
            bundle = load_policy_bundle(
                entry_path,
                trusted_signing_keys=self._trusted_signing_keys,
                require_signed_policy=self._require_signed_policy,
            )
        except ConfigError as exc:
            logger.error("policy rollback: retained history for %s no longer parses: %s", target_hash, exc)
            return False
        self._rules_path.write_bytes(entry_path.read_bytes())
        self._last_attempt_at = self._now()
        try:
            mtime = self._rules_path.stat().st_mtime
        except OSError:
            mtime = None
        self._apply(bundle, mtime)
        logger.info("policy rollback: %s restored to hash %s (version %s)", self._rules_path, bundle.hash, bundle.version)
        return True
