"""DID registration/readback preflight — `docs/PRODUCTION_READINESS_PLAN.md` §7 item 4,
Gate 4 — Evidence continuity.

Before this module, nothing in this repo checked the exporter's own device DID against
`bcc_middleware`/the Oracle before normal operation started -- `IntegrityExporter.__init__`
just loads-or-creates a local DID and assumes it works. The only place any related status
existed was `shield/backend/api.py`'s `_seed_demo`, which hardcoded
`"did_registered": False` and `"oracle_readback": "blocked_until_rpc_credentials"` as
literal placeholders (`shield/backend/store.py`'s own comment confirms these are demo-seed-
only, not wired to anything real). This module replaces that hardcoded placeholder with a
real, checkable status -- the same "explicit and checkable, not silent" discipline
`integrity-core`'s AIS-floor interim decision uses for its own indefinitely-deferred gap.

Deliberately does NOT attempt full on-chain registration (`integrity_sdk.registration.
register_agent`) -- that needs a funder private key, RPC access, and deployed contract
addresses Shield has no config surface for and no business performing on an operator's
behalf. What's checkable without any of that: does a local DID load/create cleanly, is
`bcc_middleware` reachable, and (only if `oracle_url` is configured) is the Oracle reachable
and does it already know this DID. All three are real HTTP checks (stdlib `urllib`, matching
`shield/backend/api.py`'s existing `_verify_detection_quality_receipt`/
`_verify_oracle_audit_readback` convention rather than adding a new HTTP dependency), never
a hardcoded value.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any

from integrity_sdk import did as sdk_did

_DEFAULT_TIMEOUT_SECONDS = 5.0


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _reachable(url: str, *, timeout: float) -> bool:
    request = urllib.request.Request(url, method="GET", headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return 200 <= response.status < 300
    except Exception:  # noqa: BLE001 - a preflight check reports False/None, never raises
        return False


def _oracle_registered(oracle_url: str, agent_id: str, *, timeout: float) -> bool | None:
    """True/False are conclusive answers; None means the check itself was inconclusive
    (e.g. the Oracle is reachable for /healthz but this endpoint errored for an unrelated
    reason) -- deliberately distinct from "confirmed not registered" (404)."""
    url = f"{oracle_url.rstrip('/')}/v1/agent/{urllib.parse.quote(agent_id, safe='')}"
    request = urllib.request.Request(url, method="GET", headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return 200 <= response.status < 300
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return False
        return None
    except Exception:  # noqa: BLE001
        return None


def check_did_preflight(
    *,
    bcc_middleware_url: str,
    oracle_url: str | None = None,
    agent_label: str = "xibalba-shield",
    timeout: float = _DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Real, checkable DID/readback status -- see module docstring for what "real" does
    and doesn't mean here. Never raises; a failed sub-check reports False/None in the
    result rather than aborting the whole preflight."""
    result: dict[str, Any] = {
        "checked_at": _now_iso(),
        "did": None,
        "did_loaded": False,
        "bcc_middleware_reachable": None,
        "oracle_configured": oracle_url is not None,
        "oracle_reachable": None,
        "oracle_registered": None,
    }

    try:
        agent_id, _keypair, _doc = sdk_did.load_or_create_did(agent_label)
        result["did"] = agent_id
        result["did_loaded"] = True
    except Exception as exc:  # noqa: BLE001
        result["error"] = f"DID load/create failed: {exc}"
        return result

    result["bcc_middleware_reachable"] = _reachable(f"{bcc_middleware_url.rstrip('/')}/health", timeout=timeout)

    if oracle_url:
        result["oracle_reachable"] = _reachable(f"{oracle_url.rstrip('/')}/healthz", timeout=timeout)
        if result["oracle_reachable"]:
            result["oracle_registered"] = _oracle_registered(oracle_url, agent_id, timeout=timeout)

    return result
