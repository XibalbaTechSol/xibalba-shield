"""Fetch this device's signed entitlement from the backend and write it where the gate reads it.

Design: docs/superpowers/specs/2026-11-12-shield-plans-metering-design.md §6. A separate process from
`gate-daemon` (`shield entitlement-fetch`), and never imported by the gate: billing is never in the
decision path (§1). The gate only ever reads the file this writes, through `EntitlementGate`.

A fetch replaces the file only with a document that verifies, against the keys pinned at enrollment,
for this tenant and device, as either ``ok`` (enforce) or ``plan`` (valid, without enforce -- a
legitimate downgrade after a cancellation). Anything else -- network failure, 5xx, "not configured",
a refused credential, a document that does not verify -- leaves the existing file byte-for-byte
untouched, so the gate keeps its last valid entitlement until that document's own `not_after`.

The write is atomic: a temp file in the same directory, fsync, `os.replace`, then a best-effort fsync of
the directory (Windows cannot open a directory; the rename is the atomic step either way).
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Optional, Sequence
from urllib.parse import urlencode

from .entitlement import STATUS_OK, STATUS_PLAN, verify_entitlement
from .gate_usage import _fsync_directory

logger = logging.getLogger(__name__)

ENTITLEMENT_PATH = "/api/shield/entitlement"
MAX_RESPONSE_BYTES = 65536

#: Statuses a fetched document must verify as before it may replace the file.
WRITABLE_STATUSES = frozenset({STATUS_OK, STATUS_PLAN})
#: Answers that mean "try again later" (route not deployed, issuing not configured, overload).
RETRY_STATUSES = frozenset({404, 408, 425, 429})

OUTCOME_WRITTEN = "written"
OUTCOME_RETRY = "retry"
OUTCOME_REFUSED = "refused"

#: (url, headers) -> (status, body text); raises OSError for a network failure.
GetTransport = Callable[[str, dict[str, str]], tuple[int, str]]


@dataclass(frozen=True)
class FetchOutcome:
    outcome: str            # written | retry | refused
    detail: str = ""
    status: Optional[str] = None   # the verification status of a document that arrived

    @property
    def exit_code(self) -> int:
        return {OUTCOME_WRITTEN: 0, OUTCOME_RETRY: 3}.get(self.outcome, 1)


def _urllib_get(context: Any = None, timeout: float = 10.0) -> GetTransport:
    from urllib.error import HTTPError
    from urllib.request import Request, urlopen

    def send(url: str, headers: dict[str, str]) -> tuple[int, str]:
        request = Request(url, headers=headers, method="GET")
        try:
            with urlopen(request, timeout=timeout, **({"context": context} if context else {})) as response:
                return int(getattr(response, "status", 200)), response.read(MAX_RESPONSE_BYTES).decode("utf-8", "replace")
        except HTTPError as exc:
            return int(exc.code), exc.read(4096).decode("utf-8", "replace") if exc.fp else ""

    return send


def write_entitlement_atomic(path: Path | str, document: Mapping[str, Any]) -> None:
    """Replace `path` with `document` atomically; on any failure the previous file is untouched."""
    target = Path(path)
    directory = target.parent
    directory.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(dict(document), sort_keys=True).encode("utf-8")
    fd, tmp = tempfile.mkstemp(prefix=".entitlement.", dir=directory)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, target)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    _fsync_directory(directory)


def fetch_entitlement(
    *,
    base_url: str,
    tenant_id: str,
    device_id: str,
    trusted_keys: Sequence[str],
    path: Path | str,
    transport: GetTransport,
    auth_header: Callable[[], str],
    now: Optional[Callable[[], datetime]] = None,
) -> FetchOutcome:
    """One fetch. Never raises for a network or backend problem; writes only a verified document."""
    if not trusted_keys:
        return FetchOutcome(OUTCOME_REFUSED, "no trusted entitlement keys are pinned (gate_zone.entitlement_keys "
                                             "or --entitlement-key); refusing to write a document the gate cannot verify")
    url = f"{base_url.rstrip('/')}{ENTITLEMENT_PATH}?{urlencode({'tenant_id': tenant_id, 'device_id': device_id})}"
    headers = {"Accept": "application/json"}
    try:
        authorization = auth_header()
    except Exception as exc:  # noqa: BLE001 -- a credential problem is a refusal, not a crash
        return FetchOutcome(OUTCOME_REFUSED, f"could not build the device credential: {exc}")
    if authorization:
        headers["Authorization"] = authorization
    try:
        status, text = transport(url, headers)
    except OSError as exc:
        return FetchOutcome(OUTCOME_RETRY, f"backend unreachable: {exc}")
    if status in RETRY_STATUSES or status >= 500:
        return FetchOutcome(OUTCOME_RETRY, f"backend answered {status}: {text[:200]}")
    if not 200 <= status < 300:
        return FetchOutcome(OUTCOME_REFUSED, f"backend refused ({status}): {text[:200]}")
    try:
        document = json.loads(text)["entitlement"]
    except (ValueError, KeyError, TypeError):
        return FetchOutcome(OUTCOME_REFUSED, "backend answer carried no entitlement document")
    moment = now() if now else datetime.now(timezone.utc)
    verified = verify_entitlement(document, trusted_keys=list(trusted_keys), tenant_id=tenant_id,
                                  device_id=device_id, now=moment)
    if verified not in WRITABLE_STATUSES:
        return FetchOutcome(OUTCOME_REFUSED, f"fetched entitlement does not verify ({verified}); file kept",
                            status=verified)
    try:
        write_entitlement_atomic(path, document)
    except OSError as exc:
        return FetchOutcome(OUTCOME_RETRY, f"could not write {path}: {exc}", status=verified)
    return FetchOutcome(OUTCOME_WRITTEN, f"wrote {path}", status=verified)


def fetch_for_device_config(
    device_config: Any,
    *,
    path: Path | str,
    extra_keys: Sequence[str] = (),
    transport: Optional[GetTransport] = None,
) -> FetchOutcome:
    """`fetch_entitlement` with the device config's backend, credentials and pinned keys."""
    if transport is None:
        from .config.tls import build_client_context

        transport = _urllib_get(build_client_context(device_config))
    base_url = device_config.backend_url.rstrip("/")

    def auth_header() -> str:
        from .device_assertion import device_auth_header

        return device_auth_header(
            tenant_id=device_config.tenant_id, device_id=device_config.device_id, audience=base_url,
            device_token=device_config.device_token, device_key_path=device_config.device_key_path or None,
        )

    keys = [*(device_config.gate_zone or {}).get("entitlement_keys", []), *extra_keys]
    return fetch_entitlement(
        base_url=base_url, tenant_id=device_config.tenant_id, device_id=device_config.device_id,
        trusted_keys=list(dict.fromkeys(keys)), path=path, transport=transport, auth_header=auth_header,
    )


def run(fetch: Callable[[], FetchOutcome], *, once: bool, interval: float,
        sleep: Callable[[float], None] = time.sleep) -> int:
    """Fetch once (exit code from the outcome) or forever every `interval` seconds."""
    while True:
        outcome = fetch()
        log = logger.info if outcome.outcome == OUTCOME_WRITTEN else logger.warning
        log("entitlement fetch: %s (%s)", outcome.outcome, outcome.detail)
        if once:
            return outcome.exit_code
        sleep(interval)


__all__ = [
    "ENTITLEMENT_PATH", "FetchOutcome", "OUTCOME_REFUSED", "OUTCOME_RETRY", "OUTCOME_WRITTEN",
    "WRITABLE_STATUSES", "fetch_entitlement", "fetch_for_device_config", "run", "write_entitlement_atomic",
]
