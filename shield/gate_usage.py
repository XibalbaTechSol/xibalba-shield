"""Usage reports from the gate's own receipts (Shield plans & metering design, §3).

The gate daemon writes one signed, chained receipt per tool-call decision and a signed checkpoint every
`checkpoint_every` receipts (`shield.gate_receipts`). This module turns those files into usage reports for
the backend's `POST /api/shield/usage`:

* one report per signed checkpoint the backend has not yet acknowledged, covering exactly
  ``[previous tree_size, tree_size)`` -- so every reported range is already covered by a signature the device
  produced, and nothing past the last checkpoint is ever reported;
* per-class counts from `integrity_sdk.billing.classify_for_billing`, the same exclusion set the local AIS
  scorer uses (zone-mask denials and gate faults are never billable);
* a cursor file (`usage_cursor.json`, next to the receipts) holding, per `log_id`, the last tree_size the
  backend acknowledged. A reinstall writes a new chain with a new `log_id`, which starts from 0.

What this module never does (§1): it is not in the decision path. It runs as its own subcommand, reads the
receipt files without writing them (a torn final line is the writer's to repair, not ours), and a backend
that is down or does not know the route yet only delays reporting.

Before reporting, the log is verified against the gate's signing key: every receipt signature, contiguous
sequence numbers, the hash chain, and each new checkpoint's Merkle root over its prefix. A log that does not
verify raises `UsageReportError` and nothing is reported.
"""

from __future__ import annotations

import json
import logging
import os
import random
import tempfile
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from integrity_sdk.billing import (
    BILLABLE,
    EXCLUDED_FAULT,
    EXCLUDED_MASK,
    classify_for_billing,
)
from integrity_sdk.core.receipts import ReceiptError, verify_log

from .gate_receipts import CHECKPOINTS_FILENAME, RECEIPTS_FILENAME

logger = logging.getLogger(__name__)

REPORT_SCHEMA = "xibalba.shield.usage-report.v1"
CURSOR_FILENAME = "usage_cursor.json"
CURSOR_SCHEMA = "xibalba.shield.usage-cursor.v1"
USAGE_PATH = "/api/shield/usage"


class UsageReportError(Exception):
    """The receipt log cannot be reported: it does not verify, or a file is corrupt."""


@dataclass(frozen=True)
class UsageReport:
    log_id: str
    seq_from: int
    seq_to: int
    counts: dict[str, int]
    checkpoint: dict[str, Any]

    @property
    def tree_size(self) -> int:
        return self.seq_to + 1

    def body(self, *, tenant_id: str, device_id: str) -> dict[str, Any]:
        """The §3.1 request body."""
        return {
            "schema": REPORT_SCHEMA,
            "tenant_id": tenant_id,
            "device_id": device_id,
            "log_id": self.log_id,
            "seq_from": self.seq_from,
            "seq_to": self.seq_to,
            "counts": dict(self.counts),
            "checkpoint": dict(self.checkpoint),
        }


# --------------------------------------------------------------------------- reading


def _read_jsonl_readonly(path: Path, what: str) -> list[dict[str, Any]]:
    """Complete JSON lines only. A final line without a newline is a write in progress: ignored, not repaired."""
    if not path.exists():
        return []
    data = path.read_bytes()
    complete = data[: data.rfind(b"\n") + 1]
    rows: list[dict[str, Any]] = []
    for number, line in enumerate(complete.split(b"\n")[:-1], start=1):
        try:
            row = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise UsageReportError(f"{what} {path} line {number} is not valid JSON: {exc}") from exc
        if not isinstance(row, dict):
            raise UsageReportError(f"{what} {path} line {number} is not a JSON object")
        rows.append(row)
    return rows


def _empty_counts() -> dict[str, int]:
    return {BILLABLE: 0, EXCLUDED_MASK: 0, EXCLUDED_FAULT: 0}


# --------------------------------------------------------------------------- cursor


def load_cursor(receipt_dir: Path | str) -> dict[str, int]:
    """`{log_id: acknowledged tree_size}`; empty when no report was ever acknowledged."""
    path = Path(receipt_dir) / CURSOR_FILENAME
    if not path.exists():
        return {}
    try:
        doc = json.loads(path.read_text())
        logs = doc["logs"]
        if doc.get("schema") != CURSOR_SCHEMA or not isinstance(logs, dict):
            raise ValueError("unexpected cursor shape")
        cursor = {str(k): int(v) for k, v in logs.items()}
    except (OSError, ValueError, KeyError, TypeError) as exc:
        # Refuse rather than restart from 0: re-sending acknowledged ranges is harmless (the backend's ledger
        # treats identical replays as no-ops) but silently doing so would hide a corrupted state file.
        raise UsageReportError(f"usage cursor {path} is unreadable: {exc}") from exc
    if any(v < 0 for v in cursor.values()):
        raise UsageReportError(f"usage cursor {path} has a negative tree_size")
    return cursor


def save_cursor(receipt_dir: Path | str, cursor: Mapping[str, int]) -> None:
    """Atomic: temp file in the same directory, fsync, rename, fsync the directory."""
    directory = Path(receipt_dir)
    payload = json.dumps({"schema": CURSOR_SCHEMA, "logs": dict(cursor)}, sort_keys=True).encode()
    fd, tmp = tempfile.mkstemp(prefix=".usage_cursor.", dir=directory)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, directory / CURSOR_FILENAME)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    _fsync_directory(directory)


def _fsync_directory(directory: Path) -> None:
    """Make the rename durable where the platform allows it (POSIX). Windows refuses to open a directory, and
    the rename itself is already the atomic step, so this is best effort -- the same posture as the SDK writer."""
    try:
        dir_fd = os.open(directory, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(dir_fd)
    except OSError:
        pass
    finally:
        os.close(dir_fd)


# --------------------------------------------------------------------------- building


def build_reports(
    receipt_dir: Path | str,
    cursor: Mapping[str, int],
    *,
    trusted_signers: list[str],
) -> list[UsageReport]:
    """One report per signed checkpoint beyond `cursor`, oldest first. Raises `UsageReportError` on a bad log."""
    if not trusted_signers:
        raise UsageReportError("a trusted receipt signer key is required to verify the log before reporting")
    directory = Path(receipt_dir)
    receipts = _read_jsonl_readonly(directory / RECEIPTS_FILENAME, "receipt log")
    checkpoints = _read_jsonl_readonly(directory / CHECKPOINTS_FILENAME, "checkpoint log")
    if not receipts or not checkpoints:
        return []

    log_id = receipts[0].get("log_id")
    if not isinstance(log_id, str) or not log_id:
        raise UsageReportError("receipt 0 has no log_id")
    acknowledged = int(cursor.get(log_id, 0))

    # Only checkpoints of this log, in increasing tree_size; a clean close can repeat a size already covered.
    covering: list[dict[str, Any]] = []
    for checkpoint in checkpoints:
        size = checkpoint.get("tree_size")
        if checkpoint.get("log_id") != log_id:
            raise UsageReportError("a checkpoint belongs to a different log than the receipts")
        if not isinstance(size, int) or isinstance(size, bool) or size < 1:
            raise UsageReportError(f"checkpoint has an invalid tree_size {size!r}")
        if covering and size < covering[-1]["tree_size"]:
            raise UsageReportError("checkpoints go backwards")
        if not covering or size > covering[-1]["tree_size"]:
            covering.append(checkpoint)
    if covering and acknowledged > covering[-1]["tree_size"]:
        raise UsageReportError(
            f"the cursor says {acknowledged} receipts were reported but the log's last checkpoint covers "
            f"{covering[-1]['tree_size']}: the log was truncated or replaced under the same log_id"
        )
    pending = [cp for cp in covering if cp["tree_size"] > acknowledged]
    if not pending:
        return []

    # Whole chain once, then each new checkpoint's root over its own prefix.
    try:
        verify_log(receipts, trusted_signers=trusted_signers)
        for checkpoint in pending:
            verify_log(receipts[: checkpoint["tree_size"]], trusted_signers=trusted_signers, checkpoint=checkpoint)
    except ReceiptError as exc:
        raise UsageReportError(f"receipt log does not verify ({exc.code}): {exc}") from exc

    reports: list[UsageReport] = []
    start = acknowledged
    for checkpoint in pending:
        end = checkpoint["tree_size"]
        counts = _empty_counts()
        for receipt in receipts[start:end]:
            counts[classify_for_billing(receipt)] += 1
        reports.append(UsageReport(log_id=log_id, seq_from=start, seq_to=end - 1, counts=counts, checkpoint=dict(checkpoint)))
        start = end
    return reports


# --------------------------------------------------------------------------- uploading

#: (status, response text) or raises OSError for a network failure.
Transport = Callable[[str, bytes, dict[str, str]], tuple[int, str]]


def _urllib_transport(context: Any = None, timeout: float = 10.0) -> Transport:
    from urllib.error import HTTPError
    from urllib.request import Request, urlopen

    def send(url: str, body: bytes, headers: dict[str, str]) -> tuple[int, str]:
        request = Request(url, data=body, headers=headers, method="POST")
        try:
            with urlopen(request, timeout=timeout, **({"context": context} if context else {})) as response:
                return int(getattr(response, "status", 200)), response.read(4096).decode("utf-8", "replace")
        except HTTPError as exc:
            return int(exc.code), exc.read(4096).decode("utf-8", "replace") if exc.fp else ""

    return send


@dataclass
class UploadOutcome:
    sent: int = 0
    acknowledged: int = 0
    retry_later: bool = False
    rejected: str | None = None


class UsageUploader:
    """Sends reports in order and advances the cursor only for ranges the backend acknowledged.

    * 2xx -- acknowledged (a replay of an identical range is a 200 from the ledger); advance and continue.
    * 400/401/403/409/422 -- the backend refused this range. Stop, do not advance, surface the reason: the
      same bytes would be refused again, and a 409 means the backend holds a *different* body for this range.
    * 404, 408, 429, 5xx, network errors -- try again later (the route may not be deployed yet). Stop, do not
      advance; `run` backs off.
    """

    RETRY_STATUSES = frozenset({404, 408, 425, 429})

    def __init__(
        self,
        base_url: str,
        tenant_id: str,
        device_id: str,
        device_token: str = "",
        *,
        device_key_path: str = "",
        transport: Transport | None = None,
        auth_header: Callable[[], str] | None = None,
    ) -> None:
        if not base_url:
            raise ValueError("a backend URL is required to upload usage reports")
        self.base_url = base_url.rstrip("/")
        self.tenant_id = tenant_id
        self.device_id = device_id
        self.device_token = device_token
        self.device_key_path = device_key_path
        self.transport = transport or _urllib_transport()
        self._auth_header = auth_header

    @classmethod
    def from_device_config(cls, device_config: Any, *, transport: Transport | None = None) -> UsageUploader:
        if transport is None:
            from .config.tls import build_client_context

            transport = _urllib_transport(build_client_context(device_config))
        return cls(
            device_config.backend_url, device_config.tenant_id, device_config.device_id,
            device_config.device_token, device_key_path=device_config.device_key_path, transport=transport,
        )

    def _headers(self) -> dict[str, str]:
        if self._auth_header is not None:
            authorization = self._auth_header()
        else:
            from .device_assertion import device_auth_header

            authorization = device_auth_header(
                tenant_id=self.tenant_id, device_id=self.device_id, audience=self.base_url,
                device_token=self.device_token, device_key_path=self.device_key_path or None,
            )
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        if authorization:
            headers["Authorization"] = authorization
        return headers

    def upload(self, receipt_dir: Path | str, reports: list[UsageReport]) -> UploadOutcome:
        outcome = UploadOutcome()
        cursor = load_cursor(receipt_dir)
        for report in reports:
            body = json.dumps(report.body(tenant_id=self.tenant_id, device_id=self.device_id), sort_keys=True).encode()
            outcome.sent += 1
            try:
                status, text = self.transport(self.base_url + USAGE_PATH, body, self._headers())
            except OSError as exc:
                logger.warning("usage report %s[%d..%d] not sent: %s", report.log_id, report.seq_from, report.seq_to, exc)
                outcome.retry_later = True
                return outcome
            if 200 <= status < 300:
                cursor[report.log_id] = report.tree_size
                save_cursor(receipt_dir, cursor)
                outcome.acknowledged += 1
                continue
            if status in self.RETRY_STATUSES or status >= 500:
                logger.warning("usage report %s[%d..%d]: backend HTTP %d, will retry",
                               report.log_id, report.seq_from, report.seq_to, status)
                outcome.retry_later = True
                return outcome
            outcome.rejected = f"HTTP {status}: {text[:500]}"
            logger.error("usage report %s[%d..%d] refused by the backend (%s); not advancing",
                         report.log_id, report.seq_from, report.seq_to, outcome.rejected)
            return outcome
        return outcome


def backoff_delays(*, base: float = 5.0, cap: float = 900.0, jitter: Callable[[], float] = random.random):
    """Exponential delays with full jitter, capped: 5s, 10s, 20s ... at most `cap`."""
    attempt = 0
    while True:
        ceiling = min(cap, base * (2 ** attempt))
        yield ceiling * (0.5 + 0.5 * jitter())
        attempt = min(attempt + 1, 32)


def run(
    receipt_dir: Path | str,
    uploader: UsageUploader,
    *,
    trusted_signers: list[str],
    once: bool = False,
    interval: float = 300.0,
    sleep: Callable[[float], None] = time.sleep,
    delays: Any | None = None,
) -> int:
    """Report until stopped (or one pass with `once`). Exit codes: 0 ok, 1 log/refusal error, 3 retry pending."""
    delays = delays or backoff_delays()
    while True:
        reports = build_reports(receipt_dir, load_cursor(receipt_dir), trusted_signers=trusted_signers)
        outcome = uploader.upload(receipt_dir, reports)
        if outcome.rejected:
            return 1
        if once:
            return 3 if outcome.retry_later else 0
        if outcome.retry_later:
            sleep(next(delays))
            continue
        delays = backoff_delays()
        sleep(interval)
