"""Usage-report ledger: the backend half of `shield usage-report` (design §3, Phase 3a).

A device reports gated-decision counts per receipt range. Each range ends on a checkpoint the
device already signed, so the backend never trusts a bare number:

* the checkpoint must verify, and its signer must be the key this device is *currently* bound to
  (`did:integrity:sha256(pubkey)` == `devices.integrity_agent_id`). A key the device no longer
  holds cannot add to its bill; a rotated device's old logs are refused (an under-count, which
  costs us and not the customer);
* `checkpoint.log_id == log_id`, `checkpoint.tree_size == seq_to + 1`, and the three class
  counts sum to the range length.

The per-class split is still self-reported (design §3.4); Phase 4 audits it.

Ledger rules (design §3.3), keyed by `(tenant_id, log_id, seq_from)`:

* identical replay -> 200 no-op; same start with a different body -> 409;
* a range intersecting a stored one for that log -> 409;
* gaps are accepted and *derived at read time*, never stored or invented;
* a reinstall is a new `log_id` starting at 0, so it adds to the total.

Usage is attributed to the period in which the backend *received* it (design §5), so only
`received_at` is stored and the period is computed by the query.

Billing is never in a gate's decision path (design §1): nothing here is consulted by a gate.
"""
from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from http import HTTPStatus
from typing import Any

from integrity_sdk.core.receipts import ReceiptError, verify_checkpoint
from integrity_sdk.core.signing import public_key_from_multibase
from integrity_sdk.did import fingerprint_for_pubkey

from ..gate_usage import REPORT_SCHEMA  # one schema constant for the device and the backend

COUNT_FIELDS = ("billable", "excluded_mask", "excluded_fault")
_REPORT_FIELDS = frozenset({"schema", "tenant_id", "device_id", "log_id", "seq_from", "seq_to", "counts", "checkpoint"})
_PERIOD_LEN = len("YYYY-MM")


class UsageRejected(Exception):
    """A report the backend refuses; `status` is the HTTP status to answer with."""

    def __init__(self, status: HTTPStatus, message: str) -> None:
        super().__init__(message)
        self.status = status


@dataclass(frozen=True)
class _Report:
    tenant_id: str
    device_id: str
    log_id: str
    seq_from: int
    seq_to: int
    counts: dict[str, int]
    root: str


def _int(value: Any, what: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise UsageRejected(HTTPStatus.BAD_REQUEST, f"{what} must be an integer")
    if value < 0:
        raise UsageRejected(HTTPStatus.BAD_REQUEST, f"{what} must not be negative")
    return value


def _did_for_signer(signer_key: Any) -> str:
    try:
        return f"did:integrity:{fingerprint_for_pubkey(public_key_from_multibase(signer_key))}"
    except (ValueError, TypeError) as exc:
        raise UsageRejected(HTTPStatus.BAD_REQUEST, "checkpoint signer_key is not an Ed25519 multibase key") from exc


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class UsageLedgerStore:
    def __init__(
        self,
        conn: Any,
        *,
        enrolled_agent_id: Callable[[str, str], str | None],
        clock: Callable[[], str] = _now,
    ) -> None:
        self._conn = conn
        self._enrolled_agent_id = enrolled_agent_id
        self._clock = clock

    def init_schema(self) -> None:
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS usage_reports (
                tenant_id TEXT NOT NULL,
                log_id TEXT NOT NULL,
                seq_from INTEGER NOT NULL,
                seq_to INTEGER NOT NULL,
                device_id TEXT NOT NULL,
                billable INTEGER NOT NULL,
                excluded_mask INTEGER NOT NULL,
                excluded_fault INTEGER NOT NULL,
                checkpoint_root TEXT NOT NULL,
                received_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, log_id, seq_from)
            );
            CREATE INDEX IF NOT EXISTS idx_usage_reports_received ON usage_reports(tenant_id, received_at);
            """
        )
        self._conn.commit()

    # -- ingest -------------------------------------------------------------------------------

    def validate(self, body: Mapping[str, Any], *, tenant_id: str, device_id: str) -> _Report:
        """Check a report against design §3.2. `tenant_id`/`device_id` are the authenticated ids."""
        if not isinstance(body, Mapping) or set(body) != _REPORT_FIELDS:
            raise UsageRejected(HTTPStatus.BAD_REQUEST, "usage report fields do not match the report schema")
        if body["schema"] != REPORT_SCHEMA:
            raise UsageRejected(HTTPStatus.BAD_REQUEST, "unsupported usage report schema")
        if body["tenant_id"] != tenant_id or body["device_id"] != device_id:
            raise UsageRejected(HTTPStatus.FORBIDDEN, "a device may only report its own usage")
        log_id = body["log_id"]
        if not isinstance(log_id, str) or not log_id:
            raise UsageRejected(HTTPStatus.BAD_REQUEST, "log_id must be a non-empty string")
        seq_from = _int(body["seq_from"], "seq_from")
        seq_to = _int(body["seq_to"], "seq_to")
        if seq_to < seq_from:
            raise UsageRejected(HTTPStatus.BAD_REQUEST, "seq_to must not be below seq_from")
        raw_counts = body["counts"]
        if not isinstance(raw_counts, Mapping) or set(raw_counts) != set(COUNT_FIELDS):
            raise UsageRejected(HTTPStatus.BAD_REQUEST, f"counts must have exactly {', '.join(COUNT_FIELDS)}")
        counts = {name: _int(raw_counts[name], f"counts.{name}") for name in COUNT_FIELDS}
        if sum(counts.values()) != seq_to - seq_from + 1:
            raise UsageRejected(HTTPStatus.BAD_REQUEST, "counts do not sum to the reported range")

        checkpoint = body["checkpoint"]
        if not isinstance(checkpoint, Mapping):
            raise UsageRejected(HTTPStatus.BAD_REQUEST, "checkpoint must be an object")
        if checkpoint.get("log_id") != log_id:
            raise UsageRejected(HTTPStatus.BAD_REQUEST, "checkpoint log_id does not match the report")
        if checkpoint.get("tree_size") != seq_to + 1:
            raise UsageRejected(HTTPStatus.BAD_REQUEST, "checkpoint tree_size must equal seq_to + 1")

        # Who signed it must be decided by the backend's record, never by the key in the body.
        enrolled = self._enrolled_agent_id(tenant_id, device_id)
        if not enrolled:
            raise UsageRejected(HTTPStatus.FORBIDDEN, "device has no registered signing identity")
        signer_key = checkpoint.get("signer_key")
        if _did_for_signer(signer_key) != enrolled:
            raise UsageRejected(HTTPStatus.FORBIDDEN, "checkpoint is not signed by this device's registered key")
        try:
            verify_checkpoint(checkpoint, trusted_signers=[signer_key])
        except ReceiptError as exc:
            raise UsageRejected(HTTPStatus.BAD_REQUEST, f"checkpoint does not verify: {exc}") from exc
        return _Report(tenant_id, device_id, log_id, seq_from, seq_to, counts, str(checkpoint["root"]))

    def record(self, body: Mapping[str, Any], *, tenant_id: str, device_id: str) -> tuple[HTTPStatus, dict[str, Any]]:
        """Validate and store one report. Returns `(status, payload)`; raises `UsageRejected`."""
        report = self.validate(body, tenant_id=tenant_id, device_id=device_id)
        stored = (report.device_id, report.seq_to, *(report.counts[c] for c in COUNT_FIELDS), report.root)
        # `with conn` holds the connection lock for the whole transaction, so the replay and
        # overlap checks and the insert are one atomic step under concurrent requests.
        with self._conn:
            existing = self._conn.execute(
                "SELECT device_id, seq_to, billable, excluded_mask, excluded_fault, checkpoint_root "
                "FROM usage_reports WHERE tenant_id=? AND log_id=? AND seq_from=?",
                (report.tenant_id, report.log_id, report.seq_from),
            ).fetchone()
            if existing is not None:
                if tuple(existing) == stored:
                    return HTTPStatus.OK, {"ok": True, "replay": True}
                raise UsageRejected(HTTPStatus.CONFLICT, "a different report is already stored for this range")
            if self._conn.execute(
                "SELECT 1 FROM usage_reports WHERE tenant_id=? AND log_id=? AND seq_from<=? AND seq_to>=? LIMIT 1",
                (report.tenant_id, report.log_id, report.seq_to, report.seq_from),
            ).fetchone():
                raise UsageRejected(HTTPStatus.CONFLICT, "range overlaps a stored report for this log")
            self._conn.execute(
                "INSERT INTO usage_reports (tenant_id, log_id, seq_from, seq_to, device_id, billable, "
                "excluded_mask, excluded_fault, checkpoint_root, received_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (report.tenant_id, report.log_id, report.seq_from, report.seq_to, report.device_id,
                 *(report.counts[c] for c in COUNT_FIELDS), report.root, self._clock()),
            )
        return HTTPStatus.CREATED, {"ok": True, "replay": False}

    # -- read ---------------------------------------------------------------------------------

    def summary(self, *, tenant_id: str, period: str) -> dict[str, Any]:
        """Usage received in `period` (`YYYY-MM`, UTC), per device, plus every log's gaps.

        Synthetic devices are left out of totals (design §4.3). Gaps are computed over each log's
        whole history, because a hole is a fact about the chain, not about one month.
        """
        if len(period) != _PERIOD_LEN or period[4] != "-" or not (period[:4] + period[5:]).isdigit():
            raise ValueError("period must be YYYY-MM")
        rows = self._conn.execute(
            "SELECT u.device_id AS device_id, SUM(u.billable) AS billable, SUM(u.excluded_mask) AS excluded_mask, "
            "SUM(u.excluded_fault) AS excluded_fault, COUNT(*) AS reports "
            "FROM usage_reports u JOIN devices d ON d.tenant_id=u.tenant_id AND d.device_id=u.device_id "
            "WHERE u.tenant_id=? AND substr(u.received_at, 1, 7)=? AND d.synthetic=0 "
            "GROUP BY u.device_id ORDER BY u.device_id",
            (tenant_id, period),
        ).fetchall()
        devices = [dict(row) for row in rows]
        totals = {name: sum(int(d[name]) for d in devices) for name in COUNT_FIELDS}
        return {"tenant_id": tenant_id, "period": period, "totals": totals, "devices": devices,
                "gaps": self.gaps(tenant_id=tenant_id)}

    def gaps(self, *, tenant_id: str) -> list[dict[str, Any]]:
        """Holes in each log's reported ranges, including a first range that starts above 0.

        The unreported tail after the last range is not a gap: it is waiting for its checkpoint.
        """
        rows = self._conn.execute(
            "SELECT log_id, device_id, seq_from, seq_to FROM usage_reports WHERE tenant_id=? ORDER BY log_id, seq_from",
            (tenant_id,),
        ).fetchall()
        found: list[dict[str, Any]] = []
        expected: dict[str, int] = {}
        for row in rows:
            start = expected.get(row["log_id"], 0)
            if row["seq_from"] > start:
                found.append({"log_id": row["log_id"], "device_id": row["device_id"],
                              "seq_from": start, "seq_to": row["seq_from"] - 1})
            expected[row["log_id"]] = row["seq_to"] + 1
        return found

