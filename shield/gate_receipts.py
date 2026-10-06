"""Durable, signed, chained decision receipts for Shield's gate daemon (integrity-core B2).

What this module is, and is not
-------------------------------
The receipt *format* -- signing domain, hash chain, checkpoint, Merkle root, offline
verification -- is `integrity_sdk.core.receipts` (SDK contract C4), shared with BCC and with
`integrity-cli`'s independent verifier. Nothing here invents a receipt field or a hash rule.
This module is the *emitting side* the SDK deliberately leaves to each gate: a writer that is
safe under concurrent requests, that survives a crash, that refuses to continue a log it
cannot verify, and that says plainly when a decision could not be recorded.

Two files live in the receipt directory, both JSON Lines, both created ``0600``:

``receipts.jsonl``
    One signed receipt per line, in `seq` order. A line is written and ``fsync``-ed *before*
    the daemon answers the harness, so a receipt the caller was told about is on disk.
``checkpoints.jsonl``
    One signed checkpoint per line. A checkpoint commits to the Merkle root over the first
    `tree_size` receipts; holding one (or an anchored copy, integrity-core B4) is what lets a
    verifier detect *tail truncation*, which a bare hash chain cannot show.

Failure posture (stated per module, as this repository requires)
----------------------------------------------------------------
* **Starting up fails closed.** A configured log that cannot be verified end to end with the
  configured key -- a bad signature, a gap, a broken link, a missing tail, a different log id,
  a rotated key -- raises `ReceiptSetupError` and the daemon does not start. Silently
  continuing, or starting a fresh log beside the old one, would erase exactly the evidence the
  log exists to preserve. There is no auto-repair of a log that fails verification.
* **One narrow, deliberate exception: a torn final line.** A crash mid-write leaves a last line
  with no trailing newline. The daemon only answers *after* the newline and ``fsync``, so that
  record was never acknowledged to anyone; it is discarded with a warning and the file is
  truncated back to the last complete line. Anything else wrong with a line is corruption.
* **Recording a decision fails open to the caller, loudly.** If a receipt cannot be written
  (disk full, I/O error) `record` raises `ReceiptWriteError` and the in-memory chain is *not*
  advanced, so the next success is still contiguous. Whether the *decision* then stands is the
  daemon's call (`strict_receipts`); this module never decides policy.
* **A write that fails part-way is rolled back** by truncating the file to its prior length.
  If even that fails the writer marks itself broken and refuses all further records rather than
  append after unknown bytes.

Known limits, stated rather than implied
----------------------------------------
* Deleting `checkpoints.jsonl`, or truncating *both* files consistently, cannot be detected from
  the files alone. That is what anchoring a checkpoint externally (B4) closes.
* The whole log is held in memory and re-verified at start-up, and a checkpoint recomputes the
  Merkle root over every receipt (O(n)). Fine for a developer-machine gate; log rotation and
  incremental trees are `[PLANNED]`.
* Rotating the signing key starts a new log: `ReceiptLog.resume` trusts only the configured
  key, so an old log fails with UNTRUSTED_SIGNER. That is refusal, not silent re-signing.
* Same-uid processes can read and append to these files like any other file of the user; the
  signature, not the file mode, is what makes a receipt authentic.

Privacy
-------
A receipt carries the agent's DID, the event class, the decision, a reason code and control
ids. The device and the action are HMAC-SHA256 values under an organization-held key
(`hmac_identifier`), so the tool *name* and the device id never appear in the file in the
clear. Tool input content never reaches this module at all.
"""

from __future__ import annotations

import json
import logging
import os
import stat
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence

from integrity_sdk.core.receipts import ReceiptError, ReceiptLog, hmac_identifier, receipt_hash
from integrity_sdk.did import Keypair

logger = logging.getLogger(__name__)

RECEIPTS_FILENAME = "receipts.jsonl"
CHECKPOINTS_FILENAME = "checkpoints.jsonl"

#: Receipts between automatic checkpoints. A clean shutdown always writes a final one.
DEFAULT_CHECKPOINT_EVERY = 100

#: `core.receipts.hmac_identifier` refuses shorter keys; checked here too so the operator gets
#: a sentence naming the file rather than a bare ValueError from deep in the SDK.
MIN_HMAC_KEY_BYTES = 32


class ReceiptSetupError(Exception):
    """The receipt log or its keys cannot be used; the daemon must not start with them."""


class ReceiptWriteError(Exception):
    """One decision could not be recorded. The chain was not advanced."""


@dataclass(frozen=True)
class ReceiptRef:
    """What the daemon tells the caller about a recorded receipt."""

    seq: int
    hash: str


def default_log_id(hmac_key: bytes, device_id: str) -> str:
    """A stable log id for one device that does not contain the device id.

    `log_id` is written into every receipt in the clear, so deriving it as ``f"...:{device_id}"``
    would put the raw device id in the file the HMAC identifiers exist to keep it out of -- which
    the first version of this daemon did, and only a live run against the real file showed.
    The id is the first 16 hex digits of the same HMAC the receipts use for the device, so it is
    stable for a device and key, differs between devices, and reveals nothing without the key.
    Rotating the HMAC key therefore starts a new log, which `GateReceiptWriter` refuses to mix
    with the old one -- the same outcome as rotating the signing key.
    """
    return "shield-gate:" + hmac_identifier(hmac_key, "device", device_id).removeprefix("hmac-sha256:")[:16]


def _require_private(path: Path, what: str) -> None:
    """Refuse a secret that other local users can read.

    A signing key readable by others lets them forge receipts; a readable HMAC key lets them
    brute-force the device and action identifiers back out of a log.
    """
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
    except OSError as exc:
        raise ReceiptSetupError(f"cannot read {what} {path}: {exc}") from exc
    if mode & 0o077:
        raise ReceiptSetupError(
            f"{what} {path} is accessible to other users (mode {mode:04o}); run `chmod 600 {path}`"
        )


def load_hmac_key(path: str | os.PathLike[str]) -> bytes:
    """Read the organization-held HMAC key: raw bytes, at least `MIN_HMAC_KEY_BYTES`, mode 0600.

    The file is used byte for byte, with no stripping or decoding, so `head -c 32 /dev/urandom`
    and `openssl rand -hex 32` both work and mean the same thing every time.
    """
    key_path = Path(path)
    _require_private(key_path, "receipt HMAC key")
    key = key_path.read_bytes()
    if len(key) < MIN_HMAC_KEY_BYTES:
        raise ReceiptSetupError(
            f"receipt HMAC key {key_path} is {len(key)} bytes; at least {MIN_HMAC_KEY_BYTES} are required"
        )
    return key


def load_signer(path: str | os.PathLike[str]) -> Keypair:
    """Read the Ed25519 receipt-signing key (PEM) without ever creating one.

    Deliberately read-only, for the reason `device_assertion.load_device_keypair` gives: a
    helper that mints a replacement key when it cannot read the old one destroys an identity.
    """
    key_path = Path(path)
    _require_private(key_path, "receipt signing key")
    try:
        return Keypair.from_pem(key_path.read_bytes())
    except (OSError, ValueError) as exc:
        raise ReceiptSetupError(f"receipt signing key {key_path} is not a readable Ed25519 PEM: {exc}") from exc


def _read_jsonl(path: Path, what: str) -> list[dict[str, Any]]:
    """Parse a JSON Lines file, discarding (and truncating away) one torn final line.

    See the module docstring: only a final line with no trailing newline is treated as a crash
    artifact. A complete line that is not a JSON object is corruption and refuses start-up.
    """
    if not path.exists():
        return []
    data = path.read_bytes()
    if data and not data.endswith(b"\n"):
        keep = data.rfind(b"\n") + 1
        logger.warning(
            "%s %s ended in an incomplete line (%d bytes, never acknowledged); discarding it",
            what, path, len(data) - keep,
        )
        with path.open("r+b") as handle:
            handle.truncate(keep)
        data = data[:keep]
    rows: list[dict[str, Any]] = []
    for number, line in enumerate(data.split(b"\n")[:-1], start=1):
        try:
            row = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ReceiptSetupError(f"{what} {path} line {number} is not valid JSON: {exc}") from exc
        if not isinstance(row, dict):
            raise ReceiptSetupError(f"{what} {path} line {number} is not a JSON object")
        rows.append(row)
    return rows


class GateReceiptWriter:
    """Append-only, thread-safe receipt log for one gate daemon.

    One lock covers "build receipt, write it, advance the chain": two concurrent requests that
    both read the same head would otherwise sign two receipts with one `seq` and one
    `prev_hash`, forking the chain. The daemon is a threaded server, so this is not theoretical.
    """

    def __init__(
        self,
        directory: str | os.PathLike[str],
        *,
        signer: Keypair,
        hmac_key: bytes,
        log_id: str,
        checkpoint_every: int = DEFAULT_CHECKPOINT_EVERY,
    ) -> None:
        if len(hmac_key) < MIN_HMAC_KEY_BYTES:
            raise ReceiptSetupError(f"receipt HMAC key must be at least {MIN_HMAC_KEY_BYTES} bytes")
        if checkpoint_every < 1:
            raise ReceiptSetupError("checkpoint_every must be at least 1")
        self._hmac_key = hmac_key
        self._checkpoint_every = checkpoint_every
        self._lock = threading.Lock()
        self._broken = False
        self._closed = False

        self.directory = Path(directory)
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._receipts_path = self.directory / RECEIPTS_FILENAME
        self._checkpoints_path = self.directory / CHECKPOINTS_FILENAME

        receipts = _read_jsonl(self._receipts_path, "receipt log")
        checkpoints = _read_jsonl(self._checkpoints_path, "checkpoint log")
        # `ReceiptLog.resume` verifies against whatever log id the receipts carry; it does not
        # compare it with the one configured. Without this, pointing a daemon configured for one
        # device at another device's log would resume and happily extend it.
        for row in (*receipts, *checkpoints):
            if row.get("log_id") != log_id:
                raise ReceiptSetupError(
                    f"{self.directory} holds log {row.get('log_id')!r}, but this daemon is configured "
                    f"for log {log_id!r}; use a different --receipt-dir"
                )
        try:
            self._log = ReceiptLog.resume(signer, log_id, receipts, checkpoints)
        except ReceiptError as exc:
            raise ReceiptSetupError(
                f"the existing receipt log in {self.directory} does not verify with the configured key "
                f"({exc}); refusing to extend it. Move it aside deliberately if it should be retired."
            ) from exc

        last_checkpoint_size = checkpoints[-1]["tree_size"] if checkpoints else 0
        self._since_checkpoint = len(receipts) - last_checkpoint_size
        self._receipts_fd = os.open(self._receipts_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        self._checkpoints_fd = os.open(self._checkpoints_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        self._receipts_size = os.fstat(self._receipts_fd).st_size
        self._checkpoints_size = os.fstat(self._checkpoints_fd).st_size

    # ------------------------------------------------------------------ introspection ---

    @property
    def signer_key(self) -> str:
        """The multibase public key a verifier must trust (`integrity verify --trusted-signer`)."""
        return self._log.signer_key

    @property
    def log_id(self) -> str:
        return self._log.log_id

    @property
    def receipt_count(self) -> int:
        with self._lock:
            return len(self._log.receipts)

    # ------------------------------------------------------------------------ writing ---

    def _append_durably(self, fd: int, size: int, document: Mapping[str, Any]) -> int:
        """Write one line and fsync it; on failure restore the file to `size` and re-raise.

        Returns the new size. If the rollback itself fails the writer is marked broken, because
        appending after unknown bytes would corrupt the log silently.
        """
        line = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
        try:
            view = memoryview(line)
            while view:
                written = os.write(fd, view)
                view = view[written:]
            os.fsync(fd)
        except OSError:
            try:
                os.ftruncate(fd, size)
            except OSError:
                self._broken = True
                logger.critical("receipt log could not be rolled back after a failed write; writer disabled")
            raise
        return size + len(line)

    def record(
        self,
        *,
        agent_did: str,
        device_id: str,
        tool_name: str,
        tool_input_sha256: Optional[str],
        event_class: str,
        pack_hash: str,
        decision: str,
        reason_code: str,
        mode: str,
        controls: Sequence[str] = (),
    ) -> ReceiptRef:
        """Sign, persist and return a receipt for one decision, or raise `ReceiptWriteError`.

        `device_id` and the tool are hashed here, so a caller cannot forget to. The action
        identifier binds the tool name *and* the input digest, so it identifies this exact call
        to someone holding the HMAC key and the input, and nothing to anyone else.
        """
        device_hmac = hmac_identifier(self._hmac_key, "device", device_id)
        action_hmac = hmac_identifier(self._hmac_key, "action", f"{tool_name}\x00{tool_input_sha256 or ''}")
        with self._lock:
            if self._closed:
                raise ReceiptWriteError("the receipt writer is closed")
            if self._broken:
                raise ReceiptWriteError("the receipt writer is disabled after an unrecoverable write failure")
            try:
                receipt = self._log.append(
                    agent_did=agent_did, device_id_hmac=device_hmac, action_hmac=action_hmac,
                    event_class=event_class, pack_hash=pack_hash, decision=decision,
                    reason_code=reason_code, mode=mode, controls=controls,
                )
            except (ReceiptError, ValueError) as exc:
                raise ReceiptWriteError(f"receipt rejected by the SDK: {exc}") from exc
            try:
                self._receipts_size = self._append_durably(self._receipts_fd, self._receipts_size, receipt)
            except OSError as exc:
                # The SDK appended in memory first. Undo that, or the next receipt would chain
                # to one that is not on disk and the log would fail its own verification.
                self._log.receipts.pop()
                raise ReceiptWriteError(f"could not write the receipt: {exc}") from exc
            self._since_checkpoint += 1
            if self._since_checkpoint >= self._checkpoint_every:
                try:
                    self._checkpoint_locked()
                except ReceiptWriteError as exc:
                    # The receipt is already durable; failing it now would report a recorded
                    # decision as unrecorded. The next record retries the checkpoint.
                    logger.error("periodic checkpoint failed: %s", exc)
            return ReceiptRef(seq=receipt["seq"], hash=receipt_hash(receipt))

    def _checkpoint_locked(self) -> dict[str, Any]:
        try:
            checkpoint = self._log.checkpoint()
        except ValueError as exc:  # an empty log
            raise ReceiptWriteError(str(exc)) from exc
        try:
            self._checkpoints_size = self._append_durably(self._checkpoints_fd, self._checkpoints_size, checkpoint)
        except OSError as exc:
            self._log.checkpoints.pop()
            raise ReceiptWriteError(f"could not write the checkpoint: {exc}") from exc
        self._since_checkpoint = 0
        return checkpoint

    def checkpoint(self) -> dict[str, Any]:
        """Sign and persist a checkpoint over every receipt so far (the value B4 anchors)."""
        with self._lock:
            if self._closed or self._broken:
                raise ReceiptWriteError("the receipt writer is not accepting writes")
            return self._checkpoint_locked()

    def close(self) -> None:
        """Write a final checkpoint if receipts arrived since the last one, then release the files."""
        with self._lock:
            if self._closed:
                return
            if self._since_checkpoint > 0 and not self._broken:
                try:
                    self._checkpoint_locked()
                except ReceiptWriteError as exc:
                    logger.error("final checkpoint failed: %s", exc)
            self._closed = True
            for fd in (self._receipts_fd, self._checkpoints_fd):
                try:
                    os.close(fd)
                except OSError:
                    pass
