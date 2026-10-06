"""Shield's local gate daemon: a Unix socket that answers PreToolUse (B2).

Why a socket at all
-------------------
`integrity-cli`'s `integrity hooks install --gate shield` wires a harness's
PreToolUse hook to `python -m integrity_sdk.hook_runner`. That runner is a
short-lived process spawned once per tool call, so it cannot hold a warm
`PolicyEngine`: constructing one means installing a verified pack into OPA, which
is far too slow to do per keystroke. This daemon holds the warm engine and answers
over a Unix socket, which also keeps the request on-device -- no port is opened and
no loopback TCP listener exists for another local user to reach.

Until this module existed, `integrity_sdk.hook_runner.SUPPORTED_GATES` named only
`bcc` and refused `shield` outright rather than silently falling back (this
repository's "no silent mocks" rule). This is the counterpart that lets that
refusal be lifted.

What it decides, and what it deliberately does not
--------------------------------------------------
A decision here comes from `PolicyEngine.evaluate` -- Tier 1, the deterministic
OPA/Rego verdict against the verified pack -- and nothing else. It does **not** go
through `agent_core.router.EventRouter`, for two reasons. The router's `handle()`
calls `ActionBroker.contain()` (a real SIGSTOP against a process) for any `contain`
decision, which is the wrong response to a tool call that has not run yet and whose
"process" is the harness itself. And the router requires the full exporter,
event-log, SLM, Jev and memory stack that `shield run` wires up, none of which a
gate needs to answer allow/deny.

[PLANNED] The consequence, stated rather than implied: this daemon does not yet emit
a signed, chained receipt per decision. That is the remaining half of
`docs/EXECUTION_PLAN.md` B2's second bullet ("signed chained receipts with
checkpoints"), and it is why `evaluate_pre_tool_use` takes its evaluator as a
parameter -- wiring a receipt-emitting evaluator in later is an argument change, not
a rewrite of this module.

Fail-closed, and where the fail-open boundary actually is
--------------------------------------------------------
This daemon fails **closed**: an OPA outage, a missing pack, a malformed request or
an unexpected internal error all deny in enforce mode. `PolicyEngine.evaluate`
already supplies most of that (`core.decision.resolve`'s `evaluator_error` and
`NO_PACK` branches), and this module adds the same posture for its own parse and
transport errors.

The fail-OPEN tradeoff lives one layer out, in `integrity_sdk.hook_runner`: if this
daemon is unreachable the harness proceeds with `checked: False` rather than
bricking the session. That split is deliberate -- the enforcement component fails
closed, the dev-shell-facing shim fails open and says so. A caller must never treat
an unchecked allow as an authorized one.

Observe mode (`enforcement_mode="observe"`) always answers `allow` while reporting
the verdict it *would* have enforced in `action`, with `enforced: false`. That
mirrors `EventRouter`'s own observe posture rather than inventing a second one.

Privacy
-------
The request carries `tool_input_sha256`, a digest of the tool's input, and **not the input
itself**. Nothing in the evaluation path reads tool content -- `AgentEvent` carries only the
tool *name* -- so a daemon that accepted raw commands and file contents would be receiving
data it has no use for, which is exactly what `integrity_sdk.hook_runner` already refuses to
send to `bcc_middleware`. If a future policy needs content, that is a deliberate protocol
change (a new version), not something to have been quietly accepting all along. Any `tool_input`
field a client sends anyway is ignored and never logged. Log lines carry `tool_name` and the
digest only, consistent with A3's rule that Shield's exports carry labels and HMAC-protected
references rather than raw command content.
"""

from __future__ import annotations

import json
import logging
import os
import re
import signal
import socket
import socketserver
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Optional

from .policy_engine.engine import EvaluationContext, PolicyEngine
from .schemas.events import AgentActivity, AgentContext, AgentEvent, AgentInfo, PolicyDecision

logger = logging.getLogger(__name__)

PROTOCOL_VERSION = 1

#: The largest request this daemon will read. A PreToolUse payload carrying a file
#: write can be large, but it is not unbounded, and an unbounded read on a socket any
#: local process can connect to is a trivial memory-exhaustion lever.
MAX_REQUEST_BYTES = 4 * 1024 * 1024

#: Actions that permit the call to proceed. `contain` and `escalate` are denials
#: here for the same reason `guardrail_hooks.tool_execution.guard_tool_call` treats
#: them so: this gate decides one pending tool call, while device containment and
#: human escalation are Agent Core's job (spec §4.2), not something a PreToolUse
#: answer can carry out.
PERMITTING_ACTIONS = frozenset({"allow", "log_only"})


class GateProtocolError(ValueError):
    """A request this daemon cannot parse or does not support."""


#: A request's digest is a lowercase SHA-256 hex string, or this marker when the client could not
#: canonicalize the input (an input that cannot be hashed must not become a failed tool call).
#:
#: Matched with `fullmatch`, and unanchored on purpose: Python's `$` also matches just before a
#: trailing newline, so `re.match(r"^...$", digest + "\n")` succeeds -- which would let a client
#: smuggle a newline into an audit log line and forge a second entry.
_DIGEST_RE = re.compile(r"[0-9a-f]{64}|uncanonicalizable")


@dataclass(frozen=True)
class GateRequest:
    """One PreToolUse question. Carries a digest of the tool input, never the input."""

    agent_id: str
    tool_name: str
    tool_input_sha256: Optional[str] = None
    event: str = "pre_tool_use"

    @classmethod
    def from_json(cls, raw: bytes) -> "GateRequest":
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise GateProtocolError(f"request is not valid UTF-8 JSON: {exc}") from exc
        if not isinstance(payload, Mapping):
            raise GateProtocolError("request must be a JSON object")

        version = payload.get("v", PROTOCOL_VERSION)
        if version != PROTOCOL_VERSION:
            raise GateProtocolError(
                f"unsupported protocol version {version!r}; this daemon speaks v{PROTOCOL_VERSION}"
            )
        event = str(payload.get("event") or "pre_tool_use")
        if event != "pre_tool_use":
            raise GateProtocolError(f"unsupported event {event!r}; this daemon answers pre_tool_use only")

        tool_name = payload.get("tool_name")
        if not isinstance(tool_name, str) or not tool_name:
            raise GateProtocolError("tool_name is required and must be a non-empty string")

        agent_id = payload.get("agent_id")
        if not isinstance(agent_id, str) or not agent_id:
            raise GateProtocolError("agent_id is required and must be a non-empty string")

        digest = payload.get("tool_input_sha256")
        if digest is not None and not (isinstance(digest, str) and _DIGEST_RE.fullmatch(digest)):
            # Rejected rather than coerced: this value ends up in an audit log line, and a
            # free-form string there is a log-injection vector (embedded newlines, ANSI codes).
            raise GateProtocolError("tool_input_sha256 must be 64 lowercase hex characters")

        # Unknown fields -- including a raw `tool_input` -- are deliberately ignored, and are
        # never read into the request, so they cannot reach a log line.
        return cls(agent_id=agent_id, tool_name=tool_name, tool_input_sha256=digest, event=event)


Evaluator = Callable[[AgentEvent, EvaluationContext], PolicyDecision]


def evaluate_pre_tool_use(
    request: GateRequest,
    *,
    evaluator: Evaluator,
    ctx: EvaluationContext,
    device_id: str,
    enforcement_mode: str = "enforce",
) -> dict[str, Any]:
    """Answer one PreToolUse question. Never raises; fails closed in enforce mode.

    `evaluator` is normally a bound `PolicyEngine.evaluate`. It is a parameter so the
    [PLANNED] receipt-emitting evaluator (B2's signed-chained-receipts half) can be
    substituted without changing this function.
    """
    event = AgentEvent(
        device_id=device_id,
        agent=AgentInfo(agent_id=request.agent_id, name=request.agent_id, type="llm_tool"),
        context=AgentContext(tools_called=[request.tool_name]),
        activity=AgentActivity(type="tool_execution", risk_level="low"),
    )

    try:
        decision = evaluator(event, ctx)
    except Exception as exc:  # noqa: BLE001 -- fail closed on ANY evaluator failure
        # PolicyEngine.evaluate already converts OPA outages and a missing pack into a
        # fail-closed deny internally, so reaching here means something further out of
        # contract. Denying is still the right answer in enforce mode: an unexplained
        # evaluator failure is not evidence that the call is safe.
        logger.error("evaluator raised for %s (%s); failing closed", request.tool_name, exc)
        return _response(
            action="deny",
            reason=f"shield gate evaluator error, failing closed: {exc!r}",
            rule_id="_evaluator_error",
            policy_version="",
            policy_hash="",
            invocation_id="",
            enforcement_mode=enforcement_mode,
        )

    return _response(
        action=decision.decision.action,
        reason=decision.decision.reason,
        rule_id=decision.rule.rule_id,
        policy_version=decision.policy.version,
        policy_hash=decision.policy.hash,
        invocation_id=decision.invocation_id,
        enforcement_mode=enforcement_mode,
    )


def _response(
    *,
    action: str,
    reason: str,
    rule_id: str,
    policy_version: str,
    policy_hash: str,
    invocation_id: str,
    enforcement_mode: str,
) -> dict[str, Any]:
    """Collapse Shield's 5-way action onto the gate's allow/deny wire contract.

    `action` is reported alongside `decision` so a caller can record the real verdict
    (`contain`, `escalate`) rather than only the collapsed one -- and so observe mode can
    say what it would have done.
    """
    enforced = enforcement_mode != "observe"
    permitted = action in PERMITTING_ACTIONS
    return {
        "v": PROTOCOL_VERSION,
        # In observe mode the call always proceeds; `action` still carries the verdict.
        "decision": "allow" if (permitted or not enforced) else "deny",
        "checked": True,
        "action": action,
        "enforced": enforced,
        "reason": reason,
        "rule_id": rule_id,
        "policy_version": policy_version,
        "policy_hash": policy_hash,
        "invocation_id": invocation_id,
    }


def _error_response(message: str, *, enforcement_mode: str) -> dict[str, Any]:
    """A request this daemon could not parse. Fails closed in enforce mode.

    `checked` is True: a policy engine did not rule on this call, but the daemon
    deliberately refused it, which is a real verdict rather than an absent one. An
    unreachable daemon -- the genuinely unchecked case -- is reported by the caller.
    """
    return {
        "v": PROTOCOL_VERSION,
        "decision": "allow" if enforcement_mode == "observe" else "deny",
        "checked": True,
        "action": "deny",
        "enforced": enforcement_mode != "observe",
        "reason": f"shield gate rejected the request, failing closed: {message}",
        "rule_id": "_bad_request",
        "policy_version": "",
        "policy_hash": "",
        "invocation_id": "",
    }


class _GateHandler(socketserver.StreamRequestHandler):
    """One connection, one request, one response, then close.

    Request framing is a single JSON object terminated by a newline. One exchange per
    connection keeps this immune to a half-written request desynchronising a long-lived
    stream, and the harness spawns a fresh process per tool call anyway.
    """

    # Without this a hung client holds a worker thread forever.
    timeout = 10.0

    def handle(self) -> None:  # pragma: no cover - exercised via the real socket in tests
        server: "GateServer" = self.server  # type: ignore[assignment]
        try:
            raw = self.rfile.readline(MAX_REQUEST_BYTES + 1)
        except (TimeoutError, socket.timeout, OSError) as exc:
            logger.warning("gate request read failed: %s", exc)
            return

        if not raw:
            return
        if len(raw) > MAX_REQUEST_BYTES:
            self._write(_error_response(
                f"request exceeds {MAX_REQUEST_BYTES} bytes", enforcement_mode=server.enforcement_mode))
            return

        try:
            request = GateRequest.from_json(raw)
        except GateProtocolError as exc:
            logger.warning("gate request rejected: %s", exc)
            self._write(_error_response(str(exc), enforcement_mode=server.enforcement_mode))
            return

        response = evaluate_pre_tool_use(
            request,
            evaluator=server.evaluator,
            ctx=server.ctx,
            device_id=server.device_id,
            enforcement_mode=server.enforcement_mode,
        )
        # tool_name and the client-supplied digest only; tool_input is never read. See Privacy.
        logger.info(
            "gate %s tool=%s input_sha256=%s action=%s rule=%s",
            response["decision"], request.tool_name,
            request.tool_input_sha256 or "-", response["action"], response["rule_id"],
        )
        self._write(response)

    def _write(self, response: Mapping[str, Any]) -> None:
        try:
            self.wfile.write(json.dumps(response).encode("utf-8") + b"\n")
            self.wfile.flush()
        except OSError as exc:
            logger.warning("gate response write failed: %s", exc)


class GateServer(socketserver.ThreadingUnixStreamServer):
    """Threaded Unix-socket server holding one warm `PolicyEngine`.

    Threaded because an OPA query is network I/O: a single-threaded server would
    serialize concurrent tool calls behind each other. `PolicyEngine.evaluate` holds its
    own `_install_lock`, so a concurrent `install_pack` (hot reload) cannot be observed
    half-applied by an evaluation in flight.
    """

    daemon_threads = True
    # Without this, restarting after an unclean exit can fail on a lingering address.
    allow_reuse_address = True

    def __init__(
        self,
        socket_path: Path,
        *,
        evaluator: Evaluator,
        ctx: EvaluationContext,
        device_id: str,
        enforcement_mode: str = "enforce",
    ) -> None:
        self.evaluator = evaluator
        self.ctx = ctx
        self.device_id = device_id
        self.enforcement_mode = enforcement_mode
        self.socket_path = Path(socket_path)
        super().__init__(str(self.socket_path), _GateHandler)

    def server_bind(self) -> None:
        # Create the socket with 0600 from the outset. Binding first and chmod-ing after
        # leaves a window in which any local user can connect, and this socket decides
        # whether an agent's tool calls run.
        self.socket_path.parent.mkdir(parents=True, exist_ok=True)
        previous_umask = os.umask(0o177)
        try:
            super().server_bind()
        finally:
            os.umask(previous_umask)
        os.chmod(self.socket_path, 0o600)

    def server_close(self) -> None:
        super().server_close()
        # A stale socket file left behind makes the next start fail with EADDRINUSE on a
        # path nothing is listening to, which reads as a mysterious bind error.
        try:
            self.socket_path.unlink()
        except FileNotFoundError:
            pass
        except OSError as exc:
            logger.warning("could not remove socket %s: %s", self.socket_path, exc)


#: AF_UNIX paths are limited to ~108 bytes by the kernel's sockaddr_un, and the error on
#: overflow is an opaque OSError at bind time rather than anything naming the length. Checked
#: explicitly so a long XDG_RUNTIME_DIR fails with a sentence an operator can act on.
MAX_SOCKET_PATH_BYTES = 100


def default_socket_path() -> Path:
    """Where the gate listens when no path is given.

    `XIBALBA_SHIELD_GATE_SOCKET` wins, so a harness hook and the daemon can be pointed at
    one path from a single env var. Otherwise this prefers `XDG_RUNTIME_DIR`, which is
    per-user, mode 0700 and cleaned up on logout -- the right home for a socket that gates
    tool execution. It falls back to `~/.xibalba-shield` where that is unset (a bare
    container, a cron-style shell), matching the directory the rest of Shield already uses
    for per-device state.
    """
    override = os.environ.get("XIBALBA_SHIELD_GATE_SOCKET")
    if override:
        return Path(override)
    runtime_dir = os.environ.get("XDG_RUNTIME_DIR")
    base = Path(runtime_dir) if runtime_dir else Path.home() / ".xibalba-shield"
    return base / "xibalba-shield" / "gate.sock" if runtime_dir else base / "gate.sock"


def check_socket_path(socket_path: Path) -> None:
    """Raise a legible error if `socket_path` cannot be bound as an AF_UNIX address."""
    encoded = len(str(socket_path).encode("utf-8"))
    if encoded > MAX_SOCKET_PATH_BYTES:
        raise OSError(
            f"socket path is {encoded} bytes, over the ~{MAX_SOCKET_PATH_BYTES}-byte AF_UNIX "
            f"limit: {socket_path}. Pass a shorter --socket or set XIBALBA_SHIELD_GATE_SOCKET."
        )


def remove_stale_socket(socket_path: Path) -> bool:
    """Remove `socket_path` if it exists but nothing is listening on it.

    Returns True if a stale socket was removed. A live socket is left alone and reported
    via `OSError`, so starting a second daemon on one path fails loudly instead of
    stealing the first one's path.
    """
    socket_path = Path(socket_path)
    if not socket_path.exists():
        return False
    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        probe.settimeout(0.5)
        probe.connect(str(socket_path))
    except (ConnectionRefusedError, FileNotFoundError):
        socket_path.unlink(missing_ok=True)
        return True
    else:
        raise OSError(f"a gate daemon is already listening on {socket_path}")
    finally:
        probe.close()


def serve_forever(
    socket_path: Path,
    *,
    engine: PolicyEngine,
    ctx: EvaluationContext,
    device_id: str,
    enforcement_mode: str = "enforce",
    ready: Optional[threading.Event] = None,
) -> GateServer:
    """Bind `socket_path` and serve until shut down. Returns the server for the caller to close.

    `ready` is set once the socket is bound and accepting, so a test or supervisor can
    wait on it rather than polling for the socket file to appear.
    """
    check_socket_path(Path(socket_path))
    remove_stale_socket(Path(socket_path))
    server = GateServer(
        Path(socket_path), evaluator=engine.evaluate, ctx=ctx,
        device_id=device_id, enforcement_mode=enforcement_mode,
    )
    if ready is not None:
        ready.set()

    # systemd stops a service with SIGTERM, whose default action ends the process without
    # running `finally`, so every ordinary stop would leave the socket file behind. Turn
    # SIGTERM into SystemExit so the `finally` below runs `server_close()`, which unlinks it.
    # `server.shutdown()` is deliberately not used from the handler: it blocks until the
    # serve loop exits, and that loop is running on this same thread.
    #
    # signal.signal() only works from the main thread, so a caller embedding this in a worker
    # thread simply gets no handler and keeps the previous behavior rather than a ValueError.
    previous_handler = None
    if threading.current_thread() is threading.main_thread():
        def _terminate(_signum: int, _frame: object) -> None:
            raise SystemExit(0)
        previous_handler = signal.signal(signal.SIGTERM, _terminate)
    try:
        server.serve_forever()
    finally:
        server.server_close()
        if previous_handler is not None:
            signal.signal(signal.SIGTERM, previous_handler)
    return server
