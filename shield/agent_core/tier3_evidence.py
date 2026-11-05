"""Typed, bounded, digest-only evidence for Tier 3 cloud adjudication (invariant I5).

STATUS: design intent. `build_evidence` exists and is tested, but no `Tier3Backend` exists yet and
`router.py` still fails closed to contain ("no Tier 3 configured"). Nothing calls this function today.
It is meant to be called by a Tier 3 BACKEND with an `EscalationRequest`, never by the router.

Why this is a security boundary
-------------------------------
The returned dict is the entire description of an event that may leave the endpoint and be shown to a
cloud model. Process names, command lines, file paths and tool inputs are ATTACKER-CONTROLLED: a
process can be named to read as instructions. Properties that hold:

1. Attacker text is only ever a bounded VALUE inside a typed field of a nested dict. This module never
   builds a prompt and never concatenates evidence into a string. Keeping the value out of an
   instruction position is the caller's duty; the shape here (fixed keys, values only) is what makes
   that possible.
2. Tool input is represented by a sha256 DIGEST, never the raw value -- the same discipline as
   `gate_receipts.py` / `gate_daemon.py` (`tool_input_sha256`: 64 lowercase hex, input never read
   back). A digest supplied by the caller is accepted only if it is exactly 64 lowercase hex.
3. Truncation is DISCLOSED, never silent. A value cut to `max_field_len` looks complete unless told
   otherwise, and an attacker can park a hostile tail past the cut. So whenever a string is truncated
   (or a list is capped or loses items) the result carries a top-level `truncated` dict keyed by field
   path (e.g. "process.name") holding `original_len` and a sha256 of the FULL original value (for
   `cmdline`, of the redacted full value), so the adjudicator knows it sees a prefix and can still
   match the whole. Lists record `original_count`, `dropped_items`, `items_truncated` and a sha256 of
   the full list. The 64-char digests themselves are exempt from `max_field_len`.
4. `process.cmdline` is credential-redacted BEFORE bounding: `Bearer <tok>`, `--password/--token/
   --secret/--api-key/--auth...` flags, `key=value` pairs for those names, and `Authorization:` header
   values have the VALUE replaced by "[REDACTED]" and the path is listed in top-level `redacted`.
   This is best-effort pattern matching, not a guarantee: an obfuscated secret can survive. Only the
   first 65536 characters of a cmdline are scanned (bounds regex cost); the digest then covers that
   redacted prefix and `original_len` reveals the rest was not examined.

Fail-closed posture
-------------------
This is an ALLOWLIST. Every key in the result is written out explicitly below, and each value is read
from a named attribute. Event and decision objects are never iterated, `vars()`-copied or splatted, so
a field added to an event later is OMITTED, not forwarded, until someone deliberately adds it here and
a test. Anything of an unexpected type (these are plain dataclasses; nothing validates types at runtime)
is omitted rather than coerced. Integers outside +/-2**63 and non-finite floats are omitted, lists are
capped at `MAX_ITEMS`, lone surrogates are handled, so the result always survives `json.dumps`.

Currently unreachable (documented, not mocked)
----------------------------------------------
* `tool_input` / `tool_input_sha256`: no event class carries either today, so `tool_input_digest` is
  never emitted for a real event. The code path exists and is tested with ad-hoc attributes.
* `ais_impact`: no `EscalationRequest` carries it today, so it is never emitted for a real request.
  When present it is passed through as a finite number only; it is never computed or approximated here.
* `device_id` and `tenant_id` are deliberately omitted. If correlation is needed, a future backend task
  should add an opaque request id; it does not belong here.

Caller contract
---------------
`max_field_len` must be a positive int; otherwise `ValueError` is raised. The caller is responsible for
not passing garbage, and the Tier 3 backend is expected to validate it at construction. A dispatch
wrapper should still catch `Exception` from this function and fail closed.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from typing import Any

DEFAULT_MAX_FIELD_LEN = 512
MAX_ITEMS = 32
_INT_LIMIT = 2**63
_REDACT_SCAN_CAP = 65536
_REDACTED = "[REDACTED]"

_SHA256_HEX = re.compile(r"[0-9a-f]{64}\Z")

_SECRET_NAME = r"(?:password|passwd|pwd|passphrase|token|secret|api[-_]?key|apikey|credential|auth)"
_VALUE = r"""(?:"[^"]*"|'[^']*'|[^\s"']+)"""
_REDACTIONS = (
    (re.compile(r"(?i)\b(bearer\s+)" + _VALUE), r"\1" + _REDACTED),
    (re.compile(r"(?i)\b(authorization\s*[:=]\s*(?:(?:basic|bearer|token)\s+)?)" + _VALUE),
     r"\1" + _REDACTED),
    # dashed flags: --password=x, --password x, -api-key=x
    (re.compile(r"(?i)(--?[\w-]*" + _SECRET_NAME + r"[\w-]*(?:=|\s+))" + _VALUE), r"\1" + _REDACTED),
    # bare key=value: api_key=x, SECRET=x, password:x
    (re.compile(r"(?i)(\b[\w.]*" + _SECRET_NAME + r"[\w.]*\s*[=:]\s*)" + _VALUE), r"\1" + _REDACTED),
)


def _sha(s: str) -> str:
    # surrogatepass: lone surrogates (surrogateescape-decoded filenames) must not raise.
    return hashlib.sha256(s.encode("utf-8", "surrogatepass")).hexdigest()


def _redact(s: str) -> str:
    for pattern, repl in _REDACTIONS:
        s = pattern.sub(repl, s)
    return s


class _Ctx:
    def __init__(self, n: int) -> None:
        self.n = n
        self.truncated: dict[str, dict[str, Any]] = {}
        self.redacted: list[str] = []


def _text(value: Any, ctx: _Ctx, path: str, redact: bool = False) -> str | None:
    if not isinstance(value, str):
        return None
    s = value
    unscanned = False
    if redact:
        head = value[:_REDACT_SCAN_CAP]
        unscanned = len(value) > len(head)
        s = _redact(head)
        if s != head:
            ctx.redacted.append(path)
    if len(s) > ctx.n or unscanned:
        ctx.truncated[path] = {"original_len": len(value), "sha256": _sha(s)}
    return s[: ctx.n]


def _int(value: Any) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool) and -_INT_LIMIT < value < _INT_LIMIT:
        return value
    return None


def _float(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return float(value) if -_INT_LIMIT < value < _INT_LIMIT else None  # guard BEFORE converting
    if isinstance(value, float) and math.isfinite(value):
        return value
    return None


def _bool(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


def _str_list(value: Any, ctx: _Ctx, path: str) -> list[str] | None:
    if not isinstance(value, (list, tuple)):
        return None
    strs = [v for v in value if isinstance(v, str)]
    kept = strs[:MAX_ITEMS]
    out = [v[: ctx.n] for v in kept]
    items_truncated = sum(1 for v in kept if len(v) > ctx.n)
    dropped = len(value) - len(kept)
    if dropped or items_truncated:
        ctx.truncated[path] = {
            "original_count": len(value),
            "dropped_items": dropped,
            "items_truncated": items_truncated,
            "sha256": _sha(json.dumps(strs)),
        }
    return out


def _section(obj: Any, spec: dict[str, str], ctx: _Ctx, prefix: str) -> dict[str, Any] | None:
    """Copy ONLY the named attributes of `obj`, each through its typed reader; drop absent/mistyped."""
    if obj is None:
        return None
    out: dict[str, Any] = {}
    for key, kind in spec.items():
        raw = getattr(obj, key, None)
        path = f"{prefix}.{key}"
        if kind == "s":
            v: Any = _text(raw, ctx, path)
        elif kind == "c":  # command line: credential-redacted before bounding
            v = _text(raw, ctx, path, redact=True)
        elif kind == "i":
            v = _int(raw)
        elif kind == "f":
            v = _float(raw)
        elif kind == "b":
            v = _bool(raw)
        else:
            v = _str_list(raw, ctx, path)
        if v is not None:
            out[key] = v
    return out


def _decision(decision: Any, ctx: _Ctx, prefix: str) -> dict[str, Any] | None:
    return _section(
        decision,
        {"action": "s", "reason": "s", "severity": "s", "tier": "s", "confidence": "f",
         "risk_score": "f", "human_required": "b", "evidence": "l"},
        ctx,
        prefix,
    )


def _tool_input_digest(event: Any) -> str | None:
    supplied = getattr(event, "tool_input_sha256", None)
    if isinstance(supplied, str) and _SHA256_HEX.match(supplied):
        return supplied
    raw = getattr(event, "tool_input", None)
    if isinstance(raw, bytes):
        return hashlib.sha256(raw).hexdigest()
    if isinstance(raw, str):
        return _sha(raw)
    return None  # absent or unknown shape: omit rather than guess a serialization


def build_evidence(request: Any, *, max_field_len: int = DEFAULT_MAX_FIELD_LEN) -> dict[str, Any]:
    """Build the bounded evidence dict for an `EscalationRequest`. See the module docstring.

    Fixed keys only (allowlist, fail-closed: unknown fields are omitted, never forwarded). Every string
    is at most `max_field_len` characters; any truncation is disclosed under `truncated` with a digest
    of the full value. Tool input appears only as `tool_input_digest`. Raises `ValueError` for a
    non-positive `max_field_len` (caller's responsibility; the backend validates it at construction).
    """
    if isinstance(max_field_len, bool) or not isinstance(max_field_len, int) or max_field_len < 1:
        raise ValueError("max_field_len must be a positive int")
    ctx = _Ctx(max_field_len)
    event = getattr(request, "event", None)

    ev: dict[str, Any] = {}
    for key, raw in (("class", getattr(event, "klass", None)), ("time", getattr(event, "time", None))):
        v = _text(raw, ctx, key)
        if v is not None:
            ev[key] = v

    sections = {
        "process": (getattr(event, "process", None),
                    {"pid": "i", "name": "s", "exe_path": "s", "cmdline": "c", "hash_sha256": "s",
                     "ppid": "i", "parent_name": "s"}),
        "file": (getattr(event, "file", None), {"path": "s", "name": "s", "ext": "s", "type": "s"}),
        "flow": (getattr(event, "flow", None),
                 {"src_ip": "s", "src_port": "i", "dst_ip": "s", "dst_port": "i", "protocol": "s",
                  "direction": "s"}),
        "dns": (getattr(event, "dns", None), {"query_name": "s", "resolved_ips": "l"}),
        "agent": (getattr(event, "agent", None), {"agent_id": "s", "name": "s", "type": "s"}),
        "context": (getattr(event, "context", None),
                    {"data_sources": "l", "tools_called": "l", "model_endpoint": "s"}),
        "activity": (getattr(event, "activity", None),
                     {"type": "s", "severity": "s", "outcome": "s", "risk_level": "s",
                      "policy_violation": "b"}),
    }
    for key, (obj, spec) in sections.items():
        built = _section(obj, spec, ctx, key)
        if built is not None:
            ev[key] = built

    digest = _tool_input_digest(event)
    if digest is not None:
        ev["tool_input_digest"] = digest

    for key, decision in (("tier1", getattr(request, "tier1_decision", None)),
                          ("tier2", getattr(request, "tier2_decision", None))):
        built = _decision(decision, ctx, key)
        if built is not None:
            ev[key] = built

    reason = _text(getattr(request, "reason", None), ctx, "escalation_reason")
    if reason is not None:
        ev["escalation_reason"] = reason

    ais = _float(getattr(request, "ais_impact", None))  # hint only: passed through, never derived
    if ais is not None:
        ev["ais_impact"] = ais

    if ctx.truncated:
        ev["truncated"] = ctx.truncated
    if ctx.redacted:
        ev["redacted"] = ctx.redacted
    return ev
