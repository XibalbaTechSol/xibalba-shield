"""Typed, bounded, digest-only evidence for Tier 3 cloud adjudication (invariant I5).

STATUS: design intent. `build_evidence` exists and is tested, but no `Tier3Backend` exists yet and
`router.py` still fails closed to contain ("no Tier 3 configured"). Nothing calls this function today.
It is meant to be called by a Tier 3 BACKEND with an `EscalationRequest`, never by the router.

Why this is a security boundary
-------------------------------
The returned dict is the entire description of an event that may leave the endpoint and be shown to a
cloud model. Process names, command lines, file paths and tool inputs are ATTACKER-CONTROLLED: a
process can be named to read as instructions. Two independent properties hold:

1. Attacker text is only ever a bounded VALUE inside a typed field of a nested dict. This module never
   builds a prompt and never concatenates evidence into a string. Keeping the value out of an
   instruction position is the caller's duty; the shape here (fixed keys, values only) is what makes
   that possible.
2. Tool input is represented by a sha256 DIGEST, never the raw value -- the same discipline as
   `gate_receipts.py` / `gate_daemon.py` (`tool_input_sha256`: 64 lowercase hex, input never read
   back). A digest supplied by the caller is accepted only if it is exactly 64 lowercase hex.

Fail-closed posture
-------------------
This is an ALLOWLIST. Every key in the result is written out explicitly below, and each value is read
from a named attribute. Event and decision objects are never iterated, `vars()`-copied or splatted, so
a field added to an event later is OMITTED, not forwarded, until someone deliberately adds it here and
a test. Anything of an unexpected type (these are plain dataclasses; nothing validates types at runtime)
is omitted rather than coerced. Every string is truncated to `max_field_len`, lists are capped at
`MAX_ITEMS`, and non-finite floats are dropped so the result always survives `json.dumps`.

Not done here
-------------
* No AIS computation or approximation. `ais_impact` is a hint: passed through only if the request
  already carries a finite number, never derived.
* `device_id` and `tenant_id` are deliberately not included; the backend already holds the request.
* Events carry no `tool_input` today. The builder reads an optional `tool_input` (digested) or
  `tool_input_sha256` (validated) attribute from the event so a backend/gate can supply one.
"""

from __future__ import annotations

import hashlib
import math
import re
from typing import Any

DEFAULT_MAX_FIELD_LEN = 512
MAX_ITEMS = 32

_SHA256_HEX = re.compile(r"[0-9a-f]{64}\Z")


def _text(value: Any, n: int) -> str | None:
    return value[:n] if isinstance(value, str) else None


def _int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _float(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value) if math.isfinite(value) else None


def _bool(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


def _str_list(value: Any, n: int) -> list[str] | None:
    if not isinstance(value, (list, tuple)):
        return None
    return [v[:n] for v in value[:MAX_ITEMS] if isinstance(v, str)]


def _section(obj: Any, spec: dict[str, str], n: int) -> dict[str, Any] | None:
    """Copy ONLY the named attributes of `obj`, each through its typed reader; drop absent/mistyped."""
    if obj is None:
        return None
    out: dict[str, Any] = {}
    for key, kind in spec.items():
        raw = getattr(obj, key, None)
        if kind == "s":
            v: Any = _text(raw, n)
        elif kind == "i":
            v = _int(raw)
        elif kind == "f":
            v = _float(raw)
        elif kind == "b":
            v = _bool(raw)
        else:
            v = _str_list(raw, n)
        if v is not None:
            out[key] = v
    return out


def _decision(decision: Any, n: int) -> dict[str, Any] | None:
    return _section(
        decision,
        {"action": "s", "reason": "s", "severity": "s", "tier": "s", "confidence": "f",
         "risk_score": "f", "human_required": "b", "evidence": "l"},
        n,
    )


def _tool_input_digest(event: Any) -> str | None:
    supplied = getattr(event, "tool_input_sha256", None)
    if isinstance(supplied, str) and _SHA256_HEX.match(supplied):
        return supplied
    raw = getattr(event, "tool_input", None)
    if isinstance(raw, bytes):
        data = raw
    elif isinstance(raw, str):
        data = raw.encode("utf-8", "surrogatepass")
    else:
        return None  # absent or unknown shape: omit rather than guess a serialization
    return hashlib.sha256(data).hexdigest()


def build_evidence(request: Any, *, max_field_len: int = DEFAULT_MAX_FIELD_LEN) -> dict[str, Any]:
    """Build the bounded evidence dict for an `EscalationRequest`. See the module docstring.

    Fixed keys only (allowlist, fail-closed: unknown fields are omitted, never forwarded). Every string
    is at most `max_field_len` characters, including nested and list members. Tool input appears only
    as `tool_input_digest`. Raises `ValueError` for a non-positive `max_field_len`.
    """
    if isinstance(max_field_len, bool) or not isinstance(max_field_len, int) or max_field_len < 1:
        raise ValueError("max_field_len must be a positive int")
    n = max_field_len
    event = getattr(request, "event", None)

    ev: dict[str, Any] = {}
    for key, raw in (("class", getattr(event, "klass", None)), ("time", getattr(event, "time", None))):
        v = _text(raw, n)
        if v is not None:
            ev[key] = v

    sections = {
        "process": (getattr(event, "process", None),
                    {"pid": "i", "name": "s", "exe_path": "s", "cmdline": "s", "hash_sha256": "s",
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
        built = _section(obj, spec, n)
        if built is not None:
            ev[key] = built

    digest = _tool_input_digest(event)
    if digest is not None:
        ev["tool_input_digest"] = digest

    for key, decision in (("tier1", getattr(request, "tier1_decision", None)),
                          ("tier2", getattr(request, "tier2_decision", None))):
        built = _decision(decision, n)
        if built is not None:
            ev[key] = built

    reason = _text(getattr(request, "reason", None), n)
    if reason is not None:
        ev["escalation_reason"] = reason

    ais = _float(getattr(request, "ais_impact", None))  # hint only: passed through, never derived
    if ais is not None:
        ev["ais_impact"] = ais
    return ev
