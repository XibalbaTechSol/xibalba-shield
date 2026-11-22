"""Deterministic local advisory matching with explicit freshness, provenance, and signature verification."""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import time
from pathlib import Path
from typing import Any


def _canonical_bytes(doc: dict[str, Any]) -> bytes:
    filtered = {k: v for k, v in doc.items() if k not in ("signature", "signature_algorithm", "signer_key_id")}
    return json.dumps(filtered, sort_keys=True, separators=(",", ":")).encode("utf-8")


def verify_advisory_signature(doc: dict[str, Any], key: str | bytes) -> bool:
    """Verify an HMAC-SHA256 or Ed25519 signature over an advisory source."""
    sig_hex = doc.get("signature")
    if not sig_hex or not isinstance(sig_hex, str):
        return False
    algo = str(doc.get("signature_algorithm", "hmac-sha256")).lower()
    payload = _canonical_bytes(doc)

    if algo in ("hmac-sha256", "hmac"):
        key_bytes = key.encode("utf-8") if isinstance(key, str) else key
        expected = hmac.new(key_bytes, payload, hashlib.sha256).hexdigest()
        return hmac.compare_digest(sig_hex, expected)
    elif algo in ("ed25519",):
        try:
            from cryptography.hazmat.primitives.asymmetric import ed25519
            if isinstance(key, str):
                pub_bytes = bytes.fromhex(key) if len(key) == 64 else key.encode("utf-8")
            else:
                pub_bytes = key
            pub_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
            sig_bytes = bytes.fromhex(sig_hex)
            pub_key.verify(sig_bytes, payload)
            return True
        except Exception:
            return False
    return False


def sign_advisory_source(doc: dict[str, Any], key: str | bytes, algorithm: str = "hmac-sha256") -> dict[str, Any]:
    """Helper to attach a cryptographic signature to an advisory source dictionary."""
    signed = dict(doc)
    signed["signature_algorithm"] = algorithm
    payload = _canonical_bytes(signed)

    if algorithm.lower() in ("hmac-sha256", "hmac"):
        key_bytes = key.encode("utf-8") if isinstance(key, str) else key
        signed["signature"] = hmac.new(key_bytes, payload, hashlib.sha256).hexdigest()
    elif algorithm.lower() in ("ed25519",):
        from cryptography.hazmat.primitives.asymmetric import ed25519
        if isinstance(key, str):
            priv_bytes = bytes.fromhex(key) if len(key) == 64 else key.encode("utf-8")
        else:
            priv_bytes = key
        priv_key = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
        signed["signature"] = priv_key.sign(payload).hex()
    else:
        raise ValueError(f"unsupported signature algorithm: {algorithm}")
    return signed


def load_advisories(
    path: Path,
    *,
    max_age_seconds: int = 86400,
    expected_key: str | bytes | None = None,
    require_signature: bool = False,
) -> dict[str, Any]:
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    doc = json.loads(raw)
    if not isinstance(doc, dict) or not isinstance(doc.get("advisories"), list):
        raise ValueError("advisory source must contain an advisories array")
    updated = float(doc.get("updated_at", 0))
    if updated <= 0 or time.time() - updated > max_age_seconds:
        raise ValueError("advisory source is stale")

    signature_verified = None
    if expected_key is not None or require_signature:
        if "signature" not in doc:
            raise ValueError("unsigned advisory source: signature is required")
        if expected_key is not None:
            if not verify_advisory_signature(doc, expected_key):
                raise ValueError("invalid advisory signature")
            signature_verified = True
    elif "signature" in doc and expected_key is not None:
        signature_verified = verify_advisory_signature(doc, expected_key)

    return {
        "source_hash": digest,
        "updated_at": updated,
        "advisories": doc["advisories"],
        "signer": doc.get("signer"),
        "signature_verified": signature_verified,
    }


_VERSION_SPLIT_RE = re.compile(r"(\d+|[a-zA-Z]+)")


def parse_version(v: str) -> tuple[int | str, ...]:
    """Parse version string into comparable tuple of ints and strings."""
    parts = []
    clean = str(v).strip().lstrip("v")
    for token in _VERSION_SPLIT_RE.findall(clean):
        if token.isdigit():
            parts.append(int(token))
        else:
            parts.append(token.lower())
    return tuple(parts)


def _compare_version_tuples(a: tuple[int | str, ...], b: tuple[int | str, ...]) -> int:
    len_a, len_b = len(a), len(b)
    for i in range(max(len_a, len_b)):
        p_a = a[i] if i < len_a else 0
        p_b = b[i] if i < len_b else 0
        if isinstance(p_a, int) and isinstance(p_b, int):
            if p_a != p_b:
                return -1 if p_a < p_b else 1
        elif isinstance(p_a, str) and isinstance(p_b, str):
            if p_a != p_b:
                return -1 if p_a < p_b else 1
        else:
            # Number beats string (e.g. 1.0 > 1.0-alpha)
            return 1 if isinstance(p_a, int) else -1
    return 0


def version_satisfies(installed_version: str, spec: str) -> bool:
    """Check if installed version satisfies range specification (e.g. '< 2.0.0', '>= 1.0.0, < 2.0.0', '== 1.2.3')."""
    spec = spec.strip()
    if not spec:
        return False
    installed_tuple = parse_version(installed_version)

    clauses = [c.strip() for c in spec.split(",") if c.strip()]
    for clause in clauses:
        m = re.match(r"^(<=|>=|<|>|==|!=|=|)\s*(.*)$", clause)
        if not m:
            continue
        op, target = m.groups()
        op = "==" if op in ("", "=") else op
        target_tuple = parse_version(target)
        cmp = _compare_version_tuples(installed_tuple, target_tuple)

        if op == "<" and not (cmp < 0):
            return False
        elif op == "<=" and not (cmp <= 0):
            return False
        elif op == ">" and not (cmp > 0):
            return False
        elif op == ">=" and not (cmp >= 0):
            return False
        elif op == "==" and not (cmp == 0):
            return False
        elif op == "!=" and not (cmp != 0):
            return False
    return True


def match_advisories(inventory: dict[str, Any], source: dict[str, Any], *, max_findings: int = 256) -> dict[str, Any]:
    if max_findings < 1:
        raise ValueError("max_findings must be positive")
    packages = [p for p in inventory.get("packages", []) if isinstance(p, dict) and p.get("name")]
    pkg_by_name: dict[str, list[str]] = {}
    for p in packages:
        name = str(p.get("name"))
        ver = str(p.get("version", ""))
        pkg_by_name.setdefault(name, []).append(ver)

    findings = []
    for advisory in source.get("advisories", []):
        if not isinstance(advisory, dict):
            continue
        pkg_name = advisory.get("package")
        if not pkg_name or pkg_name not in pkg_by_name:
            continue

        adv_ver = advisory.get("version")
        adv_range = advisory.get("version_range") or adv_ver
        if not adv_range:
            continue

        for installed_ver in pkg_by_name[pkg_name]:
            matched = False
            # Check range if operator exists, or exact match
            if any(op in str(adv_range) for op in ("<", ">", "=", "!")):
                matched = version_satisfies(installed_ver, str(adv_range))
            else:
                matched = (installed_ver == str(adv_ver))

            if matched:
                finding = {
                    "id": advisory.get("id"),
                    "package": pkg_name,
                    "version": installed_ver,
                    "vulnerable_spec": adv_range,
                    "severity": advisory.get("severity"),
                    "summary": advisory.get("summary"),
                    "fixed_version": advisory.get("fixed_version"),
                }
                finding["priority"] = {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(
                    str(finding.get("severity")).lower(), 0
                )
                findings.append(finding)
                if len(findings) >= max_findings:
                    break
        if len(findings) >= max_findings:
            break

    findings.sort(key=lambda item: item["priority"], reverse=True)
    return {
        "status": "matched",
        "source_hash": source.get("source_hash"),
        "updated_at": source.get("updated_at"),
        "known_findings": findings,
    }


def build_remediation_plan(findings: list[dict[str, Any]], *, maintenance_window: str | None = None) -> dict[str, Any]:
    """Build approval-required remediation intent; this function never executes a package change."""
    actions = []
    for finding in findings[:256]:
        fixed = finding.get("fixed_version")
        if not fixed:
            continue
        actions.append({
            "package": finding.get("package"),
            "from_version": finding.get("version"),
            "to_version": fixed,
            "advisory_id": finding.get("id"),
            "priority": finding.get("priority", 0),
            "requires_approval": True,
        })
    return {
        "status": "approval_required",
        "maintenance_window": maintenance_window,
        "actions": sorted(actions, key=lambda item: item["priority"], reverse=True),
        "executed": False,
    }
