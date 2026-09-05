"""
Configuration & update module — spec/xibalba-shield-v1.md §4.6.

§4.6 asks for policies loadable from local files or a tenant cloud API, safe update paths, and
per-tenant feature flags. Local-file loading lives here; the network fetch/update client lives
in `shield.config.distribution` so JSON parsing and HTTP/update mechanics stay separate.

This module owns no policy *logic* — it only turns JSON on disk into the same `PolicyRule`/
`DeviceConfig` objects the rest of the stack already uses (`PolicyRule.from_dict` does the
real parsing; this module just reads the file and reports errors clearly). A malformed file
raises `ConfigError` with a message naming the actual problem — never silently skips a bad
rule or falls back to an empty rule set, since a policy engine that silently loaded zero
rules because of a typo would fail-open in the worst possible way without saying so.
"""

from __future__ import annotations

import json
import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..schemas.policy_rule import PolicyRule


class ConfigError(Exception):
    """Raised for any local-file config problem — missing file, invalid JSON, or a
    structurally invalid rule/config shape. Always names the file and the specific
    problem, never a bare 'invalid config'."""


@dataclass(frozen=True)
class PolicyBundle:
    rules: list[PolicyRule]
    version: str
    hash: str
    revision: int | None = None
    # Real signature state for operator/dashboard visibility -- distinct from
    # trusted_policy_hashes' exact-byte allowlist, which doesn't tell you anything
    # about who signed a bundle, only whether this exact content was pre-approved.
    signed: bool = False
    signer_public_key: str | None = None
    expires_at: str | None = None


def _load_json_file(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    if not path.exists():
        raise ConfigError(f"{label} file not found: {path}")

    raw = path.read_bytes()
    try:
        doc = json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise ConfigError(f"{label} file {path} is not valid JSON: {exc}") from exc

    if not isinstance(doc, dict):
        raise ConfigError(f"{label} file {path} must be a JSON object")
    return doc, raw


def load_policy_bundle(
    path: Path | str,
    *,
    trusted_signing_keys: list[str] | None = None,
    require_signed_policy: bool = False,
) -> PolicyBundle:
    """Load a policy bundle from a local JSON file. Two shapes are understood:

    - Legacy/unsigned: `{"rules": [...], "policy_version": "...", "policy_revision": N}`
      — loaded exactly as before, with no behavior change for anyone not opting into
      signing, UNLESS `require_signed_policy` is true, in which case this shape is
      rejected outright (fail closed, matching this repo's own stated posture).
    - Signed: `{"policy": {...same fields, plus optional "expires_at"...},
      "signature": "...", "signer_public_key": "..."}` (see `shield/config/signing.py`
      for the exact algorithm) — verified via `verify_policy_signature` before the
      inner `policy` object's rules are parsed at all.

    Returns rules in file order — the Policy Engine's first-match-wins semantics make
    that order load-bearing, so this function must not reorder or deduplicate.

    Raises `ConfigError` (never returns a partial/empty list) if the file is missing,
    isn't valid JSON, isn't shaped as either of the above, any individual rule fails to
    parse, or (when applicable) the signature/expiry/trust checks fail — better to
    refuse the whole bundle loudly than silently drop one bad rule and run with fewer
    policies than the operator intended."""
    p = Path(path)
    doc, raw_bytes = _load_json_file(p, "policy rules")

    signed = False
    signer_public_key: str | None = None
    if "policy" in doc:
        from .signing import verify_policy_signature  # local import: avoids a hard
        # integrity_sdk import for every caller of this module that never touches a
        # signed bundle at all (mirrors integrity_exporter's own lazy-import reasoning
        # elsewhere in this repo).

        result = verify_policy_signature(doc, trusted_signing_keys or [])
        if require_signed_policy and not result.verified:
            raise ConfigError(f"policy rules file {p}: signature verification failed: {result.reason}")
        signed = result.verified
        signer_public_key = result.signer_public_key if result.verified else None
        policy_doc = doc["policy"]
        if not isinstance(policy_doc, dict):
            raise ConfigError(f"policy rules file {p}: \"policy\" must be an object")
    elif "rules" in doc:
        if require_signed_policy:
            raise ConfigError(f"policy rules file {p}: unsigned bundle rejected — require_signed_policy is set")
        policy_doc = doc
    else:
        raise ConfigError(f"policy rules file {p} must be a JSON object with a top-level \"rules\" array or a signed \"policy\" object")

    raw_rules = policy_doc.get("rules")
    if raw_rules is None:
        raise ConfigError(f"policy rules file {p} must contain a \"rules\" array")
    if not isinstance(raw_rules, list):
        raise ConfigError(f"policy rules file {p}: \"rules\" must be an array, got {type(raw_rules).__name__}")

    rules: list[PolicyRule] = []
    for i, raw_rule in enumerate(raw_rules):
        if not isinstance(raw_rule, dict):
            raise ConfigError(f"policy rules file {p}: rules[{i}] must be an object, got {type(raw_rule).__name__}")
        try:
            rules.append(PolicyRule.from_dict(raw_rule))
        except KeyError as exc:
            raise ConfigError(f"policy rules file {p}: rules[{i}] is missing required field {exc}") from exc
        except TypeError as exc:
            raise ConfigError(f"policy rules file {p}: rules[{i}] has an invalid shape: {exc}") from exc

    version = str(policy_doc.get("policy_version", policy_doc.get("version", "")))
    revision = policy_doc.get("policy_revision")
    if revision is not None and (isinstance(revision, bool) or not isinstance(revision, int) or revision < 0):
        raise ConfigError(f"policy rules file {p}: \"policy_revision\" must be a non-negative integer")
    expires_at = policy_doc.get("expires_at")
    if expires_at is not None and not isinstance(expires_at, str):
        raise ConfigError(f"policy rules file {p}: \"expires_at\" must be a string")
    return PolicyBundle(
        rules=rules, version=version, hash=f"sha256:{hashlib.sha256(raw_bytes).hexdigest()}", revision=revision,
        signed=signed, signer_public_key=signer_public_key, expires_at=expires_at,
    )


def load_policy_rules(path: Path | str) -> list[PolicyRule]:
    return load_policy_bundle(path).rules


@dataclass
class DeviceConfig:
    """Device/tenant identity and per-tenant feature flags — the other real piece of §4.6
    this module builds. `feature_flags` is a flat `name -> bool` map; unknown flag names
    default to `False` via `.flag()` rather than raising, so a newer config file with a
    flag an older binary doesn't know about degrades safely instead of crashing."""

    device_id: str
    tenant_id: str = ""
    device_role: str = ""
    bcc_middleware_url: str = "http://localhost:8000"
    oracle_url: str = "http://localhost:8080"
    backend_url: str = ""
    # integrity-core docs/plans/2026-08-18-phase1-canonical-intent-encoding-proposal.md:
    # every BCC commitment this device's exporter signs must now bind chain_id +
    # verifying_contract. Defaults match Base Sepolia (CLAUDE.md's "Live deployment").
    chain_id: int = 84532
    verifying_contract: str = "0x72e21e44AdD6d6e7CAa02eaedF078630afC40819"
    tenant_policy_url: str = ""
    device_token: str = ""
    feature_flags: dict[str, bool] = field(default_factory=dict)
    sensitive_paths: list[str] = field(default_factory=list)
    trusted_policy_hashes: list[str] = field(default_factory=list)
    reject_policy_downgrades: bool = False
    # Signer-based trust (see shield/config/signing.py), alongside the exact-hash
    # allowlist above rather than replacing it -- empty list preserves today's
    # hash-allowlist-only behavior for existing deployments that haven't opted in.
    trusted_signing_keys: list[str] = field(default_factory=list)
    require_signed_policy: bool = False

    def flag(self, name: str, default: bool = False) -> bool:
        return self.feature_flags.get(name, default)


def load_device_config(path: Path | str) -> DeviceConfig:
    """Load device/tenant config from a local JSON file. `device_id` is the only required
    field — everything else has the same defaults `DeviceConfig` itself would use if
    constructed directly, so a minimal config file (`{"device_id": "..."}`) is valid."""
    p = Path(path)
    doc, _raw = _load_json_file(p, "device config")
    if "device_id" not in doc:
        raise ConfigError(f"device config file {p} is missing required field \"device_id\"")

    known_fields = {
        "device_id",
        "tenant_id",
        "device_role",
        "bcc_middleware_url",
        "oracle_url",
        "backend_url",
        "chain_id",
        "verifying_contract",
        "tenant_policy_url",
        "device_token",
        "feature_flags",
        "sensitive_paths",
        "trusted_policy_hashes",
        "reject_policy_downgrades",
        "trusted_signing_keys",
        "require_signed_policy",
    }
    unknown = set(doc.keys()) - known_fields
    if unknown:
        raise ConfigError(f"device config file {p} has unknown field(s): {sorted(unknown)}")

    kwargs: dict[str, Any] = {k: v for k, v in doc.items() if k != "feature_flags"}
    kwargs["feature_flags"] = doc.get("feature_flags", {})
    if "sensitive_paths" in kwargs and not isinstance(kwargs["sensitive_paths"], list):
        raise ConfigError(f"device config file {p}: \"sensitive_paths\" must be an array")
    if any(not isinstance(pattern, str) for pattern in kwargs.get("sensitive_paths", [])):
        raise ConfigError(f"device config file {p}: every \"sensitive_paths\" entry must be a string")
    if "reject_policy_downgrades" in kwargs and not isinstance(kwargs["reject_policy_downgrades"], bool):
        raise ConfigError(f"device config file {p}: \"reject_policy_downgrades\" must be a boolean")
    if "trusted_policy_hashes" in kwargs and not isinstance(kwargs["trusted_policy_hashes"], list):
        raise ConfigError(f"device config file {p}: \"trusted_policy_hashes\" must be an array")
    if any(not isinstance(policy_hash, str) for policy_hash in kwargs.get("trusted_policy_hashes", [])):
        raise ConfigError(f"device config file {p}: every \"trusted_policy_hashes\" entry must be a string")
    if "trusted_signing_keys" in kwargs and not isinstance(kwargs["trusted_signing_keys"], list):
        raise ConfigError(f"device config file {p}: \"trusted_signing_keys\" must be an array")
    if any(not isinstance(key, str) for key in kwargs.get("trusted_signing_keys", [])):
        raise ConfigError(f"device config file {p}: every \"trusted_signing_keys\" entry must be a string")
    if "require_signed_policy" in kwargs and not isinstance(kwargs["require_signed_policy"], bool):
        raise ConfigError(f"device config file {p}: \"require_signed_policy\" must be a boolean")
    return DeviceConfig(**kwargs)
