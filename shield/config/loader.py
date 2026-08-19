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


def load_policy_bundle(path: Path | str) -> PolicyBundle:
    """Load a policy bundle from a local JSON file, shaped `{"rules": [...]}` where each
    entry is the same dict shape `PolicyRule.from_dict` already accepts (spec §7). Returns
    rules in file order — the Policy Engine's first-match-wins semantics make that order
    load-bearing, so this function must not reorder or deduplicate.

    Raises `ConfigError` (never returns a partial/empty list) if the file is missing,
    isn't valid JSON, isn't shaped `{"rules": [...]}`, or any individual rule fails to
    parse — better to refuse the whole bundle loudly than silently drop one bad rule and
    run with fewer policies than the operator intended."""
    p = Path(path)
    doc, raw_bytes = _load_json_file(p, "policy rules")

    if "rules" not in doc:
        raise ConfigError(f"policy rules file {p} must be a JSON object with a top-level \"rules\" array")

    raw_rules = doc["rules"]
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

    version = str(doc.get("policy_version", doc.get("version", "")))
    return PolicyBundle(rules=rules, version=version, hash=f"sha256:{hashlib.sha256(raw_bytes).hexdigest()}")


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
        "chain_id",
        "verifying_contract",
        "tenant_policy_url",
        "device_token",
        "feature_flags",
        "sensitive_paths",
        "trusted_policy_hashes",
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
    if "trusted_policy_hashes" in kwargs and not isinstance(kwargs["trusted_policy_hashes"], list):
        raise ConfigError(f"device config file {p}: \"trusted_policy_hashes\" must be an array")
    if any(not isinstance(policy_hash, str) for policy_hash in kwargs.get("trusted_policy_hashes", [])):
        raise ConfigError(f"device config file {p}: every \"trusted_policy_hashes\" entry must be a string")
    return DeviceConfig(**kwargs)
