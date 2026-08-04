"""
Configuration & update module — spec/xibalba-shield-v1.md §4.6, the local-file half only.

§4.6 asks for three things: "Policies loadable from local files or a tenant cloud API; safe
auto-update for agent code and policy bundles; per-tenant feature flags." Only the first half
of the first item is built here — local-file loading of policy rules (§7's real, already-
tested shape) and device/tenant config, including feature flags.

**Deliberately NOT built, and why:** a tenant cloud API client would have no real server to
verify itself against — nothing in this monorepo or `integrity-latest` runs one — so building
it now would mean shipping an unverified network client, exactly the kind of untested code
this project's no-silent-mocks rule exists to prevent. "Safe auto-update for agent code" is a
materially different, higher-stakes problem (verified downloads, rollback, signature checking
on the update payload itself) that deserves its own real design pass, not a few functions
bolted onto a config loader. Both stay `[PLANNED]`.

This module owns no policy *logic* — it only turns JSON on disk into the same `PolicyRule`/
`DeviceConfig` objects the rest of the stack already uses (`PolicyRule.from_dict` does the
real parsing; this module just reads the file and reports errors clearly). A malformed file
raises `ConfigError` with a message naming the actual problem — never silently skips a bad
rule or falls back to an empty rule set, since a policy engine that silently loaded zero
rules because of a typo would fail-open in the worst possible way without saying so.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..schemas.policy_rule import PolicyRule


class ConfigError(Exception):
    """Raised for any local-file config problem — missing file, invalid JSON, or a
    structurally invalid rule/config shape. Always names the file and the specific
    problem, never a bare 'invalid config'."""


def load_policy_rules(path: Path | str) -> list[PolicyRule]:
    """Load a policy bundle from a local JSON file, shaped `{"rules": [...]}` where each
    entry is the same dict shape `PolicyRule.from_dict` already accepts (spec §7). Returns
    rules in file order — the Policy Engine's first-match-wins semantics make that order
    load-bearing, so this function must not reorder or deduplicate.

    Raises `ConfigError` (never returns a partial/empty list) if the file is missing,
    isn't valid JSON, isn't shaped `{"rules": [...]}`, or any individual rule fails to
    parse — better to refuse the whole bundle loudly than silently drop one bad rule and
    run with fewer policies than the operator intended."""
    p = Path(path)
    if not p.exists():
        raise ConfigError(f"policy rules file not found: {p}")

    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ConfigError(f"policy rules file {p} is not valid JSON: {exc}") from exc

    if not isinstance(doc, dict) or "rules" not in doc:
        raise ConfigError(f"policy rules file {p} must be a JSON object with a top-level \"rules\" array")

    raw_rules = doc["rules"]
    if not isinstance(raw_rules, list):
        raise ConfigError(f"policy rules file {p}: \"rules\" must be an array, got {type(raw_rules).__name__}")

    rules: list[PolicyRule] = []
    for i, raw in enumerate(raw_rules):
        if not isinstance(raw, dict):
            raise ConfigError(f"policy rules file {p}: rules[{i}] must be an object, got {type(raw).__name__}")
        try:
            rules.append(PolicyRule.from_dict(raw))
        except KeyError as exc:
            raise ConfigError(f"policy rules file {p}: rules[{i}] is missing required field {exc}") from exc
        except TypeError as exc:
            raise ConfigError(f"policy rules file {p}: rules[{i}] has an invalid shape: {exc}") from exc

    return rules


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
    feature_flags: dict[str, bool] = field(default_factory=dict)

    def flag(self, name: str, default: bool = False) -> bool:
        return self.feature_flags.get(name, default)


def load_device_config(path: Path | str) -> DeviceConfig:
    """Load device/tenant config from a local JSON file. `device_id` is the only required
    field — everything else has the same defaults `DeviceConfig` itself would use if
    constructed directly, so a minimal config file (`{"device_id": "..."}`) is valid."""
    p = Path(path)
    if not p.exists():
        raise ConfigError(f"device config file not found: {p}")

    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ConfigError(f"device config file {p} is not valid JSON: {exc}") from exc

    if not isinstance(doc, dict):
        raise ConfigError(f"device config file {p} must be a JSON object")
    if "device_id" not in doc:
        raise ConfigError(f"device config file {p} is missing required field \"device_id\"")

    known_fields = {"device_id", "tenant_id", "device_role", "bcc_middleware_url", "oracle_url", "feature_flags"}
    unknown = set(doc.keys()) - known_fields
    if unknown:
        raise ConfigError(f"device config file {p} has unknown field(s): {sorted(unknown)}")

    kwargs: dict[str, Any] = {k: v for k, v in doc.items() if k != "feature_flags"}
    kwargs["feature_flags"] = doc.get("feature_flags", {})
    return DeviceConfig(**kwargs)
