"""
Metadata-only content classifier for DLP guardrails.

Shield should classify and enforce on risk labels without storing prompt/output bodies in the
endpoint log. This module therefore inspects structured metadata only: category labels from an
upstream classifier, data-source names, file paths, and model endpoint names.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field


@dataclass(frozen=True)
class ClassificationRule:
    category: str
    severity: str = "medium"
    path_globs: tuple[str, ...] = ()
    data_source_globs: tuple[str, ...] = ()
    endpoint_globs: tuple[str, ...] = ()


@dataclass(frozen=True)
class Classification:
    categories: list[str] = field(default_factory=list)
    risk_level: str = "low"


_RISK_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


DEFAULT_CLASSIFICATION_RULES = (
    ClassificationRule("secret", "critical", path_globs=("*.pem", "*.key", "*/.ssh/*", "*/secrets/*")),
    ClassificationRule("phi", "high", data_source_globs=("*ehr*", "*clinical*", "*patient*")),
    ClassificationRule("regulated", "high", data_source_globs=("*pci*", "*financial*", "*payroll*")),
    ClassificationRule("external_model", "medium", endpoint_globs=("http://*", "https://*")),
)


def classify_metadata(
    *,
    supplied_categories: list[str] | tuple[str, ...] = (),
    file_paths: list[str] | tuple[str, ...] = (),
    data_sources: list[str] | tuple[str, ...] = (),
    model_endpoint: str = "",
    rules: tuple[ClassificationRule, ...] = DEFAULT_CLASSIFICATION_RULES,
) -> Classification:
    categories: set[str] = {category.strip().lower() for category in supplied_categories if category.strip()}
    risk = "low"

    for rule in rules:
        if _matches_any(file_paths, rule.path_globs) or _matches_any(data_sources, rule.data_source_globs):
            categories.add(rule.category)
            risk = _max_risk(risk, rule.severity)
        if model_endpoint and any(fnmatch.fnmatch(model_endpoint.lower(), pattern.lower()) for pattern in rule.endpoint_globs):
            categories.add(rule.category)
            risk = _max_risk(risk, rule.severity)

    return Classification(categories=sorted(categories), risk_level=risk)


def _matches_any(values: list[str] | tuple[str, ...], patterns: tuple[str, ...]) -> bool:
    return any(fnmatch.fnmatch(value.lower(), pattern.lower()) for value in values for pattern in patterns)


def _max_risk(left: str, right: str) -> str:
    return left if _RISK_ORDER.get(left, 0) >= _RISK_ORDER.get(right, 0) else right
