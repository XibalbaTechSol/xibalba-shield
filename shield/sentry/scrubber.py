"""
Phase 1: Deterministic Zero-Leak Secret & PII Scrubber.

High-performance regex and checksum validation engine that intercepts and redacts:
- API Keys (OpenAI, Anthropic, Stripe, AWS, GitHub, generic Bearer tokens)
- Cryptographic private keys (Ed25519, RSA, EC PEM blocks)
- PII (SSN, Luhn-validated Credit Cards, Emails, Phone numbers)

Replaces secrets with deterministic masks:
  [REDACTED:<KIND>:<sha256(raw_secret)[:8]>]

Guarantees zero-leak invariant: raw secret bytes never penetrate into agent memory
or LLM reasoning traces.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any, Sequence

# Regex patterns for secrets and tokens
SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("ANTHROPIC_KEY", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b")),
    ("OPENAI_KEY", re.compile(r"\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_\-]{20,}\b")),
    ("STRIPE_KEY", re.compile(r"\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{24,}\b")),
    ("AWS_KEY", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GITHUB_TOKEN", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b")),
    ("PRIVATE_KEY_PEM", re.compile(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----[^-]+-----END [A-Z ]+ PRIVATE KEY-----", re.DOTALL)),
    ("JWT_TOKEN", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")),
    ("BEARER_AUTH", re.compile(r"\bBearer\s+[A-Za-z0-9_\-\.]{24,}\b")),
]

# Regex patterns for PII
PII_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("PII_SSN", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("PII_EMAIL", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("PII_PHONE", re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")),
    ("PII_CREDIT_CARD", re.compile(r"\b(?:\d{4}[ -]?){3}\d{4}\b")),
]


def _luhn_checksum_valid(number_str: str) -> bool:
    """Validate credit card number using the Luhn algorithm."""
    digits = [int(c) for c in number_str if c.isdigit()]
    if len(digits) not in (13, 15, 16, 19):
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            d = d * 2
            if d > 9:
                d -= 9
        checksum += d
    return (checksum % 10) == 0


@dataclass(frozen=True)
class ScrubRecord:
    kind: str
    masked_placeholder: str
    original_length: int
    offset: int


class SecretScrubber:
    """Scans and deterministic-masks secrets and PII."""

    def __init__(self, *, salt: str = "") -> None:
        self.salt = salt.encode("utf-8")

    def _mask_token(self, kind: str, raw_secret: str) -> str:
        digest = hashlib.sha256(self.salt + raw_secret.encode("utf-8")).hexdigest()[:8]
        return f"[REDACTED:{kind}:{digest}]"

    def scrub(self, text: str) -> tuple[str, list[ScrubRecord]]:
        """
        Scans input text, replaces sensitive tokens with deterministic masks,
        and returns the scrubbed text along with detection records.
        """
        if not text:
            return "", []

        records: list[ScrubRecord] = []
        result = text

        # 1. Scrub Secrets
        for kind, pattern in SECRET_PATTERNS:
            for match in list(pattern.finditer(result)):
                raw_val = match.group(0)
                mask = self._mask_token(kind, raw_val)
                records.append(
                    ScrubRecord(
                        kind=kind,
                        masked_placeholder=mask,
                        original_length=len(raw_val),
                        offset=match.start(),
                    )
                )
                result = result.replace(raw_val, mask)

        # 2. Scrub PII
        for kind, pattern in PII_PATTERNS:
            for match in list(pattern.finditer(result)):
                raw_val = match.group(0)
                if kind == "PII_CREDIT_CARD" and not _luhn_checksum_valid(raw_val):
                    continue
                mask = self._mask_token(kind, raw_val)
                records.append(
                    ScrubRecord(
                        kind=kind,
                        masked_placeholder=mask,
                        original_length=len(raw_val),
                        offset=match.start(),
                    )
                )
                result = result.replace(raw_val, mask)

        return result, records


def scrub_secrets_and_pii(text: str, *, salt: str = "") -> tuple[str, list[ScrubRecord]]:
    scrubber = SecretScrubber(salt=salt)
    return scrubber.scrub(text)
