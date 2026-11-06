"""Supabase Auth integration for Xibalba Shield.

Provides asymmetric JWKS-based JWT verification for Supabase Auth tokens
and helpers for initiating Google OAuth flows via the shared Supabase
Auth broker.
"""
from __future__ import annotations

import logging
import os
from typing import Any
import urllib.parse

import jwt
from jwt import PyJWKClient

logger = logging.getLogger(__name__)

DEFAULT_SUPABASE_URL = "https://ftspunijfgcbkuybobhf.supabase.co"
DEFAULT_AUDIENCE = "authenticated"
SUPPORTED_PROVIDERS = ("google",)


class SupabaseAuthError(RuntimeError):
    """Raised when Supabase Auth token validation fails."""


class SupabaseAuthVerifier:
    def __init__(
        self,
        supabase_url: str | None = None,
        audience: str | None = None,
        jwks_client: PyJWKClient | None = None,
    ) -> None:
        raw_url = supabase_url or os.getenv("SUPABASE_URL", DEFAULT_SUPABASE_URL)
        self.supabase_url = raw_url.strip().rstrip("/")
        self.audience = (audience or os.getenv("SUPABASE_JWT_AUDIENCE", DEFAULT_AUDIENCE)).strip()
        self.jwks_url = f"{self.supabase_url}/auth/v1/.well-known/jwks.json"
        self._jwks_client = jwks_client or PyJWKClient(self.jwks_url)

    def get_authorization_url(self, provider: str, redirect_to: str) -> str:
        provider_norm = provider.strip().lower()
        if provider_norm not in SUPPORTED_PROVIDERS:
            raise ValueError(f"Unsupported OAuth provider: {provider}")
        params = {
            "provider": provider_norm,
            "redirect_to": redirect_to.strip(),
        }
        return f"{self.supabase_url}/auth/v1/authorize?{urllib.parse.urlencode(params)}"

    def verify_token(self, token: str) -> dict[str, Any]:
        cleaned = token.strip()
        if not cleaned:
            raise SupabaseAuthError("Missing access token")
        try:
            signing_key = self._jwks_client.get_signing_key_from_jwt(cleaned)
            claims = jwt.decode(
                cleaned,
                signing_key.key,
                algorithms=["RS256", "ES256", "EdDSA"],
                audience=self.audience,
                options={
                    "verify_exp": True,
                    "verify_aud": bool(self.audience),
                },
            )
            return claims
        except Exception as exc:
            logger.warning("Supabase JWT verification failed: %s", exc)
            raise SupabaseAuthError(f"Invalid or expired Supabase token: {exc}") from exc
