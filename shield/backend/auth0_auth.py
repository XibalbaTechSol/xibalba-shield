"""Auth0 ID/Access-token verification and authorization URL generation for Xibalba Shield."""
from __future__ import annotations

import logging
import os
from typing import Any
import urllib.parse

import jwt
from jwt.jwks_client import PyJWKClient

logger = logging.getLogger(__name__)

DEFAULT_AUTH0_DOMAIN = "dev-2acdt0dlqgi0pqcu.us.auth0.com"
DEFAULT_AUTH0_CLIENT_ID = "Yj3RdbTXctEWUQPYc2gLvQ7OTQkL5t6u"
SUPPORTED_PROVIDERS = ("google", "github", "auth0")


class Auth0Error(RuntimeError):
    """Raised when Auth0 token verification or authorization fails."""


class Auth0Verifier:
    def __init__(
        self,
        domain: str | None = None,
        *,
        client_id: str | None = None,
        audience: str | None = None,
        jwks_client: PyJWKClient | None = None,
    ) -> None:
        raw_domain = domain if domain is not None else os.getenv("AUTH0_DOMAIN", DEFAULT_AUTH0_DOMAIN)
        self.domain = raw_domain.strip().removeprefix("https://").removeprefix("http://").rstrip("/")
        if not self.domain:
            raise ValueError("Auth0 domain must not be empty")
        self.client_id = (client_id or os.getenv("AUTH0_CLIENT_ID", DEFAULT_AUTH0_CLIENT_ID)).strip()
        self.audience = (audience or os.getenv("AUTH0_AUDIENCE", "")).strip() or None
        self.issuer = f"https://{self.domain}/"
        self.expected_audience = self.client_id or self.audience
        self.jwks_url = f"{self.issuer}.well-known/jwks.json"
        self._jwks_client = jwks_client or PyJWKClient(self.jwks_url, timeout=10)

    def get_authorization_url(
        self,
        provider: str = "google",
        redirect_to: str = "",
        nonce: str = "shield_auth0_nonce",
    ) -> str:
        provider_norm = provider.strip().lower()
        effective_redirect = redirect_to.strip()
        params: dict[str, str] = {
            "client_id": self.client_id,
            "response_type": "token id_token",
            "redirect_uri": effective_redirect,
            "scope": "openid profile email",
            "nonce": nonce,
        }
        if provider_norm == "google":
            params["connection"] = "google-oauth2"
        elif provider_norm == "github":
            params["connection"] = "github"

        return f"https://{self.domain}/authorize?{urllib.parse.urlencode(params)}"

    def verify_token(self, token: str) -> dict[str, Any]:
        cleaned = token.strip()
        if not cleaned:
            raise Auth0Error("Missing access or ID token")
        if len(cleaned) > 16384:
            raise Auth0Error("Auth0 token exceeds maximum allowed size")

        try:
            signing_key = self._jwks_client.get_signing_key_from_jwt(cleaned)
            decode_options: dict[str, Any] = {"require": ["exp", "iat", "sub", "iss"]}
            decode_kwargs: dict[str, Any] = {
                "algorithms": ["RS256"],
                "issuer": self.issuer,
                "options": decode_options,
            }
            if self.expected_audience:
                decode_options["require"].append("aud")
                decode_kwargs["audience"] = self.expected_audience
            else:
                decode_options["verify_aud"] = False

            claims = jwt.decode(cleaned, signing_key.key, **decode_kwargs)
            return claims
        except Exception as exc:
            logger.warning("Auth0 JWT verification failed: %s", exc)
            raise Auth0Error(f"Invalid or expired Auth0 token: {exc}") from exc
