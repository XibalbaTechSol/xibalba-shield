"""OIDC and OAuth 2.0 social authentication provider integration."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode
import urllib.request
import urllib.error
import jwt


class OAuthError(RuntimeError):
    """Raised when an OAuth / OIDC authorization, token exchange, or validation fails."""


@dataclass(frozen=True)
class OAuthUserInfo:
    provider: str
    provider_user_id: str
    email: str
    display_name: str
    email_verified: bool
    raw: dict[str, Any] = field(default_factory=dict)


def generate_pkce() -> tuple[str, str]:
    """Generate a high-entropy PKCE code_verifier and code_challenge (S256). RFC 7636."""
    code_verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return code_verifier, code_challenge


def sign_oauth_state(
    secret: bytes | str,
    *,
    provider: str = "google",
    code_verifier: str,
    redirect_uri: str = "",
    tenant_id: str = "",
    ttl_seconds: int = 600,
) -> str:
    """Pack and sign an HMAC-SHA256 state string to protect against CSRF and replay attacks."""
    secret_bytes = secret.encode("utf-8") if isinstance(secret, str) else secret
    now = int(time.time())
    payload = {
        "p": provider,
        "v": code_verifier,
        "r": redirect_uri,
        "ten": tenant_id,
        "t": now,
        "exp": now + ttl_seconds,
        "n": secrets.token_hex(16),
    }
    raw_json = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    sig = hmac.new(secret_bytes, raw_json, hashlib.sha256).digest()
    p_b64 = base64.urlsafe_b64encode(raw_json).decode("ascii").rstrip("=")
    s_b64 = base64.urlsafe_b64encode(sig).decode("ascii").rstrip("=")
    return f"{p_b64}.{s_b64}"


def verify_oauth_state(
    secret: bytes | str,
    state_token: str,
    expected_provider: str = "google",
) -> dict[str, Any]:
    """Verify state token signature, expiration, and provider binding."""
    if not state_token or not secret:
        raise OAuthError("State token and secret are required")
    secret_bytes = secret.encode("utf-8") if isinstance(secret, str) else secret
    parts = state_token.split(".")
    if len(parts) != 2:
        raise OAuthError("Malformed OAuth state token")
    p_b64, s_b64 = parts
    try:
        p_padding = "=" * (-len(p_b64) % 4)
        raw_json = base64.urlsafe_b64decode(p_b64 + p_padding)
        s_padding = "=" * (-len(s_b64) % 4)
        expected_sig = base64.urlsafe_b64decode(s_b64 + s_padding)
    except Exception as exc:
        raise OAuthError("Invalid base64 encoding in state token") from exc

    actual_sig = hmac.new(secret_bytes, raw_json, hashlib.sha256).digest()
    if not hmac.compare_digest(actual_sig, expected_sig):
        raise OAuthError("Invalid or tampered OAuth state signature")

    try:
        payload = json.loads(raw_json.decode("utf-8"))
    except Exception as exc:
        raise OAuthError("Invalid JSON in OAuth state") from exc

    if payload.get("p") != expected_provider:
        raise OAuthError(f"OAuth state provider mismatch: expected {expected_provider}, got {payload.get('p')}")

    now = int(time.time())
    if payload.get("exp", 0) < now:
        raise OAuthError("OAuth state has expired; please restart the sign-in flow")

    return payload


class OIDCClient:
    def __init__(
        self,
        discovery_url: str,
        client_id: str,
        client_secret: str,
        redirect_uri: str = "",
        *,
        config: dict[str, Any] | None = None,
        jwks_client: Any | None = None,
    ):
        self.client_id = client_id.strip()
        self.client_secret = client_secret.strip()
        self.redirect_uri = redirect_uri.strip()
        self.discovery_url = discovery_url.strip()
        self._config: dict[str, Any] = dict(config) if config else {}
        self._jwks_client: Any | None = jwks_client

    def _load_config(self) -> None:
        if not self._config:
            if not self.discovery_url:
                raise OAuthError("OIDC discovery URL is not configured")
            try:
                req = urllib.request.Request(self.discovery_url, headers={"User-Agent": "Xibalba-Shield/1.0"})
                with urllib.request.urlopen(req, timeout=10) as resp:
                    self._config = json.loads(resp.read().decode("utf-8"))
            except Exception as exc:
                raise OAuthError(f"Failed to load OIDC discovery configuration: {exc}") from exc
        if self._jwks_client is None and "jwks_uri" in self._config:
            self._jwks_client = jwt.PyJWKClient(self._config["jwks_uri"])

    def get_authorization_url(
        self,
        state: str,
        *,
        code_challenge: str | None = None,
        redirect_uri: str | None = None,
        prompt: str = "select_account",
    ) -> str:
        self._load_config()
        endpoint = self._config.get("authorization_endpoint") or "https://accounts.google.com/o/oauth2/v2/auth"
        effective_redirect = (redirect_uri or self.redirect_uri).strip()
        params: dict[str, str] = {
            "client_id": self.client_id,
            "response_type": "code",
            "scope": "openid email profile",
            "redirect_uri": effective_redirect,
            "state": state,
            "prompt": prompt,
        }
        if code_challenge:
            params["code_challenge"] = code_challenge
            params["code_challenge_method"] = "S256"
        return f"{endpoint}?{urlencode(params)}"

    def exchange_code(
        self,
        code: str,
        *,
        code_verifier: str | None = None,
        redirect_uri: str | None = None,
    ) -> dict[str, Any]:
        self._load_config()
        endpoint = self._config.get("token_endpoint") or "https://oauth2.googleapis.com/token"
        effective_redirect = (redirect_uri or self.redirect_uri).strip()
        payload: dict[str, str] = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": effective_redirect,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }
        if code_verifier:
            payload["code_verifier"] = code_verifier
        data = urlencode(payload).encode("utf-8")
        req = urllib.request.Request(
            endpoint,
            data=data,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "Xibalba-Shield/1.0",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            err_body = exc.read().decode("utf-8", errors="replace")
            raise OAuthError(f"OIDC token exchange failed (HTTP {exc.code}): {err_body}") from exc
        except Exception as exc:
            raise OAuthError(f"OIDC token exchange network error: {exc}") from exc

    def verify_id_token(self, token: str) -> dict[str, Any]:
        self._load_config()
        if self._jwks_client is None:
            raise OAuthError("JWKS client not initialized")
        try:
            signing_key = self._jwks_client.get_signing_key_from_jwt(token)
            expected_iss = self._config.get("issuer", "https://accounts.google.com")
            issuers = [expected_iss]
            if expected_iss == "https://accounts.google.com":
                issuers.append("accounts.google.com")
            return jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256", "ES256"],
                audience=self.client_id,
                issuer=issuers if len(issuers) > 1 else expected_iss,
                options={"verify_exp": True, "verify_aud": True, "verify_iss": True},
            )
        except Exception as exc:
            raise OAuthError(f"OIDC ID token verification failed: {exc}") from exc

    def fetch_userinfo(self, access_token: str) -> dict[str, Any]:
        self._load_config()
        endpoint = self._config.get("userinfo_endpoint") or "https://openidconnect.googleapis.com/v1/userinfo"
        req = urllib.request.Request(
            endpoint,
            headers={
                "Authorization": f"Bearer {access_token}",
                "User-Agent": "Xibalba-Shield/1.0",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except Exception as exc:
            raise OAuthError(f"OIDC userinfo fetch failed: {exc}") from exc

    def get_user_info(self, tokens: dict[str, Any]) -> OAuthUserInfo:
        claims: dict[str, Any] = {}
        if "id_token" in tokens and tokens["id_token"]:
            try:
                claims = self.verify_id_token(tokens["id_token"])
            except Exception:
                if "access_token" in tokens and tokens["access_token"]:
                    claims = self.fetch_userinfo(tokens["access_token"])
                else:
                    raise
        elif "access_token" in tokens and tokens["access_token"]:
            claims = self.fetch_userinfo(tokens["access_token"])
        else:
            raise OAuthError("Token response contains neither id_token nor access_token")

        email = str(claims.get("email", "")).strip().lower()
        sub = str(claims.get("sub", "")).strip()
        display_name = str(claims.get("name") or claims.get("given_name") or (email.split("@")[0] if email else "")).strip()
        email_verified = bool(claims.get("email_verified", False))

        if not email or not sub:
            raise OAuthError("OIDC provider did not return required email or subject (sub)")
        if not email_verified:
            raise OAuthError("OIDC provider reported email is not verified")

        return OAuthUserInfo(
            provider="google",
            provider_user_id=sub,
            email=email,
            display_name=display_name,
            email_verified=email_verified,
            raw=claims,
        )
