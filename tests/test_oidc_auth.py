"""Tests for OIDC / Google OAuth authentication and session establishment."""
from __future__ import annotations

import json
import secrets
import threading
import time
import urllib.parse
import urllib.request
from http import HTTPStatus
from pathlib import Path
from typing import Any

import pytest

from shield.backend.api import SESSION_COOKIE_NAME, make_handler, run_server
from shield.backend.oidc import (
    OIDCClient,
    OAuthError,
    OAuthUserInfo,
    generate_pkce,
    sign_oauth_state,
    verify_oauth_state,
)
from shield.backend.store import ShieldStore


class MockOIDCClient(OIDCClient):
    """Hermetic OIDC client for offline testing without network access."""

    def __init__(
        self,
        *,
        client_id: str = "mock-client-id.apps.googleusercontent.com",
        client_secret: str = "mock-client-secret",
        redirect_uri: str = "http://127.0.0.1:8765/api/shield/auth/oidc/callback",
        mock_user: dict[str, Any] | None = None,
    ):
        config = {
            "issuer": "https://accounts.google.com",
            "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
            "token_endpoint": "https://oauth2.googleapis.com/token",
            "userinfo_endpoint": "https://openidconnect.googleapis.com/v1/userinfo",
            "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
        }
        super().__init__(
            discovery_url="https://accounts.google.com/.well-known/openid-configuration",
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri,
            config=config,
        )
        self.mock_user = mock_user or {
            "sub": "google-user-12345",
            "email": "operator@xibalba.io",
            "name": "Operator Alice",
            "email_verified": True,
        }
        self.last_exchanged_code: str | None = None
        self.last_code_verifier: str | None = None

    def exchange_code(
        self,
        code: str,
        *,
        code_verifier: str | None = None,
        redirect_uri: str | None = None,
    ) -> dict[str, Any]:
        self.last_exchanged_code = code
        self.last_code_verifier = code_verifier
        if code == "invalid-code":
            raise OAuthError("OIDC token exchange failed: bad authorization code")
        return {
            "access_token": "mock-access-token",
            "token_type": "Bearer",
            "expires_in": 3600,
        }

    def fetch_userinfo(self, access_token: str) -> dict[str, Any]:
        return self.mock_user


def test_pkce_generation():
    verifier, challenge = generate_pkce()
    assert len(verifier) >= 43
    assert len(challenge) > 20
    assert verifier != challenge


def test_oauth_state_signing_and_verification():
    secret = "test-secret-key-123"
    verifier = "my-code-verifier"
    state = sign_oauth_state(
        secret,
        provider="google",
        code_verifier=verifier,
        redirect_uri="https://app.onrender.com/api/shield/auth/oidc/callback",
        tenant_id="tenant-x",
    )
    assert "." in state

    payload = verify_oauth_state(secret, state, expected_provider="google")
    assert payload["p"] == "google"
    assert payload["v"] == verifier
    assert payload["r"] == "https://app.onrender.com/api/shield/auth/oidc/callback"
    assert payload["ten"] == "tenant-x"

    # Signature tampering fails
    tampered = state[:-4] + "abcd"
    with pytest.raises(OAuthError, match="signature|tampered"):
        verify_oauth_state(secret, tampered, expected_provider="google")

    # Provider mismatch fails
    with pytest.raises(OAuthError, match="provider mismatch"):
        verify_oauth_state(secret, state, expected_provider="github")

    # Expired token fails
    expired_state = sign_oauth_state(
        secret,
        provider="google",
        code_verifier=verifier,
        ttl_seconds=-10,
    )
    with pytest.raises(OAuthError, match="expired"):
        verify_oauth_state(secret, expired_state, expected_provider="google")


def test_store_oauth_account_creation_and_login(tmp_path: Path):
    db_path = tmp_path / "shield_test.db"
    store = ShieldStore(db_path)

    # 1. First login auto-provisions account and tenant
    account, token = store.authenticate_or_create_oauth_account(
        email="operator@xibalba.io",
        provider="google",
        provider_user_id="google-sub-999",
        display_name="Operator X",
    )
    assert account["email"] == "operator@xibalba.io"
    assert account["display_name"] == "Operator X"
    assert account["email_verified"] is True
    assert account["role"] == "tenant_admin"
    assert account["tenant_id"].startswith("operator")
    assert token

    # Check session resolution
    session = store.session_for_token(token)
    assert session is not None
    assert session["email"] == "operator@xibalba.io"

    # 2. Subsequent login returns existing account and issues fresh session
    account2, token2 = store.authenticate_or_create_oauth_account(
        email="operator@xibalba.io",
        provider="google",
        provider_user_id="google-sub-999",
        display_name="Operator X Updated",
    )
    assert account2["id"] == account["id"]
    assert account2["tenant_id"] == account["tenant_id"]
    assert token2 != token

    # 3. Inactive account is blocked
    with store._conn:
        store._conn.execute("UPDATE accounts SET status='inactive' WHERE account_id=?", (account["id"],))
    with pytest.raises(ValueError, match="inactive"):
        store.authenticate_or_create_oauth_account(
            email="operator@xibalba.io",
            provider="google",
            provider_user_id="google-sub-999",
        )


def test_backend_oidc_endpoints(tmp_path: Path):
    db_path = tmp_path / "shield_oidc.db"
    mock_client = MockOIDCClient(
        mock_user={
            "sub": "sub-google-444",
            "email": "render.operator@example.com",
            "name": "Render Operator",
            "email_verified": True,
        }
    )
    admin_token = secrets.token_hex(16)
    server = run_server(
        host="127.0.0.1",
        port=0,
        db_path=db_path,
        admin_token=admin_token,
        oidc_client=mock_client,
        auth_secret="render-oauth-secret",
    )
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    base_url = f"http://127.0.0.1:{server.server_port}"

    try:
        # 1. Test /api/shield/auth/providers
        req = urllib.request.Request(f"{base_url}/api/shield/auth/providers")
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode())
            assert data["google"] is True

        # 2. Test /api/shield/auth/oidc/login returns JSON redirect URL
        req = urllib.request.Request(f"{base_url}/api/shield/auth/oidc/login?tenant_id=demo-tenant")
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode())
            assert "redirect_url" in data
            assert "state" in data
            auth_url = data["redirect_url"]
            state = data["state"]
            assert "accounts.google.com" in auth_url
            assert "code_challenge=" in auth_url
            assert f"state={state}" in auth_url

        # 3. Test /api/shield/auth/oidc/callback with invalid state fails
        bad_cb_url = f"{base_url}/api/shield/auth/oidc/callback?code=mock-code&state=tampered.state"
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(bad_cb_url)
        assert exc_info.value.code == HTTPStatus.BAD_REQUEST

        # 4. Test /api/shield/auth/oidc/callback with valid code and state redirects and sets cookie
        class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
            def http_error_303(self, req, fp, code, msg, headers):
                return fp
            def http_error_302(self, req, fp, code, msg, headers):
                return fp

        opener = urllib.request.build_opener(NoRedirectHandler)
        cb_url = f"{base_url}/api/shield/auth/oidc/callback?code=good-code&state={urllib.parse.quote(state)}"
        resp = opener.open(cb_url)
        assert resp.status in (HTTPStatus.SEE_OTHER, HTTPStatus.FOUND)
        set_cookie = resp.headers.get("Set-Cookie", "")
        assert f"{SESSION_COOKIE_NAME}=" in set_cookie
        assert "HttpOnly" in set_cookie

        session_token = set_cookie.split(f"{SESSION_COOKIE_NAME}=")[1].split(";")[0]

        # 5. Verify /api/shield/auth/me accepts the session cookie and returns operator identity
        me_req = urllib.request.Request(
            f"{base_url}/api/shield/auth/me",
            headers={"Cookie": f"{SESSION_COOKIE_NAME}={session_token}"},
        )
        with urllib.request.urlopen(me_req) as me_resp:
            me_data = json.loads(me_resp.read().decode())
            assert me_data["account"]["email"] == "render.operator@example.com"
            assert me_data["account"]["display_name"] == "Render Operator"
            assert me_data["tenant_id"] == "demo-tenant"

        # 6. Test direct browser redirect via /api/shield/auth/oidc/login?redirect=1
        red_req = urllib.request.Request(f"{base_url}/api/shield/auth/oidc/login?redirect=1")
        red_resp = opener.open(red_req)
        assert red_resp.status == HTTPStatus.FOUND
        assert "accounts.google.com" in red_resp.headers.get("Location", "")

        # 7. Test POST /api/shield/auth/oidc/callback JSON endpoint
        post_login_req = urllib.request.Request(
            f"{base_url}/api/shield/auth/oidc/login",
            data=json.dumps({"tenant_id": "json-tenant"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(post_login_req) as post_login_resp:
            post_login_data = json.loads(post_login_resp.read().decode())
            post_state = post_login_data["state"]

        post_cb_req = urllib.request.Request(
            f"{base_url}/api/shield/auth/oidc/callback",
            data=json.dumps({"code": "post-good-code", "state": post_state}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(post_cb_req) as post_cb_resp:
            post_cb_data = json.loads(post_cb_resp.read().decode())
            assert post_cb_data["ok"] is True
            assert post_cb_data["account"]["email"] == "render.operator@example.com"
            assert f"{SESSION_COOKIE_NAME}=" in post_cb_resp.headers.get("Set-Cookie", "")

    finally:
        server.shutdown()
        server.server_close()


def test_unverified_google_email_rejected():
    mock_client = MockOIDCClient(
        mock_user={
            "sub": "sub-unverified",
            "email": "attacker@example.com",
            "name": "Attacker",
            "email_verified": False,
        }
    )
    with pytest.raises(OAuthError, match="not verified"):
        mock_client.get_user_info({"access_token": "token"})

