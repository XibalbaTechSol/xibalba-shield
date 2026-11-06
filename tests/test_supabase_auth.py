"""Tests for Supabase Auth integration in Xibalba Shield."""
from __future__ import annotations

import json
from pathlib import Path
import threading
import urllib.parse
import urllib.request
from http import HTTPStatus

from cryptography.hazmat.primitives.asymmetric import rsa
import jwt
import pytest

from shield.backend.api import SESSION_COOKIE_NAME, run_server
from shield.backend.supabase_auth import SupabaseAuthVerifier, SupabaseAuthError


class MockJWK:
    def __init__(self, key):
        self.key = key


class MockJWKClient:
    def __init__(self, key):
        self.mock_key = key

    def get_signing_key_from_jwt(self, token: str):
        return MockJWK(self.mock_key)


def test_supabase_auth_verifier_unit():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    verifier = SupabaseAuthVerifier(
        supabase_url="https://test.supabase.co",
        audience="authenticated",
        jwks_client=MockJWKClient(public_key),
    )

    # Google is supported
    auth_url = verifier.get_authorization_url("google", "https://shield.test/auth")
    assert "https://test.supabase.co/auth/v1/authorize" in auth_url
    assert "provider=google" in auth_url
    assert "redirect_to=https%3A%2F%2Fshield.test%2Fauth" in auth_url

    # Unsupported provider raises ValueError
    with pytest.raises(ValueError, match="Unsupported OAuth provider"):
        verifier.get_authorization_url("unsupported", "https://shield.test/auth")

    # Valid token verification
    token = jwt.encode(
        {"sub": "sub-12345", "email": "operator@shield.io", "aud": "authenticated", "exp": 9999999999},
        private_key,
        algorithm="RS256",
    )
    claims = verifier.verify_token(token)
    assert claims["sub"] == "sub-12345"
    assert claims["email"] == "operator@shield.io"

    # Token with invalid audience fails
    bad_aud_token = jwt.encode(
        {"sub": "sub-12345", "email": "operator@shield.io", "aud": "wrong-aud", "exp": 9999999999},
        private_key,
        algorithm="RS256",
    )
    with pytest.raises(SupabaseAuthError):
        verifier.verify_token(bad_aud_token)


def test_backend_supabase_oauth_endpoints(tmp_path: Path):
    db_path = tmp_path / "shield_supabase.db"
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    verifier = SupabaseAuthVerifier(
        supabase_url="https://ftspunijfgcbkuybobhf.supabase.co",
        audience="authenticated",
        jwks_client=MockJWKClient(public_key),
    )

    server = run_server(
        host="127.0.0.1",
        port=0,
        db_path=db_path,
        admin_token="test-admin-token",
        supabase_verifier=verifier,
    )
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    base_url = f"http://127.0.0.1:{server.server_port}"

    try:
        # 1. Test /api/shield/auth/providers returns google=True, github=False
        req = urllib.request.Request(f"{base_url}/api/shield/auth/providers")
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode())
            assert data["google"] is True
            assert data["github"] is False

        # 2. Test /api/shield/auth/oauth/google/authorize?redirect=0 returns JSON
        req = urllib.request.Request(
            f"{base_url}/api/shield/auth/oauth/google/authorize?redirect_to=http://127.0.0.1/callback&redirect=0",
            headers={"Accept": "application/json"},
        )
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode())
            assert "authorization_url" in data
            assert "ftspunijfgcbkuybobhf.supabase.co" in data["authorization_url"]
            assert "provider=google" in data["authorization_url"]

        # 3. Test /api/shield/auth/supabase/session creates and authenticates user
        token = jwt.encode(
            {
                "sub": "supabase-user-789",
                "email": "supabase.operator@example.com",
                "aud": "authenticated",
                "exp": 9999999999,
                "user_metadata": {"full_name": "Supabase Operator"},
                "app_metadata": {"provider": "google"},
            },
            private_key,
            algorithm="RS256",
        )
        post_req = urllib.request.Request(
            f"{base_url}/api/shield/auth/supabase/session",
            data=json.dumps({"access_token": token}).encode(),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(post_req) as resp:
            assert resp.status == HTTPStatus.OK
            body = json.loads(resp.read().decode())
            assert body["ok"] is True
            assert body["account"]["email"] == "supabase.operator@example.com"
            assert body["tenant_id"] is not None
            set_cookie = resp.headers.get("Set-Cookie")
            assert set_cookie is not None
            assert SESSION_COOKIE_NAME in set_cookie
            assert "HttpOnly" in set_cookie

        # 4. Test /api/shield/auth/supabase/session with invalid token fails with 401
        bad_req = urllib.request.Request(
            f"{base_url}/api/shield/auth/supabase/session",
            data=json.dumps({"access_token": "invalid.jwt.token"}).encode(),
            headers={"Content-Type": "application/json"},
        )
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(bad_req)
        assert exc_info.value.code == HTTPStatus.UNAUTHORIZED

    finally:
        server.shutdown()
        server.server_close()
