"""Unit and integration tests for Auth0 token verification and session flow."""
import json
from pathlib import Path
import pytest
from unittest.mock import MagicMock
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from shield.backend.auth0_auth import Auth0Verifier, Auth0Error
from shield.backend.api import run_server
import threading
import urllib.request


class MockJWK:
    def __init__(self, key):
        self.key = key


class MockJWKClient:
    def __init__(self, key):
        self.mock_key = key

    def get_signing_key_from_jwt(self, token: str):
        return MockJWK(self.mock_key)


def test_auth0_verifier_init():
    verifier = Auth0Verifier("dev-2acdt0dlqgi0pqcu.us.auth0.com", client_id="test_client_id")
    assert verifier.domain == "dev-2acdt0dlqgi0pqcu.us.auth0.com"
    assert verifier.issuer == "https://dev-2acdt0dlqgi0pqcu.us.auth0.com/"
    assert verifier.expected_audience == "test_client_id"


def test_auth0_verifier_authorization_url():
    verifier = Auth0Verifier("dev-2acdt0dlqgi0pqcu.us.auth0.com", client_id="test_client_id")
    google_url = verifier.get_authorization_url("google", redirect_to="http://localhost:5173/")
    assert "https://dev-2acdt0dlqgi0pqcu.us.auth0.com/authorize" in google_url
    assert "connection=google-oauth2" in google_url
    assert "client_id=test_client_id" in google_url
    assert "response_type=token+id_token" in google_url or "response_type=token%20id_token" in google_url

    github_url = verifier.get_authorization_url("github", redirect_to="http://localhost:5173/")
    assert "connection=github" in github_url


def test_auth0_verifier_invalid_domain():
    with pytest.raises(ValueError, match="Auth0 domain must not be empty"):
        Auth0Verifier("")


def test_auth0_verifier_empty_token():
    verifier = Auth0Verifier("dev-2acdt0dlqgi0pqcu.us.auth0.com")
    with pytest.raises(Auth0Error, match="Missing access or ID token"):
        verifier.verify_token("")


def test_auth0_verifier_token_too_long():
    verifier = Auth0Verifier("dev-2acdt0dlqgi0pqcu.us.auth0.com")
    with pytest.raises(Auth0Error, match="Auth0 token exceeds maximum allowed size"):
        verifier.verify_token("a" * 17000)


def test_auth0_session_endpoint_flow(tmp_path: Path):
    db_path = tmp_path / "shield_auth0.db"
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    verifier = Auth0Verifier(
        domain="dev-2acdt0dlqgi0pqcu.us.auth0.com",
        client_id="test_cid",
        jwks_client=MockJWKClient(public_key),
    )

    valid_token = jwt.encode(
        {
            "sub": "auth0|google-oauth2|123456789",
            "email": "testuser@xibalba.example",
            "name": "Test User",
            "exp": 9999999999,
            "iat": 1000000000,
            "iss": "https://dev-2acdt0dlqgi0pqcu.us.auth0.com/",
            "aud": "test_cid",
        },
        private_key,
        algorithm="RS256",
    )

    server = run_server(
        host="127.0.0.1",
        port=0,
        db_path=db_path,
        admin_token="admin_tok",
        auth0_verifier=verifier,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_port}"

    try:
        # 1. Test /api/shield/auth/providers returns auth0
        req = urllib.request.Request(f"{base_url}/api/shield/auth/providers")
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode())
            assert data["google"] is True
            assert data["auth0"] is True

        # 2. Test /api/shield/auth/oauth/google/authorize redirects to Auth0
        auth_req = urllib.request.Request(
            f"{base_url}/api/shield/auth/oauth/google/authorize?redirect_to=http://localhost:5173/&redirect=0",
            headers={"Accept": "application/json"},
        )
        with urllib.request.urlopen(auth_req) as resp:
            auth_data = json.loads(resp.read().decode())
            assert "dev-2acdt0dlqgi0pqcu.us.auth0.com" in auth_data["authorization_url"]
            assert "connection=google-oauth2" in auth_data["authorization_url"]

        # 3. Test /api/shield/auth/auth0/session with id_token
        body = json.dumps({"id_token": valid_token}).encode()
        session_req = urllib.request.Request(
            f"{base_url}/api/shield/auth/auth0/session",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(session_req) as resp:
            data = json.loads(resp.read().decode())
            assert data["ok"] is True
            assert data["account"]["email"] == "testuser@xibalba.example"
            assert "shield_session=" in resp.headers.get("Set-Cookie", "")

        # 4. Test /api/shield/auth/supabase/session also accepts Auth0 token
        body2 = json.dumps({"access_token": valid_token}).encode()
        session_req2 = urllib.request.Request(
            f"{base_url}/api/shield/auth/supabase/session",
            data=body2,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(session_req2) as resp:
            data2 = json.loads(resp.read().decode())
            assert data2["ok"] is True
            assert data2["account"]["email"] == "testuser@xibalba.example"
    finally:
        server.shutdown()
