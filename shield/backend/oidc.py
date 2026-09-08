import json
import os
import urllib.request
from typing import Any, Dict
import jwt

class OIDCClient:
    def __init__(self, discovery_url: str, client_id: str, client_secret: str, redirect_uri: str):
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.discovery_url = discovery_url
        self._config: Dict[str, Any] = {}
        self._jwks_client: jwt.PyJWKClient | None = None

    def _load_config(self) -> None:
        if not self._config:
            req = urllib.request.Request(self.discovery_url, headers={"User-Agent": "Xibalba-Shield/1.0"})
            with urllib.request.urlopen(req) as resp:
                self._config = json.loads(resp.read())
            self._jwks_client = jwt.PyJWKClient(self._config["jwks_uri"])

    def get_authorization_url(self, state: str) -> str:
        self._load_config()
        endpoint = self._config["authorization_endpoint"]
        from urllib.parse import urlencode
        params = {
            "client_id": self.client_id,
            "response_type": "code",
            "scope": "openid email profile",
            "redirect_uri": self.redirect_uri,
            "state": state
        }
        return f"{endpoint}?{urlencode(params)}"

    def exchange_code(self, code: str) -> Dict[str, Any]:
        self._load_config()
        endpoint = self._config["token_endpoint"]
        from urllib.parse import urlencode
        data = urlencode({
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.redirect_uri,
            "client_id": self.client_id,
            "client_secret": self.client_secret
        }).encode("utf-8")
        req = urllib.request.Request(endpoint, data=data, headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Xibalba-Shield/1.0"
        })
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read())

    def verify_id_token(self, token: str) -> Dict[str, Any]:
        self._load_config()
        assert self._jwks_client is not None
        signing_key = self._jwks_client.get_signing_key_from_jwt(token)
        return jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256", "ES256"],
            audience=self.client_id,
            issuer=self._config["issuer"],
            options={"verify_exp": True, "verify_aud": True, "verify_iss": True}
        )
