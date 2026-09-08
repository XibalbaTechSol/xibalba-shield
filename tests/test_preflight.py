"""Coverage for `shield/integrity_exporter/preflight.py` -- the real, checkable DID/
bcc_middleware/Oracle readback status that replaces the previously hardcoded
`"did_registered": False` / `"oracle_readback": "blocked_until_rpc_credentials"` demo-seed
placeholders (`shield/backend/api.py`). HTTP is exercised against a real local `http.server`
instance rather than mocked -- `urllib.request` is stdlib, and a real socket round-trip is
cheap and catches URL-construction bugs a mock would hide."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import patch

import pytest

from shield.integrity_exporter import check_did_preflight


class _Handler(BaseHTTPRequestHandler):
    routes: dict[str, int] = {}

    def do_GET(self):  # noqa: N802 - stdlib method name
        status = self.routes.get(self.path)
        if status is None:
            # Any unlisted path (e.g. an unexpected query string) is a real 404, not a
            # silent pass -- keeps assertions on exact request paths honest.
            status = 404
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *_args):  # noqa: D401 - silence default stderr request logging
        pass


@pytest.fixture
def fake_server():
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        thread.join(timeout=2)


def _url(server: HTTPServer) -> str:
    host, port = server.server_address
    return f"http://{host}:{port}"


@patch("shield.integrity_exporter.preflight.sdk_did.load_or_create_did")
def test_reports_did_load_failure_without_raising(mock_load_did):
    mock_load_did.side_effect = RuntimeError("disk full")

    result = check_did_preflight(bcc_middleware_url="http://unused")

    assert result["did_loaded"] is False
    assert "disk full" in result["error"]


@patch("shield.integrity_exporter.preflight.sdk_did.load_or_create_did")
def test_all_reachable_and_registered(mock_load_did, fake_server):
    mock_load_did.return_value = ("did:test:agent", object(), {})
    _Handler.routes = {"/health": 200, "/healthz": 200, "/v1/agent/did%3Atest%3Aagent": 200}

    result = check_did_preflight(bcc_middleware_url=_url(fake_server), oracle_url=_url(fake_server))

    assert result["did"] == "did:test:agent"
    assert result["did_loaded"] is True
    assert result["bcc_middleware_reachable"] is True
    assert result["oracle_reachable"] is True
    assert result["oracle_registered"] is True


@patch("shield.integrity_exporter.preflight.sdk_did.load_or_create_did")
def test_oracle_404_means_not_yet_registered_not_an_error(mock_load_did, fake_server):
    mock_load_did.return_value = ("did:test:agent", object(), {})
    _Handler.routes = {"/health": 200, "/healthz": 200}  # /v1/agent/... unlisted -> 404

    result = check_did_preflight(bcc_middleware_url=_url(fake_server), oracle_url=_url(fake_server))

    assert result["oracle_reachable"] is True
    assert result["oracle_registered"] is False


@patch("shield.integrity_exporter.preflight.sdk_did.load_or_create_did")
def test_unreachable_bcc_middleware_reports_false_not_raise(mock_load_did):
    mock_load_did.return_value = ("did:test:agent", object(), {})

    result = check_did_preflight(bcc_middleware_url="http://127.0.0.1:1", timeout=0.5)

    assert result["bcc_middleware_reachable"] is False


@patch("shield.integrity_exporter.preflight.sdk_did.load_or_create_did")
def test_no_oracle_url_skips_oracle_checks(mock_load_did, fake_server):
    mock_load_did.return_value = ("did:test:agent", object(), {})
    _Handler.routes = {"/health": 200}

    result = check_did_preflight(bcc_middleware_url=_url(fake_server))

    assert result["oracle_configured"] is False
    assert result["oracle_reachable"] is None
    assert result["oracle_registered"] is None
