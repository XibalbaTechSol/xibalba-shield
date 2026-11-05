"""The backend serves the built React operator console (`ui/dist`) when one is present.

Why this suite exists: until 2026-11-04 nothing in the Python package served `ui/dist`. Locally
the `Caddyfile` did it (`root * /srv/shield/ui/dist` + `try_files` + `reverse_proxy /api/*`), so
the gap was invisible -- but the Render deployment runs bare `shield-backend` with nothing in
front, and operators got `_console_html()`, the built-in light-mode fallback console, instead of
the real dark Industry-steel UI. The build step that produced `ui/dist` was discarded.

The session cookie is `SameSite=Strict`, so the UI and the API must stay on one origin; serving
the UI from the backend is what keeps sign-in working. These tests pin that contract.
"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from http import HTTPStatus
from http.server import ThreadingHTTPServer

import pytest

from shield.backend.api import make_handler
from shield.backend.store import ShieldStore

ADMIN = "test-admin-token"

INDEX_MARKER = "<!-- built-react-console -->"
ASSET_JS = 'console.log("shield console bundle");\n'


@pytest.fixture(autouse=True)
def _no_real_oracle_identity_lookups(monkeypatch):
    """Mirrors tests/test_backend.py: `_enrich_device` would otherwise make real oracle HTTP
    calls. Stubbed to the documented fail-open shape."""
    monkeypatch.setattr(
        "shield.backend.api.resolve_agent_identities",
        lambda dids, oracle_url, **kw: {
            did: {
                "did": did,
                "on_chain": False,
                "seen": False,
                "handle": None,
                "name": None,
                "local_label": None,
                "wallet_address": None,
                "display_name": did,
            }
            for did in dids
        },
    )


def _build_dist(tmp_path):
    """A minimal stand-in for a real `vite build` output tree.

    Written as bytes, not text. `write_text` applies the platform's newline translation, so on
    Windows every `\\n` here would land on disk as `\\r\\n` -- the server would then serve those
    bytes faithfully and a byte-for-byte assertion would fail for a difference the fixture
    introduced, not the handler. A real build output is bytes; this fixture is too.
    """
    dist = tmp_path / "ui" / "dist"
    (dist / "assets").mkdir(parents=True)
    (dist / "index.html").write_bytes(
        (
            f'<!doctype html>\n<html lang="en">{INDEX_MARKER}'
            '<head><script type="module" src="/assets/app.js"></script></head>'
            '<body><div id="root"></div></body></html>\n'
        ).encode("utf-8")
    )
    (dist / "assets" / "app.js").write_bytes(ASSET_JS.encode("utf-8"))
    (dist / "favicon.svg").write_bytes(b"<svg xmlns='http://www.w3.org/2000/svg'/>")
    return dist


def _start_backend(tmp_path, *, ui_dir=None):
    store = ShieldStore(tmp_path / "shield.sqlite3")
    handler = make_handler(store=store, admin_token=ADMIN, ui_dir=ui_dir)
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_port}"


def _get(url, *, accept="text/html"):
    req = urllib.request.Request(url, headers={"Accept": accept}, method="GET")
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, resp.read(), dict(resp.headers)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(), dict(exc.headers)


def test_root_serves_built_react_console_when_dist_present(tmp_path):
    """The whole point: `/` must return the built React index, not the fallback console."""
    dist = _build_dist(tmp_path)
    server, base = _start_backend(tmp_path, ui_dir=dist)
    try:
        status, body, headers = _get(f"{base}/")
        text = body.decode("utf-8")
        assert status == HTTPStatus.OK
        assert INDEX_MARKER in text, "served page is not the built React index"
        # The fallback console is a self-contained light-mode page; it must not appear.
        assert "color-scheme: light" not in text
        assert "text/html" in headers.get("Content-Type", "")
    finally:
        server.shutdown()
        server.server_close()


def test_ui_asset_is_served_with_javascript_content_type(tmp_path):
    """A 200 on `/` proves nothing if the JS bundle it references 404s."""
    dist = _build_dist(tmp_path)
    server, base = _start_backend(tmp_path, ui_dir=dist)
    try:
        status, body, headers = _get(f"{base}/assets/app.js", accept="*/*")
        assert status == HTTPStatus.OK
        assert body.decode("utf-8") == ASSET_JS
        assert "javascript" in headers.get("Content-Type", "").lower()
    finally:
        server.shutdown()
        server.server_close()


def test_unknown_client_route_falls_back_to_index_html(tmp_path):
    """SPA deep links (e.g. a bookmarked /settings) must boot the app, not 404."""
    dist = _build_dist(tmp_path)
    server, base = _start_backend(tmp_path, ui_dir=dist)
    try:
        status, body, _ = _get(f"{base}/settings")
        assert status == HTTPStatus.OK
        assert INDEX_MARKER in body.decode("utf-8")
    finally:
        server.shutdown()
        server.server_close()


def test_api_routes_win_over_static_and_spa_fallback(tmp_path):
    """Ordering guard: static serving must never shadow or swallow `/api/*`.

    Without this, the SPA fallback would answer unmatched API paths with index.html, turning a
    clean 404/JSON error into an HTML page and breaking every client error path.
    """
    dist = _build_dist(tmp_path)
    # A decoy file laid out exactly where the health route lives.
    (dist / "api" / "shield").mkdir(parents=True)
    (dist / "api" / "shield" / "health").write_text("DECOY", encoding="utf-8")
    server, base = _start_backend(tmp_path, ui_dir=dist)
    try:
        status, body, _ = _get(f"{base}/api/shield/health", accept="application/json")
        assert status == HTTPStatus.OK
        assert json.loads(body) == {"ok": True, "service": "xibalba-shield-backend"}

        # An unmatched API path must not be answered with the SPA shell.
        status, body, _ = _get(f"{base}/api/shield/does-not-exist", accept="application/json")
        assert status == HTTPStatus.NOT_FOUND
        assert INDEX_MARKER not in body.decode("utf-8")
    finally:
        server.shutdown()
        server.server_close()


def test_path_traversal_outside_dist_is_refused(tmp_path):
    """Static serving must not become an arbitrary-file read."""
    dist = _build_dist(tmp_path)
    secret = tmp_path / "secret.txt"
    secret.write_text("TOP-SECRET", encoding="utf-8")
    server, base = _start_backend(tmp_path, ui_dir=dist)
    try:
        # Three levels: dist/assets -> dist -> ui -> tmp_path, where the secret lives.
        # Pre-encoded so the traversal survives to the handler rather than being
        # normalised away in transit (verified: the handler does receive it verbatim).
        status, body, _ = _get(f"{base}/assets/..%2f..%2f..%2fsecret.txt", accept="*/*")
        assert b"TOP-SECRET" not in body
        assert status in (HTTPStatus.NOT_FOUND, HTTPStatus.FORBIDDEN, HTTPStatus.BAD_REQUEST, HTTPStatus.OK)
        if status == HTTPStatus.OK:
            # Only acceptable OK is the SPA shell, never the secret.
            assert INDEX_MARKER in body.decode("utf-8")
    finally:
        server.shutdown()
        server.server_close()


def test_default_ui_dir_points_at_the_repo_build_and_is_none_when_absent(tmp_path, monkeypatch):
    """The plumbing that makes this work in production.

    Without a default, the deployment would still serve the fallback console unless someone
    remembered to pass `--ui-dir` -- which is exactly how this gap went unnoticed before.
    """
    from shield.backend.api import default_ui_dir

    fake_repo = tmp_path / "repo"
    (fake_repo / "shield" / "backend").mkdir(parents=True)
    module_file = fake_repo / "shield" / "backend" / "api.py"
    module_file.write_text("", encoding="utf-8")
    monkeypatch.setattr("shield.backend.api.__file__", str(module_file))

    assert default_ui_dir() is None, "must be None until a build exists"

    dist = fake_repo / "ui" / "dist"
    dist.mkdir(parents=True)
    (dist / "index.html").write_text("<!doctype html>", encoding="utf-8")
    assert default_ui_dir() == dist.resolve()


def test_ui_dir_env_var_overrides_the_default(monkeypatch, tmp_path):
    """Lets a container image place the build somewhere else without a code change."""
    from shield.backend.api import default_ui_dir

    dist = tmp_path / "custom" / "dist"
    dist.mkdir(parents=True)
    (dist / "index.html").write_text("<!doctype html>", encoding="utf-8")
    monkeypatch.setenv("SHIELD_UI_DIR", str(dist))
    assert default_ui_dir() == dist.resolve()


def test_root_falls_back_to_builtin_console_without_a_dist(tmp_path):
    """Regression guard: with no built UI (plain `pip install`, dev box), behaviour is unchanged."""
    server, base = _start_backend(tmp_path, ui_dir=None)
    try:
        status, body, _ = _get(f"{base}/")
        text = body.decode("utf-8")
        assert status == HTTPStatus.OK
        assert "Xibalba Shield" in text
        assert INDEX_MARKER not in text
    finally:
        server.shutdown()
        server.server_close()
