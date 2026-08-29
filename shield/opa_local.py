"""Supervise one explicitly selected Open Policy Agent (OPA) bundle for local smoke runs."""
from __future__ import annotations

import json
import socket
import subprocess
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
import hashlib
from urllib.error import URLError
from urllib.request import Request, urlopen

PACKAGE_ROOT = Path(__file__).resolve().parent
PROFILES = {
    "smb": PACKAGE_ROOT / "policies/rego/smb.rego",
    "professional-services": PACKAGE_ROOT / "policies/rego/professional-services.rego",
    "regulated": PACKAGE_ROOT / "policies/rego/regulated.rego",
}

PROFILE_PROBES = {
    "smb": ({"event": {"process": {"exe_path": "/opt/ai/tool"}}}, "smb-contain-shadow-ai-processes"),
    "professional-services": ({"event": {"agent": {"agent_id": "probe"}}, "ctx": {"registered_agent_ids": {}}}, "ps-deny-unregistered-agents"),
    "regulated": ({"event": {"context": {"data_sources": ["claims_phi"]}}, "ctx": {"registered_agent_ids": {"probe": True}}}, "regulated-deny-phi-context"),
}


def selected_profile_metadata(profile: str) -> tuple[str, str]:
    bundle = PROFILES.get(profile)
    if bundle is None:
        raise ValueError(f"unsupported OPA profile: {profile!r}")
    return "1.0.0", f"sha256:{hashlib.sha256(bundle.read_bytes()).hexdigest()}"


def _unused_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _query(url: str, input_payload: dict) -> dict:
    request = Request(
        f"{url}/v1/data/shield/policy",
        data=json.dumps({"input": input_payload}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urlopen(request, timeout=0.5) as response:
        payload = json.loads(response.read())
    result = payload.get("result")
    if not isinstance(result, dict):
        raise RuntimeError("OPA policy probe returned no object result")
    required = {"allow", "action", "message", "rule_id", "name", "version"}
    if not required.issubset(result):
        raise RuntimeError("OPA policy probe returned an incompatible result shape")
    return result


@contextmanager
def supervised_opa(profile: str, *, opa_binary: str = "opa", port: int | None = None, timeout: float = 5.0):
    """Start exactly one allowlisted bundle and yield its verified URL."""
    bundle = PROFILES.get(profile)
    if bundle is None:
        raise ValueError(f"unsupported OPA profile: {profile!r}")
    if not bundle.is_file():
        raise FileNotFoundError(bundle)
    selected_port = port or _unused_port()
    url = f"http://127.0.0.1:{selected_port}"
    # Never leave an unread PIPE attached to a long-lived OPA process: enough output would fill
    # the pipe and deadlock the policy engine. A temporary file preserves bounded startup
    # diagnostics without requiring a reader thread.
    with tempfile.TemporaryFile(mode="w+") as diagnostics:
        process = subprocess.Popen(
            [opa_binary, "run", "--server", "--addr", f"127.0.0.1:{selected_port}", str(bundle)],
            stdout=diagnostics,
            stderr=subprocess.STDOUT,
            text=True,
        )
        deadline = time.monotonic() + timeout
        try:
            probe_input, expected_rule = PROFILE_PROBES[profile]
            last_error: Exception | None = None
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    diagnostics.seek(0)
                    output = diagnostics.read().strip()
                    raise RuntimeError(f"OPA exited before readiness ({process.returncode}): {output}")
                try:
                    result = _query(url, probe_input)
                    if result["rule_id"] != expected_rule or result["version"] != "1.0.0":
                        raise RuntimeError("OPA readiness probe returned an unexpected selected-profile rule")
                    yield url
                    return
                except (OSError, URLError, ValueError, RuntimeError) as exc:
                    last_error = exc
                    time.sleep(0.05)
            raise TimeoutError(f"OPA profile {profile!r} did not become ready: {last_error}")
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2)
