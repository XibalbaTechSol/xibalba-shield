"""Supervise one explicitly selected Integrity pack (`policies/packs/<profile>/`) for
local smoke runs, via `integrity_sdk.core.opa.OpaClient` -- the same client `PolicyEngine`
itself uses, so a `local-run` smoke pass proves the same install/query path production
enforcement takes, not a parallel one."""
from __future__ import annotations

import shutil
import socket
import subprocess
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path

from integrity_sdk.core.opa import OpaClient, OpaError
from integrity_sdk.core.packs import LoadedPack, load_pack, sign_pack
from integrity_sdk.did import Keypair, public_key_multibase

from .pack_profiles import PACK_DIRS_BY_PROFILE

PROFILE_PROBES = {
    "smb": ({"event": {"process": {"exe_path": "/opt/ai/tool"}}}, "smb-contain-shadow-ai-processes"),
    "professional-services": ({"event": {"agent": {"agent_id": "probe"}}, "ctx": {"registered_agent_ids": {}}}, "ps-deny-unregistered-agents"),
    "regulated": ({"event": {"context": {"data_sources": ["claims_phi"]}}, "ctx": {"registered_agent_ids": {"probe": True}}}, "regulated-deny-phi-context"),
}


def load_signed_profile_pack(profile: str, *, _tmp_dir: Path | None = None) -> LoadedPack:
    """Sign the built-in `profile` pack with a fresh ephemeral key and load+verify it back.

    Local-only trust: this key exists only for the returned `LoadedPack`, never persisted
    or reused across calls, and is never a real deployment's trusted signer -- see
    `shield/pack_signing.py` for the operator-held key `shield run`'s real enforcement path
    (and `shield sign-pack`) actually use.
    """
    pack_dir = PACK_DIRS_BY_PROFILE.get(profile)
    if pack_dir is None:
        raise ValueError(f"unsupported policy profile: {profile!r}")
    work_dir = Path(_tmp_dir or tempfile.mkdtemp(prefix="shield-local-run-")) / profile
    shutil.copytree(pack_dir, work_dir)
    signer = Keypair.generate()
    sign_pack(work_dir, signer)
    return load_pack(work_dir, trusted_signers=[public_key_multibase(signer.public_bytes())])


def _unused_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@contextmanager
def supervised_opa(profile: str, *, opa_binary: str = "opa", port: int | None = None, timeout: float = 5.0):
    """Start OPA empty, install exactly one signed pack via the real install path, verify
    it answers as expected, and yield `(url, pack)`. Never preloads a bundle file at
    process startup -- `OpaClient.install` (PUT over the REST API) is the only way policy
    ever reaches this server, matching what `shield run`'s real enforcement path does.
    Callers construct their own `PolicyEngine(opa_url=url, pack=pack)` from the yielded
    pair -- this context manager's own `OpaClient` only proves the server/pack combination
    is healthy before handing control to the caller."""
    if profile not in PACK_DIRS_BY_PROFILE:
        raise ValueError(f"unsupported OPA profile: {profile!r}")
    pack = load_signed_profile_pack(profile)
    selected_port = port or _unused_port()
    url = f"http://127.0.0.1:{selected_port}"
    client = OpaClient(url)
    # Never leave an unread PIPE attached to a long-lived OPA process: enough output would fill
    # the pipe and deadlock the policy engine. A temporary file preserves bounded startup
    # diagnostics without requiring a reader thread.
    with tempfile.TemporaryFile(mode="w+") as diagnostics:
        process = subprocess.Popen(
            [opa_binary, "run", "--server", "--addr", f"127.0.0.1:{selected_port}"],
            stdout=diagnostics,
            stderr=subprocess.STDOUT,
            text=True,
        )
        deadline = time.monotonic() + timeout
        try:
            probe_input, expected_rule = PROFILE_PROBES[profile]
            last_error: Exception | None = None
            installed = False
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    diagnostics.seek(0)
                    output = diagnostics.read().strip()
                    raise RuntimeError(f"OPA exited before readiness ({process.returncode}): {output}")
                try:
                    if not installed:
                        client.install(pack)
                        installed = True
                    result = client.query(pack, probe_input)
                    if not isinstance(result, dict) or result.get("rule_id") != expected_rule or result.get("version") != "1.0.0":
                        raise RuntimeError("OPA readiness probe returned an unexpected selected-profile rule")
                    break
                except (OpaError, OSError, ValueError, RuntimeError) as exc:
                    last_error = exc
                    installed = False  # OPA may not have been up yet for `install` to have taken
                    time.sleep(0.05)
            else:
                raise TimeoutError(f"OPA profile {profile!r} did not become ready: {last_error}")

            # Keep caller exceptions outside the readiness retry handler. A failed query in
            # the caller is a real test/application failure, not evidence that OPA needs
            # another startup attempt; catching it here breaks context-manager semantics.
            yield url, pack
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2)
