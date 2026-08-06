"""
Tenant policy distribution client.

Fetch one JSON policy bundle over HTTP(S), validate it through the same loader used by
`shield run`, optionally require its computed hash to be in the device trust allowlist, then
atomically replace the local bundle.
"""

from __future__ import annotations

import os
import tempfile
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from .loader import ConfigError, DeviceConfig, PolicyBundle, load_policy_bundle


@dataclass(frozen=True)
class PolicyFetchResult:
    path: Path
    bundle: PolicyBundle
    source_url: str


def fetch_tenant_policy(
    *,
    device_config: DeviceConfig,
    destination: Path | str,
    timeout_sec: float = 10.0,
) -> PolicyFetchResult:
    if not device_config.tenant_policy_url:
        raise ConfigError("device config does not set tenant_policy_url")

    url = device_config.tenant_policy_url
    headers = {
        "Accept": "application/json",
        "X-Shield-Device-ID": device_config.device_id,
        "X-Shield-Tenant-ID": device_config.tenant_id,
        "X-Shield-Device-Role": device_config.device_role,
    }
    if device_config.device_token:
        headers["Authorization"] = f"Bearer {device_config.device_token}"
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout_sec) as response:
            status = getattr(response, "status", 200)
            content_type = response.headers.get("Content-Type", "")
            raw = response.read()
    except urllib.error.URLError as exc:
        raise ConfigError(f"failed to fetch tenant policy from {url}: {exc}") from exc

    if status < 200 or status >= 300:
        raise ConfigError(f"tenant policy endpoint {url} returned HTTP {status}")
    if "json" not in content_type.lower():
        raise ConfigError(f"tenant policy endpoint {url} did not return JSON content")

    dest = Path(destination)
    dest.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("wb", delete=False, dir=dest.parent, prefix=f".{dest.name}.", suffix=".tmp") as tmp:
        tmp.write(raw)
        tmp_path = Path(tmp.name)

    try:
        bundle = load_policy_bundle(tmp_path)
        if device_config.trusted_policy_hashes and bundle.hash not in device_config.trusted_policy_hashes:
            raise ConfigError(f"fetched policy hash {bundle.hash} is not trusted by device config")
        os.replace(tmp_path, dest)
    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise

    return PolicyFetchResult(path=dest, bundle=bundle, source_url=url)
