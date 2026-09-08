"""
Tenant policy distribution client.

Fetch one JSON policy bundle over HTTP(S), validate it through the same loader used by
`shield run`, optionally require its computed hash to be in the device trust allowlist, then
atomically replace the local bundle.
"""

from __future__ import annotations

import os
import tempfile
import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .loader import ConfigError, DeviceConfig, PolicyBundle, load_policy_bundle
from .tls import build_client_context


@dataclass(frozen=True)
class PolicyFetchResult:
    path: Path
    bundle: PolicyBundle
    source_url: str


@dataclass(frozen=True)
class DeviceSettingsFetchResult:
    settings: dict[str, Any]
    settings_version: str
    updated_at: str | None
    source_url: str


def fetch_device_settings(*, device_config: DeviceConfig, timeout_sec: float = 2.0) -> DeviceSettingsFetchResult:
    """Fetch validated tenant settings using the enrolled device credential."""
    if not device_config.backend_url or not device_config.device_token:
        raise ConfigError("device config does not set backend_url and device_token")
    url = f"{device_config.backend_url.rstrip('/')}/api/shield/device-settings?tenant_id={urllib.parse.quote(device_config.tenant_id, safe='')}&device_id={urllib.parse.quote(device_config.device_id, safe='')}"
    request = urllib.request.Request(url, headers={
        "Accept": "application/json",
        "Authorization": f"Bearer {device_config.device_token}",
        "X-Shield-Device-ID": device_config.device_id,
        "X-Shield-Tenant-ID": device_config.tenant_id,
    })
    try:
        context = build_client_context(device_config)
        with urllib.request.urlopen(request, timeout=timeout_sec, **({"context": context} if context else {})) as response:
            status = getattr(response, "status", 200)
            payload = json.load(response)
    except (urllib.error.URLError, ValueError, json.JSONDecodeError) as exc:
        raise ConfigError(f"failed to fetch device settings from {url}: {exc}") from exc
    if status < 200 or status >= 300:
        raise ConfigError(f"device settings endpoint returned HTTP {status}")
    if not isinstance(payload, dict) or not isinstance(payload.get("settings"), dict):
        raise ConfigError("device settings response must contain a settings object")
    from ..backend.settings import settings_version, validate_settings
    settings = validate_settings(payload["settings"])
    version = str(payload.get("settings_version") or settings_version(settings))
    if version != settings_version(settings):
        raise ConfigError("device settings version does not match its contents")
    return DeviceSettingsFetchResult(settings, version, payload.get("updated_at"), url)


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
        context = build_client_context(device_config)
        with urllib.request.urlopen(request, timeout=timeout_sec, **({"context": context} if context else {})) as response:
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
