"""Client-side device pairing engine and local identity confinement for Xibalba Shield.

Confinement Guarantee:
- Each device (real or virtual) anchors its own unique identifier (hardware UUID or machine GUID).
- Each device creates and holds its own Ed25519 private key locally. Private keys NEVER leave the device.
- The agent DID (did:integrity:<fingerprint>) is cryptographically bound to that device ID.
"""

from __future__ import annotations

import base64
import hashlib
import http.server
import json
import os
import platform
import socket
import socketserver
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from integrity_sdk.did import Keypair, fingerprint_for_pubkey

DEFAULT_SHIELD_HOME = Path.home() / ".shield"
DEFAULT_CLOUD_BACKEND = "https://xibalba-shield.onrender.com"


def detect_device_id() -> str:
    """Resolve a stable hardware or virtual-machine identifier for this endpoint."""
    system = platform.system().lower()
    
    # 1. Linux machine-id
    if system == "linux":
        for path in ("/etc/machine-id", "/var/lib/dbus/machine-id", "/sys/class/dmi/id/product_uuid"):
            try:
                candidate = Path(path).read_text(encoding="utf-8").strip()
                if candidate and len(candidate) >= 8:
                    return candidate
            except (OSError, PermissionError):
                continue

    # 2. Windows MachineGuid
    if system == "windows":
        try:
            import winreg  # type: ignore[import-not-found]
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography") as key:
                guid, _ = winreg.QueryValueEx(key, "MachineGuid")
                if guid:
                    return str(guid).strip()
        except Exception:
            pass

    # 3. macOS IOPlatformUUID
    if system == "darwin":
        try:
            import subprocess
            out = subprocess.check_output(["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"], text=True)
            for line in out.splitlines():
                if "IOPlatformUUID" in line:
                    return line.split("=")[-1].replace('"', "").strip()
        except Exception:
            pass

    # 4. Fallback: Hostname + platform hash
    salt = platform.node() + ":" + platform.system() + ":" + platform.machine()
    return hashlib.sha256(salt.encode("utf-8")).hexdigest()[:32]


def detect_device_type() -> str:
    """Detect whether this endpoint is a real physical machine or a virtual machine (VM)."""
    system = platform.system().lower()
    
    if system == "linux":
        try:
            for p in ("/sys/class/dmi/id/product_name", "/sys/class/dmi/id/sys_vendor", "/sys/hypervisor/type"):
                path = Path(p)
                if path.exists():
                    text = path.read_text(encoding="utf-8").lower().strip()
                    for vm_kw in ("qemu", "kvm", "virtualbox", "vmware", "hyper-v", "bochs", "xen", "amazon", "droplet"):
                        if vm_kw in text:
                            return f"virtual ({vm_kw})"
        except (OSError, PermissionError):
            pass

    if system == "windows":
        try:
            import winreg  # type: ignore[import-not-found]
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\BIOS") as key:
                vendor, _ = winreg.QueryValueEx(key, "SystemManufacturer")
                vendor_str = str(vendor).lower()
                for vm_kw in ("qemu", "vmware", "virtualbox", "hyper-v", "microsoft corporation", "kvm"):
                    if vm_kw in vendor_str:
                        return f"virtual ({vm_kw})"
        except Exception:
            pass

    return "real"


def load_or_create_device_did(key_dir: Path | None = None) -> tuple[str, str, Keypair]:
    """Load or generate a local Ed25519 keypair strictly confined to this endpoint."""
    target_dir = Path(key_dir or (DEFAULT_SHIELD_HOME / "did"))
    target_dir.mkdir(parents=True, exist_ok=True)
    key_path = target_dir / "private_key.pem"
    
    if key_path.is_file():
        try:
            raw_pem = key_path.read_bytes()
            kp = Keypair.from_pem(raw_pem)
        except Exception:
            kp = Keypair.generate()
            key_path.write_bytes(kp.private_pem())
            try:
                key_path.chmod(0o600)
            except OSError:
                pass
    else:
        kp = Keypair.generate()
        key_path.write_bytes(kp.private_pem())
        try:
            key_path.chmod(0o600)
        except OSError:
            pass

    pub_bytes = kp.public_bytes()
    fp = fingerprint_for_pubkey(pub_bytes)
    did = f"did:integrity:{fp}"
    pub_b64 = base64.b64encode(pub_bytes).decode("ascii")
    return did, pub_b64, kp


class _LoopbackHandler(http.server.BaseHTTPRequestHandler):
    result_holder: dict[str, Any] = {}
    done_event: threading.Event | None = None

    def log_message(self, *args: Any) -> None:
        pass  # Quiet logger

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/callback":
            params = urllib.parse.parse_qs(parsed.query)
            token = params.get("token", [""])[0]
            tenant_id = params.get("tenant_id", [""])[0]
            device_id = params.get("device_id", [""])[0]
            agent_did = params.get("agent_did", [""])[0]
            if token:
                self.__class__.result_holder["token"] = token
                self.__class__.result_holder["tenant_id"] = tenant_id
                self.__class__.result_holder["device_id"] = device_id
                self.__class__.result_holder["agent_did"] = agent_did
                if self.__class__.done_event:
                    self.__class__.done_event.set()
                
                body = (
                    "<!doctype html><html><head><meta charset='utf-8'><title>Shield Device Paired</title>"
                    "<style>body{font-family:sans-serif;background:#0f172a;color:#f8fafc;display:flex;"
                    "align-items:center;justify-content:center;height:100vh;margin:0;}"
                    ".card{background:#1e293b;padding:32px;border-radius:12px;border:1px solid #334155;text-align:center;max-width:400px;}"
                    "h1{color:#38bdf8;margin-top:0;}p{color:#94a3b8;line-height:1.5;}</style></head>"
                    "<body><div class='card'><h1>&#x2713; Device Paired</h1>"
                    "<p>Your endpoint has been authorized and cryptographically bound to your Shield workspace.</p>"
                    "<p>You can close this tab and return to your terminal.</p></div></body></html>"
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
        self.send_response(404)
        self.end_headers()


class DevicePairingFlow:
    """Manages initiating pairing, loopback listener, and status polling."""

    def __init__(self, backend_url: str = DEFAULT_CLOUD_BACKEND, shield_home: Path | None = None) -> None:
        self.backend_url = backend_url.rstrip("/")
        self.shield_home = Path(shield_home or DEFAULT_SHIELD_HOME)
        self.shield_home.mkdir(parents=True, exist_ok=True)
        self.device_id = detect_device_id()
        self.device_type = detect_device_type()
        self.device_name = platform.node() or self.device_id
        self.agent_did, self.pub_b64, self.keypair = load_or_create_device_did(self.shield_home / "did")

    def request_pairing(self, callback_url: str | None = None) -> dict[str, Any]:
        """Request a new pairing session from the Shield cloud backend."""
        url = f"{self.backend_url}/api/shield/device/pair/request"
        payload = {
            "device_id": self.device_id,
            "device_name": self.device_name,
            "device_type": self.device_type,
            "agent_did": self.agent_did,
            "agent_name": f"shield-agent@{self.device_name}",
            "agent_public_key": self.pub_b64,
            "callback_url": callback_url,
            "ttl_seconds": 900,
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            err_body = exc.read().decode("utf-8")
            raise RuntimeError(f"Pairing request failed ({exc.code}): {err_body}") from exc

    def poll_status(self, device_code: str) -> dict[str, Any]:
        """Check status of a pending pairing session."""
        url = f"{self.backend_url}/api/shield/device/pair/{urllib.parse.quote(device_code)}/status"
        req = urllib.request.Request(url, headers={"Accept": "application/json"}, method="GET")
        with urllib.request.urlopen(req, timeout=8) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def run_pairing(
        self,
        *,
        timeout_seconds: int = 600,
        open_browser: bool = True,
        use_loopback: bool = True,
        loopback_port: int = 8436,
    ) -> dict[str, Any]:
        """Execute full device pairing: start loopback, request code, prompt user, await approval."""
        callback_url = None
        server = None
        done_event = threading.Event()
        _LoopbackHandler.result_holder = {}
        _LoopbackHandler.done_event = done_event

        if use_loopback:
            try:
                server = socketserver.TCPServer(("127.0.0.1", loopback_port), _LoopbackHandler)
                server_thread = threading.Thread(target=server.serve_forever, daemon=True)
                server_thread.start()
                callback_url = f"http://127.0.0.1:{loopback_port}/callback"
            except OSError:
                server = None  # Port in use or permission denied; polling fallback handles it

        try:
            req = self.request_pairing(callback_url=callback_url)
            user_code = req["user_code"]
            device_code = req["device_code"]
            verification_url = req.get("verification_url") or f"{self.backend_url}/#pair?code={user_code}"
            interval = req.get("interval", 2)

            print("\n" + "=" * 64)
            print("  Xibalba Shield · Device Pairing & Confinement Flow")
            print("=" * 64)
            print(f"  Endpoint Identity:   {self.device_name} ({self.device_type})")
            print(f"  Device ID:           {self.device_id}")
            print(f"  Confined Agent DID:  {self.agent_did}")
            print(f"  Cloud Control Plane: {self.backend_url}")
            print("-" * 64)
            print(f"  PAIRING CODE:        {user_code}")
            print(f"  AUTHORIZATION URL:   {verification_url}")
            print("-" * 64)
            print("  To authorize this device:")
            print("    1. Open the URL above in your web browser.")
            print("    2. Sign in to your Shield account (e.g. via Google OAuth).")
            print("    3. Click 'Authorize & Pair Device'.\n")

            if open_browser:
                try:
                    webbrowser.open(verification_url)
                except Exception:
                    pass

            # Await approval via loopback or polling
            start_time = time.time()
            while time.time() - start_time < timeout_seconds:
                if done_event.is_set() and _LoopbackHandler.result_holder.get("token"):
                    res = _LoopbackHandler.result_holder
                    return self._finalize_pairing(
                        tenant_id=res.get("tenant_id") or "tenant-a",
                        device_token=res["token"],
                    )

                try:
                    status = self.poll_status(device_code)
                    if status.get("status") == "approved":
                        return self._finalize_pairing(
                            tenant_id=status.get("tenant_id") or "tenant-a",
                            device_token=status["device_token"],
                        )
                    if status.get("status") == "expired":
                        raise TimeoutError("Pairing request expired.")
                except (urllib.error.URLError, TimeoutError, ConnectionError):
                    pass

                time.sleep(interval)

            raise TimeoutError("Device pairing timed out awaiting authorization.")

        finally:
            if server:
                server.shutdown()
                server.server_close()

    def _finalize_pairing(self, *, tenant_id: str, device_token: str) -> dict[str, Any]:
        """Save device configuration and prepare local policies."""
        device_config_path = self.shield_home / "device.json"
        policy_url = f"{self.backend_url}/api/shield/policies/{tenant_id}/{self.device_id}"
        config_data = {
            "device_id": self.device_id,
            "tenant_id": tenant_id,
            "device_role": f"hybrid_{self.device_type}",
            "tenant_policy_url": policy_url,
            "backend_url": self.backend_url,
            "device_token": device_token,
            "device_key_path": str(self.shield_home / "did" / "private_key.pem"),
            "feature_flags": {},
            "sensitive_paths": [],
            "trusted_policy_hashes": [],
        }
        device_config_path.write_text(json.dumps(config_data, indent=2), encoding="utf-8")
        device_config_path.chmod(0o600)

        # Cache initial policy directory
        policies_dir = self.shield_home / "policies"
        policies_dir.mkdir(parents=True, exist_ok=True)

        print("\n" + "=" * 64)
        print("  ✓ DEVICE SUCCESSFULLY PAIRED TO SHIELD CONTROL PLANE")
        print("=" * 64)
        print(f"  Account Tenant:      {tenant_id}")
        print(f"  Device ID:           {self.device_id}")
        print(f"  Agent DID:           {self.agent_did}")
        print(f"  Local Device Agent:  ACTIVE ({self.device_type})")
        print(f"  Cloud Reasoning:     ACTIVE (paired on {self.backend_url})")
        print(f"  Configuration Saved: {device_config_path}")
        print("=" * 64 + "\n")
        return config_data
