"""Explicit TLS client configuration for Shield control-plane requests."""

from __future__ import annotations

import ssl
from typing import Any


def build_client_context(config: Any) -> ssl.SSLContext | None:
    """Build a verified client context when mTLS fields are configured.

    Plain HTTP callers keep the stdlib default behavior. HTTPS callers use the
    system trust store unless a CA bundle is supplied, and client credentials
    must always be provided as a complete certificate/key pair.
    """
    backend_url = str(getattr(config, "backend_url", "") or "")
    ca_file = str(getattr(config, "backend_ca_file", "") or "")
    client_cert = str(getattr(config, "backend_client_cert", "") or "")
    client_key = str(getattr(config, "backend_client_key", "") or "")
    if bool(client_cert) != bool(client_key):
        raise ValueError("backend mTLS requires both backend_client_cert and backend_client_key")
    if not backend_url.lower().startswith("https:") and any((ca_file, client_cert, client_key)):
        raise ValueError("backend TLS client settings require an https backend_url")
    if not backend_url.lower().startswith("https:"):
        return None
    context = ssl.create_default_context(cafile=ca_file or None)
    if client_cert and client_key:
        context.load_cert_chain(certfile=client_cert, keyfile=client_key)
    return context


__all__ = ["build_client_context"]
