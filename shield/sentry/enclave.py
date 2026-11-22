"""
Phase 3: Encrypted Tenant Enclaves.

Provides zero-trust, tenant-isolated cryptographic storage for sensitive agent
memories, policy credentials, and private execution state using authenticated
AES-256-GCM envelope encryption and HKDF-SHA256 key derivation.
"""

from __future__ import annotations

import base64
import json
import os
import time
from dataclasses import dataclass
from typing import Any, Mapping

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class EnclaveError(Exception):
    """Raised when encryption or decryption fails."""


@dataclass(frozen=True)
class EnclaveEnvelope:
    schema: str
    tenant_id: str
    key_id: str
    nonce: str
    ciphertext: str
    created_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "tenant_id": self.tenant_id,
            "key_id": self.key_id,
            "nonce": self.nonce,
            "ciphertext": self.ciphertext,
            "created_at": self.created_at,
        }


class TenantEnclave:
    """Manages tenant-isolated AES-256-GCM authenticated encryption."""

    SCHEMA_VERSION = "xibalba.shield.enclave.v1"

    def __init__(self, tenant_id: str, master_secret: bytes | str) -> None:
        self.tenant_id = tenant_id
        secret_bytes = (
            master_secret.encode("utf-8") if isinstance(master_secret, str) else master_secret
        )
        if len(secret_bytes) < 16:
            raise EnclaveError("master secret must be at least 16 bytes")

        # Derive 256-bit tenant key via HKDF-SHA256
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=f"xibalba-shield:{tenant_id}".encode("utf-8"),
            info=b"tenant-enclave-aes256gcm",
        )
        self._tenant_key = hkdf.derive(secret_bytes)
        self._aesgcm = AESGCM(self._tenant_key)
        self.key_id = f"k_{self._tenant_key[:8].hex()}"

    def encrypt(
        self,
        data: bytes | str | Mapping[str, Any],
        *,
        associated_data: bytes | None = None,
    ) -> EnclaveEnvelope:
        """Encrypts data with AES-256-GCM returning an authenticated envelope."""
        if isinstance(data, (dict, list)):
            raw_bytes = json.dumps(data, sort_keys=True).encode("utf-8")
        elif isinstance(data, str):
            raw_bytes = data.encode("utf-8")
        else:
            raw_bytes = data

        aad = associated_data or self.tenant_id.encode("utf-8")
        nonce = os.urandom(12)

        try:
            ct = self._aesgcm.encrypt(nonce, raw_bytes, aad)
        except Exception as exc:
            raise EnclaveError(f"encryption failed: {exc}") from exc

        return EnclaveEnvelope(
            schema=self.SCHEMA_VERSION,
            tenant_id=self.tenant_id,
            key_id=self.key_id,
            nonce=base64.b64encode(nonce).decode("ascii"),
            ciphertext=base64.b64encode(ct).decode("ascii"),
            created_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        )

    def decrypt(
        self,
        envelope: EnclaveEnvelope | Mapping[str, Any],
        *,
        associated_data: bytes | None = None,
        as_json: bool = False,
    ) -> Any:
        """Decrypts an authenticated envelope and verifies GCM tag."""
        env = envelope if isinstance(envelope, EnclaveEnvelope) else EnclaveEnvelope(**envelope)
        if env.tenant_id != self.tenant_id:
            raise EnclaveError(f"tenant mismatch: envelope has {env.tenant_id} but enclave is {self.tenant_id}")

        aad = associated_data or self.tenant_id.encode("utf-8")
        try:
            nonce = base64.b64decode(env.nonce)
            ct = base64.b64decode(env.ciphertext)
            pt = self._aesgcm.decrypt(nonce, ct, aad)
        except Exception as exc:
            raise EnclaveError(f"decryption/tag authentication failed: {exc}") from exc

        if as_json:
            try:
                return json.loads(pt.decode("utf-8"))
            except Exception as exc:
                raise EnclaveError(f"payload is not valid JSON: {exc}") from exc

        return pt
