"""Key handling for signing Shield's Integrity packs (`integrity_sdk.core.packs`).

A dedicated Ed25519 key/trust domain, deliberately separate from `config/signing.py`'s
legacy policy-bundle key, `release/signing.py`'s package-signing key, and any agent/device
DID key -- this ecosystem's rule (see `release/signing.py`'s own docstring) is that
different blast radii never share a key file or a trust list. Owner decision
(docs/EXECUTION_PLAN.md A3, 2026-09-28): held the operator, generated and stored the same
lazy-generate/PEM/0600 way as `release/signing.py`'s key -- real HSM/multi-party custody
stays deferred to a later production-infra gate, same as every other key in this system
today.

`core.packs.sign_pack`/`load_pack` own the actual signing/verification logic; this module
only owns getting a `Keypair` onto disk safely and back.
"""

from __future__ import annotations

from pathlib import Path

from integrity_sdk.did import Keypair, public_key_multibase

DEFAULT_PACK_KEY_PATH = Path.home() / ".xibalba-shield" / "pack_signing_key.pem"


def load_or_generate_pack_keypair(path: Path = DEFAULT_PACK_KEY_PATH) -> tuple[Keypair, bool]:
    """Return `(keypair, generated)`. Loads an existing key at `path`, or generates and
    persists a new one (0600, parent dirs created) if none exists yet. Raises `ValueError`/
    `OSError` on a corrupted key file -- callers report that cleanly, same as every other
    config-loading failure in this CLI, rather than letting a raw cryptography traceback
    through."""
    if path.exists():
        return Keypair.from_pem(path.read_bytes()), False
    keypair = Keypair.generate()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(keypair.private_pem())
    path.chmod(0o600)
    return keypair, True


def pack_signer_multibase(keypair: Keypair) -> str:
    return public_key_multibase(keypair.public_bytes())
