#!/usr/bin/env python3
"""Signs a built wheel with an Ed25519 keypair -- `shield/release/signing.py`'s CLI
surface. Same lazy-generate-if-absent, PEM/0600 key-handling convention as `shield
sign-policy` (`shield/cli.py`'s `_sign_policy`), deliberately a SEPARATE key file from
the policy-signing key (see `shield/release/signing.py`'s module docstring for why).

Usage: python3 scripts/sign_release.py --key ~/.xibalba-shield/release-signing.key \\
           --wheel dist/xibalba_shield-0.1.0-py3-none-any.whl --out dist/xibalba_shield-0.1.0.attestation.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))


def main(argv: list[str] | None = None) -> int:
    from integrity_sdk.did import Keypair

    from shield.release import sign_artifact

    parser = argparse.ArgumentParser(prog="scripts/sign_release.py")
    parser.add_argument("--key", type=Path, required=True, help="Ed25519 private key PEM file; generated if it doesn't exist")
    parser.add_argument("--wheel", type=Path, required=True, help="built wheel/artifact to sign")
    parser.add_argument("--out", type=Path, required=True, help="destination attestation JSON path")
    args = parser.parse_args(argv)

    if not args.wheel.is_file():
        print(f"sign_release: artifact not found: {args.wheel}", file=sys.stderr)
        return 1

    if args.key.exists():
        try:
            keypair = Keypair.from_pem(args.key.read_bytes())
        except (ValueError, OSError) as exc:
            print(f"sign_release: cannot load existing key {args.key}: {exc}", file=sys.stderr)
            return 1
    else:
        keypair = Keypair.generate()
        args.key.parent.mkdir(parents=True, exist_ok=True)
        args.key.write_bytes(keypair.private_pem())
        args.key.chmod(0o600)
        print(f"generated a new release-signing keypair at {args.key} (0600) -- back this up, it cannot be recovered")

    attestation = sign_artifact(args.wheel, keypair)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(attestation, indent=2, sort_keys=True), encoding="utf-8")
    print(f"OK   signed {args.wheel} -> {args.out}")
    print(f"     sha256={attestation['sha256']}")
    print(f"     signer_public_key={attestation['signer_public_key']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
