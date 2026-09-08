#!/usr/bin/env python3
"""Install/rollback/list versioned Shield releases -- `shield/release/manager.py`'s CLI
surface. Closes `docs/PRODUCTION_READINESS_PLAN.md` §7 item 5's "rollback is a manual
reinstall" gap: `install` verifies a signed wheel and creates a new, independent
`<releases-dir>/<version>/` before atomically flipping `<current-link>`; `rollback` just
flips it back to an already-installed version, no reinstall.

Usage:
  python3 scripts/release_manager.py install --wheel dist/xibalba_shield-0.1.0-py3-none-any.whl \\
      --attestation dist/xibalba_shield-0.1.0.attestation.json --version 0.1.0 \\
      --releases-dir /opt/xibalba-shield/releases --current-link /opt/xibalba-shield/current \\
      --trusted-key <base64-signer-public-key>
  python3 scripts/release_manager.py rollback --version 0.0.9 \\
      --releases-dir /opt/xibalba-shield/releases --current-link /opt/xibalba-shield/current
  python3 scripts/release_manager.py list \\
      --releases-dir /opt/xibalba-shield/releases --current-link /opt/xibalba-shield/current
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))


def _cmd_install(args: argparse.Namespace) -> int:
    from shield.release import ReleaseError, install_release

    try:
        result = install_release(
            wheel_path=args.wheel,
            attestation_path=args.attestation,
            version=args.version,
            releases_dir=args.releases_dir,
            current_link=args.current_link,
            trusted_keys=args.trusted_key or None,
        )
    except ReleaseError as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        return 1
    print(f"OK   installed {result.version} at {result.release_dir}, current -> {result.version}")
    print(f"     previous_version={result.previous_version or '(none)'}")
    print(f"     signer_public_key={result.verification.signer_public_key}")
    return 0


def _cmd_rollback(args: argparse.Namespace) -> int:
    from shield.release import ReleaseError, rollback

    try:
        version = rollback(version=args.version, releases_dir=args.releases_dir, current_link=args.current_link)
    except ReleaseError as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        return 1
    print(f"OK   current -> {version} (no reinstall; restart the service to run it)")
    return 0


def _cmd_list(args: argparse.Namespace) -> int:
    from shield.release import list_releases

    releases = list_releases(releases_dir=args.releases_dir, current_link=args.current_link)
    if args.json:
        print(json.dumps(releases, indent=2))
        return 0
    if not releases:
        print(f"no releases installed at {args.releases_dir}")
        return 0
    for entry in releases:
        marker = " (current)" if entry["current"] else ""
        print(f"{entry['version']}{marker}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="scripts/release_manager.py")
    sub = parser.add_subparsers(dest="command", required=True)

    p_install = sub.add_parser("install", help="verify and install a new signed release, then activate it")
    p_install.add_argument("--wheel", type=Path, required=True)
    p_install.add_argument("--attestation", type=Path, required=True, help="JSON from scripts/sign_release.py")
    p_install.add_argument("--version", required=True)
    p_install.add_argument("--releases-dir", type=Path, required=True)
    p_install.add_argument("--current-link", type=Path, required=True)
    p_install.add_argument("--trusted-key", action="append", help="repeatable; base64 signer public key(s) to trust. Omit to accept any validly-signed artifact.")
    p_install.set_defaults(func=_cmd_install)

    p_rollback = sub.add_parser("rollback", help="flip the current release back to an already-installed version")
    p_rollback.add_argument("--version", required=True)
    p_rollback.add_argument("--releases-dir", type=Path, required=True)
    p_rollback.add_argument("--current-link", type=Path, required=True)
    p_rollback.set_defaults(func=_cmd_rollback)

    p_list = sub.add_parser("list", help="list installed releases")
    p_list.add_argument("--releases-dir", type=Path, required=True)
    p_list.add_argument("--current-link", type=Path, required=True)
    p_list.add_argument("--json", action="store_true")
    p_list.set_defaults(func=_cmd_list)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
