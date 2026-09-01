#!/usr/bin/env python3
"""Mint a signed containment-cut license key. Owner-only; not part of the shipped tool.

It needs the private signing key, which never leaves `.secrets/`. This script is the only
place in the repository that touches a private key or imports a crypto library, and it is
excluded from the package.

    CONTAINMENT_CUT_SIGNING_KEY=.secrets/license-signing-key.pem \
        python3 scripts/mint_license.py --sub "Acme Inc" --plan team --days 365
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import time
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Mint a containment-cut license key.")
    parser.add_argument("--sub", required=True, help="who the license is for (name or email)")
    parser.add_argument("--plan", default="pro", choices=["pro", "team", "enterprise"])
    parser.add_argument("--days", type=int, default=0, help="0 = perpetual")
    parser.add_argument("--features", nargs="*", default=None)
    args = parser.parse_args()

    try:
        from cryptography.hazmat.primitives import serialization
    except ImportError:
        print("pip install cryptography (owner-only dependency)", file=sys.stderr)
        return 2

    key_path = Path(os.environ.get("CONTAINMENT_CUT_SIGNING_KEY", ".secrets/license-signing-key.pem"))
    if not key_path.exists():
        print(f"signing key not found at {key_path}", file=sys.stderr)
        return 2
    private_key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)

    now = int(time.time())
    payload: dict = {"sub": args.sub, "plan": args.plan, "iat": now}
    if args.days > 0:
        payload["exp"] = now + args.days * 86400
    if args.features:
        payload["features"] = args.features

    payload_bytes = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    signature = private_key.sign(payload_bytes)

    def b64(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).decode().rstrip("=")

    print(f"Minted {args.plan} license for {args.sub!r}"
          f"{f', expires in {args.days} days' if args.days else ' (perpetual)'}:", file=sys.stderr)
    print(f"CONTAINMENTCUT-{b64(payload_bytes)}.{b64(signature)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
