"""Offline verification of a containment-cut license key.

A key is `CONTAINMENTCUT-<base64url(payload)>.<base64url(signature)>`, where the payload
is JSON and the signature is Ed25519 over the payload bytes. Verification is entirely
local: no network, no telemetry, nothing leaves the machine. It can confirm a key was
issued by the project owner and has not expired, and that is all it needs to do.
"""

from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass
from typing import Any

from .ed25519 import verify as ed_verify
from .keys import LICENSE_PUBLIC_KEY

PREFIX = "CONTAINMENTCUT-"


@dataclass(frozen=True, slots=True)
class VerifyResult:
    valid: bool
    payload: dict[str, Any] | None
    reason: str | None


def _fail(reason: str) -> VerifyResult:
    return VerifyResult(False, None, reason)


def _b64url(text: str) -> bytes | None:
    pad = "=" * (-len(text) % 4)
    try:
        return base64.urlsafe_b64decode(text + pad)
    except Exception:
        return None


def verify_license_key(
    key: str, *, public_key: bytes | None = None, now: int | None = None
) -> VerifyResult:
    if not isinstance(key, str) or not key.startswith(PREFIX):
        return _fail("Not a containment-cut license key.")
    body = key[len(PREFIX) :]
    dot = body.find(".")
    if dot < 0:
        return _fail("The key is malformed (missing signature).")

    payload_bytes = _b64url(body[:dot])
    signature = _b64url(body[dot + 1 :])
    if payload_bytes is None or signature is None:
        return _fail("The key is not valid base64url.")

    if not ed_verify(public_key or LICENSE_PUBLIC_KEY, payload_bytes, signature):
        return _fail("The signature does not verify. This key was not issued for containment-cut.")

    try:
        payload = json.loads(payload_bytes.decode("utf-8"))
    except Exception:
        return _fail("The signed payload is not valid JSON.")
    if not isinstance(payload, dict):
        return _fail("The signed payload is not an object.")

    moment = now if now is not None else int(time.time())
    exp = payload.get("exp")
    if isinstance(exp, int) and moment > exp:
        return VerifyResult(False, payload, "The license expired.")
    return VerifyResult(True, payload, None)
