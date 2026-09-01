"""Ed25519 signature *verification* in pure Python. No signing, no dependency.

WHY THIS EXISTS: a tool you run during an incident should not pull a compiled crypto
stack into the room just to check a license file. Verification is exponentiation in a
finite field; the whole of it is below, it has no state, no network and no I/O, and it
imports only hashlib from the standard library.

This follows the reference implementation in RFC 8032 (Edwards-Curve Digital Signature
Algorithm), section 6, using extended homogeneous coordinates (X, Y, Z, T) so that a
verification costs milliseconds rather than seconds. `tests/test_ed25519.py` checks it
against `cryptography`'s libsodium-backed implementation on random keys and messages,
including tampered signatures, because an implementation that only ever says "valid" is
indistinguishable from one that works until the day it matters.

SCOPE: this verifies. It cannot sign, and there is no private-key code anywhere in the
shipped package -- minting keys lives in scripts/mint_license.py, which is owner-only and
uses a real crypto library.
"""

from __future__ import annotations

import hashlib

# Curve25519 field and group parameters (RFC 8032, section 5.1).
P = 2**255 - 19
Q = 2**252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
MODP_SQRT_M1 = pow(2, (P - 1) // 4, P)


def _sha512_int(data: bytes) -> int:
    return int.from_bytes(hashlib.sha512(data).digest(), "little")


def _point_add(pt1, pt2):
    a = (pt1[1] - pt1[0]) * (pt2[1] - pt2[0]) % P
    b = (pt1[1] + pt1[0]) * (pt2[1] + pt2[0]) % P
    c = 2 * pt1[3] * pt2[3] * D % P
    dd = 2 * pt1[2] * pt2[2] % P
    e, f, g, h = b - a, dd - c, dd + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _point_mul(scalar: int, point):
    out = (0, 1, 1, 0)  # neutral element
    while scalar > 0:
        if scalar & 1:
            out = _point_add(out, point)
        point = _point_add(point, point)
        scalar >>= 1
    return out


def _point_equal(pt1, pt2) -> bool:
    if (pt1[0] * pt2[2] - pt2[0] * pt1[2]) % P != 0:
        return False
    return (pt1[1] * pt2[2] - pt2[1] * pt1[2]) % P == 0


def _recover_x(y: int, sign: int) -> int | None:
    if y >= P:
        return None
    x2 = (y * y - 1) * pow(D * y * y + 1, P - 2, P) % P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * MODP_SQRT_M1 % P
    if (x * x - x2) % P != 0:
        return None
    if (x & 1) != sign:
        x = P - x
    return x


_G_Y = 4 * pow(5, P - 2, P) % P
_G_X = _recover_x(_G_Y, 0)
G = (_G_X, _G_Y, 1, _G_X * _G_Y % P)


def _decompress(comp: bytes):
    if len(comp) != 32:
        return None
    y = int.from_bytes(comp, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % P)


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """True iff `signature` is a valid Ed25519 signature of `message` under `public_key`."""
    if len(public_key) != 32 or len(signature) != 64:
        return False
    a = _decompress(public_key)
    if a is None:
        return False
    r = _decompress(signature[:32])
    if r is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= Q:
        # Non-canonical scalar: reject rather than reduce. Malleable signatures are how
        # "verified" turns into "verified something else".
        return False
    h = _sha512_int(signature[:32] + public_key + message) % Q
    left = _point_mul(s, G)
    right = _point_add(r, _point_mul(h, a))
    return _point_equal(left, right)
