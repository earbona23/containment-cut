"""Our pure-Python Ed25519 against a real crypto library, on random keys and messages.

An implementation that only ever sees valid signatures is indistinguishable from one
that returns True. Half of these cases are supposed to fail.
"""

from __future__ import annotations

import os
import random

import pytest

from containment_cut.license.ed25519 import verify

REQUIRED = os.environ.get("CONTAINMENT_CUT_REQUIRE_DIFFERENTIAL") == "1"

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except ImportError:  # pragma: no cover
    Ed25519PrivateKey = None

if Ed25519PrivateKey is None:
    if REQUIRED:
        raise RuntimeError("CONTAINMENT_CUT_REQUIRE_DIFFERENTIAL=1 but `cryptography` is missing")
    pytestmark = pytest.mark.skip(reason="cryptography not installed")


def keypair():
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return private, public


@pytest.mark.differential
@pytest.mark.parametrize("seed", range(20))
def test_accepts_what_the_library_signed(seed):
    rng = random.Random(seed)
    private, public = keypair()
    message = bytes(rng.randrange(256) for _ in range(rng.randint(0, 200)))
    assert verify(public, message, private.sign(message))


@pytest.mark.differential
@pytest.mark.parametrize("seed", range(20))
def test_rejects_a_flipped_bit_in_the_signature(seed):
    rng = random.Random(1000 + seed)
    private, public = keypair()
    message = b"containment-cut license payload"
    signature = bytearray(private.sign(message))
    index = rng.randrange(len(signature))
    signature[index] ^= 1 << rng.randrange(8)
    assert not verify(public, message, bytes(signature))


@pytest.mark.differential
@pytest.mark.parametrize("seed", range(10))
def test_rejects_a_changed_message(seed):
    private, public = keypair()
    signature = private.sign(b"plan=pro")
    assert not verify(public, b"plan=enterprise", signature)


@pytest.mark.differential
def test_rejects_a_signature_from_a_different_key():
    private_a, _ = keypair()
    _, public_b = keypair()
    message = b"hello"
    assert not verify(public_b, message, private_a.sign(message))


def test_rejects_malformed_inputs():
    assert not verify(b"", b"m", b"\x00" * 64)
    assert not verify(b"\x00" * 32, b"m", b"\x00" * 63)
    assert not verify(b"\x00" * 31, b"m", b"\x00" * 64)


def test_rejects_a_non_canonical_scalar():
    """s >= L must be refused, not reduced. Malleability is how 'verified' drifts."""
    from containment_cut.license.ed25519 import Q

    signature = b"\x00" * 32 + (Q + 1).to_bytes(32, "little")
    assert not verify(b"\x00" * 32, b"m", signature)
