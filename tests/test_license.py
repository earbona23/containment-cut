"""License verification and storage. Offline, fail-closed, and never a network call."""

from __future__ import annotations

import base64
import json
import subprocess
import sys
from pathlib import Path

import pytest

from containment_cut.license import activate, entitlement, license_path, verify_license_key
from containment_cut.license.keys import LICENSE_PUBLIC_KEY

ROOT = Path(__file__).resolve().parents[1]
SIGNING_KEY = ROOT / ".secrets" / "license-signing-key.pem"

needs_key = pytest.mark.skipif(
    not SIGNING_KEY.exists(), reason="owner-only signing key not present (expected on CI)"
)


def mint(*args: str) -> str:
    out = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "mint_license.py"), *args],
        capture_output=True, text=True, cwd=ROOT, check=True,
    )
    return out.stdout.strip()


def test_garbage_is_rejected_with_a_reason():
    for key in ["", "nope", "CONTAINMENTCUT-nodot", "CONTAINMENTCUT-!!!.???"]:
        result = verify_license_key(key)
        assert not result.valid
        assert result.reason


def test_a_forged_key_does_not_verify():
    payload = base64.urlsafe_b64encode(json.dumps({"sub": "me", "plan": "enterprise"}).encode()).decode().rstrip("=")
    forged = f"CONTAINMENTCUT-{payload}.{'A' * 86}"
    assert not verify_license_key(forged).valid


def test_public_key_is_32_raw_bytes():
    assert len(LICENSE_PUBLIC_KEY) == 32


@needs_key
def test_minted_key_verifies_and_carries_its_payload():
    key = mint("--sub", "Test User", "--plan", "team", "--days", "30")
    result = verify_license_key(key)
    assert result.valid
    assert result.payload["sub"] == "Test User"
    assert result.payload["plan"] == "team"


@needs_key
def test_expiry_is_enforced_against_the_clock():
    key = mint("--sub", "Test User", "--days", "1")
    payload = verify_license_key(key).payload
    assert verify_license_key(key, now=payload["exp"] - 1).valid
    late = verify_license_key(key, now=payload["exp"] + 1)
    assert not late.valid
    assert late.reason == "The license expired."


@needs_key
def test_tampering_with_the_payload_invalidates_the_key():
    key = mint("--sub", "Test User", "--plan", "pro")
    body = key.split("-", 1)[1]
    payload_b64, signature = body.split(".", 1)
    raw = base64.urlsafe_b64decode(payload_b64 + "=" * (-len(payload_b64) % 4))
    upgraded = raw.replace(b'"pro"', b'"ent"')
    new_b64 = base64.urlsafe_b64encode(upgraded).decode().rstrip("=")
    assert not verify_license_key(f"CONTAINMENTCUT-{new_b64}.{signature}").valid


@needs_key
def test_activation_round_trips_through_the_config_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("CONTAINMENT_CUT_CONFIG_DIR", str(tmp_path))
    monkeypatch.delenv("CONTAINMENT_CUT_LICENSE_KEY", raising=False)
    assert not entitlement().pro
    key = mint("--sub", "Round Trip", "--plan", "pro")
    activate(key)
    assert license_path().parent == tmp_path / "containment-cut"
    ent = entitlement()
    assert ent.pro and ent.subject == "Round Trip"


def test_activation_refuses_to_store_an_invalid_key(tmp_path, monkeypatch):
    monkeypatch.setenv("CONTAINMENT_CUT_CONFIG_DIR", str(tmp_path))
    with pytest.raises(ValueError):
        activate("CONTAINMENTCUT-junk.junk")
    assert not license_path().exists()


def test_no_license_is_a_clean_no_not_an_error(tmp_path, monkeypatch):
    monkeypatch.setenv("CONTAINMENT_CUT_CONFIG_DIR", str(tmp_path))
    monkeypatch.delenv("CONTAINMENT_CUT_LICENSE_KEY", raising=False)
    ent = entitlement()
    assert ent.pro is False and ent.reason == "No license activated."


def test_signing_key_is_not_in_the_shipped_package():
    import containment_cut

    package = Path(containment_cut.__file__).parent
    assert not list(package.rglob("*.pem"))
    text = "\n".join(p.read_text(encoding="utf-8") for p in package.rglob("*.py"))
    assert "PRIVATE KEY" not in text
