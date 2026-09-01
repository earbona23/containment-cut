"""Where an activated license lives, and the one question the rest of the tool asks.

The license is stored in the user's config directory. Activation writes it; every run
re-verifies it from scratch, so an expired or edited file simply stops being Pro. There
is no network call, ever -- not at activation, not at run time.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path

from .keys import PRO_FEATURES
from .verify import verify_license_key


@dataclass(frozen=True, slots=True)
class Entitlement:
    pro: bool
    plan: str | None
    features: tuple[str, ...]
    subject: str | None
    reason: str | None


def license_path() -> Path:
    override = os.environ.get("CONTAINMENT_CUT_CONFIG_DIR")
    if override:
        base = Path(override)
    elif sys.platform == "win32":
        base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return base / "containment-cut" / "license.json"


def activate(key: str) -> dict:
    result = verify_license_key(key)
    if not result.valid:
        raise ValueError(result.reason or "Invalid license key.")
    path = license_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"key": key}, indent=2) + "\n", encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:  # pragma: no cover - Windows and odd filesystems
        pass
    return result.payload or {}


def entitlement(key: str | None = None) -> Entitlement:
    """Re-verified from disk on every call. Absence is a clean 'not Pro', not an error."""
    candidate = key or os.environ.get("CONTAINMENT_CUT_LICENSE_KEY")
    if not candidate:
        try:
            candidate = json.loads(license_path().read_text(encoding="utf-8"))["key"]
        except Exception:
            return Entitlement(False, None, (), None, "No license activated.")
    result = verify_license_key(candidate)
    if not result.valid:
        return Entitlement(False, None, (), None, result.reason)
    payload = result.payload or {}
    features = tuple(payload.get("features") or PRO_FEATURES)
    return Entitlement(True, payload.get("plan", "pro"), features, payload.get("sub"), None)
