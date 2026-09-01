"""The embedded Ed25519 public key that license keys are verified against.

Public by design -- it can only *verify* a signature, never create one. The matching
private key lives with the project owner, is generated into `.secrets/` (gitignored) and
never ships. Anyone can read, fork and run every feature of the free tool; a license key
only switches on the additive Pro surface described in `docs/pro.md`. Signing is not here
to lock the tool down. It is here so the owner can issue keys the tool trusts *offline*,
with no phone-home and no account.
"""

import base64

LICENSE_PUBLIC_KEY_B64 = "tT4CLudgDL4cYeZJyuDDwADygu+g5XUb2a2a7Zg92Fg="
LICENSE_PUBLIC_KEY: bytes = base64.b64decode(LICENSE_PUBLIC_KEY_B64)

PRO_FEATURES: tuple[str, ...] = ("live-import", "gated-execute", "multi-objective")
"""Kept small and additive. Nothing in the free tool is removed to make room for these."""
