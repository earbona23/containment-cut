# Security

## Reporting

Open a private security advisory on the repository. Please do not file a public issue for
a vulnerability.

## What this tool is, in security terms

* **It is defensive.** It computes the cheapest way to *cut* an attacker off. It does not
  find attack paths for you, does not enumerate a tenant, and does not exploit anything.
* **It has no runtime dependencies.** Nothing is pulled into the room when you run it.
* **It makes no network calls.** The open-source package contains no HTTP client and no
  credential handling; `tests/test_commands.py` fails if any module imports one.
* **It changes nothing.** Every run is a dry run. `execute` refuses, always, in this
  build.

## What a graph file contains

A tenant graph names principals, applications, role assignments and the routes between
them. That is a map of how to escalate in your directory. Treat the file, and any plan
generated from it, as **confidential**. The `.gitignore` already excludes
`*.tenant.json`, `containment-plan-*` and `out/` for that reason.

## Licensing keys

License keys are Ed25519-signed and verified offline. The public key is embedded and can
only verify. The private signing key is generated into `.secrets/`, which is gitignored,
and never ships. Verification is pure Python (`license/ed25519.py`), checked against
`cryptography` in the test suite, and rejects non-canonical scalars rather than reducing
them.
