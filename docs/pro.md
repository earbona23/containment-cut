# Free vs Pro

> **Pro is not on sale yet.** The live import, gated execution and multi-objective
> features described below are not implemented in any build today: `check_gate` refuses
> even when a valid licence is present, and `run` always raises. A licence bought now
> would switch on nothing, so there is nothing to buy. This notice comes down the day
> the features land — not before.

The algorithm is free. All of it — the exact minimum cut, the certificate, the NP-hard
approximation with its proved bound, every output format, the whole action catalogue.
Nothing has been held back to make room for a paid tier, and nothing in the free build is
crippled to sell the paid one.

What a license buys is the two things that cost *me* ongoing work: talking to live
Microsoft APIs, and doing so safely.

## Free, MIT, forever

| | |
|---|---|
| Exact minimum-cost containment cut | max-flow / min-cut with node splitting |
| Machine-checkable optimality certificate | capacity, conservation, duality, sufficiency |
| Bundled (NP-hard) instances | greedy set cover with a proved `H(d)` bound and a certified lower bound |
| Default action catalogue | 11 action kinds, real Graph / `az` commands |
| Output | terminal, JSON, Markdown, Mermaid |
| Progress curve and baseline comparison | measured, not asserted |
| Demo tenant | ships in the package |
| Runtime dependencies | none |

## Pro

| | |
|---|---|
| **Live import** | Build the graph from a real tenant: Microsoft Graph (users, groups, applications, service principals, ownerships, app-role assignments, delegated grants, directory roles, PIM eligibilities) and Azure Resource Manager (RBAC assignments and scopes). Read-only permissions only. |
| **Gated execution** | Run the plan step by step: explicit `--execute`, an acknowledgement naming the tenant, per-step confirmation showing the command *and its rollback*, a stop on the first non-2xx, and an append-only journal of what was issued and what came back. |
| **Multi-objective** | Optimise cost *and* time-to-effect *and* reversibility together, and get the Pareto frontier instead of one point — "10% more disruption buys you a plan that is entirely reversible" is a decision a responder should be allowed to make. |

Pricing and purchase: see the repository's Sponsors page. A license is a **signed file**,
verified offline with Ed25519. No account, no phone-home, no telemetry. Activation and
every subsequent run are local:

```bash
containment-cut license activate CONTAINMENTCUT-...
containment-cut license status
```

## Why execution is not in the free build

A tool that computes "disable this account" and can also *do* it is one bad argument away
from being an outage generator, and one stolen token away from being an attacker's
favourite utility. The open-source package contains no HTTP client, no credential
handling and no Graph call — there is a test that fails if any module imports one.

The free build prints the exact commands. Run them with your own change control. That is
not a limitation; for most teams it is the correct workflow.
## Pricing

**Not for sale yet — see the notice at the top of this page.** containment-cut Pro is
not currently licensed to anyone, and no licence is issued for it, because the features
a licence would unlock do not exist yet. The figures below are the intended list price
once they do.

Per organisation, unlimited seats. The licence is a signed file, verified offline — no
account, no phone-home.

| | Monthly | Annual (two months free) |
|---|:--:|:--:|
| This tool, Pro | US$29 | US$290 |
| Bundle, once this tool ships (revtriage · EntraTripwire · containment-cut) | US$69 | US$690 |

For revtriage and EntraTripwire, whose Pro features *are* implemented, email
**earbona@arrankago.com** with the name to put on the licence. You get the
key by return email, usually the same day.
