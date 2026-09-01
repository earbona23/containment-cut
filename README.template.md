# containment-cut

[![CI](https://github.com/earbona23/containment-cut/actions/workflows/ci.yml/badge.svg)](https://github.com/earbona23/containment-cut/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-3776AB)](https://www.python.org/downloads/)
[![Licence: MIT](https://img.shields.io/badge/Licence-MIT-blue.svg)](LICENSE)
[![Runtime dependencies: 0](https://img.shields.io/badge/runtime%20deps-0-2f855a)](#safety-posture)
[![Mutation tested](https://img.shields.io/badge/mutation-21%2F21%20killed-2f855a)](#mutation-testing)
[![Proved optimal](https://img.shields.io/badge/every%20plan-ships%20a%20proof-6b46c1)](#2-every-plan-ships-with-a-proof)
[![Dry run](https://img.shields.io/badge/tenant-never%20modified-0f6e6e)](#safety-posture)

**Everyone will tell you your blast radius. Nobody tells you the minimum cut to stop it.**

Attack-path tools map the damage: *from this account, the attacker can reach these 40
things.* Useful — once. Then you are standing in a war room at 3am with a graph, a
business that still has to run, and one question nobody's tool answers:

> **What is the smallest, cheapest set of things I can switch off, right now, that
> provably severs this attacker from the crown jewels?**

`containment-cut` computes exactly that. It takes a tenant graph, a compromised identity
and your crown jewels, and returns the **minimum-cost set of containment actions** that
disconnects one from the other — with the exact Microsoft Graph / Azure CLI call for each
step, in dry-run, and a machine-checkable proof that no cheaper plan exists.

It is the inverse of a blast radius. A blast radius is a reachability query. This is an
optimisation problem, and it has a right answer.

> Piece 3 of the Active Defense Trilogy — **detect** ([entra-tripwire](https://github.com/earbona23/entra-tripwire)) →
> **analyse** ([revtriage](https://github.com/earbona23/revtriage)) → **contain** (this).

---

## 30 seconds

```bash
git clone https://github.com/earbona23/containment-cut && cd containment-cut
pip install -e .            # no runtime dependencies
containment-cut demo
```

*(Not on PyPI yet. `pip install git+https://github.com/earbona23/containment-cut` also
works.)*

The bundled tenant is synthetic: a phished payroll analyst and a client secret an attacker
added to the travel-booking app. Four independent routes reach Global Administrator and
the production payments Key Vault.

{{DEMOBLOCK}}

Read the last three lines again. The reflex — **disable both compromised principals** —
works, and costs 2.4× more, because it locks the sole payroll approver out on the night
the payroll run closes. The *other* reflex, **block all the apps she can reach**, costs
13× more **and does not contain the incident at all**: one of the four routes runs through
a group and an Azure role assignment, with no application anywhere on it.

And step 5 is the interesting one. Removing `RoleManagement.ReadWrite.Directory` from the
Self-Service Portal is nowhere near the breached account. No "what can the victim reach"
heuristic proposes it. It falls out of the cut — and it is a permanent hardening, not just
a containment step.

---

## The graph, and the cut

Round nodes are compromised, hexagons are crown jewels, dashed edges (✂) are the cut.

{{MERMAID}}

---

## How it works

Full write-up with proofs: **[docs/algorithm.md](docs/algorithm.md)**.

An edge `u → v` means *whoever controls `u` can come to control `v`*. Each containment
action destroys graph elements and carries a business-impact cost. Then:

### 1. Node splitting turns "which accounts do I disable" into a flow problem

Cutting *edges* is a textbook minimum s–t cut. Cutting *vertices* becomes the same problem
after one change of variable: split every vertex `v` into `v_in → v_out` joined by an
internal arc whose capacity is the cost of destroying `v`, and re-hang each edge `u → v`
as `u_out → v_in`. Now every path through `v` must cross `v`'s internal arc, so
"disable `v`" *is* "cut that arc", at the same price.

Add a super-source into every compromised vertex and a super-sink out of every crown
jewel, and the **max-flow min-cut theorem** (Ford & Fulkerson 1956; Elias, Feinstein &
Shannon 1956) gives the exact answer. Solved with **Dinic**, `O(|V|²|E|)`, implemented
here rather than imported — because the certificate needs the arc flows, and the lower
bound in §3 needs exact rational arithmetic.

Two asymmetries, both security decisions rather than mathematics:

* the **compromised** vertex's internal arc keeps its finite cost — "disable the breached
  account" must stay a candidate, and a tool that cannot propose the obvious answer cannot
  be trusted with the clever one;
* the **crown jewel**'s is infinite — deleting the asset you are defending is not
  containment.

### 2. Every plan ships with a proof

Weak duality: every s–t flow is at most every s–t cut. So a flow whose value *equals* the
cut's cost proves the cut is minimum. The tool returns that flow, and
`verify_certificate` re-checks it in `O(V+E)` without consulting the solver:

| check | proves |
|---|---|
| `capacity` | `0 ≤ f(a) ≤ c(a)` everywhere |
| `conservation` | flow in = flow out at every interior vertex |
| `duality` | `cost(cut) = \|f\|` → **no cheaper plan exists** |
| `sufficiency` | BFS on the original graph → **this plan actually works** |

The first three prove optimality. The fourth proves correctness. They are different
claims and the tool needs both. If the certificate fails, the CLI exits **4** and says so
at the top of the output — a broken proof must never be mistaken downstream for a good
plan.

### 3. When it is NP-hard, it says so, and bounds it

One action that destroys several elements at once ("block this application" removes the
service principal *and* every permission edge on it, for one price) breaks additivity and
makes the problem NP-hard — Set Cover reduces to it.

The tool switches to **constraint generation over greedy weighted set cover**: repeatedly
solve a covering instance over the S→T paths found so far, check whether the result is a
real cut, and if not add the surviving path as a new constraint.

```
$ containment-cut demo --scenario bundled

MINIMUM CONTAINMENT CUT — 4 actions, cost 170
  APPROXIMATE — bundled actions make this NP-hard. Guarantee: cost <= H(4) · OPT = 2.083 · OPT
  Certified lower bound 170.00 → PROVED OPTIMAL for this instance
```

Same tenant, same graph, a catalogue where "block this application" and "purge her group
memberships in one pass" are single actions. The optimum drops to 170 because the bundle
is cheaper than the pieces — and although the general problem is NP-hard, the lower bound
lands exactly on the plan's cost, so *this* answer is proved optimal anyway.

> **Guarantee: `cost ≤ H(d) · OPT`**, where `d` is the largest number of constraints a
> single action covers and `H(d) = 1 + 1/2 + … + 1/d ≤ 1 + ln d`.

The proof is three lines and it is in [docs/algorithm.md §3](docs/algorithm.md): every
feasible full-problem plan must hit every S→T path, so it is feasible for the generated
covering instance, so `OPT(C) ≤ OPT(full)`; Chvátal's bound for greedy weighted set cover
gives `greedy ≤ H(d)·OPT(C)`; chain them.

> V. Chvátal, *A Greedy Heuristic for the Set-Covering Problem*, Mathematics of
> Operations Research **4**(3):233–235, 1979. (Unweighted: Johnson 1974, Lovász 1975.)

And because a worst-case bound is a poor thing to hand a responder, every bundled run also
reports a **certified lower bound** `L ≤ OPT` — price each element at
`min c(a)/|elem(a)|` and take the exact min cut of §1 with rational capacities — so
`cost / L` is a *measured* optimality gap for your instance. When it equals 1, the plan is
proved optimal even though the general problem is NP-hard.

---

## Scale

`scripts/benchmark.py` builds directory-shaped synthetic tenants (users, groups, apps,
service principals, ownerships, role assignments) and times the whole pipeline: catalogue,
node splitting, max flow, cut extraction, **certificate verification**, ordering and
progress curve. Every run asserts the plan came back proved-optimal.

{{BENCH}}

Wall clock on one laptop, single-threaded, pure Python, no dependencies — absolute numbers
are worth nothing, the *shape* is the point. The theoretical bound is `O(|V|²|E|)`;
directory-shaped graphs sit far below it because the flow value is bounded by the cut cost
rather than by the graph.

---

## Tests

```
{{TESTCOUNT}}
```

* **Exhaustive-search oracle.** `tests/conftest.py` computes the true optimum by
  branch-and-bound over every subset of actions. It shares nothing with the solver — no
  flow, no splitting — it only asks the graph "is a jewel still reachable?". The demo,
  the hand-built cases and every random graph are checked against it.
* **Property-based** (hypothesis): on random layered tenants, the plan disconnects, its
  cost equals the exhaustive optimum, the progress curve is monotone, and **every action
  in the plan is load-bearing** — drop any one and a jewel comes back. That last one is
  the property that catches a cut that is correct but not minimal.
* **Differential**: our Dinic against `networkx` on random networks *and* on the real
  split networks; our pure-Python Ed25519 against `cryptography`, including flipped bits,
  swapped messages and wrong keys. These SKIP if the library is missing — so CI sets
  `CONTAINMENT_CUT_REQUIRE_DIFFERENTIAL=1`, which turns the skip into a hard failure. A
  skipped test looks exactly like a passing one on the summary line, and that is precisely
  how a differential test quietly stops running.
* **Edge cases**: already contained · no cut possible · compromised node that *is* a crown
  jewel · zero-cost actions · cycles · parallel edges · multiple sources and multiple
  targets · a crown jewel the solver could "cheaply" delete.

### Mutation testing

Passing tests are evidence of nothing until you have watched them fail.
`scripts/mutation_test.py` breaks the algorithm on purpose — 21 targeted mutants across
the max-flow, the reduction, the certificate, the approximation, the catalogue, the
command renderer and the CLI's exit codes — and demands the suite notice.

```
{{MUTATION}}
```

The harness asserts each mutation's target text exists **and that the bytes on disk
changed**, because *a mutation that never got applied looks exactly like a mutant that
survived*: the tests pass either way. An unapplied mutation is reported as an ERROR, never
as a kill.

Mutants include: the level-graph BFS walking saturated arcs · the augmenting bottleneck
using `max` instead of `min` · the residual twin arc not being credited · the crown jewel
becoming removable · `∞` off by one · the no-cut boundary being `>` instead of `>=` ·
greedy ignoring coverage · the lower bound not sharing an action's cost across its
elements · the constraint loop returning before the plan is a cut · `removable: false`
being ignored · a missing object id becoming an invented GUID · optimality being claimed
without a certificate · a failed certificate never reaching the process exit code, so a
pipeline gating on exit status ships a plan whose proof did not verify.

Note the one marked **killed (hang)**. Letting the BFS walk saturated arcs does not make
the solver *wrong*, it makes it *never terminate* — and a suite with no time limit cannot
tell "still running" from "passed". The harness caps each run and counts a hang as a kill,
because a suite that never finishes has certainly not passed. Two other things this run
found the hard way: a `timeout` sends `SIGTERM`, which kills CPython **without running
`finally`**, so a killed harness used to leave a mutant in the tree — it now handles the
signal and verifies every target file's SHA-256 against the digest taken before it
started. And `catalog/inherent-relations-become-cuttable` first came back as an ERROR
rather than a kill, because the code had moved underneath it. That distinction is the
whole point.

---

## Using it on your tenant

Write a graph JSON — format and the full relation/action table in
**[docs/graph-format.md](docs/graph-format.md)** — and:

```bash
containment-cut plan --graph tenant.json \
  --compromised u:someone cred:leaked-secret \
  --crown-jewels role:GlobalAdministrator res:kv-prod \
  --format markdown --out plan.md
```

Exit codes, because this belongs in a pipeline:

| code | meaning |
|---|---|
| `0` | a plan was produced, or the compromise is already contained |
| `2` | bad input |
| `3` | **no cut is possible** with the available actions — a route to a jewel is made entirely of things nothing can remove |
| `4` | a plan was produced but its certificate did **not** verify — do not trust it |

Output formats: `text`, `json`, `markdown`, `mermaid`.

---

## Safety posture

* **Dry run, always.** This build computes and prints. It never changes a tenant.
* **No network code at all.** The package contains no HTTP client and no credential
  handling — `tests/test_commands.py` fails if any module imports one.
* **`execute` refuses**, loudly, and prints the plan anyway.
* **Defensive only.** This computes containment. It does not enumerate a tenant, find
  attack paths for you, or exploit anything.
* **Your graph is sensitive.** A tenant graph is a map of how to escalate in your
  directory. `.gitignore` already excludes `*.tenant.json`, `containment-plan-*` and
  `out/`.

Reporting a vulnerability, and what counts as one here: [SECURITY.md](SECURITY.md).

---

## Limitations

An optimality proof is a strong claim, so here is exactly what it does and does not cover.
Read this section before you trust a plan in a real incident.

**The proof is about the graph, not about your tenant.** `containment-cut` proves that no
cheaper plan exists *for the model you gave it*. A relation you did not model is a route it
cannot see, and it will confidently hand you a minimum cut that leaves that route open. The
certificate's `sufficiency` check verifies the plan against the graph — nothing verifies
the graph against reality. Building that graph honestly is the hard part of using this
tool, and [docs/graph-format.md](docs/graph-format.md) is mostly about that.

**The costs are yours, and the answer is only as good as they are.** "Cost" is business
impact you assign to each action. The solver optimises your numbers exactly; if removing a
group membership is priced at 25 when it actually locks out the night shift, you get a plan
that is provably optimal against the wrong objective. Price them before the incident, not
during it.

**Cost is the only objective in this build.** Time-to-effect (a revoked token dies in
minutes, a removed role assignment can take longer to propagate) and reversibility are not
in the optimisation. They are *shown* — irreversible steps are marked — but a human decides
what that is worth.

**It is a snapshot, not a pursuit.** The model assumes a static graph and an attacker who
does not act while you respond. Re-establishment is out of scope: if a dynamic group rule
re-applies a membership you removed, or the attacker still holds a path to mint a new
credential, that is a fact about your graph that you must model (`removable: false`) rather
than something the solver can infer.

**It does not find attack paths for you.** There is no tenant enumeration and no discovery.
You bring the graph; this computes the cut. That is a deliberate boundary — it is a
containment optimiser, not a second BloodHound.

**Bundled actions are NP-hard, and it says so out loud.** With actions that destroy several
elements at once the exact minimum is not computable in polynomial time. You get a proved
`H(d)·OPT` bound plus a certified lower bound, so you always know how far from optimal the
answer *could* be — frequently the gap closes to zero and the plan is proved optimal
anyway, but "approximate" means approximate.

**Nothing is contained until the plan is finished.** A minimum cut is a set, not a
sequence. The ordering exists to close the most exposure earliest, but stopping halfway
leaves a live path — the output says which jewels are still reachable after every step
precisely so that this is impossible to misread.

**Pure Python, single-threaded.** A 40,000-user synthetic tenant solves in about fifteen
seconds — the last row of the benchmark table above, measured on the same run that
produced this file. That is the design envelope; this is not built for million-node graphs.

**It never touches your tenant.** The open-source build has no network code at all. It
prints the commands; you run them, under your own change control.

## Free vs Pro

The algorithm is free. All of it. Nothing was held back to make room for a paid tier.

| | Free (MIT) | Pro |
|---|:---:|:---:|
| Exact minimum-cost cut + optimality certificate | ✅ | ✅ |
| NP-hard case with proved bound + certified gap | ✅ | ✅ |
| Full action catalogue, real Graph / `az` commands | ✅ | ✅ |
| Terminal / JSON / Markdown / Mermaid output | ✅ | ✅ |
| Runtime dependencies | none | none |
| **Live import** from Microsoft Graph + Azure RM (read-only) | — | ✅ |
| **Gated execution**: per-step confirmation, rollback shown, stop on first failure, append-only journal | — | ✅ |
| **Multi-objective**: cost × time-to-effect × reversibility, Pareto frontier | — | ✅ |

Licenses are a signed file verified **offline** with Ed25519 — no account, no phone-home,
no telemetry. Details in [docs/pro.md](docs/pro.md).

```bash
containment-cut license activate CONTAINMENTCUT-...
containment-cut license status
```

**Support the work:** [GitHub Sponsors](https://github.com/sponsors/earbona23) ·
[Patreon](https://www.patreon.com/EduardArbona) · or buy a Pro license.

---

## The trilogy

| | | |
|---|---|---|
| **Detect** | [entra-tripwire](https://github.com/earbona23/entra-tripwire) | catches the identity attack as it happens |
| **Analyse** | [revtriage](https://github.com/earbona23/revtriage) | works out what it means |
| **Contain** | **containment-cut** | computes the cheapest way to stop it |

---

## License

MIT. See [LICENSE](LICENSE).

---

<sub><b>Every number above was measured, not typed.</b> `README.md` is assembled from
`README.template.md` by `scripts/build_readme.py`, which produces each block by
<i>running the tool</i>: the demo output, the graph diagram, the benchmark table, the test
count and the mutation score are captured from real runs on the current source. The
generator refuses to write a README that claims a green suite or a clean mutation run
which did not happen — so this file cannot drift ahead of the code, and a broken build
cannot ship a README that says otherwise. Edit the template, never `README.md`.</sub>
