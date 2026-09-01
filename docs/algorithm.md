# The algorithm

Two problems live in this tool. One is polynomial and solved exactly, with a proof
attached to every answer. The other is NP-hard and solved approximately, with a stated
bound and a measured gap. Which one you are in is decided by a single property of your
action catalogue, and the tool tells you which.

---

## 1. The model

A tenant is a directed graph `G = (V, E)`.

* **Vertices** are identities, groups, applications, service principals, credentials,
  roles, permissions and resources.
* **An edge `u → v` means: whoever controls `u` can, without further help, come to
  control `v`.** Not "is related to". Not "can read". Control, or a step mechanically
  sufficient to obtain it.

That definition is the load-bearing part. It is what makes *reachability* mean "the
attacker gets there", and therefore what makes a *graph cut* mean "the attacker does not".

The edge people forget is ownership. An owner of an app registration can add a client
secret to it and then authenticate as its service principal, inheriting every permission
that principal holds. So `user --owns--> application` is a control edge, and *removing an
owner* is a containment action — one that appears in almost no incident runbook.

The other subtlety is credentials. A stolen client secret is **its own vertex**:

```
credential --authenticatesAs--> servicePrincipal
```

Rotating the secret destroys the credential vertex. It does *not* destroy the service
principal, and it does nothing to whoever can mint a new secret — that is a different
edge, and it must be cut separately. Modelling rotation as "remove the service principal"
would make the solver believe a lie and produce a plan that leaves the attacker in.

### Actions

A **containment action** `a` has a cost `c(a) ∈ ℤ≥0` (business impact, integers so that
comparisons are decisions and not rounding questions) and destroys a set of graph
elements `elem(a) ⊆ V ∪ E`.

An action is **atomic** when `|elem(a)| = 1` and **bundled** otherwise.

### The problem

> Given compromised vertices `S`, crown jewels `T`, and a catalogue of actions,
> find a minimum-cost set of actions `A` such that removing `⋃ elem(a)` leaves no
> directed path from `S` to `T`.

---

## 2. The atomic case: exact, polynomial, certified

When every action is atomic, price each element at the cheapest action that destroys it:
`w(e) = min { c(a) : elem(a) = {e} }`, and `w(e) = ∞` when nothing destroys it. The cost
of a set of elements is now additive, and the problem is a minimum-cost **mixed
node/edge cut**.

### Node splitting

Cutting edges is the textbook minimum s–t cut. Cutting *vertices* becomes the same
problem after one change of variable. Replace each vertex `v` by `v_in` and `v_out`:

```
v_in ──[ w(v) ]──> v_out            (one internal arc per vertex)
u_out ──[ w(u,v) ]──> v_in          (each original edge, re-hung)
```

Every path through `v` must traverse `v`'s internal arc, so "delete vertex `v`" and "cut
arc `(v_in, v_out)`" are the same act at the same price.

Then add a super-source `s*` with `∞` arcs into `v_in` for every `v ∈ S`, and `∞` arcs
from `t_out` to a super-sink `t*` for every `t ∈ T`.

Two asymmetries, both security decisions rather than mathematics:

| Vertex | Internal capacity | Why |
|---|---|---|
| compromised | its finite cost | "Disable the breached account" must stay a candidate. A tool that cannot propose the obvious answer cannot be trusted with the clever one. |
| crown jewel | `∞` | Deleting the asset you are defending is not containment. |

`∞` is not a float. It is `1 + Σ (finite capacities)`, which is strictly larger than any
finite cut, so a finite cut is always preferred when one exists — and a max-flow value
that *reaches* `∞` is a proof that none does.

### Correctness

By the **max-flow min-cut theorem** (Ford & Fulkerson 1956; Elias, Feinstein & Shannon
1956), the minimum s\*–t\* cut in the split network equals the maximum s\*–t\* flow, and
the arcs from the residual-reachable set of `s*` to its complement form such a cut.
Mapping those arcs back through the splitting gives a minimum-cost mixed node/edge cut
in `G`. **This is exact. There is no approximation in this path.**

### Complexity

Max flow by **Dinic (1970)**: at most `|V| − 1` phases (the shortest augmenting-path
length strictly increases each phase), each phase a blocking flow in `O(|V||E|)` with the
current-arc optimisation. Total **`O(|V|² |E|)`**, independent of the capacities — so
termination does not depend on the costs being integers, and rational capacities work
unchanged (used in §3).

The split network has `2|V| + 2` vertices and `|V| + |E| + |S| + |T|` arcs, so the bound
in terms of the tenant is `O(|V|² (|V| + |E|))`. Measured growth is in the README; on
directory-shaped graphs it is far below the worst case, because the flow value is bounded
by the cut cost rather than by the graph size.

### The certificate

Every answer ships with the arc flows, and `verify_certificate` re-checks four things
without consulting the solver:

1. **capacity** — `0 ≤ f(a) ≤ c(a)` on every arc;
2. **conservation** — inflow equals outflow at every interior vertex;
3. **duality** — `cost(cut) = |f|`. Every s–t flow is at most every s–t cut
   (weak duality), so a cut whose cost equals a *feasible* flow's value is minimum.
   **This is the optimality proof;**
4. **sufficiency** — deleting the cut really does leave no crown jewel reachable,
   checked on the original graph by plain BFS.

Checks 1–3 prove *no cheaper plan exists*. Check 4 proves *this plan works*. They are
different claims and the tool needs both. A verifier that shared the solver's reasoning
would verify nothing, so this one only reads numbers.

---

## 3. The bundled case: NP-hard, approximated, bounded

One action that destroys several elements breaks additivity. "Block this application"
removes the service principal *and* every permission edge hanging off it, for one price.
Pay once, cut many.

### Hardness

Choosing the cheapest family of actions whose union is an s–t cut is NP-hard. Set Cover
reduces to it: given a universe `U` and sets `S₁…S_m`, build a graph with one parallel
`s → t` edge per element of `U` and one action per `S_j` removing exactly the edges of
its elements. A family of actions is a cut iff the corresponding sets cover `U`. The
special case where actions are labels on edges is the **Minimum Label s–t Cut** problem,
also NP-hard.

### What the tool does

Constraint generation against a greedy weighted set cover:

```
C ← ∅                                  # a family of S→T paths, each a covering constraint
loop:
    A ← greedy weighted set cover of C using the available actions
    if removing ⋃ elem(A) disconnects S from T:  return A
    else:  add a surviving S→T path to C and repeat
```

Paths are added shortest-first: short paths are tight constraints and shrink the search
fastest.

### The guarantee

Let `d` be the largest number of constraints in `C` that any single action covers, and
`H(d) = 1 + 1/2 + … + 1/d ≤ 1 + ln d`. Then

> **cost(returned plan) ≤ H(d) · OPT**

**Proof.** Every element of every S→T path is a candidate for removal, so any feasible
containment plan for the full problem must hit every S→T path — in particular, every path
in `C`. Hence every full-problem solution is feasible for the covering instance `C`, so
`OPT(C) ≤ OPT(full)`. Chvátal's analysis of greedy weighted set cover gives
`cost(greedy on C) ≤ H(d) · OPT(C)`. Chaining, `cost(greedy) ≤ H(d) · OPT(full)`. The
loop returns only when the plan is a genuine cut, so it is feasible for the full problem
too. ∎

> V. Chvátal, *A Greedy Heuristic for the Set-Covering Problem*, Mathematics of
> Operations Research **4**(3):233–235, 1979.
> Unweighted case: D. S. Johnson (1974), L. Lovász (1975).

`d` is reported per run, with the observed value — not as a slogan.

### A lower bound, so the gap is measured

Give each element `e` the capacity

```
cap(e) = min over actions a ∋ e of   c(a) / |elem(a)|
```

and compute the exact minimum cut of §2 with those capacities. Rationals, not floats — a
bound you have to round is not a bound. Call the result `L`.

> **L ≤ OPT**

**Proof.** Let `A*` be optimal and `U = ⋃_{a ∈ A*} elem(a)`. `U` is an s–t cut, so
`L ≤ cap(U) = Σ_{e ∈ U} cap(e)`. Each `e ∈ U` lies in some `a ∈ A*`, so
`cap(e) ≤ c(a)/|elem(a)|`. Grouping the sum by action, each `a ∈ A*` contributes at most
`|elem(a)|` terms of size at most `c(a)/|elem(a)|`, i.e. at most `c(a)`. Hence
`cap(U) ≤ Σ_{a ∈ A*} c(a) = OPT`. ∎

So every bundled run reports the plan's cost, the proven ceiling `H(d)·OPT`, and `L` —
and `cost / L` is a **certified optimality gap for that instance**. When it equals 1, the
plan is proved optimal even though the general problem is NP-hard.

### Termination

Each round adds a distinct simple path, so the loop terminates. `MAX_ROUNDS` is a hard
stop; reaching it raises rather than returning a plan. An unverified containment plan is
worse than no plan.

---

## 4. What is a heuristic here, and labelled as one

The **order** of the steps. Credential rotation and grant revocation first (fast to take
effect, low blast radius), then assignment and membership removals, then account and
application disablement. This changes nothing mathematically — the set and the cost are
fixed by the solver — and the plan says so.

What is *not* a heuristic is the **progress curve**: after each step the tool re-runs
reachability and reports which crown jewels are still exposed. That number is measured.
It is usually flat until the final step, and that flatness is the most useful line on the
page: it says the plan is atomic, and stopping halfway contains nothing.
