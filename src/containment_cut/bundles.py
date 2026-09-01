"""The hard case: when one action destroys several graph elements at once.

WHERE THE POLYNOMIAL CASE ENDS
------------------------------
`cut.min_cut` is exact because each element carries its own price, so the cost of a cut
is the *sum* over the elements it contains. Real containment breaks that additivity.
"Block this application" removes the service principal **and** every permission edge
hanging off it, for one price. Pay once, cut many.

Once actions map to arbitrary subsets of elements, choosing the cheapest family of
actions whose union is an s-t cut is no longer a flow problem. It is a covering problem,
and it is NP-hard: Set Cover reduces to it. (Take a Set Cover instance, build a graph
with one parallel s->t edge per element and one action per set; a family of actions cuts
s from t exactly when the corresponding sets cover the universe.) The special case where
each action is a *label* on edges is the Minimum Label s-t Cut problem, also NP-hard.

WHAT WE DO INSTEAD, AND WHAT IT IS WORTH
----------------------------------------
Constraint generation against a greedy set cover.

    C <- {}                            # a family of S->T paths, each a covering constraint
    loop:
        A <- greedy weighted set cover of C using the available actions
        if removing A's elements disconnects S from T:  return A
        else: add a surviving S->T path to C and repeat

**Guarantee.** Let d be the largest number of constraints in C that any single action
covers, and H(d) = 1 + 1/2 + ... + 1/d <= 1 + ln d. Then

        cost(returned plan)  <=  H(d) * OPT

*Proof.* Every element of every S->T path is a candidate for removal, so any feasible
containment plan for the full problem must hit every S->T path -- in particular every
path in C. So every full-problem solution is feasible for the covering instance C, hence
OPT(C) <= OPT(full). Chvatal's analysis of greedy weighted set cover gives
cost(greedy on C) <= H(d) * OPT(C). Chain them: cost(greedy) <= H(d) * OPT(full). The
loop only returns when the plan is a genuine cut, so it is feasible for the full problem
as well. QED.

    V. Chvatal, "A Greedy Heuristic for the Set-Covering Problem", Mathematics of
    Operations Research 4(3):233-235, 1979. (Unweighted: D. S. Johnson 1974,
    L. Lovasz 1975.)

The bound is reported per run with the d actually observed, not as a slogan. On the
tenants we ship it is usually much better than the bound, and the lower bound below
usually proves it.

**A lower bound, so the gap is a measured number and not a hope.**
Give each element e the capacity min over actions a containing e of cost(a)/|elements(a)|
and compute the exact min cut with those capacities (rationals -- no floats, because a
bound you have to round is not a bound). Call it L. Then L <= OPT.

*Proof.* Let A* be an optimal plan and U its removed elements; U is an s-t cut, so
L <= capacity(U) = sum over e in U of cap(e). Each e in U lies in some a in A*, so
cap(e) <= cost(a)/|elements(a)|. Summing over U and grouping by action, each a in A*
contributes at most |elements(a)| terms of size at most cost(a)/|elements(a)|, i.e. at
most cost(a). Hence capacity(U) <= sum over A* of cost(a) = OPT. QED.

So every bundled run reports: plan cost, the proven ceiling H(d)*OPT, and L -- and
`cost/L` is a certified optimality gap for that instance.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from fractions import Fraction
from typing import Iterable, Sequence

from .cut import STATUS_CONTAINED, STATUS_CUT_FOUND, STATUS_NO_CUT, Element, min_cut
from .model import Action, EdgeKey, TenantGraph

MAX_ROUNDS = 10_000
"""Hard stop for the constraint loop. Reaching it is reported as an explicit failure,
never as a plan -- a containment tool that quietly returns a partial answer is worse
than one that returns nothing."""


@dataclass(slots=True)
class BundledResult:
    status: str
    actions: tuple[Action, ...]
    cost: int
    lower_bound: Fraction
    approximation_bound: Fraction  # H(d)
    max_set_size: int              # d
    rounds: int
    constraints: int

    @property
    def certified_gap(self) -> Fraction:
        """cost / lower_bound. 1 means "provably optimal for this instance"."""
        if self.lower_bound <= 0:
            return Fraction(0)
        return Fraction(self.cost) / self.lower_bound


def harmonic(n: int) -> Fraction:
    """H(n) = sum_{i=1..n} 1/i, exactly. Used to state the bound, so: no floats."""
    total = Fraction(0)
    for i in range(1, n + 1):
        total += Fraction(1, i)
    return total


def has_bundles(actions: Iterable[Action]) -> bool:
    return any(a.is_bundle for a in actions)


def _first_path(
    graph: TenantGraph, removed_nodes: frozenset[str], removed_edges: frozenset[EdgeKey]
) -> list[Element] | None:
    """A shortest surviving path from the compromised set to a crown jewel.

    Returned as the list of *elements* along it (nodes and edges alike), because the
    covering constraint is "destroy at least one of these". Shortest-first is deliberate:
    short paths are tight constraints and cut the search down fastest.
    """
    jewels = set(graph.crown_jewels)
    succ = graph.successors()
    starts = [s for s in graph.compromised if s not in removed_nodes]
    parent: dict[str, tuple[str, EdgeKey] | None] = {s: None for s in starts}
    queue = list(starts)
    goal: str | None = None
    while queue and goal is None:
        nxt: list[str] = []
        for u in queue:
            if u in jewels:
                goal = u
                break
            for e in succ[u]:
                if e.key in removed_edges or e.target in removed_nodes or e.target in parent:
                    continue
                parent[e.target] = (u, e.key)
                nxt.append(e.target)
        queue = nxt
    if goal is None:
        return None

    elements: list[Element] = [goal]
    cur = goal
    while parent[cur] is not None:
        prev, key = parent[cur]  # type: ignore[misc]
        elements.append(key)
        elements.append(prev)
        cur = prev
    return elements


def _greedy_set_cover(
    constraints: Sequence[frozenset[int]], actions: Sequence[Action], covers: Sequence[frozenset[int]]
) -> list[Action] | None:
    """Weighted greedy: repeatedly take the action with the best cost-per-newly-covered.

    `covers[i]` is the set of constraint indices action i hits. Returns None when the
    remaining constraints cannot all be covered (the instance is infeasible).
    """
    uncovered = set(range(len(constraints)))
    chosen: list[Action] = []
    used: set[int] = set()
    while uncovered:
        best_i = -1
        best_ratio: Fraction | None = None
        best_new = 0
        for i, cover in enumerate(covers):
            if i in used:
                continue
            new = len(cover & uncovered)
            if new == 0:
                continue
            # cost 0 actions are free wins; give them a ratio of 0 and prefer the one
            # covering most, which the tie-break below does.
            ratio = Fraction(actions[i].cost, new)
            if best_ratio is None or ratio < best_ratio or (ratio == best_ratio and new > best_new):
                best_ratio, best_i, best_new = ratio, i, new
        if best_i < 0:
            return None
        used.add(best_i)
        chosen.append(actions[best_i])
        uncovered -= covers[best_i]
    return chosen


def solve_bundled(graph: TenantGraph, max_rounds: int = MAX_ROUNDS) -> BundledResult:
    """Constraint generation + greedy set cover, with the bound and the lower bound."""
    if not graph.exposed_jewels():
        return BundledResult(
            status=STATUS_CONTAINED,
            actions=(),
            cost=0,
            lower_bound=Fraction(0),
            approximation_bound=Fraction(1),
            max_set_size=0,
            rounds=0,
            constraints=0,
        )

    actions = list(graph.actions)
    lower = lower_bound(graph)

    constraints: list[frozenset[Element]] = []
    rounds = 0
    while rounds < max_rounds:
        rounds += 1
        # Which constraints does each action hit?
        covers = [
            frozenset(j for j, c in enumerate(constraints) if a.elements & c) for a in actions
        ]
        chosen = _greedy_set_cover(constraints, actions, covers) if constraints else []
        if chosen is None:
            return BundledResult(
                status=STATUS_NO_CUT,
                actions=(),
                cost=0,
                lower_bound=lower,
                approximation_bound=Fraction(1),
                max_set_size=0,
                rounds=rounds,
                constraints=len(constraints),
            )

        removed_nodes = frozenset(n for a in chosen for n in a.removes_nodes)
        removed_edges = frozenset(k for a in chosen for k in a.removes_edges)
        path = _first_path(graph, removed_nodes, removed_edges)
        if path is None:
            d = max((len(c) for c in covers), default=0)
            return BundledResult(
                status=STATUS_CUT_FOUND,
                actions=tuple(chosen),
                cost=sum(a.cost for a in chosen),
                lower_bound=lower,
                approximation_bound=harmonic(d) if d else Fraction(1),
                max_set_size=d,
                rounds=rounds,
                constraints=len(constraints),
            )
        constraints.append(frozenset(path))

    raise RuntimeError(
        f"constraint generation did not converge in {max_rounds} rounds; "
        "no plan is returned rather than an unverified one"
    )


def lower_bound(graph: TenantGraph) -> Fraction:
    """L <= OPT for the bundled problem. See the module docstring for the proof."""
    cost_of: dict[Element, Fraction] = {}
    for action in graph.actions:
        elements = action.elements
        if not elements:
            continue
        share = Fraction(action.cost, len(elements))
        for element in elements:
            if element not in cost_of or share < cost_of[element]:
                cost_of[element] = share
    result = min_cut(graph, cost_of, zero=Fraction(0))
    if result.status == STATUS_NO_CUT:
        return Fraction(0)
    return Fraction(result.cost)
