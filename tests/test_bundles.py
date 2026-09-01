"""The NP-hard case: bundled actions, the approximation bound, and the lower bound.

Every claim the module docstring makes is checked here against exhaustive search, on
instances small enough that the true optimum is knowable.
"""

from __future__ import annotations

import random
from fractions import Fraction

import pytest

from containment_cut.bundles import harmonic, has_bundles, lower_bound, solve_bundled
from containment_cut.cut import STATUS_CUT_FOUND, STATUS_NO_CUT
from containment_cut.model import Action, Edge, Node, TenantGraph
from containment_cut.plan import METHOD_GREEDY, solve
from conftest import brute_force_min_cost, random_layered_graph


def parallel_paths(count: int, edge_cost: int, bundle_cost: int | None) -> TenantGraph:
    """s -> m_i -> t for i in 0..count-1. Optionally one action that cuts all of them."""
    nodes = {"s": Node("s", "user"), "t": Node("t", "resource")}
    edges: list[Edge] = []
    actions: list[Action] = []
    for i in range(count):
        mid = f"m{i}"
        nodes[mid] = Node(mid, "user")
        e1 = Edge("s", mid, "c")
        e2 = Edge(mid, "t", "c")
        edges += [e1, e2]
        actions.append(
            Action(id=f"cut{i}", kind="remove_group_member", cost=edge_cost,
                   title=f"cut {i}", removes_edges=frozenset({e1.key}))
        )
    if bundle_cost is not None:
        actions.append(
            Action(id="bundle", kind="disable_service_principal", cost=bundle_cost,
                   title="one action, every path",
                   removes_edges=frozenset(e.key for e in edges if e.source == "s"))
        )
    graph = TenantGraph(nodes=nodes, edges=edges, actions=actions,
                        compromised=("s",), crown_jewels=("t",))
    graph.validate()
    return graph


def test_harmonic_is_exact():
    assert harmonic(1) == Fraction(1)
    assert harmonic(3) == Fraction(11, 6)
    assert harmonic(0) == Fraction(0)


def test_has_bundles_detects_the_hard_case():
    assert not has_bundles(parallel_paths(3, 10, None).actions)
    assert has_bundles(parallel_paths(3, 10, 25).actions)


def test_bundle_wins_when_it_is_cheaper():
    graph = parallel_paths(5, 10, 25)  # five singles at 10, or one bundle at 25
    result = solve_bundled(graph)
    assert result.status == STATUS_CUT_FOUND
    assert result.cost == 25
    assert [a.id for a in result.actions] == ["bundle"]
    optimum, _ = brute_force_min_cost(graph)
    assert optimum == 25


def test_singles_win_when_the_bundle_is_overpriced():
    graph = parallel_paths(3, 4, 99)
    result = solve_bundled(graph)
    assert result.cost == 12
    assert brute_force_min_cost(graph)[0] == 12


def test_lower_bound_never_exceeds_the_true_optimum():
    for count, edge_cost, bundle_cost in [(2, 10, 15), (4, 7, 20), (5, 3, 40), (6, 9, 31)]:
        graph = parallel_paths(count, edge_cost, bundle_cost)
        optimum, _ = brute_force_min_cost(graph)
        assert lower_bound(graph) <= optimum


def test_bundled_solution_respects_its_own_guarantee():
    """cost <= H(d) * OPT, checked against exhaustive search on many random instances."""
    rng = random.Random(20260901)
    for _ in range(60):
        count = rng.randint(2, 6)
        graph = parallel_paths(count, rng.randint(1, 20), rng.randint(1, 60))
        result = solve_bundled(graph)
        optimum, _ = brute_force_min_cost(graph)
        assert result.status == STATUS_CUT_FOUND
        assert optimum is not None
        assert result.lower_bound <= optimum
        assert Fraction(result.cost) <= result.approximation_bound * optimum


def test_bundled_plan_actually_disconnects():
    rng = random.Random(7)
    for _ in range(40):
        graph = parallel_paths(rng.randint(2, 6), rng.randint(1, 15), rng.randint(1, 50))
        result = solve_bundled(graph)
        nodes = frozenset(n for a in result.actions for n in a.removes_nodes)
        edges = frozenset(k for a in result.actions for k in a.removes_edges)
        assert graph.exposed_jewels(nodes, edges) == []


def test_no_cut_possible_is_reported_not_faked():
    graph = parallel_paths(2, 5, None)
    graph.actions = []  # nothing can be removed at all
    result = solve_bundled(graph)
    assert result.status == STATUS_NO_CUT
    assert result.actions == ()


def test_plan_reports_the_np_hardness_honestly():
    plan = solve(parallel_paths(4, 10, 25))
    assert plan.method == METHOD_GREEDY
    assert plan.approximation_bound is not None
    assert any("NP-hard" in note for note in plan.notes)
    # This instance happens to be solved exactly, and the lower bound proves it.
    assert plan.total_cost == 25
    assert plan.optimal is (Fraction(plan.total_cost) == plan.lower_bound)


def test_a_bundle_that_removes_nodes_and_edges_together():
    nodes = {n: Node(n, "user") for n in ("s", "a", "b")}
    nodes["t"] = Node("t", "resource")
    edges = [Edge("s", "a", "c"), Edge("a", "t", "c"), Edge("s", "b", "c"), Edge("b", "t", "c")]
    combo = Action(
        id="combo", kind="custom", cost=5, title="disable a and cut s->b",
        removes_nodes=frozenset({"a"}), removes_edges=frozenset({("s", "b", "c")}),
    )
    singles = [
        Action(id="ca", kind="custom", cost=4, title="cut s->a", removes_edges=frozenset({("s", "a", "c")})),
        Action(id="cb", kind="custom", cost=4, title="cut s->b", removes_edges=frozenset({("s", "b", "c")})),
    ]
    graph = TenantGraph(nodes=nodes, edges=edges, actions=[combo, *singles],
                        compromised=("s",), crown_jewels=("t",))
    graph.validate()
    result = solve_bundled(graph)
    assert result.cost == 5
    assert brute_force_min_cost(graph)[0] == 5


@pytest.mark.parametrize("seed", range(25))
def test_bundled_solver_on_layered_graphs_still_disconnects(seed):
    """Take a normal graph, glue two of its actions into a bundle, and re-solve."""
    graph = random_layered_graph(random.Random(seed), layers=4, width=3)
    if len(graph.actions) < 2:
        pytest.skip("not enough actions to bundle")
    a, b = graph.actions[0], graph.actions[1]
    graph.actions = graph.actions[2:] + [
        Action(id="glued", kind="custom", cost=a.cost + b.cost - 1, title="glued",
               removes_nodes=a.removes_nodes | b.removes_nodes,
               removes_edges=a.removes_edges | b.removes_edges)
    ]
    result = solve_bundled(graph)
    if result.status != STATUS_CUT_FOUND:
        assert brute_force_min_cost(graph)[0] is None
        return
    nodes = frozenset(n for x in result.actions for n in x.removes_nodes)
    edges = frozenset(k for x in result.actions for k in x.removes_edges)
    assert graph.exposed_jewels(nodes, edges) == []
    optimum, _ = brute_force_min_cost(graph)
    assert Fraction(result.cost) <= result.approximation_bound * optimum
    assert result.lower_bound <= optimum
