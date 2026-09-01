"""The exact solver: known optima, the awkward cases, and the certificate."""

from containment_cut.cut import (
    STATUS_CONTAINED,
    STATUS_CUT_FOUND,
    STATUS_NO_CUT,
    min_cut,
    verify_certificate,
)
from containment_cut.model import Action
from containment_cut.plan import atomic_element_costs, solve
from conftest import brute_force_min_cost, make_graph


def costs_of(graph):
    return atomic_element_costs(graph.actions)[0]


def test_single_edge_is_the_cut():
    g = make_graph({"a": "user", "b": "resource"}, [("a", "b", "controls")], ["a"], ["b"],
                   edge_costs={("a", "b", "controls"): 7})
    result = min_cut(g, costs_of(g))
    assert result.status == STATUS_CUT_FOUND
    assert result.cost == 7
    assert result.cut_edges == {("a", "b", "controls")}
    assert verify_certificate(g, result).ok


def test_node_cut_beats_two_edge_cuts():
    # a -> m -> {j1, j2}. Cutting m costs 3; cutting both outgoing edges costs 4+4.
    g = make_graph(
        {"a": "user", "m": "user", "j1": "resource", "j2": "resource"},
        [("a", "m", "c"), ("m", "j1", "c"), ("m", "j2", "c")],
        ["a"], ["j1", "j2"],
        node_costs={"m": 3},
        edge_costs={("m", "j1", "c"): 4, ("m", "j2", "c"): 4},
    )
    result = min_cut(g, costs_of(g))
    assert result.cost == 3
    assert result.cut_nodes == {"m"}
    assert verify_certificate(g, result).ok


def test_two_edge_cuts_beat_the_node():
    g = make_graph(
        {"a": "user", "m": "user", "j1": "resource", "j2": "resource"},
        [("a", "m", "c"), ("m", "j1", "c"), ("m", "j2", "c")],
        ["a"], ["j1", "j2"],
        node_costs={"m": 9},
        edge_costs={("m", "j1", "c"): 4, ("m", "j2", "c"): 4},
    )
    result = min_cut(g, costs_of(g))
    assert result.cost == 8
    assert result.cut_nodes == set()
    assert len(result.cut_edges) == 2


def test_disabling_the_compromised_principal_is_a_candidate():
    # Its own node arc is cuttable: sometimes the obvious answer is the right one.
    g = make_graph(
        {"a": "user", "x": "user", "y": "user", "j": "resource"},
        [("a", "x", "c"), ("a", "y", "c"), ("x", "j", "c"), ("y", "j", "c")],
        ["a"], ["j"],
        node_costs={"a": 5},
        edge_costs={("a", "x", "c"): 4, ("a", "y", "c"): 4},
    )
    result = min_cut(g, costs_of(g))
    assert result.cost == 5
    assert result.cut_nodes == {"a"}


def test_crown_jewel_is_never_removed():
    # The only "cheap" way out would be deleting the jewel. It must not be taken.
    g = make_graph(
        {"a": "user", "j": "resource"},
        [("a", "j", "c")],
        ["a"], ["j"],
        node_costs={"j": 1, "a": 50},
        edge_costs={("a", "j", "c"): 9},
    )
    result = min_cut(g, costs_of(g))
    assert "j" not in result.cut_nodes
    assert result.cost == 9


def test_already_contained():
    g = make_graph({"a": "user", "j": "resource"}, [], ["a"], ["j"])
    result = min_cut(g, costs_of(g))
    assert result.status == STATUS_CONTAINED
    assert result.cost == 0
    assert verify_certificate(g, result).ok


def test_no_cut_possible_when_the_path_is_untouchable():
    g = make_graph({"a": "user", "j": "resource"}, [("a", "j", "inherent")], ["a"], ["j"])
    result = min_cut(g, costs_of(g))
    assert result.status == STATUS_NO_CUT
    assert verify_certificate(g, result).ok  # the "no cut" claim itself is re-derived


def test_compromised_node_that_is_itself_a_crown_jewel():
    g = make_graph({"a": "user"}, [], ["a"], ["a"], node_costs={"a": 1})
    result = min_cut(g, costs_of(g))
    assert result.status == STATUS_NO_CUT


def test_multiple_sources_and_multiple_targets():
    g = make_graph(
        {"s1": "user", "s2": "user", "m": "user", "j1": "resource", "j2": "resource"},
        [("s1", "m", "c"), ("s2", "m", "c"), ("m", "j1", "c"), ("m", "j2", "c")],
        ["s1", "s2"], ["j1", "j2"],
        node_costs={"m": 6, "s1": 4, "s2": 4},
    )
    result = min_cut(g, costs_of(g))
    assert result.cost == 6
    assert result.cut_nodes == {"m"}


def test_zero_cost_action_is_taken():
    g = make_graph({"a": "user", "j": "resource"}, [("a", "j", "c")], ["a"], ["j"],
                   edge_costs={("a", "j", "c"): 0})
    result = min_cut(g, costs_of(g))
    assert result.cost == 0
    assert result.cut_edges == {("a", "j", "c")}
    assert verify_certificate(g, result).ok


def test_cycles_do_not_break_reachability_or_the_cut():
    g = make_graph(
        {"a": "user", "b": "user", "c": "user", "j": "resource"},
        [("a", "b", "r"), ("b", "c", "r"), ("c", "a", "r"), ("c", "j", "r")],
        ["a"], ["j"],
        edge_costs={("c", "j", "r"): 2, ("a", "b", "r"): 5},
    )
    result = min_cut(g, costs_of(g))
    assert result.cost == 2
    assert verify_certificate(g, result).ok


def test_certificate_rejects_a_tampered_result():
    g = make_graph({"a": "user", "j": "resource"}, [("a", "j", "c")], ["a"], ["j"],
                   edge_costs={("a", "j", "c"): 7})
    result = min_cut(g, costs_of(g))
    assert verify_certificate(g, result).ok
    result.cut_edges = frozenset()          # claim a cut that cuts nothing
    report = verify_certificate(g, result)
    assert not report.ok
    assert report.checks["sufficiency"] is False


def test_certificate_rejects_a_cost_that_does_not_match_the_flow():
    g = make_graph({"a": "user", "j": "resource"}, [("a", "j", "c")], ["a"], ["j"],
                   edge_costs={("a", "j", "c"): 7})
    result = min_cut(g, costs_of(g))
    result.cost = 3                          # cheaper than the flow: cannot be a cut
    report = verify_certificate(g, result)
    assert not report.ok
    assert report.checks["duality"] is False


def test_matches_the_brute_force_oracle_on_a_hand_built_case():
    g = make_graph(
        {"a": "user", "b": "user", "c": "user", "d": "user", "j": "resource"},
        [("a", "b", "r"), ("a", "c", "r"), ("b", "d", "r"), ("c", "d", "r"), ("d", "j", "r")],
        ["a"], ["j"],
        node_costs={"a": 20, "b": 6, "c": 6, "d": 11},
        edge_costs={("a", "b", "r"): 5, ("a", "c", "r"): 5, ("d", "j", "r"): 12},
    )
    plan = solve(g)
    optimum, _ = brute_force_min_cost(g)
    assert optimum == 10  # cut both of a's out-edges: cheaper than d (11) or a (20)
    assert plan.total_cost == optimum
    assert plan.optimal


def test_the_cheapest_action_per_element_is_the_one_used():
    """Two actions can destroy the same element. The plan must take the cheaper one.

    Nothing else in the suite has an element with more than one action, so without this
    the min/max choice in `atomic_element_costs` is untested — a mutation flipping it
    still produces a valid cut, just a needlessly expensive one, and every other
    assertion stays green.
    """
    g = make_graph({"a": "user", "j": "resource"}, [("a", "j", "c")], ["a"], ["j"])
    key = ("a", "j", "c")
    g.actions = [
        Action(id="pricey", kind="custom", cost=90, title="the expensive way",
               removes_edges=frozenset({key})),
        Action(id="cheap", kind="custom", cost=12, title="the cheap way",
               removes_edges=frozenset({key})),
    ]
    plan = solve(g)
    assert plan.total_cost == 12
    assert [step.action.id for step in plan.steps] == ["cheap"]
    assert brute_force_min_cost(g)[0] == 12


def test_the_cheapest_action_is_chosen_for_a_node_too():
    g = make_graph({"a": "user", "m": "user", "j": "resource"},
                   [("a", "m", "c"), ("m", "j", "c")], ["a"], ["j"])
    g.actions = [
        Action(id="disable-m", kind="custom", cost=70, title="disable m",
               removes_nodes=frozenset({"m"})),
        Action(id="quarantine-m", kind="custom", cost=9, title="quarantine m",
               removes_nodes=frozenset({"m"})),
        Action(id="cut-am", kind="custom", cost=40, title="cut a->m",
               removes_edges=frozenset({("a", "m", "c")})),
    ]
    plan = solve(g)
    assert plan.total_cost == 9
    assert [step.action.id for step in plan.steps] == ["quarantine-m"]
