"""Property-based tests: the claims that must hold on graphs nobody hand-picked.

Three properties, and they are the three things the tool promises:

  1. the plan actually disconnects the compromise from the crown jewels;
  2. the plan's cost is the exact optimum -- checked against exhaustive search, not
     against the solver's own certificate, because a bug in the reduction would corrupt
     both;
  3. the certificate agrees.
"""

from __future__ import annotations

import os
import random

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from containment_cut.cut import STATUS_CONTAINED, STATUS_CUT_FOUND, STATUS_NO_CUT
from containment_cut.plan import solve
from conftest import brute_force_min_cost, random_layered_graph

# 400 examples per property, because the whole suite still runs in a couple of seconds and
# the marginal example is nearly free. Configurable for anyone who wants to run it harder
# in a nightly job: killing a bug is monotone in the budget -- a larger one can only make
# a property test more likely to fail.
MAX_EXAMPLES = int(os.environ.get("CONTAINMENT_CUT_HYPOTHESIS_EXAMPLES", "400"))

SLOW = settings(
    max_examples=MAX_EXAMPLES,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)


@given(
    seed=st.integers(min_value=0, max_value=2**31),
    layers=st.integers(min_value=2, max_value=5),
    width=st.integers(min_value=1, max_value=3),
    ratio=st.floats(min_value=0.3, max_value=1.0),
)
@SLOW
def test_plan_disconnects_and_is_optimal(seed, layers, width, ratio):
    graph = random_layered_graph(random.Random(seed), layers=layers, width=width, removable_ratio=ratio)
    plan = solve(graph)
    optimum, _ = brute_force_min_cost(graph)

    if plan.status == STATUS_CONTAINED:
        assert not graph.exposed_jewels()
        return

    if plan.status == STATUS_NO_CUT:
        # The solver refuses only when exhaustive search also finds nothing.
        assert optimum is None
        return

    assert plan.status == STATUS_CUT_FOUND
    assert optimum is not None

    removed_nodes = frozenset(n for s in plan.steps for n in s.action.removes_nodes)
    removed_edges = frozenset(k for s in plan.steps for k in s.action.removes_edges)
    # 1. it works
    assert graph.exposed_jewels(removed_nodes, removed_edges) == []
    # 2. it is exactly optimal
    assert plan.total_cost == optimum
    # 3. the certificate says so, and is not just decoration
    assert plan.certificate is not None and plan.certificate.ok
    assert plan.optimal


@given(seed=st.integers(min_value=0, max_value=2**31))
@SLOW
def test_progress_curve_is_monotone(seed):
    """Jewels never become reachable again as more actions are applied."""
    graph = random_layered_graph(random.Random(seed), layers=4, width=3)
    plan = solve(graph)
    if plan.status != STATUS_CUT_FOUND:
        return
    previous = set(plan.jewels_exposed_before)
    for step in plan.steps:
        current = set(step.jewels_reachable_after)
        assert current <= previous
        previous = current
    assert previous == set()


@given(seed=st.integers(min_value=0, max_value=2**31))
@SLOW
def test_every_action_in_the_plan_is_load_bearing(seed):
    """A minimum cut has no spare parts: drop any one action and a jewel comes back.

    This is the property that catches a solver that finds a *correct* cut but not a
    *minimal* one -- the failure mode most likely to slip past a cost comparison, because
    a redundant zero-cost action leaves the total unchanged.
    """
    graph = random_layered_graph(random.Random(seed), layers=4, width=3)
    plan = solve(graph)
    if plan.status != STATUS_CUT_FOUND or not plan.steps:
        return
    chosen = [s.action for s in plan.steps]
    for dropped in chosen:
        rest = [a for a in chosen if a.id != dropped.id]
        nodes = frozenset(n for a in rest for n in a.removes_nodes)
        edges = frozenset(k for a in rest for k in a.removes_edges)
        assert graph.exposed_jewels(nodes, edges), (
            f"action {dropped.id} (cost {dropped.cost}) is redundant; the cut is not minimal"
        )
