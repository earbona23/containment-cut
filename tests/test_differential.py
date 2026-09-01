"""Differential test: our Dinic against networkx's max-flow on the same networks.

An independent implementation is the cheapest defence against a subtle bug that our own
tests share a blind spot with. networkx is a test-only dependency and never ships.

If networkx is missing this test SKIPS -- except when CONTAINMENT_CUT_REQUIRE_DIFFERENTIAL
is set, which CI does, where it FAILS instead. A skipped test in CI looks exactly like a
passing one on the summary line, and that is precisely how a differential test quietly
stops running.
"""

from __future__ import annotations

import os
import random

import pytest

from containment_cut.cut import build_split_network
from containment_cut.maxflow import FlowNetwork
from containment_cut.plan import atomic_element_costs
from conftest import random_layered_graph

REQUIRED = os.environ.get("CONTAINMENT_CUT_REQUIRE_DIFFERENTIAL") == "1"

try:
    import networkx as nx
except ImportError:  # pragma: no cover
    nx = None

if nx is None:
    if REQUIRED:
        raise RuntimeError(
            "CONTAINMENT_CUT_REQUIRE_DIFFERENTIAL=1 but networkx is not installed: "
            "the differential oracle would have been silently skipped"
        )
    pytestmark = pytest.mark.skip(reason="networkx not installed")


@pytest.mark.differential
@pytest.mark.parametrize("seed", range(40))
def test_our_maxflow_matches_networkx(seed):
    rng = random.Random(seed)
    n = rng.randint(4, 30)
    ours = FlowNetwork(n)
    theirs = nx.DiGraph()
    theirs.add_nodes_from(range(n))
    for _ in range(rng.randint(n, 4 * n)):
        u, v = rng.randrange(n), rng.randrange(n)
        if u == v:
            continue
        cap = rng.randint(0, 25)
        ours.add_edge(u, v, cap)
        # networkx keeps one edge per pair, so accumulate parallel capacities.
        if theirs.has_edge(u, v):
            theirs[u][v]["capacity"] += cap
        else:
            theirs.add_edge(u, v, capacity=cap)
    source, sink = 0, n - 1
    mine = ours.max_flow(source, sink)
    expected = nx.maximum_flow_value(theirs, source, sink) if nx.has_path(theirs, source, sink) else 0
    assert mine == expected


@pytest.mark.differential
@pytest.mark.parametrize("seed", range(30))
def test_split_network_min_cut_matches_networkx(seed):
    """The whole reduction, not just the solver: same split network, two engines."""
    graph = random_layered_graph(random.Random(seed), layers=4, width=3)
    element_cost, _ = atomic_element_costs(graph.actions)
    net, _, src, snk, infinity = build_split_network(graph, element_cost)

    theirs = nx.DiGraph()
    for arc in net.arcs():
        u, v, cap = net.tail(arc), net.head(arc), net.capacity(arc)
        if theirs.has_edge(u, v):
            theirs[u][v]["capacity"] += cap
        else:
            theirs.add_edge(u, v, capacity=cap)
    expected = nx.maximum_flow_value(theirs, src, snk)
    assert net.max_flow(src, snk) == expected
