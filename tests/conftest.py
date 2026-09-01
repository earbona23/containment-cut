"""Shared fixtures and, more importantly, an INDEPENDENT oracle.

`brute_force_min_cost` computes the true optimum by exhaustive search with branch and
bound. It shares nothing with the solver: no flow, no node splitting, no cut. It only
asks the graph "is a jewel still reachable?", which is the definition of the problem.
That is what makes it an oracle instead of a second opinion from the same source.
"""

from __future__ import annotations

import random
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from containment_cut.catalog import with_actions  # noqa: E402
from containment_cut.model import Action, Edge, Node, TenantGraph  # noqa: E402

DEMO_PATH = Path(__file__).resolve().parents[1] / "src" / "containment_cut" / "demo" / "contoso.json"


def brute_force_min_cost(graph: TenantGraph) -> tuple[int | None, tuple[Action, ...]]:
    """True minimum over every subset of actions. Returns (None, ()) if no subset works.

    Branch and bound: actions sorted cheapest-first so a good incumbent appears early,
    then any branch whose partial cost already reaches the incumbent is abandoned.
    """
    # Removing a crown jewel is not containment; the solver forbids it, so the oracle must too.
    jewels = frozenset(graph.crown_jewels)
    actions = sorted(
        (a for a in graph.actions if not (a.removes_nodes & jewels)),
        key=lambda a: a.cost,
    )
    best_cost: int | None = None
    best_set: tuple[Action, ...] = ()

    def search(i: int, cost: int, nodes: frozenset, edges: frozenset, taken: tuple[Action, ...]) -> None:
        nonlocal best_cost, best_set
        if best_cost is not None and cost >= best_cost:
            return
        if not graph.exposed_jewels(nodes, edges):
            best_cost, best_set = cost, taken
            return
        if i >= len(actions):
            return
        a = actions[i]
        search(i + 1, cost + a.cost, nodes | a.removes_nodes, edges | a.removes_edges, taken + (a,))
        search(i + 1, cost, nodes, edges, taken)

    search(0, 0, frozenset(), frozenset(), ())
    return best_cost, best_set


def make_graph(
    nodes: dict[str, str],
    edges: list[tuple[str, str, str]],
    compromised: list[str],
    jewels: list[str],
    node_costs: dict[str, int] | None = None,
    edge_costs: dict[tuple[str, str, str], int] | None = None,
) -> TenantGraph:
    """Build a graph with explicit per-element atomic actions. No catalogue involved."""
    node_costs = node_costs or {}
    edge_costs = edge_costs or {}
    graph = TenantGraph(
        nodes={nid: Node(id=nid, kind=kind, label=nid) for nid, kind in nodes.items()},
        edges=[Edge(source=s, target=t, relation=r) for s, t, r in edges],
        compromised=tuple(compromised),
        crown_jewels=tuple(jewels),
    )
    actions: list[Action] = []
    for nid, cost in node_costs.items():
        actions.append(Action(id=f"n:{nid}", kind="disable_user", cost=cost, title=f"remove {nid}",
                              removes_nodes=frozenset({nid})))
    for key, cost in edge_costs.items():
        actions.append(Action(id=f"e:{key}", kind="remove_group_member", cost=cost,
                              title=f"cut {key}", removes_edges=frozenset({key})))
    graph.actions = actions
    return graph


def random_layered_graph(rng: random.Random, layers: int = 4, width: int = 3, removable_ratio: float = 0.7):
    """A random layered DAG with random costs and some deliberately un-cuttable elements.

    Layered so that paths exist by construction: a random graph with no path from the
    compromise to a jewel tests nothing interesting, and generating them by luck wastes
    the budget of a property test.
    """
    node_ids: list[list[str]] = []
    for layer in range(layers):
        node_ids.append([f"n{layer}_{i}" for i in range(rng.randint(1, width))])
    nodes = {nid: "user" for layer in node_ids for nid in layer}
    edges: list[tuple[str, str, str]] = []
    for layer in range(layers - 1):
        for src in node_ids[layer]:
            for dst in node_ids[layer + 1]:
                if rng.random() < 0.75:
                    edges.append((src, dst, "controls"))
        if not any(e[0] in node_ids[layer] for e in edges):
            edges.append((node_ids[layer][0], node_ids[layer + 1][0], "controls"))
    # Guarantee at least one full source-to-sink path.
    for layer in range(layers - 1):
        pair = (node_ids[layer][0], node_ids[layer + 1][0], "controls")
        if pair not in edges:
            edges.append(pair)

    compromised = node_ids[0][:1]
    jewels = node_ids[-1][:1]
    node_costs = {
        nid: rng.randint(1, 40)
        for layer in node_ids[1:-1]
        for nid in layer
        if rng.random() < removable_ratio
    }
    for nid in compromised:
        if rng.random() < removable_ratio:
            node_costs[nid] = rng.randint(1, 60)
    edge_costs = {e: rng.randint(1, 30) for e in edges if rng.random() < removable_ratio}
    return make_graph(nodes, edges, compromised, jewels, node_costs, edge_costs)


@pytest.fixture
def demo_graph():
    from containment_cut.model import load_graph

    return with_actions(load_graph(DEMO_PATH))
