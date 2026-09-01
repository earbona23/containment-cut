"""The exact core: minimum-cost mixed node/edge cut, by reduction to max-flow.

THE PROBLEM
-----------
Given a directed graph G, a set S of compromised nodes, a set T of crown jewels, and a
cost for destroying each element (node or edge), find the cheapest set of elements whose
removal leaves no directed path from S to T.

WHY THIS IS EXACTLY SOLVABLE (and why that matters)
---------------------------------------------------
Cutting *edges* is the textbook minimum s-t cut. Cutting *nodes* looks different but is
the same problem after a change of variable: **node splitting**. Replace each node v by
an entry copy v_in and an exit copy v_out joined by one internal arc

        v_in --[ cost of destroying v ]--> v_out

and re-hang every original edge u -> v as u_out -> v_in with capacity equal to the cost
of destroying that edge. Now every path through v must traverse v's internal arc, so
"delete node v" and "cut arc (v_in, v_out)" are the same act, at the same price. An
element that no available action can destroy gets capacity INFINITY, and a minimum cut
will simply route around it.

Add a super-source with infinite arcs into every compromised node's *entry* copy, and
infinite arcs from every crown jewel's *exit* copy into a super-sink. A minimum s-t cut
in this network is a minimum-cost mixed node/edge cut in the original graph, and by the
**max-flow min-cut theorem** (Ford & Fulkerson 1956; Elias, Feinstein & Shannon 1956)
it is computed exactly by any max-flow algorithm. We use Dinic: **O(|V|^2 |E|)**.

Two deliberate asymmetries, both of them security decisions rather than maths:

* A **compromised** node's internal arc keeps its finite cost. "Disable the breached
  account" must stay on the table as a candidate — it is often right, and a tool that
  cannot propose the obvious answer cannot be trusted with the clever one.
* A **crown jewel**'s internal arc is INFINITY. Deleting the thing you are protecting is
  not containment.

INFINITY is not a float. It is `1 + sum of every finite capacity in the network`, which
is strictly greater than the cost of any finite cut, so a finite cut is always preferred
when one exists, and a max-flow value that reaches it proves that none exists.

WHAT YOU GET BACK
-----------------
A `CutResult` carrying the cut *and its optimality certificate*: the arc flows. Weak
duality says every s-t flow is at most every s-t cut, so a flow whose value equals the
cut's cost proves the cut is minimum — and that proof is checkable in O(V+E) by code
that knows nothing about how the cut was found (`verify_certificate`). Every plan this
tool prints ships with one.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Hashable, Mapping

from .maxflow import FlowNetwork
from .model import EdgeKey, TenantGraph

Element = Hashable  # a node id (str) or an edge key (tuple[str, str, str])

STATUS_CONTAINED = "already-contained"
STATUS_CUT_FOUND = "cut-found"
STATUS_NO_CUT = "no-cut-possible"


@dataclass(frozen=True, slots=True)
class Arc:
    """One arc of the split network, kept so the certificate is self-contained."""

    tail: int
    head: int
    capacity: Any
    flow: Any
    element: Element | None  # None for the super-source/sink and infinite arcs


@dataclass(slots=True)
class CutResult:
    status: str
    cost: Any
    cut_nodes: frozenset[str]
    cut_edges: frozenset[EdgeKey]
    flow_value: Any
    arcs: list[Arc] = field(default_factory=list)
    source_node: int = -1
    sink_node: int = -1
    infinity: Any = 0

    @property
    def elements(self) -> frozenset[Element]:
        return frozenset(self.cut_nodes) | frozenset(self.cut_edges)


def build_split_network(
    graph: TenantGraph,
    element_cost: Mapping[Element, Any],
    zero: Any = 0,
) -> tuple[FlowNetwork, dict[int, Element], int, int, Any]:
    """Construct the node-split flow network. Returns (net, arc->element, src, snk, INF).

    `element_cost` maps a node id or an edge key to the cost of destroying it. Anything
    absent is un-destroyable and gets INFINITY.
    """
    order = list(graph.nodes)
    index = {n: i for i, n in enumerate(order)}
    n = len(order)

    finite_total = zero
    for value in element_cost.values():
        finite_total += value
    infinity = finite_total + 1

    net = FlowNetwork(2 * n + 2, zero=zero)
    src, snk = 2 * n, 2 * n + 1
    arc_element: dict[int, Element] = {}

    jewels = set(graph.crown_jewels)
    for node_id, i in index.items():
        # Deleting the asset you are defending is not containment: infinite capacity.
        cap = infinity if node_id in jewels else element_cost.get(node_id, infinity)
        arc = net.add_edge(2 * i, 2 * i + 1, cap)
        if node_id not in jewels and node_id in element_cost:
            arc_element[arc] = node_id

    for edge in graph.edges:
        cap = element_cost.get(edge.key, infinity)
        arc = net.add_edge(2 * index[edge.source] + 1, 2 * index[edge.target], cap)
        if edge.key in element_cost:
            arc_element[arc] = edge.key

    for node_id in graph.compromised:
        net.add_edge(src, 2 * index[node_id], infinity)
    for node_id in graph.crown_jewels:
        net.add_edge(2 * index[node_id] + 1, snk, infinity)

    return net, arc_element, src, snk, infinity


def min_cut(graph: TenantGraph, element_cost: Mapping[Element, Any], zero: Any = 0) -> CutResult:
    """Minimum-cost mixed node/edge cut separating `graph.compromised` from the jewels."""
    if not graph.exposed_jewels():
        return CutResult(
            status=STATUS_CONTAINED,
            cost=zero,
            cut_nodes=frozenset(),
            cut_edges=frozenset(),
            flow_value=zero,
        )

    net, arc_element, src, snk, infinity = build_split_network(graph, element_cost, zero)
    value = net.max_flow(src, snk)

    if value >= infinity:
        # No finite cut exists: some S-to-T path is made entirely of elements that no
        # action can destroy. Saying "no plan" is the only honest answer here; inventing
        # a partial plan would report containment that did not happen.
        return CutResult(
            status=STATUS_NO_CUT,
            cost=infinity,
            cut_nodes=frozenset(),
            cut_edges=frozenset(),
            flow_value=value,
            infinity=infinity,
        )

    reachable = net.residual_reachable(src)
    cut_nodes: set[str] = set()
    cut_edges: set[EdgeKey] = set()
    for arc, element in arc_element.items():
        if net.tail(arc) in reachable and net.head(arc) not in reachable:
            if isinstance(element, tuple):
                cut_edges.add(element)
            else:
                cut_nodes.add(element)

    cost = zero
    for element in list(cut_nodes) + list(cut_edges):
        cost += element_cost[element]

    arcs = [
        Arc(net.tail(a), net.head(a), net.capacity(a), net.flow(a), arc_element.get(a))
        for a in net.arcs()
    ]
    return CutResult(
        status=STATUS_CUT_FOUND,
        cost=cost,
        cut_nodes=frozenset(cut_nodes),
        cut_edges=frozenset(cut_edges),
        flow_value=value,
        arcs=arcs,
        source_node=src,
        sink_node=snk,
        infinity=infinity,
    )


# ---- the certificate ----------------------------------------------------------


@dataclass(slots=True)
class CertificateReport:
    ok: bool
    checks: dict[str, bool]
    reasons: list[str]

    # Deliberately NOT truthy-by-ok. A report object that is falsy when the certificate
    # fails makes `if report and not report.ok:` dead code -- which is exactly how a
    # failed proof once got rendered as silence. Ask for `.ok` explicitly.


def verify_certificate(graph: TenantGraph, result: CutResult, zero: Any = 0) -> CertificateReport:
    """Re-check, from scratch, that the returned cut is *minimum* and *sufficient*.

    Four independent checks. Nothing here calls the solver; it only reads the numbers the
    solver produced, which is the point — a verifier that shares the solver's reasoning
    verifies nothing.

      1. capacity      0 <= f(a) <= c(a) on every arc
      2. conservation  inflow == outflow at every node except the super source/sink
      3. duality       cut cost == |f|.  Every s-t flow is at most every s-t cut
                       (weak duality), so a cut whose cost equals a feasible flow's
                       value is minimum. This is the optimality proof.
      4. sufficiency   deleting the cut really does leave no crown jewel reachable
                       from the compromised set, checked on the ORIGINAL graph.

    Checks 1-3 prove "no cheaper plan exists". Check 4 proves "this plan works". They are
    different claims and a tool needs both.
    """
    checks: dict[str, bool] = {}
    reasons: list[str] = []

    if result.status == STATUS_CONTAINED:
        still = graph.exposed_jewels()
        checks["sufficiency"] = not still
        if still:
            reasons.append(f"claimed already-contained but these jewels are reachable: {still}")
        return CertificateReport(ok=not still, checks=checks, reasons=reasons)

    if result.status == STATUS_NO_CUT:
        # The honest claim is "no finite cut". Re-derive it: with every destroyable
        # element removed, a jewel is still reachable.
        # Take every action at once -- the most a plan could ever do -- and show a jewel
        # is STILL reachable. That is what "no cut possible" claims, so that is what gets
        # checked. Crown jewels themselves are never removable.
        removable_nodes = frozenset(
            n for a in graph.actions for n in a.removes_nodes if n not in graph.crown_jewels
        )
        removable_edges = frozenset(k for a in graph.actions for k in a.removes_edges)
        still = graph.exposed_jewels(removable_nodes, removable_edges)
        checks["no-cut-is-real"] = bool(still)
        if not still:
            reasons.append("claimed no-cut-possible, but removing every available action's elements does contain it")
        return CertificateReport(ok=bool(still), checks=checks, reasons=reasons)

    # 1. capacity
    cap_ok = all(zero <= a.flow <= a.capacity for a in result.arcs)
    checks["capacity"] = cap_ok
    if not cap_ok:
        reasons.append("some arc carries flow outside [0, capacity]")

    # 2. conservation
    balance: dict[int, Any] = {}
    for a in result.arcs:
        balance[a.tail] = balance.get(a.tail, zero) - a.flow
        balance[a.head] = balance.get(a.head, zero) + a.flow
    interior_ok = all(
        v == zero for node, v in balance.items() if node not in (result.source_node, result.sink_node)
    )
    checks["conservation"] = interior_ok
    if not interior_ok:
        bad = [n for n, v in balance.items() if v != zero and n not in (result.source_node, result.sink_node)]
        reasons.append(f"flow is not conserved at split-network nodes {bad[:5]}")

    out_of_source = -balance.get(result.source_node, zero)
    value_ok = out_of_source == result.flow_value
    checks["flow-value"] = value_ok
    if not value_ok:
        reasons.append(f"flow leaving the source is {out_of_source}, not the claimed {result.flow_value}")

    # 3. weak duality
    duality_ok = result.cost == result.flow_value
    checks["duality"] = duality_ok
    if not duality_ok:
        reasons.append(f"cut cost {result.cost} != max-flow value {result.flow_value}; optimality unproven")

    # 4. sufficiency
    still = graph.exposed_jewels(result.cut_nodes, result.cut_edges)
    checks["sufficiency"] = not still
    if still:
        reasons.append(f"after the cut these jewels are still reachable: {still}")

    ok = all(checks.values())
    return CertificateReport(ok=ok, checks=checks, reasons=reasons)
