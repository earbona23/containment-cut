"""Dinic's maximum-flow algorithm, written here rather than imported.

WHY OUR OWN: three reasons, none of them "not invented here".

1. *Certificates.* The value of this tool is not the number it prints, it is the proof
   that the number is optimal. That proof needs the final **arc flows**, not just the
   flow value, so that an independent verifier can re-check capacity, conservation and
   weak duality (see `cut.verify_certificate`). Most library APIs hand back a value and
   a partition; we need the flow itself.
2. *Exact arithmetic.* The bundled-action lower bound (`bundles.lower_bound`) needs
   capacities that are rationals, not floats — a float min-cut can report 184.99999999
   and turn a proof into a rounding argument. Dinic is agnostic to the numeric type as
   long as it is an ordered ring, so `Fraction` works unchanged.
3. *Zero runtime dependencies* during an incident (see pyproject.toml).

CORRECTNESS: Dinic (1970) computes a maximum flow. Each phase builds the BFS level
graph and pushes a blocking flow; the shortest augmenting-path length strictly increases
between phases, so there are at most |V|-1 phases, and a blocking flow costs O(|V||E|)
with the current-arc optimisation. Total: **O(|V|^2 |E|)**, independent of capacities —
so termination does not depend on the costs being integers.

MAX-FLOW MIN-CUT (Ford & Fulkerson 1956; Elias, Feinstein & Shannon 1956): the value of
a maximum s-t flow equals the capacity of a minimum s-t cut, and the set of vertices
reachable from s in the residual network is the source side of such a cut.
"""

from __future__ import annotations

from collections import deque
from typing import Iterable


class FlowNetwork:
    """A directed network with residual arcs stored in adjacent pairs (e, e^1).

    Capacities may be any type supporting comparison and +/- with a zero of the same
    type (int and fractions.Fraction are both used in this project).
    """

    __slots__ = ("_to", "_cap", "_orig_cap", "_adj", "_level", "_it", "_zero")

    def __init__(self, num_nodes: int = 0, zero=0) -> None:
        self._to: list[int] = []
        self._cap: list = []
        self._orig_cap: list = []
        self._adj: list[list[int]] = [[] for _ in range(num_nodes)]
        self._level: list[int] = []
        self._it: list[int] = []
        self._zero = zero

    # ---- construction ---------------------------------------------------------

    @property
    def num_nodes(self) -> int:
        return len(self._adj)

    @property
    def num_arcs(self) -> int:
        """Forward arcs only (each has a hidden residual twin)."""
        return len(self._to) // 2

    def add_node(self) -> int:
        self._adj.append([])
        return len(self._adj) - 1

    def add_edge(self, u: int, v: int, capacity) -> int:
        """Add u->v with the given capacity. Returns the arc id (its twin is id^1)."""
        if capacity < self._zero:
            raise ValueError("capacity must be non-negative")
        arc = len(self._to)
        self._to.append(v)
        self._cap.append(capacity)
        self._adj[u].append(arc)
        self._to.append(u)
        self._cap.append(self._zero)
        self._adj[v].append(arc + 1)
        self._orig_cap.append(capacity)
        self._orig_cap.append(self._zero)
        return arc

    # ---- queries --------------------------------------------------------------

    def capacity(self, arc: int):
        return self._orig_cap[arc]

    def flow(self, arc: int):
        """Flow pushed along a forward arc = how much of its capacity was consumed."""
        return self._orig_cap[arc] - self._cap[arc]

    def head(self, arc: int) -> int:
        return self._to[arc]

    def tail(self, arc: int) -> int:
        return self._to[arc ^ 1]

    def arcs(self) -> Iterable[int]:
        return range(0, len(self._to), 2)

    def outgoing(self, node: int) -> list[int]:
        return self._adj[node]

    # ---- the algorithm --------------------------------------------------------

    def max_flow(self, source: int, sink: int):
        """Push a maximum flow from source to sink and return its value."""
        if source == sink:
            raise ValueError("source and sink must differ")
        total = self._zero
        while self._build_levels(source, sink):
            self._it = [0] * len(self._adj)
            while True:
                pushed = self._augment(source, sink)
                if pushed == self._zero:
                    break
                total += pushed
        return total

    def _build_levels(self, source: int, sink: int) -> bool:
        """BFS over arcs with residual capacity. True if the sink is still reachable."""
        self._level = [-1] * len(self._adj)
        self._level[source] = 0
        queue = deque([source])
        while queue:
            u = queue.popleft()
            for arc in self._adj[u]:
                v = self._to[arc]
                if self._cap[arc] > self._zero and self._level[v] < 0:
                    self._level[v] = self._level[u] + 1
                    queue.append(v)
        return self._level[sink] >= 0

    def _augment(self, source: int, sink: int):
        """Find one augmenting path in the level graph and saturate it.

        Iterative on purpose: a recursive DFS blows the Python stack on the 20k-node
        graphs in the benchmark, and a tool that crashes on a big tenant is a tool that
        fails exactly when the tenant is interesting.
        """
        path: list[int] = []
        u = source
        while True:
            if u == sink:
                bottleneck = min(self._cap[arc] for arc in path)
                for arc in path:
                    self._cap[arc] -= bottleneck
                    self._cap[arc ^ 1] += bottleneck
                return bottleneck
            advanced = False
            adj_u = self._adj[u]
            while self._it[u] < len(adj_u):
                arc = adj_u[self._it[u]]
                v = self._to[arc]
                if self._cap[arc] > self._zero and self._level[v] == self._level[u] + 1:
                    path.append(arc)
                    u = v
                    advanced = True
                    break
                self._it[u] += 1
            if advanced:
                continue
            # Dead end: retreat, and mark u unusable for the rest of this phase.
            self._level[u] = -1
            if u == source:
                return self._zero
            arc = path.pop()
            u = self._to[arc ^ 1]
            self._it[u] += 1

    def residual_reachable(self, source: int) -> set[int]:
        """Vertices reachable from `source` along arcs with residual capacity.

        After a maximum flow this is the source side of a minimum cut.
        """
        seen = {source}
        queue = deque([source])
        while queue:
            u = queue.popleft()
            for arc in self._adj[u]:
                v = self._to[arc]
                if self._cap[arc] > self._zero and v not in seen:
                    seen.add(v)
                    queue.append(v)
        return seen
