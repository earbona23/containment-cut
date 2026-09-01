"""The tenant model: what a node is, what an edge means, and what an action removes.

The whole tool rests on one modelling decision, so it is worth being explicit about it.

An edge ``u -> v`` means: **whoever controls u can, without further help, come to
control v.** Not "u is related to v". Not "u can read v". Control, or a step that is
mechanically sufficient to obtain control. That is what makes reachability in this graph
mean "the attacker gets there", and it is what lets a graph cut mean "the attacker does
not get there".

The nuance that catches people: *ownership of an application is control of it.* An owner
can add a client secret to the app and then authenticate as its service principal,
inheriting every permission that principal holds. So `user --owns--> application` is a
real control edge, and "remove the owner" is a real containment action — one that almost
never appears in an incident runbook.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping

SCHEMA_VERSION = 1

EdgeKey = tuple[str, str, str]
"""(source, target, relation) — the identity of an edge. Parallel edges between the same
pair of nodes are distinct as long as the relation differs, which is what you want: a
user can both *own* an app and be a *member* of a group that can reach it."""


class GraphError(ValueError):
    """The input graph is malformed. Always raised with the offending id in the text."""


@dataclass(frozen=True, slots=True)
class Node:
    id: str
    kind: str
    label: str = ""
    attrs: Mapping[str, Any] = field(default_factory=dict)

    @property
    def display(self) -> str:
        return self.label or self.id


@dataclass(frozen=True, slots=True)
class Edge:
    source: str
    target: str
    relation: str
    attrs: Mapping[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> EdgeKey:
        return (self.source, self.target, self.relation)


@dataclass(frozen=True, slots=True)
class Action:
    """One containment action, and exactly which graph elements it destroys.

    `cost` is *business impact*, an integer on whatever scale the operator chooses (the
    default catalogue uses 0-1000 points). Integers, not floats, so that "is this cut
    cheaper than that one" is a decision and not a rounding question.

    An action may remove several elements at once (`removes_nodes` / `removes_edges`
    with more than one entry). That single fact is what separates the polynomial case
    from the NP-hard one — see `bundles`.
    """

    id: str
    kind: str
    cost: int
    title: str
    removes_nodes: frozenset[str] = frozenset()
    removes_edges: frozenset[EdgeKey] = frozenset()
    rationale: str = ""
    target_ref: Mapping[str, Any] = field(default_factory=dict)
    reversible: bool = True

    @property
    def is_bundle(self) -> bool:
        return len(self.removes_nodes) + len(self.removes_edges) > 1

    @property
    def elements(self) -> frozenset:
        """The graph elements this action destroys, as a single set.

        Node ids are strings, edge keys are 3-tuples — disjoint by construction, so they
        can live in one set without a tag.
        """
        return frozenset(self.removes_nodes) | frozenset(self.removes_edges)


@dataclass(slots=True)
class TenantGraph:
    nodes: dict[str, Node]
    edges: list[Edge]
    actions: list[Action] = field(default_factory=list)
    compromised: tuple[str, ...] = ()
    crown_jewels: tuple[str, ...] = ()
    tenant: str = ""

    # ---- derived views --------------------------------------------------------

    def successors(self) -> dict[str, list[Edge]]:
        out: dict[str, list[Edge]] = {n: [] for n in self.nodes}
        for e in self.edges:
            out[e.source].append(e)
        return out

    def edge_by_key(self) -> dict[EdgeKey, Edge]:
        return {e.key: e for e in self.edges}

    def reachable(
        self,
        sources: Iterable[str],
        removed_nodes: frozenset[str] = frozenset(),
        removed_edges: frozenset[EdgeKey] = frozenset(),
    ) -> set[str]:
        """Forward reachability with a set of elements deleted.

        This is the ground truth the whole tool is judged against: a plan is correct if
        and only if, after deleting what it removes, no crown jewel is in this set.
        """
        succ = self.successors()
        seen: set[str] = set()
        stack = [s for s in sources if s not in removed_nodes]
        seen.update(stack)
        while stack:
            u = stack.pop()
            for e in succ[u]:
                if e.key in removed_edges or e.target in removed_nodes:
                    continue
                if e.target not in seen:
                    seen.add(e.target)
                    stack.append(e.target)
        return seen

    def exposed_jewels(
        self,
        removed_nodes: frozenset[str] = frozenset(),
        removed_edges: frozenset[EdgeKey] = frozenset(),
    ) -> list[str]:
        reach = self.reachable(self.compromised, removed_nodes, removed_edges)
        return [j for j in self.crown_jewels if j in reach]

    # ---- validation -----------------------------------------------------------

    def validate(self) -> None:
        seen_edges: set[EdgeKey] = set()
        for e in self.edges:
            for ref, role in ((e.source, "source"), (e.target, "target")):
                if ref not in self.nodes:
                    raise GraphError(f"edge {e.key} names an unknown {role} node {ref!r}")
            if e.key in seen_edges:
                raise GraphError(f"duplicate edge {e.key}")
            seen_edges.add(e.key)

        seen_actions: set[str] = set()
        for a in self.actions:
            if a.id in seen_actions:
                raise GraphError(f"duplicate action id {a.id!r}")
            seen_actions.add(a.id)
            if not isinstance(a.cost, int) or isinstance(a.cost, bool):
                raise GraphError(f"action {a.id!r}: cost must be an int, got {a.cost!r}")
            if a.cost < 0:
                raise GraphError(f"action {a.id!r}: cost must be >= 0, got {a.cost}")
            if not a.elements:
                raise GraphError(f"action {a.id!r} removes nothing")
            for n in a.removes_nodes:
                if n not in self.nodes:
                    raise GraphError(f"action {a.id!r} removes unknown node {n!r}")
            for k in a.removes_edges:
                if k not in seen_edges:
                    raise GraphError(f"action {a.id!r} removes unknown edge {k}")

        for group, label in ((self.compromised, "compromised"), (self.crown_jewels, "crown jewel")):
            for n in group:
                if n not in self.nodes:
                    raise GraphError(f"{label} node {n!r} is not in the graph")
        if not self.compromised:
            raise GraphError("no compromised node given: there is nothing to contain")
        if not self.crown_jewels:
            raise GraphError("no crown jewels given: there is nothing to protect")


# ---- (de)serialisation --------------------------------------------------------


def _edge_key_from(raw: Any) -> EdgeKey:
    if isinstance(raw, (list, tuple)) and len(raw) == 3:
        return (str(raw[0]), str(raw[1]), str(raw[2]))
    raise GraphError(f"edge reference must be [source, target, relation], got {raw!r}")


def graph_from_dict(data: Mapping[str, Any]) -> TenantGraph:
    version = data.get("version", SCHEMA_VERSION)
    if version != SCHEMA_VERSION:
        raise GraphError(f"unsupported graph schema version {version!r} (expected {SCHEMA_VERSION})")

    nodes: dict[str, Node] = {}
    for raw in data.get("nodes", []):
        if "id" not in raw:
            raise GraphError(f"node without an id: {raw!r}")
        node = Node(
            id=str(raw["id"]),
            kind=str(raw.get("kind", "unknown")),
            label=str(raw.get("label", "")),
            attrs={k: v for k, v in raw.items() if k not in {"id", "kind", "label"}},
        )
        if node.id in nodes:
            raise GraphError(f"duplicate node id {node.id!r}")
        nodes[node.id] = node

    edges = [
        Edge(
            source=str(raw["source"]),
            target=str(raw["target"]),
            relation=str(raw.get("relation", "controls")),
            attrs={k: v for k, v in raw.items() if k not in {"source", "target", "relation"}},
        )
        for raw in data.get("edges", [])
    ]

    actions = [
        Action(
            id=str(raw["id"]),
            kind=str(raw.get("kind", "custom")),
            cost=raw.get("cost", 0),
            title=str(raw.get("title", raw["id"])),
            removes_nodes=frozenset(str(n) for n in raw.get("removes_nodes", ())),
            removes_edges=frozenset(_edge_key_from(k) for k in raw.get("removes_edges", ())),
            rationale=str(raw.get("rationale", "")),
            target_ref=dict(raw.get("target_ref", {})),
            reversible=bool(raw.get("reversible", True)),
        )
        for raw in data.get("actions", [])
    ]

    graph = TenantGraph(
        nodes=nodes,
        edges=edges,
        actions=actions,
        compromised=tuple(str(n) for n in data.get("compromised", ())),
        crown_jewels=tuple(str(n) for n in data.get("crown_jewels", ())),
        tenant=str(data.get("tenant", "")),
    )
    return graph


def load_graph(path: str | Path) -> TenantGraph:
    with open(path, "r", encoding="utf-8") as fh:
        return graph_from_dict(json.load(fh))
