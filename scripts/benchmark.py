#!/usr/bin/env python3
"""How big a tenant can this chew through, and how does it grow?

Generates synthetic tenants with the shape of a real directory -- users, groups, roles,
applications, service principals, a few resources -- at increasing scale, and times the
end-to-end `solve()` (graph load, action catalogue, node splitting, max flow, cut
extraction, certificate verification, plan ordering, progress curve).

Reported numbers are wall clock on one machine and mean nothing as absolutes. What they
show is the SHAPE of the growth, which is the only thing a complexity claim can be
checked against.

    python3 scripts/benchmark.py             # default ladder
    python3 scripts/benchmark.py --max 40000
"""

from __future__ import annotations

import argparse
import random
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from containment_cut.model import Action, Edge, Node, TenantGraph  # noqa: E402
from containment_cut.plan import solve  # noqa: E402


def synthetic_tenant(users: int, seed: int = 0, compromised_fraction: float = 0.005) -> TenantGraph:
    """A directory-shaped random tenant: ~1 group per 20 users, ~1 app per 40 users.

    Deliberately NOT an easy instance. A single compromised user with three memberships
    has a three-arc cut, and timing that measures graph construction, not max flow. So a
    fraction of the population is compromised and account disablement is priced out of
    reach, which forces a wide surgical cut and a max flow whose value grows with the
    tenant -- i.e. the case the complexity bound is actually about.
    """
    rng = random.Random(seed)
    groups = max(2, users // 20)
    apps = max(2, users // 40)
    roles = max(2, apps // 4)

    nodes: dict[str, Node] = {}
    edges: list[Edge] = []
    actions: list[Action] = []

    def add(node_id: str, kind: str) -> None:
        nodes[node_id] = Node(node_id, kind, node_id)

    for i in range(users):
        add(f"u{i}", "user")
    for i in range(groups):
        add(f"g{i}", "group")
    for i in range(apps):
        add(f"app{i}", "application")
        add(f"sp{i}", "servicePrincipal")
    for i in range(roles):
        add(f"role{i}", "role")
    add("jewel", "resource")

    seen: set[tuple[str, str, str]] = set()

    def link(src: str, dst: str, relation: str, cost: int | None) -> None:
        edge = Edge(src, dst, relation)
        if edge.key in seen:   # random generation happily proposes the same membership twice
            return
        seen.add(edge.key)
        edges.append(edge)
        if cost is not None:
            actions.append(
                Action(id=f"e{len(actions)}", kind="remove_group_member", cost=cost,
                       title="cut", removes_edges=frozenset({edge.key}))
            )

    for i in range(users):
        for _ in range(rng.randint(1, 3)):
            link(f"u{i}", f"g{rng.randrange(groups)}", "memberOf", rng.randint(5, 60))
        if rng.random() < 0.15:
            link(f"u{i}", f"app{rng.randrange(apps)}", "owns", rng.randint(10, 50))
    for i in range(apps):
        link(f"app{i}", f"sp{i}", "hasServicePrincipal", None)
        link(f"sp{i}", f"role{rng.randrange(roles)}", "hasAppRole", rng.randint(20, 90))
    for i in range(groups):
        link(f"g{i}", f"role{rng.randrange(roles)}", "hasRoleAssignment", rng.randint(15, 70))
    for i in range(roles):
        link(f"role{i}", "jewel", "grantsAccessTo", None)

    # Disablement priced out of reach on purpose: it would collapse every instance to
    # "one action per compromised user" and the benchmark would measure nothing.
    for i in range(users):
        actions.append(
            Action(id=f"n{i}", kind="disable_user", cost=100_000,
                   title="disable", removes_nodes=frozenset({f"u{i}"}))
        )

    breached = max(1, int(users * compromised_fraction))
    graph = TenantGraph(nodes=nodes, edges=edges, actions=actions,
                        compromised=tuple(f"u{i}" for i in range(breached)),
                        crown_jewels=("jewel",))
    graph.validate()
    return graph


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--max", type=int, default=20000)
    parser.add_argument("--seed", type=int, default=1)
    args = parser.parse_args()

    ladder = [n for n in (100, 500, 1000, 2500, 5000, 10000, 20000, 40000, 80000) if n <= args.max]
    print(f"{'users':>8} {'nodes':>8} {'edges':>8} {'actions':>8} {'breached':>9} "
          f"{'build s':>9} {'solve s':>9} {'cost':>9} {'steps':>6}")
    for users in ladder:
        t0 = time.perf_counter()
        graph = synthetic_tenant(users, seed=args.seed)
        t1 = time.perf_counter()
        plan = solve(graph)
        t2 = time.perf_counter()
        assert plan.optimal, "benchmark instance was not solved to a proved optimum"
        print(
            f"{users:>8} {len(graph.nodes):>8} {len(graph.edges):>8} {len(graph.actions):>8} "
            f"{len(graph.compromised):>9} {t1 - t0:>9.3f} {t2 - t1:>9.3f} "
            f"{plan.total_cost:>9} {len(plan.steps):>6}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
