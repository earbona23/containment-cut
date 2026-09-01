"""From a cut to a plan: pick the solver, order the steps, and say what is proven.

The set of actions and its total cost come from the solver and are not negotiable. What
this module adds is everything an operator needs to act on it:

* the order to run them in, which changes nothing mathematically and everything
  operationally;
* the *progress curve* -- how many crown jewels are still reachable after each step --
  computed, not asserted. It is usually flat until the last step, and that flatness is
  the most useful thing on the page: it says the plan is atomic, and stopping halfway
  contains nothing;
* the comparison against what a responder does by reflex, which is the only honest way
  to claim the tool was worth running.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from fractions import Fraction
from typing import Mapping

from . import bundles as bundles_mod
from .catalog import with_actions
from .commands import Command, render
from .cut import (
    STATUS_CONTAINED,
    STATUS_CUT_FOUND,
    STATUS_NO_CUT,
    CertificateReport,
    CutResult,
    Element,
    min_cut,
    verify_certificate,
)
from .model import Action, EdgeKey, TenantGraph

METHOD_EXACT = "exact-min-cut"
METHOD_GREEDY = "greedy-cover"

# Operational urgency. Lower runs first. This orders the plan; it never changes it.
_TIER = {
    "rotate_credential": 0,
    "revoke_oauth2_grant": 1,
    "remove_owner": 1,
    "remove_group_member": 1,
    "remove_directory_role_assignment": 1,
    "remove_azure_role_assignment": 1,
    "remove_app_role_grant": 1,
    "remove_app_role_assignment": 1,
    "disable_device": 2,
    "disable_user": 2,
    "disable_service_principal": 3,
}


@dataclass(slots=True)
class Step:
    order: int
    action: Action
    commands: list[Command]
    jewels_reachable_after: list[str]


@dataclass(slots=True)
class Baseline:
    """What gets done without this tool, priced with the same cost model."""

    name: str
    available: bool
    cost: int | None
    is_a_cut: bool
    note: str = ""


@dataclass(slots=True)
class ContainmentPlan:
    status: str
    method: str
    total_cost: int
    steps: list[Step]
    jewels_exposed_before: list[str]
    certificate: CertificateReport | None
    baselines: list[Baseline] = field(default_factory=list)
    # bundled-case reporting; None when the exact solver was used
    lower_bound: Fraction | None = None
    approximation_bound: Fraction | None = None
    max_set_size: int | None = None
    rounds: int | None = None
    notes: list[str] = field(default_factory=list)

    @property
    def optimal(self) -> bool:
        """True only when optimality is *proved* for this run, not merely likely."""
        if self.status != STATUS_CUT_FOUND:
            return False
        if self.method == METHOD_EXACT:
            return self.certificate is not None and self.certificate.ok
        return self.lower_bound is not None and Fraction(self.total_cost) == self.lower_bound


def atomic_element_costs(actions: list[Action]) -> tuple[dict[Element, int], dict[Element, Action]]:
    """Cheapest single-element action per element. Only defined when nothing is bundled."""
    cost: dict[Element, int] = {}
    by: dict[Element, Action] = {}
    for action in actions:
        if action.is_bundle:
            continue
        (element,) = tuple(action.elements)
        if element not in cost or action.cost < cost[element]:
            cost[element] = action.cost
            by[element] = action
    return cost, by


def _order(actions: list[Action]) -> list[Action]:
    return sorted(actions, key=lambda a: (_TIER.get(a.kind, 2), a.cost, a.id))


def _progress(graph: TenantGraph, ordered: list[Action]) -> list[list[str]]:
    curve: list[list[str]] = []
    nodes: set[str] = set()
    edges: set[EdgeKey] = set()
    for action in ordered:
        nodes |= set(action.removes_nodes)
        edges |= set(action.removes_edges)
        curve.append(graph.exposed_jewels(frozenset(nodes), frozenset(edges)))
    return curve


def _baselines(graph: TenantGraph) -> list[Baseline]:
    out: list[Baseline] = []

    # "Disable everything the attacker touched" -- the reflex.
    picks: list[Action] = []
    missing: list[str] = []
    for node_id in graph.compromised:
        candidates = [
            a
            for a in graph.actions
            if a.removes_nodes == frozenset({node_id}) and not a.removes_edges
        ]
        if not candidates:
            missing.append(node_id)
        else:
            picks.append(max(candidates, key=lambda a: a.cost))
    if missing:
        out.append(
            Baseline(
                "disable every compromised principal",
                available=False,
                cost=None,
                is_a_cut=False,
                note=f"no disable action exists for {', '.join(missing)}",
            )
        )
    else:
        nodes = frozenset(n for a in picks for n in a.removes_nodes)
        edges = frozenset(k for a in picks for k in a.removes_edges)
        still = graph.exposed_jewels(nodes, edges)
        out.append(
            Baseline(
                "disable every compromised principal",
                available=True,
                cost=sum(a.cost for a in picks),
                is_a_cut=not still,
                note="" if not still else f"and it still leaves {', '.join(still)} reachable",
            )
        )

    # "Block all the apps" -- the second reflex, and the one that quietly fails. Disabling
    # every service principal the attacker can reach feels decisive; it does nothing to a
    # route that runs through a group and an Azure role assignment. Priced and checked
    # here so the plan can say so rather than imply it.
    reachable = graph.reachable(graph.compromised)
    sp_actions = [
        a
        for a in graph.actions
        if a.kind == "disable_service_principal" and (a.removes_nodes & reachable)
    ]
    if sp_actions:
        nodes = frozenset(n for a in sp_actions for n in a.removes_nodes)
        still = graph.exposed_jewels(nodes, frozenset())
        out.append(
            Baseline(
                "disable every reachable service principal",
                available=True,
                cost=sum(a.cost for a in sp_actions),
                is_a_cut=not still,
                note="" if not still else f"and it does NOT contain the incident: {', '.join(still)} stays reachable",
            )
        )

    # "Cut everything you can" -- the panic option.
    nodes = frozenset(n for a in graph.actions for n in a.removes_nodes if n not in graph.crown_jewels)
    edges = frozenset(k for a in graph.actions for k in a.removes_edges)
    still = graph.exposed_jewels(nodes, edges)
    covering = [a for a in graph.actions if not (a.removes_nodes & frozenset(graph.crown_jewels))]
    out.append(
        Baseline(
            "take every available action",
            available=True,
            cost=sum(a.cost for a in covering),
            is_a_cut=not still,
            note="the upper bound on damage a responder can do",
        )
    )
    return out


def solve(graph: TenantGraph, costs: Mapping[str, int] | None = None) -> ContainmentPlan:
    """Compute a containment plan. Never mutates the tenant; never touches the network."""
    graph = with_actions(graph, costs)
    graph.validate()

    exposed_before = graph.exposed_jewels()
    if not exposed_before:
        return ContainmentPlan(
            status=STATUS_CONTAINED,
            method=METHOD_EXACT,
            total_cost=0,
            steps=[],
            jewels_exposed_before=[],
            certificate=None,
            notes=["No crown jewel is reachable from the compromised set. Nothing to cut."],
        )

    if bundles_mod.has_bundles(graph.actions):
        return _solve_bundled(graph, exposed_before)
    return _solve_exact(graph, exposed_before)


def _finish(
    graph: TenantGraph,
    chosen: list[Action],
    method: str,
    certificate: CertificateReport | None,
    exposed_before: list[str],
    **extra,
) -> ContainmentPlan:
    ordered = _order(chosen)
    curve = _progress(graph, ordered)
    steps = [
        Step(order=i + 1, action=a, commands=render(a), jewels_reachable_after=curve[i])
        for i, a in enumerate(ordered)
    ]
    return ContainmentPlan(
        status=STATUS_CUT_FOUND,
        method=method,
        total_cost=sum(a.cost for a in chosen),
        steps=steps,
        jewels_exposed_before=exposed_before,
        certificate=certificate,
        baselines=_baselines(graph),
        **extra,
    )


def _solve_exact(graph: TenantGraph, exposed_before: list[str]) -> ContainmentPlan:
    element_cost, action_for = atomic_element_costs(graph.actions)
    result: CutResult = min_cut(graph, element_cost)
    certificate = verify_certificate(graph, result)

    if result.status == STATUS_NO_CUT:
        return ContainmentPlan(
            status=STATUS_NO_CUT,
            method=METHOD_EXACT,
            total_cost=0,
            steps=[],
            jewels_exposed_before=exposed_before,
            certificate=certificate,
            baselines=_baselines(graph),
            notes=[
                "There is a route from the compromised set to a crown jewel made entirely "
                "of elements no available action can remove. Widen the action catalogue "
                "or accept that containment here needs a change outside this model.",
            ],
        )

    chosen = [action_for[e] for e in result.elements]
    return _finish(graph, chosen, METHOD_EXACT, certificate, exposed_before)


def _solve_bundled(graph: TenantGraph, exposed_before: list[str]) -> ContainmentPlan:
    result = bundles_mod.solve_bundled(graph)
    if result.status == STATUS_NO_CUT:
        return ContainmentPlan(
            status=STATUS_NO_CUT,
            method=METHOD_GREEDY,
            total_cost=0,
            steps=[],
            jewels_exposed_before=exposed_before,
            certificate=None,
            baselines=_baselines(graph),
            notes=["Some route to a crown jewel is untouchable by every available action."],
        )

    chosen = list(result.actions)
    nodes = frozenset(n for a in chosen for n in a.removes_nodes)
    edges = frozenset(k for a in chosen for k in a.removes_edges)
    still = graph.exposed_jewels(nodes, edges)
    certificate = CertificateReport(
        ok=not still,
        checks={"sufficiency": not still, "duality": False},
        reasons=[]
        if not still
        else [f"after the plan these jewels are still reachable: {still}"],
    )
    notes = [
        "At least one action removes several graph elements at once, so this instance is "
        "NP-hard and the plan is an approximation, not a proved optimum.",
    ]
    if result.certified_gap == 1:
        notes.append(
            "The instance-specific lower bound equals the plan's cost, which proves this "
            "particular plan IS optimal."
        )
    return _finish(
        graph,
        chosen,
        METHOD_GREEDY,
        certificate,
        exposed_before,
        lower_bound=result.lower_bound,
        approximation_bound=result.approximation_bound,
        max_set_size=result.max_set_size,
        rounds=result.rounds,
        notes=notes,
    )
