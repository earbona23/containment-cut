"""Rendering a plan for humans, for pipelines, and for a diagram.

One rule runs through all three: never print a number without printing what backs it.
"Cost 185" on its own is a claim; "cost 185, and here is the flow of value 185 that proves
no cheaper plan exists" is a result.
"""

from __future__ import annotations

import json
from fractions import Fraction
from typing import Any

from .cut import STATUS_CONTAINED, STATUS_CUT_FOUND, STATUS_NO_CUT
from .model import TenantGraph
from .plan import METHOD_EXACT, ContainmentPlan

RESET, BOLD, DIM, RED, GREEN, YELLOW, CYAN = (
    "\033[0m", "\033[1m", "\033[2m", "\033[31m", "\033[32m", "\033[33m", "\033[36m",
)


def _paint(enabled: bool):
    if enabled:
        return lambda text, code: f"{code}{text}{RESET}"
    return lambda text, _code: text


def terminal(plan: ContainmentPlan, graph: TenantGraph, color: bool = True) -> str:
    c = _paint(color)
    out: list[str] = []
    out.append(c("containment-cut", BOLD) + c("  ·  DRY RUN. Nothing was changed.", DIM))
    if graph.tenant:
        out.append(c(f"tenant: {graph.tenant}", DIM))
    out.append("")

    out.append(c("Compromised:", BOLD) + " " + ", ".join(graph.nodes[n].display for n in graph.compromised))
    out.append(c("Crown jewels:", BOLD) + " " + ", ".join(graph.nodes[n].display for n in graph.crown_jewels))

    if plan.status == STATUS_CONTAINED:
        out.append("")
        out.append(c("ALREADY CONTAINED", GREEN) + " — no crown jewel is reachable from the compromised set.")
        return "\n".join(out)

    exposed = ", ".join(graph.nodes[j].display for j in plan.jewels_exposed_before)
    out.append(c("Exposed now:", RED) + " " + exposed)

    if plan.status == STATUS_NO_CUT:
        out.append("")
        out.append(c("NO CUT POSSIBLE", RED))
        for note in plan.notes:
            out.append("  " + note)
        return "\n".join(out)

    out.append("")
    out.append(c(f"MINIMUM CONTAINMENT CUT — {len(plan.steps)} actions, cost {plan.total_cost}", BOLD))
    if plan.method == METHOD_EXACT:
        proved = plan.certificate is not None and plan.certificate.ok
        out.append(
            c("  PROVED OPTIMAL", GREEN) + c(" (max-flow certificate verified)", DIM)
            if proved
            else c("  OPTIMALITY NOT PROVED — certificate failed", RED)
        )
    else:
        bound = plan.approximation_bound or Fraction(1)
        out.append(
            c("  APPROXIMATE", YELLOW)
            + f" — bundled actions make this NP-hard. Guarantee: cost <= H({plan.max_set_size}) · OPT"
            + f" = {float(bound):.3f} · OPT"
        )
        if plan.lower_bound is not None and plan.lower_bound > 0:
            gap = float(Fraction(plan.total_cost) / plan.lower_bound)
            verdict = "PROVED OPTIMAL for this instance" if gap == 1.0 else f"at most {gap:.3f}x optimal"
            out.append(f"  Certified lower bound {float(plan.lower_bound):.2f} → {verdict}")
    out.append("")

    for step in plan.steps:
        flag = "" if step.action.reversible else c("  [IRREVERSIBLE]", YELLOW)
        out.append(c(f"  {step.order}. {step.action.title}", BOLD) + c(f"   cost {step.action.cost}", DIM) + flag)
        if step.action.rationale:
            out.append(c(f"     why: {step.action.rationale}", DIM))
        for command in step.commands:
            head = f"     $ [{command.tool}] "
            body = command.text.replace("\n", "\n     " + " " * (len(head) - 5))
            out.append(c(head + body, CYAN))
            if command.note:
                out.append(c(f"       ! {command.note}", DIM))
            if command.docs:
                out.append(c(f"       ref {command.docs}", DIM))
        remaining = step.jewels_reachable_after
        state = (
            c("crown jewels reachable: none", GREEN)
            if not remaining
            else c(f"crown jewels still reachable: {', '.join(remaining)}", YELLOW)
        )
        out.append(f"     → after this step, {state}")
        out.append("")

    # When each jewel actually stops being reachable -- measured from the progress curve,
    # not assumed. A responder interrupted at step k needs to know exactly what is still
    # open, and "the plan is atomic" is a claim that has to be true to be printed.
    closed_at: dict[str, int] = {}
    for step in plan.steps:
        for jewel in plan.jewels_exposed_before:
            if jewel not in closed_at and jewel not in step.jewels_reachable_after:
                closed_at[jewel] = step.order
    if closed_at:
        out.append(c("Where the exposure actually closes", BOLD))
        for jewel, order in sorted(closed_at.items(), key=lambda kv: kv[1]):
            out.append(f"  · {graph.nodes[jewel].display}: contained after step {order}")
        last = max(closed_at.values())
        if last == len(plan.steps) and len(plan.steps) > 1:
            out.append(
                c("  Nothing is contained until the plan is finished. ", YELLOW)
                + "Stopping early leaves a live path."
            )
        out.append("")

    if plan.baselines:
        out.append(c("What this saved you", BOLD))
        for baseline in plan.baselines:
            if not baseline.available:
                out.append(f"  · {baseline.name}: not available — {baseline.note}")
                continue
            verdict = "" if baseline.is_a_cut else c("  ← DOES NOT CONTAIN THE INCIDENT", RED)
            ratio = f" ({baseline.cost / plan.total_cost:.1f}x this plan)" if plan.total_cost else ""
            out.append(f"  · {baseline.name}: cost {baseline.cost}{ratio}{verdict}")
            if baseline.note and baseline.is_a_cut:
                out.append(c(f"      {baseline.note}", DIM))
        out.append("")

    for note in plan.notes:
        out.append(c("  note: " + note, DIM))
    if plan.certificate is not None and not plan.certificate.ok:
        out.append(c("  CERTIFICATE FAILED:", RED))
        for reason in plan.certificate.reasons:
            out.append(c("    - " + reason, RED))
    return "\n".join(out)


def to_dict(plan: ContainmentPlan, graph: TenantGraph) -> dict[str, Any]:
    return {
        "tool": "containment-cut",
        "mode": "dry-run",
        "tenant": graph.tenant,
        "status": plan.status,
        "method": plan.method,
        "total_cost": plan.total_cost,
        "optimality_proved": plan.optimal,
        "compromised": list(graph.compromised),
        "crown_jewels": list(graph.crown_jewels),
        "jewels_exposed_before": plan.jewels_exposed_before,
        "certificate": None
        if plan.certificate is None
        else {"ok": plan.certificate.ok, "checks": plan.certificate.checks, "reasons": plan.certificate.reasons},
        "approximation": None
        if plan.method == METHOD_EXACT
        else {
            "np_hard_because": "at least one action removes more than one graph element",
            "guarantee": f"cost <= H({plan.max_set_size}) * OPT",
            "guarantee_value": float(plan.approximation_bound or 1),
            "lower_bound": float(plan.lower_bound or 0),
            "certified_gap": (
                float(Fraction(plan.total_cost) / plan.lower_bound)
                if plan.lower_bound
                else None
            ),
            "rounds": plan.rounds,
        },
        "steps": [
            {
                "order": step.order,
                "action_id": step.action.id,
                "kind": step.action.kind,
                "title": step.action.title,
                "cost": step.action.cost,
                "reversible": step.action.reversible,
                "rationale": step.action.rationale,
                "removes_nodes": sorted(step.action.removes_nodes),
                "removes_edges": [list(k) for k in sorted(step.action.removes_edges)],
                "commands": [
                    {"tool": c.tool, "command": c.text, "note": c.note, "docs": c.docs}
                    for c in step.commands
                ],
                "jewels_reachable_after": step.jewels_reachable_after,
            }
            for step in plan.steps
        ],
        "baselines": [
            {
                "name": b.name,
                "available": b.available,
                "cost": b.cost,
                "contains_the_incident": b.is_a_cut,
                "note": b.note,
            }
            for b in plan.baselines
        ],
        "notes": plan.notes,
    }


def to_json(plan: ContainmentPlan, graph: TenantGraph) -> str:
    return json.dumps(to_dict(plan, graph), indent=2)


def _safe(node_id: str) -> str:
    return "".join(ch if ch.isalnum() else "_" for ch in node_id)


def mermaid(plan: ContainmentPlan, graph: TenantGraph) -> str:
    """The graph with the cut drawn on it. Cut elements are dashed and marked."""
    cut_nodes = {n for step in plan.steps for n in step.action.removes_nodes}
    cut_edges = {k for step in plan.steps for k in step.action.removes_edges}
    lines = ["flowchart LR"]
    for node in graph.nodes.values():
        shape = f'["{node.display}"]'
        if node.id in graph.crown_jewels:
            shape = f'{{{{"{node.display}"}}}}'
        elif node.id in graph.compromised:
            shape = f'(("{node.display}"))'
        lines.append(f"  {_safe(node.id)}{shape}")
    for edge in graph.edges:
        arrow = "-.->" if edge.key in cut_edges else "-->"
        label = f"|{edge.relation}{' ✂' if edge.key in cut_edges else ''}|"
        lines.append(f"  {_safe(edge.source)} {arrow}{label} {_safe(edge.target)}")
    lines.append("  classDef compromised fill:#c0392b,stroke:#7b241c,color:#fff;")
    lines.append("  classDef jewel fill:#1e8449,stroke:#145a32,color:#fff;")
    lines.append("  classDef cut fill:#f39c12,stroke:#9c640c,color:#000;")
    if graph.compromised:
        lines.append("  class " + ",".join(_safe(n) for n in graph.compromised) + " compromised;")
    if graph.crown_jewels:
        lines.append("  class " + ",".join(_safe(n) for n in graph.crown_jewels) + " jewel;")
    if cut_nodes:
        lines.append("  class " + ",".join(_safe(n) for n in sorted(cut_nodes)) + " cut;")
    return "\n".join(lines)


def markdown(plan: ContainmentPlan, graph: TenantGraph) -> str:
    out = ["# Containment plan (DRY RUN — nothing was changed)", ""]
    if graph.tenant:
        out += [f"**Tenant:** {graph.tenant}", ""]
    out += [
        f"**Compromised:** {', '.join(graph.nodes[n].display for n in graph.compromised)}",
        "",
        f"**Crown jewels:** {', '.join(graph.nodes[n].display for n in graph.crown_jewels)}",
        "",
    ]
    if plan.status != STATUS_CUT_FOUND:
        out += [f"**Status:** `{plan.status}`", ""] + plan.notes
        return "\n".join(out)

    out += [
        f"**Total business impact:** {plan.total_cost} · "
        + ("**proved optimal**" if plan.optimal else "approximate")
        + f" · method `{plan.method}`",
        "",
        "| # | Action | Cost | Reversible | Jewels reachable after |",
        "|---|--------|-----:|:----------:|------------------------|",
    ]
    for step in plan.steps:
        remaining = ", ".join(step.jewels_reachable_after) or "none"
        out.append(
            f"| {step.order} | {step.action.title} | {step.action.cost} | "
            f"{'yes' if step.action.reversible else '**no**'} | {remaining} |"
        )
    out += ["", "## Commands", ""]
    for step in plan.steps:
        out += [f"### {step.order}. {step.action.title}", ""]
        if step.action.rationale:
            out += [f"> {step.action.rationale}", ""]
        for command in step.commands:
            out += [f"```{command.tool}", command.text, "```", ""]
            if command.note:
                out += [f"*{command.note}*", ""]
    out += ["## Graph", "", "```mermaid", mermaid(plan, graph), "```", ""]
    return "\n".join(out)
