"""Ordering, the progress curve, the baselines, and every output format."""

import json

from containment_cut import report
from containment_cut.cut import STATUS_CONTAINED, STATUS_NO_CUT
from containment_cut.model import Action
from containment_cut.plan import solve
from conftest import make_graph


def test_ordering_puts_credential_rotation_first_and_disablement_last(demo_graph):
    plan = solve(demo_graph)
    kinds = [step.action.kind for step in plan.steps]
    assert kinds[0] == "rotate_credential"
    assert kinds == sorted(kinds, key=lambda k: {"rotate_credential": 0}.get(k, 1))


def test_ordering_does_not_change_the_cost_or_the_set(demo_graph):
    plan = solve(demo_graph)
    assert plan.total_cost == sum(step.action.cost for step in plan.steps)
    assert len({step.action.id for step in plan.steps}) == len(plan.steps)


def test_already_contained_plan_is_empty_and_says_so():
    graph = make_graph({"a": "user", "j": "resource"}, [], ["a"], ["j"], node_costs={"a": 1})
    plan = solve(graph)
    assert plan.status == STATUS_CONTAINED
    assert plan.steps == []
    assert plan.optimal is False  # nothing was proved, because nothing was needed
    text = report.terminal(plan, graph, color=False)
    assert "ALREADY CONTAINED" in text


def test_no_cut_plan_refuses_rather_than_half_containing():
    graph = make_graph({"a": "user", "j": "resource"}, [("a", "j", "inherent")], ["a"], ["j"])
    graph.actions = [Action("noop", "custom", 1, "noop", removes_nodes=frozenset({"a"}))]
    graph.actions = []
    graph.actions = [Action("x", "custom", 1, "x", removes_nodes=frozenset({"j"}))]
    plan = solve(graph)
    assert plan.status == STATUS_NO_CUT
    assert plan.steps == []
    assert "NO CUT POSSIBLE" in report.terminal(plan, graph, color=False)


def test_json_output_is_valid_and_carries_the_certificate(demo_graph):
    plan = solve(demo_graph)
    data = json.loads(report.to_json(plan, demo_graph))
    assert data["mode"] == "dry-run"
    assert data["optimality_proved"] is True
    assert data["certificate"]["ok"] is True
    assert set(data["certificate"]["checks"]) == {
        "capacity", "conservation", "flow-value", "duality", "sufficiency"
    }
    assert len(data["steps"]) == 5
    assert all(step["commands"] for step in data["steps"])


def test_markdown_and_mermaid_render(demo_graph):
    plan = solve(demo_graph)
    md = report.markdown(plan, demo_graph)
    assert "# Containment plan (DRY RUN" in md
    assert "```mermaid" in md
    mm = report.mermaid(plan, demo_graph)
    assert mm.startswith("flowchart LR")
    assert "-.->" in mm  # at least one edge is drawn as cut
    assert mm.count("✂") == sum(len(s.action.removes_edges) for s in plan.steps)


def test_terminal_output_never_claims_more_than_it_proved(demo_graph):
    plan = solve(demo_graph)
    text = report.terminal(plan, demo_graph, color=False)
    assert "PROVED OPTIMAL" in text
    assert "DRY RUN" in text
    plan.certificate.ok = False
    plan.certificate.reasons = ["synthetic failure"]
    # A failed certificate must revoke the claim everywhere it is made, not just in prose.
    assert plan.optimal is False
    assert json.loads(report.to_json(plan, demo_graph))["optimality_proved"] is False
    broken = report.terminal(plan, demo_graph, color=False)
    assert "OPTIMALITY NOT PROVED" in broken
    assert "synthetic failure" in broken
