"""Input validation. Every one of these used to be a silent wrong answer."""

import json

import pytest

from containment_cut.model import Action, Edge, GraphError, Node, TenantGraph, graph_from_dict
from conftest import DEMO_PATH, make_graph


def base():
    return make_graph({"a": "user", "j": "resource"}, [("a", "j", "c")], ["a"], ["j"],
                      edge_costs={("a", "j", "c"): 1})


def test_unknown_edge_endpoint_is_rejected():
    g = base()
    g.edges.append(Edge("a", "ghost", "c"))
    with pytest.raises(GraphError, match="ghost"):
        g.validate()


def test_duplicate_edge_is_rejected():
    g = base()
    g.edges.append(Edge("a", "j", "c"))
    with pytest.raises(GraphError, match="duplicate edge"):
        g.validate()


def test_action_removing_an_unknown_node_is_rejected():
    g = base()
    g.actions.append(Action("x", "custom", 1, "x", removes_nodes=frozenset({"nope"})))
    with pytest.raises(GraphError, match="nope"):
        g.validate()


def test_action_removing_an_unknown_edge_is_rejected():
    g = base()
    g.actions.append(Action("x", "custom", 1, "x", removes_edges=frozenset({("a", "j", "other")})))
    with pytest.raises(GraphError, match="unknown edge"):
        g.validate()


@pytest.mark.parametrize("cost", [-1, 1.5, "3", True])
def test_bad_costs_are_rejected(cost):
    g = base()
    g.actions.append(Action("x", "custom", cost, "x", removes_nodes=frozenset({"a"})))
    with pytest.raises(GraphError):
        g.validate()


def test_action_that_removes_nothing_is_rejected():
    g = base()
    g.actions.append(Action("x", "custom", 1, "x"))
    with pytest.raises(GraphError, match="removes nothing"):
        g.validate()


def test_missing_compromised_or_jewels_is_rejected():
    g = base()
    g.compromised = ()
    with pytest.raises(GraphError, match="nothing to contain"):
        g.validate()
    g = base()
    g.crown_jewels = ()
    with pytest.raises(GraphError, match="nothing to protect"):
        g.validate()


def test_unknown_schema_version_is_rejected():
    with pytest.raises(GraphError, match="schema version"):
        graph_from_dict({"version": 99, "nodes": [], "edges": []})


def test_duplicate_node_id_is_rejected():
    with pytest.raises(GraphError, match="duplicate node"):
        graph_from_dict({"version": 1, "nodes": [{"id": "a"}, {"id": "a"}], "edges": []})


def test_demo_file_round_trips_and_validates():
    data = json.loads(DEMO_PATH.read_text(encoding="utf-8"))
    graph = graph_from_dict(data)
    assert graph.tenant.startswith("contoso-demo")
    assert len(graph.nodes) == len(data["nodes"])
    assert len(graph.edges) == len(data["edges"])


def test_parallel_edges_with_different_relations_are_distinct():
    graph = TenantGraph(
        nodes={"a": Node("a", "user"), "b": Node("b", "user")},
        edges=[Edge("a", "b", "owns"), Edge("a", "b", "memberOf")],
        actions=[Action("x", "custom", 1, "x", removes_edges=frozenset({("a", "b", "owns")}))],
        compromised=("a",),
        crown_jewels=("b",),
    )
    graph.validate()
    assert graph.exposed_jewels(frozenset(), frozenset({("a", "b", "owns")})) == ["b"]
    assert graph.exposed_jewels(
        frozenset(), frozenset({("a", "b", "owns"), ("a", "b", "memberOf")})
    ) == []
