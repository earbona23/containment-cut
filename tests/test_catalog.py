"""The default catalogue: what it will and will not offer to destroy."""

from containment_cut.catalog import INHERENT_RELATIONS, derive_actions, with_actions
from containment_cut.model import Edge, Node, TenantGraph


def tiny(relation: str, **edge_attrs) -> TenantGraph:
    edge = Edge("u", "g", relation, attrs=edge_attrs)
    return TenantGraph(
        nodes={"u": Node("u", "user"), "g": Node("g", "group")},
        edges=[edge],
        compromised=("u",),
        crown_jewels=("g",),
    )


def test_inherent_relations_produce_no_action():
    for relation in INHERENT_RELATIONS:
        actions = derive_actions(tiny(relation))
        assert all(not a.removes_edges for a in actions), relation


def test_removable_false_removes_the_action():
    assert any(a.removes_edges for a in derive_actions(tiny("memberOf")))
    assert not any(a.removes_edges for a in derive_actions(tiny("memberOf", removable=False)))


def test_cost_override_wins_over_the_default():
    actions = derive_actions(tiny("memberOf", containment_cost=7))
    edge_action = next(a for a in actions if a.removes_edges)
    assert edge_action.cost == 7


def test_credential_is_a_node_and_rotation_is_irreversible():
    graph = TenantGraph(
        nodes={"c": Node("c", "credential"), "s": Node("s", "servicePrincipal")},
        edges=[Edge("c", "s", "authenticatesAs")],
        compromised=("c",),
        crown_jewels=("s",),
    )
    actions = derive_actions(graph)
    rotate = next(a for a in actions if a.kind == "rotate_credential")
    assert rotate.removes_nodes == frozenset({"c"})
    assert rotate.reversible is False
    # `authenticatesAs` is how the platform works, not configuration: no edge action.
    assert not any(a.removes_edges for a in actions)


def test_groups_roles_and_permissions_have_no_node_action():
    """You contain a group by removing a membership, not by deleting the group."""
    for kind in ("group", "role", "permission", "resource", "application"):
        graph = TenantGraph(
            nodes={"x": Node("x", kind), "j": Node("j", "resource")},
            edges=[Edge("x", "j", "grantsAccessTo")],
            compromised=("x",),
            crown_jewels=("j",),
        )
        assert derive_actions(graph) == []


def test_declared_actions_are_taken_at_their_word():
    graph = tiny("memberOf")
    from containment_cut.model import Action

    graph.actions = [Action("only", "custom", 1, "only", removes_nodes=frozenset({"u"}))]
    assert [a.id for a in with_actions(graph).actions] == ["only"]


def test_pricing_an_inherent_relation_does_not_make_it_cuttable():
    """`canAssign` is what a permission MEANS. A cost on it must not create an action.

    Without this the INHERENT_RELATIONS guard is dead code — every inherent relation is
    also absent from EDGE_ACTIONS, so the guard never changes an outcome and a mutation
    that deletes it survives. Pricing is the case that separates them.
    """
    assert not any(a.removes_edges for a in derive_actions(tiny("canAssign", containment_cost=5)))


def test_a_tenant_can_override_inherency_explicitly_per_edge():
    actions = derive_actions(tiny("canAssign", containment_cost=5, removable=True))
    edge_action = next(a for a in actions if a.removes_edges)
    assert edge_action.kind == "remove_edge"
    assert edge_action.cost == 5


def test_an_unknown_relation_is_cuttable_only_when_the_graph_prices_it():
    assert not any(a.removes_edges for a in derive_actions(tiny("someCustomRelation")))
    actions = derive_actions(tiny("someCustomRelation", containment_cost=12))
    edge_action = next(a for a in actions if a.removes_edges)
    assert edge_action.kind == "remove_edge"
    assert edge_action.cost == 12


def test_remove_edge_renders_an_honest_placeholder_not_an_invented_call():
    from containment_cut.commands import render

    action = next(a for a in derive_actions(tiny("someCustomRelation", containment_cost=12)) if a.removes_edges)
    text = render(action)[0].text
    assert "someCustomRelation" in text
    assert "graph.microsoft.com" not in text
