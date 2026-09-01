"""Max-flow on graphs whose optimum is known by hand or by theory."""

from fractions import Fraction

import pytest

from containment_cut.maxflow import FlowNetwork


def test_diamond_known_optimum():
    net = FlowNetwork(4)
    net.add_edge(0, 1, 3)
    net.add_edge(0, 2, 2)
    net.add_edge(1, 2, 1)
    net.add_edge(1, 3, 2)
    net.add_edge(2, 3, 3)
    # Source out-capacity is 5 and sink in-capacity is 5; both are achievable.
    assert net.max_flow(0, 3) == 5


def test_bottleneck_in_the_middle():
    net = FlowNetwork(4)
    net.add_edge(0, 1, 100)
    net.add_edge(1, 2, 1)
    net.add_edge(2, 3, 100)
    assert net.max_flow(0, 3) == 1


def test_disconnected_is_zero():
    net = FlowNetwork(3)
    net.add_edge(0, 1, 5)
    assert net.max_flow(0, 2) == 0
    assert net.residual_reachable(0) == {0, 1}


def test_antiparallel_edges():
    net = FlowNetwork(2)
    net.add_edge(0, 1, 4)
    net.add_edge(1, 0, 7)
    assert net.max_flow(0, 1) == 4


def test_parallel_edges_add_up():
    net = FlowNetwork(2)
    for cap in (1, 2, 3):
        net.add_edge(0, 1, cap)
    assert net.max_flow(0, 1) == 6


def test_fractions_are_exact():
    net = FlowNetwork(3, zero=Fraction(0))
    net.add_edge(0, 1, Fraction(1, 3))
    net.add_edge(1, 2, Fraction(1, 2))
    value = net.max_flow(0, 2)
    assert value == Fraction(1, 3)
    assert isinstance(value, Fraction)


def test_flow_conservation_holds_after_solving():
    net = FlowNetwork(6)
    arcs = [
        net.add_edge(0, 1, 10), net.add_edge(0, 2, 10),
        net.add_edge(1, 2, 2), net.add_edge(1, 3, 4), net.add_edge(1, 4, 8),
        net.add_edge(2, 4, 9), net.add_edge(3, 5, 10), net.add_edge(4, 3, 6),
        net.add_edge(4, 5, 10),
    ]
    value = net.max_flow(0, 5)
    assert value == 19  # classic CLRS-style instance
    balance = {}
    for arc in arcs:
        f = net.flow(arc)
        assert 0 <= f <= net.capacity(arc)
        balance[net.tail(arc)] = balance.get(net.tail(arc), 0) - f
        balance[net.head(arc)] = balance.get(net.head(arc), 0) + f
    for node in (1, 2, 3, 4):
        assert balance.get(node, 0) == 0
    assert -balance[0] == value


def test_source_equals_sink_is_rejected():
    net = FlowNetwork(2)
    with pytest.raises(ValueError):
        net.max_flow(0, 0)


def test_negative_capacity_is_rejected():
    net = FlowNetwork(2)
    with pytest.raises(ValueError):
        net.add_edge(0, 1, -1)


def test_long_chain_does_not_blow_the_stack():
    # The blocking-flow search is iterative on purpose; a recursive one dies around here.
    n = 8000
    net = FlowNetwork(n)
    for i in range(n - 1):
        net.add_edge(i, i + 1, 3)
    assert net.max_flow(0, n - 1) == 3
