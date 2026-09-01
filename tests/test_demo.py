"""The shipped demo tenant, pinned to numbers verified by exhaustive search.

If the catalogue, the cost model or the reduction drifts, these break. They are the
regression net for the example every reader will run first.
"""

from containment_cut.cut import STATUS_CUT_FOUND
from containment_cut.plan import METHOD_EXACT, solve
from conftest import brute_force_min_cost


def test_demo_optimum_equals_exhaustive_search(demo_graph):
    plan = solve(demo_graph)
    optimum, _ = brute_force_min_cost(demo_graph)
    assert plan.status == STATUS_CUT_FOUND
    assert plan.method == METHOD_EXACT
    assert optimum == 185
    assert plan.total_cost == 185
    assert plan.optimal


def test_demo_cut_is_exactly_these_five_actions(demo_graph):
    plan = solve(demo_graph)
    assert {step.action.id for step in plan.steps} == {
        "rotate_credential:cred:travelbot-secret-2",
        "remove_group_member:u:ana.reyes->g:helpdesk-tier1",
        "remove_group_member:u:ana.reyes->g:finance-app-admins",
        "remove_owner:u:ana.reyes->app:AcmeExpense",
        "remove_app_role_grant:sp:SelfServicePortal->perm:RoleManagement.ReadWrite.Directory",
    }


def test_demo_does_not_touch_the_irrelevant_grant(demo_graph):
    """The SharePoint delegated grant is real, cuttable and reaches nothing critical.

    A tool that lists it is padding the plan; during an incident that costs attention,
    which is the scarcest thing in the room.
    """
    plan = solve(demo_graph)
    assert all("sp-hr-site" not in step.action.id for step in plan.steps)


def test_demo_does_not_disable_the_payroll_analyst(demo_graph):
    """The whole point: contain her access without locking her out mid-payroll-run."""
    plan = solve(demo_graph)
    assert all(step.action.kind != "disable_user" for step in plan.steps)
    assert all(step.action.kind != "disable_service_principal" for step in plan.steps)


def test_demo_finds_the_action_far_from_the_compromise(demo_graph):
    """The Self-Service Portal permission is nowhere near the breached account.

    No reachability-from-the-victim heuristic proposes it; it comes out of the cut.
    """
    plan = solve(demo_graph)
    assert any("SelfServicePortal" in step.action.id for step in plan.steps)


def test_demo_baselines_are_worse_and_one_of_them_does_not_even_work(demo_graph):
    plan = solve(demo_graph)
    by_name = {b.name: b for b in plan.baselines}
    reflex = by_name["disable every compromised principal"]
    assert reflex.cost == 445 and reflex.is_a_cut
    block_apps = by_name["disable every reachable service principal"]
    assert block_apps.cost == 2400
    assert block_apps.is_a_cut is False  # the Key Vault route has no application on it
    assert by_name["take every available action"].cost > plan.total_cost


def test_demo_dynamic_group_membership_is_not_proposed(demo_graph):
    """`removable: false` must mean it never appears, not that it is merely expensive."""
    plan = solve(demo_graph)
    assert all("all-employees" not in step.action.id for step in plan.steps)


def test_demo_progress_curve_is_measured(demo_graph):
    plan = solve(demo_graph)
    assert plan.jewels_exposed_before == ["role:GlobalAdministrator", "res:kv-prod-payments"]
    assert plan.steps[-1].jewels_reachable_after == []
    # Global Administrator survives until the very last action.
    assert "role:GlobalAdministrator" in plan.steps[-2].jewels_reachable_after


def test_bundled_scenario_is_np_hard_and_still_provably_optimal_here(demo_graph):
    """Same tenant, bundled catalogue: the approximate solver, checked against brute force.

    The bundle `purge-ana-groups` (35) beats the two separate removals (25 + 25), so the
    optimum is genuinely lower than the atomic one — and the certified lower bound happens
    to match the plan's cost, which proves optimality on an instance whose general problem
    is NP-hard.
    """
    from containment_cut.demo.bundled import bundled_actions
    from containment_cut.plan import METHOD_GREEDY

    demo_graph.actions = bundled_actions(demo_graph)
    plan = solve(demo_graph)
    optimum, _ = brute_force_min_cost(demo_graph)

    assert plan.method == METHOD_GREEDY
    assert optimum == 170
    assert plan.total_cost == 170
    assert plan.total_cost <= plan.approximation_bound * optimum   # the proved guarantee
    assert plan.lower_bound <= optimum                             # the proved lower bound
    assert plan.lower_bound == 170                                 # ...and here it is tight
    assert plan.optimal                                            # so optimality IS proved
    assert any("purge-ana-groups" == step.action.id for step in plan.steps)
