"""The default action catalogue: which graph elements can actually be destroyed, and
what it costs the business to destroy them.

Two things here are opinions, and they are the opinions that make the output useful.

WHAT IS NOT REMOVABLE
---------------------
Most edges in an identity graph are not configuration -- they are consequences of how
the platform works. `RoleManagement.ReadWrite.Directory --canAssign--> GlobalAdmin` is
not a setting anyone can delete at 3am; it is what that permission *means*. Likewise
`application --hasServicePrincipal--> servicePrincipal`, and `role --grantsAccessTo-->
resource`. Marking these un-cuttable is what forces the solver to find the edge you
*can* cut, which is the whole point. A model where everything is removable produces
plans nobody can execute.

WHY A STOLEN CREDENTIAL IS ITS OWN NODE
---------------------------------------
"Rotate the app secret" is not the same act as "disable the app", and modelling it as a
node cut on the service principal would be a lie the solver would happily believe: it
would conclude that rotating the secret also stops the app's *owner*, who can simply
mint a new one. So a compromised credential is a node of its own

        credential --authenticatesAs--> servicePrincipal

and rotation removes the credential. The service principal survives; every other route
into it survives; only the attacker's key dies. The graph then tells the truth, and the
plan contains both actions when both are needed.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Mapping

from .model import Action, Edge, Node, TenantGraph

# Business impact, in points. A tenant should override these; the defaults exist so that
# a first run produces something rather than demanding a spreadsheet.
DEFAULT_COSTS: dict[str, int] = {
    "disable_user": 100,
    "disable_service_principal": 300,
    "disable_device": 80,
    "rotate_credential": 45,
    "remove_group_member": 25,
    "remove_directory_role_assignment": 40,
    "remove_azure_role_assignment": 40,
    "remove_app_role_grant": 60,
    "remove_app_role_assignment": 60,
    "revoke_oauth2_grant": 50,
    "remove_owner": 30,
}

# node kind -> the action that destroys the node itself
NODE_ACTIONS: dict[str, str] = {
    "user": "disable_user",
    "servicePrincipal": "disable_service_principal",
    "device": "disable_device",
    "credential": "rotate_credential",
}

# edge relation -> the action that destroys that specific edge
EDGE_ACTIONS: dict[str, str] = {
    "memberOf": "remove_group_member",
    "hasRoleAssignment": "remove_directory_role_assignment",
    "hasAzureRoleAssignment": "remove_azure_role_assignment",
    "hasAppRole": "remove_app_role_grant",
    "hasAppRoleAssignment": "remove_app_role_assignment",
    "hasDelegatedGrant": "revoke_oauth2_grant",
    "owns": "remove_owner",
}

# Relations that describe how the platform works, not how it is configured.
INHERENT_RELATIONS: frozenset[str] = frozenset(
    {
        "canAssign",
        "canResetPasswordOf",
        "hasServicePrincipal",
        "grantsAccessTo",
        "contains",
        "canAddCredentialsTo",
        "authenticatesAs",
        "impersonates",
    }
)

IRREVERSIBLE_KINDS: frozenset[str] = frozenset({"rotate_credential"})
"""Rotating a secret cannot be undone -- the old value is gone. Flagged so the plan can
say so out loud before anyone runs it."""


def _cost(kind: str, attrs: Mapping[str, object], costs: Mapping[str, int]) -> int | None:
    if attrs.get("removable") is False:
        return None
    override = attrs.get("containment_cost", attrs.get("business_cost"))
    if override is not None:
        if not isinstance(override, int) or isinstance(override, bool):
            raise TypeError(f"containment_cost/business_cost must be an int, got {override!r}")
        return override
    return costs.get(kind, DEFAULT_COSTS.get(kind))


def _node_action(node: Node, costs: Mapping[str, int]) -> Action | None:
    kind = NODE_ACTIONS.get(node.kind)
    if kind is None:
        return None
    cost = _cost(kind, node.attrs, costs)
    if cost is None:
        return None
    return Action(
        id=f"{kind}:{node.id}",
        kind=kind,
        cost=cost,
        title=f"{_verb(kind)} {node.display}",
        removes_nodes=frozenset({node.id}),
        rationale=_NODE_RATIONALE.get(kind, ""),
        target_ref={"node": node.id, **{k: v for k, v in node.attrs.items() if k.endswith("_id")}},
        reversible=kind not in IRREVERSIBLE_KINDS,
    )


def _edge_action(edge: Edge, graph: TenantGraph, costs: Mapping[str, int]) -> Action | None:
    # An inherent relation is not configuration, so pricing it does not make it cuttable.
    # A tenant that genuinely CAN delete one (a custom role definition, say) says so
    # explicitly with `"removable": true` -- and has to say it per edge, because the
    # default must never be "the platform's own semantics are negotiable".
    if edge.relation in INHERENT_RELATIONS and edge.attrs.get("removable") is not True:
        return None
    kind = EDGE_ACTIONS.get(edge.relation)
    if kind is None:
        # A relation the catalogue has never heard of can still be cut, but only if the
        # graph prices it. Silently inventing a cost for an unknown relation would put
        # actions in a plan that nobody chose and nobody can run.
        if "containment_cost" not in edge.attrs:
            return None
        kind = "remove_edge"
    cost = _cost(kind, edge.attrs, costs)
    if cost is None:
        return None
    src = graph.nodes[edge.source].display
    dst = graph.nodes[edge.target].display
    return Action(
        id=f"{kind}:{edge.source}->{edge.target}",
        kind=kind,
        cost=cost,
        title=_EDGE_TITLE[kind].format(source=src, target=dst),
        removes_edges=frozenset({edge.key}),
        rationale=_EDGE_RATIONALE.get(kind, ""),
        target_ref={
            "source": edge.source,
            "target": edge.target,
            "relation": edge.relation,
            **{k: v for k, v in edge.attrs.items() if k.endswith("_id")},
        },
        reversible=kind not in IRREVERSIBLE_KINDS,
    )


_NODE_RATIONALE = {
    "disable_user": "Blocks sign-in for the account and, with the companion call, kills every live refresh token.",
    "disable_service_principal": "Blocks all authentication to the enterprise application. Everything it automates stops.",
    "disable_device": "Removes the device's ability to obtain primary refresh tokens.",
    "rotate_credential": "Destroys the specific key the attacker holds. Anyone who can mint a new one is unaffected -- that is a separate edge.",
}

_EDGE_RATIONALE = {
    "remove_group_member": "Surgical: the group and everyone else in it keep working.",
    "remove_directory_role_assignment": "Removes one Entra role assignment; the role and its other holders are untouched.",
    "remove_azure_role_assignment": "Removes one Azure RBAC assignment at its scope.",
    "remove_app_role_grant": "Removes an application permission from the service principal. Often a permanent hardening, not just containment.",
    "remove_app_role_assignment": "Removes the assignment that lets these principals sign in to the application.",
    "revoke_oauth2_grant": "Deletes the delegated consent grant; the app loses the scopes it was consented.",
    "remove_owner": "Ownership of an app is control of it -- an owner can add a credential and authenticate as the service principal.",
}

_EDGE_RATIONALE["remove_edge"] = (
    "Custom relation priced by the tenant graph. Supply the command in the action definition."
)

_EDGE_TITLE = {
    "remove_edge": "Sever {source} -> {target}",
    "remove_group_member": "Remove {source} from group {target}",
    "remove_directory_role_assignment": "Remove the {target} role assignment from {source}",
    "remove_azure_role_assignment": "Remove the Azure role assignment {target} from {source}",
    "remove_app_role_grant": "Remove the {target} application permission from {source}",
    "remove_app_role_assignment": "Remove {source}'s app role assignment on {target}",
    "revoke_oauth2_grant": "Revoke {source}'s delegated grant on {target}",
    "remove_owner": "Remove {source} as an owner of {target}",
}

_VERBS = {
    "disable_user": "Disable sign-in for",
    "disable_service_principal": "Disable the service principal",
    "disable_device": "Disable device",
    "rotate_credential": "Rotate/remove credential",
}


def _verb(kind: str) -> str:
    return _VERBS.get(kind, kind.replace("_", " ").capitalize())


def derive_actions(graph: TenantGraph, costs: Mapping[str, int] | None = None) -> list[Action]:
    """Generate the default containment actions for a graph that declares none."""
    costs = costs or {}
    actions: list[Action] = []
    for node in graph.nodes.values():
        action = _node_action(node, costs)
        if action is not None:
            actions.append(action)
    for edge in graph.edges:
        action = _edge_action(edge, graph, costs)
        if action is not None:
            actions.append(action)
    return actions


def with_actions(graph: TenantGraph, costs: Mapping[str, int] | None = None) -> TenantGraph:
    """Return the graph with an action set: its own if it declares one, else the default.

    A graph that declares actions is taken at its word and nothing is generated. Mixing
    the two silently would mean a tenant could not *remove* a default it disagreed with,
    and the whole cost model would stop being theirs.
    """
    if graph.actions:
        return graph
    graph.actions = derive_actions(graph, costs)
    return graph


def rescale(action: Action, cost: int) -> Action:
    return replace(action, cost=cost)
