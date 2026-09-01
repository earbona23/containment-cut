"""The same synthetic tenant, priced with BUNDLED actions -- the NP-hard branch.

The atomic demo prices every graph element separately, which makes the problem a flow
problem and the answer provably optimal. Reality is not always that kind: "block this
application" removes the service principal *and* every permission edge hanging off it,
for one price. One action, several elements, and the cost of a plan stops being the sum
over what it destroys.

This catalogue adds three such bundles to the Contoso tenant so the approximate solver,
its H(d) guarantee and its certified lower bound can be seen doing their job on something
other than a unit test.

Loaded by `containment-cut demo --scenario bundled`.
"""

from __future__ import annotations

from ..model import Action, TenantGraph

E = lambda s, t, r: (s, t, r)  # noqa: E731 - a table of edge keys reads better this way


def bundled_actions(graph: TenantGraph) -> list[Action]:
    """Replace the derived catalogue with one that contains real bundles."""
    return [
        Action(
            id="rotate-travelbot-secret", kind="rotate_credential", cost=45, reversible=False,
            title="Rotate the TravelBot client secret the attacker added",
            removes_nodes=frozenset({"cred:travelbot-secret-2"}),
            rationale="Destroys the attacker's key. TravelBot keeps working on its legitimate secret.",
            target_ref={"application_id": "bbbb2222-0000-4000-8000-000000000003",
                        "key_id": "dddd4444-0000-4000-8000-000000000001"},
        ),
        Action(
            id="disable-travelbot", kind="disable_service_principal", cost=700,
            title="Disable the TravelBot enterprise application",
            removes_nodes=frozenset({"sp:TravelBot"}),
            removes_edges=frozenset({
                E("sp:TravelBot", "role:KeyVaultSecretsUser", "hasAzureRoleAssignment"),
                E("sp:TravelBot", "res:sp-hr-site", "hasDelegatedGrant"),
            }),
            rationale="BUNDLE: blocking the app also takes its role assignment and its delegated grant.",
            target_ref={"object_id": "cccc3333-0000-4000-8000-000000000003"},
        ),
        Action(
            id="purge-ana-groups", kind="remove_group_member", cost=35,
            title="Emergency group purge: remove Ana from every removable group",
            removes_edges=frozenset({
                E("u:ana.reyes", "g:helpdesk-tier1", "memberOf"),
                E("u:ana.reyes", "g:finance-app-admins", "memberOf"),
            }),
            rationale="BUNDLE: one scripted pass over her memberships, cheaper than two separate changes.",
        ),
        Action(
            id="remove-ana-helpdesk", kind="remove_group_member", cost=25,
            title="Remove Ana from Helpdesk Tier 1",
            removes_edges=frozenset({E("u:ana.reyes", "g:helpdesk-tier1", "memberOf")}),
            target_ref={"group_id": "aaaa1111-0000-4000-8000-000000000001",
                        "member_id": "11111111-1111-4111-8111-111111111111"},
        ),
        Action(
            id="remove-ana-finance", kind="remove_group_member", cost=25,
            title="Remove Ana from Finance App Admins",
            removes_edges=frozenset({E("u:ana.reyes", "g:finance-app-admins", "memberOf")}),
            target_ref={"group_id": "aaaa1111-0000-4000-8000-000000000002",
                        "member_id": "11111111-1111-4111-8111-111111111111"},
        ),
        Action(
            id="remove-ana-ownership", kind="remove_owner", cost=30,
            title="Remove Ana as an owner of AcmeExpense",
            removes_edges=frozenset({E("u:ana.reyes", "app:AcmeExpense", "owns")}),
            target_ref={"application_id": "bbbb2222-0000-4000-8000-000000000002",
                        "owner_id": "11111111-1111-4111-8111-111111111111"},
        ),
        Action(
            id="disable-ana", kind="disable_user", cost=400,
            title="Disable sign-in for Ana Reyes",
            removes_nodes=frozenset({"u:ana.reyes"}),
            target_ref={"object_id": "11111111-1111-4111-8111-111111111111"},
        ),
        Action(
            id="strip-portal-permission", kind="remove_app_role_grant", cost=60,
            title="Remove RoleManagement.ReadWrite.Directory from the Self-Service Portal",
            removes_edges=frozenset({
                E("sp:SelfServicePortal", "perm:RoleManagement.ReadWrite.Directory", "hasAppRole")
            }),
            rationale="Permanent hardening, not just containment.",
            target_ref={"resource_sp_id": "00000003-0000-0000-c000-000000000000",
                        "assignment_id": "ffff6666-0000-4000-8000-000000000004"},
        ),
        Action(
            id="block-portal", kind="disable_service_principal", cost=250,
            title="Block the Self-Service Portal application",
            removes_nodes=frozenset({"sp:SelfServicePortal"}),
            removes_edges=frozenset({
                E("g:all-employees", "sp:SelfServicePortal", "hasAppRoleAssignment"),
                E("sp:SelfServicePortal", "perm:RoleManagement.ReadWrite.Directory", "hasAppRole"),
            }),
            rationale="BUNDLE: disabling the app also voids its assignment and its permission.",
            target_ref={"object_id": "cccc3333-0000-4000-8000-000000000004"},
        ),
        Action(
            id="remove-marco-ownership", kind="remove_owner", cost=30,
            title="Remove Marco as an owner of LegacyReporting",
            removes_edges=frozenset({E("u:marco.diaz", "app:LegacyReporting", "owns")}),
            target_ref={"application_id": "bbbb2222-0000-4000-8000-000000000001",
                        "owner_id": "22222222-2222-4222-8222-222222222222"},
        ),
        Action(
            id="strip-legacy-permission", kind="remove_app_role_grant", cost=60,
            title="Remove RoleManagement.ReadWrite.Directory from LegacyReporting",
            removes_edges=frozenset({
                E("sp:LegacyReporting", "perm:RoleManagement.ReadWrite.Directory", "hasAppRole")
            }),
            target_ref={"resource_sp_id": "00000003-0000-0000-c000-000000000000",
                        "assignment_id": "ffff6666-0000-4000-8000-000000000001"},
        ),
        Action(
            id="strip-acme-permission", kind="remove_app_role_grant", cost=60,
            title="Remove Application.ReadWrite.All from AcmeExpense",
            removes_edges=frozenset({
                E("sp:AcmeExpense", "perm:Application.ReadWrite.All", "hasAppRole")
            }),
            target_ref={"resource_sp_id": "00000003-0000-0000-c000-000000000000",
                        "assignment_id": "ffff6666-0000-4000-8000-000000000002"},
        ),
        Action(
            id="remove-helpdesk-role", kind="remove_directory_role_assignment", cost=40,
            title="Remove the Helpdesk Administrator assignment from Helpdesk Tier 1",
            removes_edges=frozenset({
                E("g:helpdesk-tier1", "role:HelpdeskAdministrator", "hasRoleAssignment")
            }),
            target_ref={"assignment_id": "eeee5555-0000-4000-8000-000000000001"},
        ),
        Action(
            id="remove-finance-kv-role", kind="remove_azure_role_assignment", cost=40,
            title="Remove Key Vault Contributor from Finance App Admins",
            removes_edges=frozenset({
                E("g:finance-app-admins", "role:KeyVaultContributor", "hasAzureRoleAssignment")
            }),
            target_ref={"assignment_id": "/subscriptions/.../roleAssignments/77777777-0000-4000-8000-000000000001"},
        ),
        Action(
            id="remove-travelbot-kv-role", kind="remove_azure_role_assignment", cost=120,
            title="Remove Key Vault Secrets User from TravelBot",
            removes_edges=frozenset({
                E("sp:TravelBot", "role:KeyVaultSecretsUser", "hasAzureRoleAssignment")
            }),
            target_ref={"assignment_id": "/subscriptions/.../roleAssignments/77777777-0000-4000-8000-000000000002"},
        ),
        Action(
            id="remove-allemployees-portal", kind="remove_app_role_assignment", cost=200,
            title="Remove the All Employees assignment on the Self-Service Portal",
            removes_edges=frozenset({
                E("g:all-employees", "sp:SelfServicePortal", "hasAppRoleAssignment")
            }),
            target_ref={"principal_id": "aaaa1111-0000-4000-8000-000000000003",
                        "assignment_id": "ffff6666-0000-4000-8000-000000000003"},
        ),
    ]
