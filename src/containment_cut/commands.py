"""Rendering each containment action as the concrete call an operator would make.

Everything here is a STRING. This module imports no HTTP client and this package has no
network code at all: the free tool computes a plan and prints it, and that is the end of
its authority. Executing the plan is a deliberate, separately-licensed, step-by-step
gated act (see `execute`).

Placeholders. When the graph does not carry the real object id, the command is emitted
with an angle-bracket placeholder -- `<objectId of ana.reyes>` -- rather than a guessed
GUID. A command that looks runnable but is not is worse than one that visibly needs a
value filled in.

Every endpoint below is v1.0 Microsoft Graph or Azure CLI, with the reference URL kept
next to it so a reader can check it rather than trust it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from .model import Action


@dataclass(frozen=True, slots=True)
class Command:
    tool: str  # "graph" | "powershell" | "az"
    text: str
    note: str = ""
    docs: str = ""


def _ref(target: Mapping[str, object], key: str, label: str) -> str:
    value = target.get(key)
    return str(value) if value else f"<{label}>"


def render(action: Action) -> list[Command]:
    """The concrete calls for one action, in the order they should be issued."""
    t = action.target_ref
    kind = action.kind

    if kind == "disable_user":
        uid = _ref(t, "object_id", f"objectId of {t.get('node', 'the user')}")
        return [
            Command(
                "graph",
                f'PATCH https://graph.microsoft.com/v1.0/users/{uid}\n{{ "accountEnabled": false }}',
                "Blocks new sign-ins. Existing refresh tokens stay valid until the next call.",
                "https://learn.microsoft.com/graph/api/user-update",
            ),
            Command(
                "graph",
                f"POST https://graph.microsoft.com/v1.0/users/{uid}/revokeSignInSessions",
                "MANDATORY companion. Disabling alone leaves live refresh tokens working; "
                "this invalidates them. Propagation takes a few minutes.",
                "https://learn.microsoft.com/graph/api/user-revokesigninsessions",
            ),
            Command(
                "powershell",
                f"Update-MgUser -UserId {uid} -AccountEnabled:$false\n"
                f"Revoke-MgUserSignInSession -UserId {uid}",
                "",
                "https://learn.microsoft.com/powershell/module/microsoft.graph.users.actions/revoke-mgusersigninsession",
            ),
        ]

    if kind == "disable_service_principal":
        sid = _ref(t, "object_id", f"objectId of {t.get('node', 'the service principal')}")
        return [
            Command(
                "graph",
                f'PATCH https://graph.microsoft.com/v1.0/servicePrincipals/{sid}\n'
                f'{{ "accountEnabled": false }}',
                "Every workload authenticating as this principal stops. Confirm the owner is on the call.",
                "https://learn.microsoft.com/graph/api/serviceprincipal-update",
            ),
            Command(
                "powershell",
                f"Update-MgServicePrincipal -ServicePrincipalId {sid} -AccountEnabled:$false",
            ),
        ]

    if kind == "rotate_credential":
        app = _ref(t, "application_id", "objectId of the application")
        key = _ref(t, "key_id", "keyId of the compromised secret")
        return [
            Command(
                "graph",
                f'POST https://graph.microsoft.com/v1.0/applications/{app}/removePassword\n'
                f'{{ "keyId": "{key}" }}',
                "IRREVERSIBLE. Issue the replacement secret (addPassword) to the legitimate "
                "owner FIRST if the workload must keep running.",
                "https://learn.microsoft.com/graph/api/application-removepassword",
            ),
            Command(
                "graph",
                f'POST https://graph.microsoft.com/v1.0/applications/{app}/removeKey\n'
                f'{{ "keyId": "{key}", "proof": "<self-signed JWT proof>" }}',
                "Use removeKey instead when the compromised credential is a certificate.",
                "https://learn.microsoft.com/graph/api/application-removekey",
            ),
        ]

    if kind == "disable_device":
        did = _ref(t, "object_id", "objectId of the device")
        return [
            Command(
                "graph",
                f'PATCH https://graph.microsoft.com/v1.0/devices/{did}\n{{ "accountEnabled": false }}',
                "",
                "https://learn.microsoft.com/graph/api/device-update",
            )
        ]

    if kind == "remove_group_member":
        gid = _ref(t, "group_id", f"objectId of group {t.get('target', '')}")
        mid = _ref(t, "member_id", f"objectId of {t.get('source', '')}")
        return [
            Command(
                "graph",
                f"DELETE https://graph.microsoft.com/v1.0/groups/{gid}/members/{mid}/$ref",
                "Surgical. The group and its other members are unaffected. "
                "If the group's membership is a dynamic rule, this will be re-applied -- "
                "model that edge as removable: false instead.",
                "https://learn.microsoft.com/graph/api/group-delete-members",
            ),
            Command("powershell", f"Remove-MgGroupMemberByRef -GroupId {gid} -DirectoryObjectId {mid}"),
        ]

    if kind == "remove_directory_role_assignment":
        aid = _ref(t, "assignment_id", "unifiedRoleAssignment id")
        return [
            Command(
                "graph",
                f"DELETE https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments/{aid}",
                "If the assignment is PIM-eligible rather than active, remove the eligibility "
                "schedule too or it can simply be re-activated.",
                "https://learn.microsoft.com/graph/api/unifiedroleassignment-delete",
            ),
            Command(
                "powershell",
                f"Remove-MgRoleManagementDirectoryRoleAssignment -UnifiedRoleAssignmentId {aid}",
                "",
                "https://learn.microsoft.com/powershell/module/microsoft.graph.identity.governance/remove-mgrolemanagementdirectoryroleassignment",
            ),
        ]

    if kind == "remove_azure_role_assignment":
        aid = _ref(t, "assignment_id", "full /subscriptions/... roleAssignment id")
        return [
            Command(
                "az",
                f"az role assignment delete --ids {aid}",
                "Azure RBAC, not Entra roles. Check the scope: deleting at a parent scope "
                "removes more than the path you are cutting.",
                "https://learn.microsoft.com/cli/azure/role/assignment",
            )
        ]

    if kind == "remove_app_role_grant":
        sid = _ref(t, "resource_sp_id", "objectId of the RESOURCE service principal (e.g. Microsoft Graph)")
        aid = _ref(t, "assignment_id", "appRoleAssignment id")
        return [
            Command(
                "graph",
                f"DELETE https://graph.microsoft.com/v1.0/servicePrincipals/{sid}/appRoleAssignedTo/{aid}",
                "Removes an application permission held by the client service principal. "
                "Frequently worth keeping removed after the incident.",
                "https://learn.microsoft.com/graph/api/serviceprincipal-delete-approleassignedto",
            )
        ]

    if kind == "remove_app_role_assignment":
        pid = _ref(t, "principal_id", "objectId of the assigned principal (user or group)")
        aid = _ref(t, "assignment_id", "appRoleAssignment id")
        return [
            Command(
                "graph",
                f"DELETE https://graph.microsoft.com/v1.0/servicePrincipals/{pid}/appRoleAssignments/{aid}",
                "Removes the assignment that lets the principal sign in to the application.",
                "https://learn.microsoft.com/graph/api/serviceprincipal-delete-approleassignments",
            )
        ]

    if kind == "revoke_oauth2_grant":
        gid = _ref(t, "grant_id", "oAuth2PermissionGrant id")
        return [
            Command(
                "graph",
                f"DELETE https://graph.microsoft.com/v1.0/oauth2PermissionGrants/{gid}",
                "Deletes delegated consent. Tokens already issued keep their scopes until "
                "they expire -- pair with revokeSignInSessions on the affected users.",
                "https://learn.microsoft.com/graph/api/oauth2permissiongrant-delete",
            )
        ]

    if kind == "remove_owner":
        app = _ref(t, "application_id", f"objectId of application {t.get('target', '')}")
        own = _ref(t, "owner_id", f"objectId of {t.get('source', '')}")
        return [
            Command(
                "graph",
                f"DELETE https://graph.microsoft.com/v1.0/applications/{app}/owners/{own}/$ref",
                "The action almost no runbook lists. An owner can add a client secret to the "
                "app and then authenticate as its service principal, inheriting every "
                "permission it holds. Removing ownership closes that door without touching "
                "the application itself.",
                "https://learn.microsoft.com/graph/api/application-delete-owners",
            )
        ]

    if kind == "remove_edge":
        return [
            Command(
                "graph",
                f"# Custom relation {t.get('relation', '?')}: "
                f"{t.get('source', '?')} -> {t.get('target', '?')}\n"
                "# The catalogue has no template for this relation. Put the exact call in "
                "the action's definition in your graph file.",
                "Priced by your graph, so the plan can reason about it, but only you know "
                "how to execute it.",
            )
        ]

    return [
        Command(
            "graph",
            f"# No command template for action kind {kind!r}. "
            f"Removes: {sorted(map(str, action.elements))}",
            "Custom action: supply the command in the graph file's action definition.",
        )
    ]
