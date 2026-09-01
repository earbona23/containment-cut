# Tenant graph format

One JSON file. Version `1`.

```json
{
  "version": 1,
  "tenant": "contoso.onmicrosoft.com",
  "compromised": ["u:ana.reyes", "cred:travelbot-secret-2"],
  "crown_jewels": ["role:GlobalAdministrator", "res:kv-prod-payments"],
  "nodes": [ ... ],
  "edges": [ ... ],
  "actions": [ ... ]
}
```

`compromised` and `crown_jewels` can be overridden on the command line with
`--compromised` and `--crown-jewels`.

## Nodes

```json
{ "id": "u:ana.reyes", "kind": "user", "label": "Ana Reyes",
  "object_id": "1111...", "business_cost": 400 }
```

`id` and `kind` are required; everything else becomes an attribute.

| kind | node action the catalogue offers | notes |
|---|---|---|
| `user` | `disable_user` (+ mandatory session revocation) | |
| `servicePrincipal` | `disable_service_principal` | |
| `device` | `disable_device` | |
| `credential` | `rotate_credential` | irreversible; model a stolen secret as one of these |
| `group`, `role`, `permission`, `application`, `resource` | none | you contain a group by removing a membership, not by deleting the group |

Attributes the tool reads:

* `business_cost` / `containment_cost` — integer impact of destroying this node.
* `removable: false` — no action exists for this node, at any price.
* `object_id`, `application_id`, `key_id`, `group_id`, … — any key ending in `_id` is
  passed into the rendered command. Missing ids become visible `<placeholders>`, never
  guessed GUIDs.

## Edges

```json
{ "source": "u:ana.reyes", "target": "g:helpdesk-tier1", "relation": "memberOf",
  "group_id": "aaaa...", "member_id": "1111..." }
```

An edge's identity is `(source, target, relation)`, so parallel edges with different
relations are distinct — a user can both *own* an app and be a *member* of a group that
reaches it.

| relation | action | |
|---|---|---|
| `memberOf` | `remove_group_member` | |
| `hasRoleAssignment` | `remove_directory_role_assignment` | Entra role |
| `hasAzureRoleAssignment` | `remove_azure_role_assignment` | Azure RBAC |
| `hasAppRole` | `remove_app_role_grant` | application permission held by an SP |
| `hasAppRoleAssignment` | `remove_app_role_assignment` | principal assigned to an app |
| `hasDelegatedGrant` | `revoke_oauth2_grant` | |
| `owns` | `remove_owner` | ownership is control |
| `canAssign`, `canResetPasswordOf`, `hasServicePrincipal`, `grantsAccessTo`, `contains`, `canAddCredentialsTo`, `authenticatesAs` | **none** | inherent: how the platform works, not configuration you can delete at 3am |

Marking inherent relations un-cuttable is what forces the solver to find the edge you
*can* cut. A model where everything is removable produces plans nobody can execute.

Two escape hatches, both explicit and both per-edge:

* **A relation the catalogue has never heard of** becomes cuttable as a generic
  `remove_edge` action *only if the edge carries a `containment_cost`.* Without a price
  the tool proposes nothing, because inventing a cost would put an action in a plan that
  nobody chose. The rendered "command" is an honest placeholder telling you to supply the
  call — never a fabricated Graph URL.
* **An inherent relation** stays un-cuttable even when priced. If your tenant genuinely
  can delete one — a custom role definition, say — add `"removable": true` to that edge.
  It has to be said edge by edge: the default must never be "the platform's own semantics
  are negotiable".

Edge attributes: `containment_cost` (int), `removable: false`, and any `*_id` used by the
command templates.

**Dynamic groups:** a membership produced by a dynamic rule will be re-applied after you
remove it. Model that edge as `"removable": false`, not as an expensive one.

## Actions (optional)

If the file declares `actions`, they are used **verbatim and nothing is generated** — the
cost model is then entirely yours. Omit the key to get the default catalogue.

```json
{ "id": "block-app", "kind": "disable_service_principal", "cost": 700,
  "title": "Block the TravelBot enterprise application",
  "removes_nodes": ["sp:TravelBot"],
  "removes_edges": [["sp:TravelBot", "role:KeyVaultSecretsUser", "hasAzureRoleAssignment"]],
  "reversible": true,
  "target_ref": { "object_id": "cccc..." } }
```

An action listing more than one element is a **bundle**, and a single bundle anywhere in
the catalogue switches the whole instance from the exact solver to the approximate one.
The output says so, with the bound and the measured gap.

## Cost overrides

`--costs costs.json` with `{ "action_kind": int }` changes the catalogue defaults without
editing the graph:

```json
{ "disable_user": 500, "remove_group_member": 10 }
```

## Where the graph comes from

The free build reads the file. Producing it from a live tenant — Microsoft Graph and
Azure Resource Manager, with ownership, app-role and PIM-eligibility edges — is the Pro
importer (`docs/pro.md`). The format is documented and stable precisely so you can write
your own collector and never need one.
