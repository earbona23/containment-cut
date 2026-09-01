"""Command rendering: real endpoints, and visible placeholders when ids are missing."""

import pytest

from containment_cut.catalog import derive_actions
from containment_cut.commands import render
from containment_cut.model import Action, Edge, Node, TenantGraph
from containment_cut.plan import solve

KNOWN_KINDS = [
    "disable_user", "disable_service_principal", "rotate_credential", "disable_device",
    "remove_group_member", "remove_directory_role_assignment", "remove_azure_role_assignment",
    "remove_app_role_grant", "remove_app_role_assignment", "revoke_oauth2_grant", "remove_owner",
]


@pytest.mark.parametrize("kind", KNOWN_KINDS)
def test_every_catalogue_kind_renders_a_command(kind):
    action = Action(id="x", kind=kind, cost=1, title="x", removes_nodes=frozenset({"n"}))
    commands = render(action)
    assert commands
    assert all(c.text for c in commands)
    assert not any("No command template" in c.text for c in commands)


def test_missing_ids_become_visible_placeholders_not_guesses():
    action = Action(id="x", kind="disable_user", cost=1, title="x",
                    removes_nodes=frozenset({"u:someone"}), target_ref={"node": "u:someone"})
    text = render(action)[0].text
    assert "<objectId of u:someone>" in text
    assert "00000000" not in text


def test_real_ids_are_used_when_present(demo_graph):
    plan = solve(demo_graph)
    step = next(s for s in plan.steps if s.action.kind == "remove_owner")
    text = "\n".join(c.text for c in step.commands)
    assert "bbbb2222-0000-4000-8000-000000000002" in text
    assert "<" not in text


def test_disable_user_always_carries_the_session_revocation_companion():
    action = Action(id="x", kind="disable_user", cost=1, title="x",
                    removes_nodes=frozenset({"u"}), target_ref={"object_id": "GUID"})
    text = "\n".join(c.text for c in render(action))
    assert "revokeSignInSessions" in text
    note = next(c.note for c in render(action) if "revokeSignInSessions" in c.text)
    assert "MANDATORY" in note


def test_unknown_kind_says_so_instead_of_inventing_a_call():
    action = Action(id="x", kind="teleport_the_attacker", cost=1, title="x",
                    removes_nodes=frozenset({"n"}))
    assert "No command template" in render(action)[0].text


def test_every_derived_action_on_the_demo_renders_something(demo_graph):
    for action in derive_actions(demo_graph):
        assert render(action)


def test_no_module_in_the_package_imports_an_http_client():
    """The free build must be incapable of touching a tenant. Checked, not asserted."""
    import pathlib

    import containment_cut

    root = pathlib.Path(containment_cut.__file__).parent
    banned = ("import requests", "import httpx", "import urllib.request", "from urllib.request",
              "import http.client", "aiohttp", "socket.socket")
    offenders = []
    for path in root.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        offenders += [f"{path.name}: {b}" for b in banned if b in text]
    assert offenders == []
