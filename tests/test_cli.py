"""The command line, including the exit codes a pipeline depends on."""

from __future__ import annotations

import json

import pytest

from containment_cut.cli import main


def run(capsys, *argv) -> tuple[int, str, str]:
    code = main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_demo_runs_and_exits_zero(capsys):
    code, out, _ = run(capsys, "demo", "--no-color")
    assert code == 0
    assert "MINIMUM CONTAINMENT CUT" in out
    assert "PROVED OPTIMAL" in out
    assert "DRY RUN" in out


def test_demo_json_is_machine_readable(capsys):
    code, out, _ = run(capsys, "demo", "--format", "json")
    assert code == 0
    data = json.loads(out)
    assert data["total_cost"] == 185
    assert data["optimality_proved"] is True
    assert data["mode"] == "dry-run"


def test_no_cut_exits_three(capsys, tmp_path):
    graph = {
        "version": 1,
        # A group (no node action in the catalogue) reaching a resource through an
        # inherent relation: nothing on the path can be destroyed, so there is no plan.
        "nodes": [{"id": "a", "kind": "group"}, {"id": "j", "kind": "resource"}],
        "edges": [{"source": "a", "target": "j", "relation": "grantsAccessTo"}],
        "compromised": ["a"],
        "crown_jewels": ["j"],
    }
    path = tmp_path / "t.json"
    path.write_text(json.dumps(graph))
    code, out, _ = run(capsys, "plan", "--graph", str(path), "--no-color")
    assert code == 3
    assert "NO CUT POSSIBLE" in out


def test_bad_input_exits_two(capsys, tmp_path):
    path = tmp_path / "broken.json"
    path.write_text('{"version": 1, "nodes": [{"id": "a"}], "edges": [], "compromised": ["ghost"], "crown_jewels": ["a"]}')
    code, _, err = run(capsys, "plan", "--graph", str(path))
    assert code == 2
    assert "ghost" in err


def test_missing_file_exits_two(capsys):
    code, _, err = run(capsys, "plan", "--graph", "/nonexistent/tenant.json")
    assert code == 2
    assert "input error" in err


def test_overriding_the_targets_on_the_command_line(capsys):
    code, out, _ = run(
        capsys, "demo", "--no-color",
        "--compromised", "u:marco.diaz",
        "--crown-jewels", "role:GlobalAdministrator",
    )
    assert code == 0
    # Marco reaches Global Admin only by owning LegacyReporting; that is the whole cut.
    assert "LegacyReporting" in out


def test_execute_always_refuses_and_never_exits_zero(capsys):
    code, out, err = run(
        capsys, "execute", "--graph",
        str(__import__("pathlib").Path(__file__).resolve().parents[1]
            / "src" / "containment_cut" / "demo" / "contoso.json"),
        "--no-color", "--execute", "--i-understand-this-changes", "contoso",
    )
    assert code == 1
    assert "EXECUTION REFUSED" in err
    assert "never calls Microsoft Graph" in err
    assert "MINIMUM CONTAINMENT CUT" in out  # the plan is still shown


def test_execute_refuses_without_the_flags(capsys):
    from containment_cut.execute import check_gate
    from containment_cut.model import load_graph
    from containment_cut.plan import solve
    import pathlib

    graph = load_graph(pathlib.Path(__file__).resolve().parents[1]
                       / "src" / "containment_cut" / "demo" / "contoso.json")
    plan = solve(graph)
    assert check_gate(plan, execute_flag=False, acknowledged="x").reason.startswith("dry-run is the default")
    assert "--i-understand-this-changes" in check_gate(plan, execute_flag=True, acknowledged=None).reason
    assert check_gate(plan, execute_flag=True, acknowledged="contoso").allowed is False


def test_license_status_without_a_license(capsys, tmp_path, monkeypatch):
    monkeypatch.setenv("CONTAINMENT_CUT_CONFIG_DIR", str(tmp_path))
    monkeypatch.delenv("CONTAINMENT_CUT_LICENSE_KEY", raising=False)
    code, out, _ = run(capsys, "license", "status")
    assert code == 0
    assert "pro: no" in out


def test_license_activate_rejects_junk(capsys, tmp_path, monkeypatch):
    monkeypatch.setenv("CONTAINMENT_CUT_CONFIG_DIR", str(tmp_path))
    code, _, err = run(capsys, "license", "activate", "CONTAINMENTCUT-x.y")
    assert code == 2
    assert "license not activated" in err


def test_writing_to_a_file(capsys, tmp_path):
    out_path = tmp_path / "plan.md"
    code, _, err = run(capsys, "demo", "--format", "markdown", "--out", str(out_path))
    assert code == 0
    assert out_path.read_text().startswith("# Containment plan (DRY RUN")
    assert str(out_path) in err


@pytest.mark.parametrize("fmt", ["text", "json", "markdown", "mermaid"])
def test_every_format_produces_output(capsys, fmt):
    code, out, _ = run(capsys, "demo", "--format", fmt, "--no-color")
    assert code == 0 and out.strip()
