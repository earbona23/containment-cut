"""The command line. Dry-run by default, and loud about what it did and did not prove.

Exit codes are part of the contract, because this belongs in a pipeline:

    0  a plan was produced, or the compromise is already contained
    2  bad input (unreadable graph, unknown node id, malformed cost file)
    3  no cut is possible with the available actions
    4  a plan was produced but its certificate did NOT verify -- do not trust it

Code 4 exists so that a broken proof can never be mistaken for a good plan by anything
downstream. The plan is still printed, with the failure on top: hiding it would be worse.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import report
from .cut import STATUS_CONTAINED, STATUS_CUT_FOUND, STATUS_NO_CUT
from .execute import check_gate
from .license import activate, entitlement, license_path
from .model import GraphError, graph_from_dict, load_graph
from .plan import solve

DEMO_GRAPH = Path(__file__).parent / "demo" / "contoso.json"


def _load(args) -> "tuple[object, object]":
    path = DEMO_GRAPH if getattr(args, "demo", False) else Path(args.graph)
    graph = load_graph(path)
    if getattr(args, "scenario", "atomic") == "bundled":
        from .demo.bundled import bundled_actions

        graph.actions = bundled_actions(graph)
    if getattr(args, "compromised", None):
        graph.compromised = tuple(args.compromised)
    if getattr(args, "crown_jewels", None):
        graph.crown_jewels = tuple(args.crown_jewels)
    costs = {}
    if getattr(args, "costs", None):
        costs = json.loads(Path(args.costs).read_text(encoding="utf-8"))
        if not all(isinstance(v, int) for v in costs.values()):
            raise GraphError("every value in the cost file must be an integer")
    return graph, costs


def cmd_plan(args) -> int:
    graph, costs = _load(args)
    plan = solve(graph, costs)

    fmt = args.format
    if fmt == "json":
        text = report.to_json(plan, graph)
    elif fmt == "markdown":
        text = report.markdown(plan, graph)
    elif fmt == "mermaid":
        text = report.mermaid(plan, graph)
    else:
        text = report.terminal(plan, graph, color=sys.stdout.isatty() and not args.no_color)

    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
        print(f"written to {args.out}", file=sys.stderr)
    else:
        print(text)

    if plan.status == STATUS_NO_CUT:
        return 3
    if plan.status == STATUS_CUT_FOUND and plan.certificate is not None and not plan.certificate.ok:
        return 4
    return 0


def cmd_execute(args) -> int:
    graph, costs = _load(args)
    plan = solve(graph, costs)
    gate = check_gate(plan, execute_flag=args.execute, acknowledged=args.i_understand_this_changes)
    print(report.terminal(plan, graph, color=sys.stdout.isatty() and not args.no_color))
    print()
    print(f"EXECUTION REFUSED: {gate.reason}", file=sys.stderr)
    print(
        "The open-source build never calls Microsoft Graph. Run the printed commands "
        "yourself, with your own change control.",
        file=sys.stderr,
    )
    return 1


def cmd_license(args) -> int:
    if args.license_command == "activate":
        try:
            payload = activate(args.key)
        except ValueError as exc:
            print(f"license not activated: {exc}", file=sys.stderr)
            return 2
        print(f"activated: plan={payload.get('plan')} for {payload.get('sub')}")
        print(f"stored at {license_path()}")
        return 0
    ent = entitlement()
    if ent.pro:
        print(f"pro: yes · plan={ent.plan} · features={', '.join(ent.features)} · subject={ent.subject}")
    else:
        print(f"pro: no ({ent.reason})")
        print("The free build computes and proves the plan. See docs/pro.md for what a license adds.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="containment-cut",
        description="Compute the cheapest set of actions that severs a compromise from the crown jewels.",
        epilog="Dry run by default. This tool never changes a tenant.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def add_graph_args(p, demo_default=False):
        if not demo_default:
            p.add_argument("--graph", required=True, help="tenant graph JSON (see docs/graph-format.md)")
        p.add_argument("--compromised", nargs="+", help="override the graph's compromised node ids")
        p.add_argument("--crown-jewels", nargs="+", dest="crown_jewels", help="override the crown jewel node ids")
        p.add_argument("--costs", help="JSON file of {action_kind: int} cost overrides")
        p.add_argument("--format", choices=["text", "json", "markdown", "mermaid"], default="text")
        p.add_argument("--out", help="write to a file instead of stdout")
        p.add_argument("--no-color", action="store_true")

    p_plan = sub.add_parser("plan", help="compute a containment plan (dry run)")
    add_graph_args(p_plan)
    p_plan.set_defaults(func=cmd_plan, demo=False)

    p_demo = sub.add_parser("demo", help="run the bundled synthetic tenant")
    add_graph_args(p_demo, demo_default=True)
    p_demo.add_argument(
        "--scenario", choices=["atomic", "bundled"], default="atomic",
        help="atomic: every action destroys one element, solved exactly. "
             "bundled: some actions destroy several at once, which is NP-hard — "
             "shows the approximation and its bounds on the same tenant.",
    )
    p_demo.set_defaults(func=cmd_plan, demo=True, graph=str(DEMO_GRAPH))

    p_exec = sub.add_parser("execute", help="refuses: execution is gated and Pro-only")
    add_graph_args(p_exec)
    p_exec.add_argument("--execute", action="store_true")
    p_exec.add_argument("--i-understand-this-changes", dest="i_understand_this_changes")
    p_exec.set_defaults(func=cmd_execute, demo=False)

    p_lic = sub.add_parser("license", help="activate or inspect a Pro license")
    p_lic.add_argument("license_command", choices=["activate", "status"])
    p_lic.add_argument("key", nargs="?")
    p_lic.set_defaults(func=cmd_license)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except GraphError as exc:
        print(f"input error: {exc}", file=sys.stderr)
        return 2
    except FileNotFoundError as exc:
        print(f"input error: {exc}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as exc:
        print(f"input error: not valid JSON — {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
