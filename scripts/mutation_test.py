#!/usr/bin/env python3
"""Mutation testing for the core algorithm. Are the tests load-bearing, or decoration?

A test suite that passes is evidence of nothing until you have watched it fail. This
harness breaks the algorithm on purpose, one small edit at a time, and demands that the
suite notice. A mutant the tests do not kill is a line of code nothing is checking.

THE TRAP THIS HARNESS AVOIDS: a mutation that never got applied looks *exactly* like a
mutant that survived -- the tests pass in both cases. So every mutation asserts its
target text is present before editing and that the file bytes actually changed after.
A mutation that cannot be applied is reported as an ERROR, never as a kill and never as
a survivor.

    python3 scripts/mutation_test.py            # all mutants
    python3 scripts/mutation_test.py --list
"""

from __future__ import annotations

import argparse
import hashlib
import signal
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "containment_cut"


@dataclass(frozen=True)
class Mutant:
    name: str
    path: Path
    old: str
    new: str
    breaks: str  # what should now be wrong


MUTANTS: list[Mutant] = [
    Mutant(
        "maxflow/level-graph-accepts-saturated-arcs",
        SRC / "maxflow.py",
        "if self._cap[arc] > self._zero and self._level[v] < 0:",
        "if self._cap[arc] >= self._zero and self._level[v] < 0:",
        "BFS walks arcs with no residual capacity, so the flow can exceed the true maximum",
    ),
    Mutant(
        "maxflow/bottleneck-uses-max",
        SRC / "maxflow.py",
        "bottleneck = min(self._cap[arc] for arc in path)",
        "bottleneck = max(self._cap[arc] for arc in path)",
        "pushes more than an arc can carry",
    ),
    Mutant(
        "maxflow/residual-twin-not-credited",
        SRC / "maxflow.py",
        "self._cap[arc ^ 1] += bottleneck",
        "self._cap[arc ^ 1] -= bottleneck",
        "no back-arc, so flow cannot be re-routed and the maximum is missed",
    ),
    Mutant(
        "maxflow/residual-reachability-ignores-capacity",
        SRC / "maxflow.py",
        "if self._cap[arc] > self._zero and v not in seen:",
        "if v not in seen:",
        "the source side of the cut becomes the whole graph",
    ),
    Mutant(
        "cut/crown-jewel-becomes-removable",
        SRC / "cut.py",
        "cap = infinity if node_id in jewels else element_cost.get(node_id, infinity)",
        "cap = element_cost.get(node_id, infinity)",
        "the solver may 'contain' the incident by deleting the asset it defends",
    ),
    Mutant(
        "cut/infinity-off-by-one",
        SRC / "cut.py",
        "infinity = finite_total + 1",
        "infinity = finite_total",
        "an un-cuttable element becomes as cheap as cutting everything else",
    ),
    Mutant(
        "cut/no-cut-detection-boundary",
        SRC / "cut.py",
        "if value >= infinity:",
        "if value > infinity:",
        "a graph with no possible cut gets a plan invented for it",
    ),
    Mutant(
        "cut/cut-side-condition-dropped",
        SRC / "cut.py",
        "if net.tail(arc) in reachable and net.head(arc) not in reachable:",
        "if net.tail(arc) in reachable:",
        "every arc leaving the source side is called part of the cut",
    ),
    Mutant(
        "cut/compromised-entry-is-cuttable",
        SRC / "cut.py",
        "for node_id in graph.compromised:\n        net.add_edge(src, 2 * index[node_id], infinity)",
        "for node_id in graph.compromised:\n        net.add_edge(src, 2 * index[node_id], 0)",
        "the max flow is zero and the plan is empty",
    ),
    Mutant(
        "cut/duality-check-is-a-rubber-stamp",
        SRC / "cut.py",
        "duality_ok = result.cost == result.flow_value",
        "duality_ok = True",
        "the certificate stops proving optimality",
    ),
    Mutant(
        "cut/sufficiency-check-is-a-rubber-stamp",
        SRC / "cut.py",
        "still = graph.exposed_jewels(result.cut_nodes, result.cut_edges)\n    checks[\"sufficiency\"] = not still",
        "still = []\n    checks[\"sufficiency\"] = not still",
        "the certificate stops proving the plan works",
    ),
    Mutant(
        "bundles/greedy-ignores-coverage",
        SRC / "bundles.py",
        "ratio = Fraction(actions[i].cost, new)",
        "ratio = Fraction(actions[i].cost, 1)",
        "greedy stops being greedy and the H(d) analysis no longer applies",
    ),
    Mutant(
        "bundles/lower-bound-does-not-share-cost",
        SRC / "bundles.py",
        "share = Fraction(action.cost, len(elements))",
        "share = Fraction(action.cost, 1)",
        "the 'lower' bound can exceed the true optimum, so it proves nothing",
    ),
    Mutant(
        "bundles/loop-returns-before-it-is-a-cut",
        SRC / "bundles.py",
        "        path = _first_path(graph, removed_nodes, removed_edges)\n        if path is None:",
        "        path = _first_path(graph, removed_nodes, removed_edges)\n        if True:",
        "an incomplete plan is returned as if it contained the incident",
    ),
    Mutant(
        "plan/picks-the-most-expensive-action-per-element",
        SRC / "plan.py",
        "if element not in cost or action.cost < cost[element]:",
        "if element not in cost or action.cost > cost[element]:",
        "the plan is a valid cut but not the cheapest one",
    ),
    Mutant(
        "plan/progress-curve-is-not-cumulative",
        SRC / "plan.py",
        "        nodes |= set(action.removes_nodes)\n        edges |= set(action.removes_edges)",
        "        nodes = set(action.removes_nodes)\n        edges = set(action.removes_edges)",
        "the 'jewels still reachable' column stops describing the plan so far",
    ),
    Mutant(
        "catalog/inherent-relations-become-cuttable",
        SRC / "catalog.py",
        'if edge.relation in INHERENT_RELATIONS and edge.attrs.get("removable") is not True:',
        'if False and edge.attrs.get("removable") is not True:',
        "plans start proposing edges nobody can actually delete",
    ),
    Mutant(
        "commands/placeholder-becomes-an-invented-guid",
        SRC / "commands.py",
        'return str(value) if value else f"<{label}>"',
        'return str(value) if value else "00000000-0000-0000-0000-000000000000"',
        "a command that cannot be run looks exactly like one that can",
    ),
    Mutant(
        "plan/optimality-is-claimed-without-a-certificate",
        SRC / "plan.py",
        "        if self.method == METHOD_EXACT:\n            return self.certificate is not None and self.certificate.ok",
        "        if self.method == METHOD_EXACT:\n            return True",
        "the tool says PROVED OPTIMAL when nothing was proved",
    ),
    Mutant(
        "catalog/removable-false-is-ignored",
        SRC / "catalog.py",
        'if attrs.get("removable") is False:\n        return None',
        'if attrs.get("removable") is None and False:\n        return None',
        "elements explicitly marked un-removable are proposed anyway",
    ),
]


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


_IN_FLIGHT: dict[Path, str] = {}


def _restore_and_die(signum, _frame):  # pragma: no cover - only on SIGTERM/SIGINT
    """A killed harness must not leave a mutant behind.

    `timeout` sends SIGTERM, and CPython's default handler exits WITHOUT running
    `finally`. Without this, a run that hits its time limit leaves the source mutated and
    the next green suite is green for the wrong reason.
    """
    for path, original in _IN_FLIGHT.items():
        path.write_text(original, encoding="utf-8")
    print(f"\ninterrupted by signal {signum}; restored {len(_IN_FLIGHT)} file(s)", file=sys.stderr)
    sys.exit(130)


SUITE_TIMEOUT_S = 300
"""A mutant may not fail the suite -- it may HANG it.

`maxflow/level-graph-accepts-saturated-arcs` is exactly that: letting the BFS walk
saturated arcs makes the level graph always reach the sink, so the phase loop never ends.
Without a timeout the harness waits forever, and "still running" is indistinguishable from
"survived". A run that exceeds the limit is counted as killed-by-hang and labelled as
such, because a suite that never finishes has certainly not passed.
"""


def run_suite() -> tuple[bool, str]:
    """Returns (mutant_survived, how). `how` is 'pass', 'fail' or 'hang'."""
    import os

    env = dict(os.environ)
    # The full suite runs in about a second, so the harness runs the REAL one -- no
    # reduced hypothesis budget, no subset. A mutation score measured against a weaker
    # suite than the one people run is a number about the wrong thing.
    env.setdefault("CONTAINMENT_CUT_REQUIRE_DIFFERENTIAL", "1")
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", "-x", "-q", "--no-header", "-p", "no:cacheprovider"],
            cwd=ROOT, capture_output=True, text=True, env=env, timeout=SUITE_TIMEOUT_S,
        )
    except subprocess.TimeoutExpired:
        return False, "hang"
    return proc.returncode == 0, ("pass" if proc.returncode == 0 else "fail")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--only", help="substring filter on the mutant name")
    args = parser.parse_args()

    mutants = [m for m in MUTANTS if not args.only or args.only in m.name]
    if args.list:
        for m in mutants:
            print(f"{m.name}\n    {m.path.name}: {m.breaks}")
        return 0

    signal.signal(signal.SIGTERM, _restore_and_die)
    signal.signal(signal.SIGINT, _restore_and_die)
    before = {m.path: digest(m.path) for m in mutants}

    print("Baseline: running the suite unmutated ...", flush=True)
    baseline_ok, how = run_suite()
    if not baseline_ok:
        print(f"BASELINE {how.upper()}S. Fix the suite before measuring anything.", file=sys.stderr)
        return 2
    print("Baseline green.\n", flush=True)

    killed: list[str] = []
    survived: list[str] = []
    errored: list[str] = []

    for mutant in mutants:
        original = mutant.path.read_text(encoding="utf-8")
        if mutant.old not in original:
            errored.append(f"{mutant.name}: target text not found in {mutant.path.name}")
            print(f"  ERROR  {mutant.name} — target text not found", flush=True)
            continue
        mutated = original.replace(mutant.old, mutant.new, 1)
        if mutated == original:
            errored.append(f"{mutant.name}: replacement changed nothing")
            print(f"  ERROR  {mutant.name} — replacement was a no-op", flush=True)
            continue
        _IN_FLIGHT[mutant.path] = original
        mutant.path.write_text(mutated, encoding="utf-8")
        # Paranoia, and the reason this harness exists: confirm the bytes on disk moved.
        assert mutant.path.read_text(encoding="utf-8") == mutated
        try:
            survived_this, how = run_suite()
        finally:
            mutant.path.write_text(original, encoding="utf-8")
            assert mutant.path.read_text(encoding="utf-8") == original
            _IN_FLIGHT.pop(mutant.path, None)
        if survived_this:
            survived.append(f"{mutant.name} — {mutant.breaks}")
            print(f"  SURVIVED  {mutant.name}", flush=True)
        else:
            label = "killed (hang)" if how == "hang" else "killed"
            killed.append(mutant.name)
            print(f"  {label:<13} {mutant.name}", flush=True)

    drifted = [str(path) for path, before_digest in before.items() if digest(path) != before_digest]
    if drifted:
        print(f"\nSOURCE TREE IS DIRTY after the run: {drifted}", file=sys.stderr)
        print("A mutant was left behind. Restore from git before trusting any test result.", file=sys.stderr)
        return 2

    total = len(mutants)
    print(f"\n{len(killed)}/{total} mutants killed, {len(survived)} survived, {len(errored)} errors")
    for line in survived:
        print(f"  SURVIVED: {line}")
    for line in errored:
        print(f"  ERROR: {line}")
    return 0 if not survived and not errored else 1


if __name__ == "__main__":
    raise SystemExit(main())
