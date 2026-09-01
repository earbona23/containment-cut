#!/usr/bin/env python3
"""Assemble README.md from README.template.md by RUNNING the tool.

Every number and every block of output in the README is produced by executing the thing
it describes. Nothing in the README is typed by hand, so nothing in it can quietly drift
away from what the code does.

    python3 scripts/build_readme.py                  # runs everything (slow: mutation)
    python3 scripts/build_readme.py --mutation-from out.txt
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY_EXE = sys.executable


def run(*argv: str) -> str:
    proc = subprocess.run([PY_EXE, *argv], cwd=ROOT, capture_output=True, text=True)
    if proc.returncode != 0:
        raise SystemExit(f"{argv} exited {proc.returncode}\n{proc.stdout}\n{proc.stderr}")
    return proc.stdout.rstrip("\n")


def condensed_demo() -> str:
    """The demo output with the per-command detail elided, so the README stays readable."""
    raw = run("-m", "containment_cut", "demo", "--no-color").splitlines()
    kept: list[str] = []
    elided = False
    for line in raw:
        stripped = line.strip()
        if stripped.startswith(("$ [", "!", "ref ", "{ \"", '{ "')) or stripped.startswith("Revoke-Mg"):
            if not elided:
                kept.append("     ...exact Graph / az / PowerShell calls for this step...")
                elided = True
            continue
        if line.startswith("     ") and not stripped.startswith(("why:", "→", "·")):
            continue
        if stripped.startswith("why:"):
            continue
        elided = False
        kept.append(line)
    text = "\n".join(kept)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return "```\n$ containment-cut demo\n\n" + text.strip() + "\n```"


def mermaid_block() -> str:
    return "```mermaid\n" + run("-m", "containment_cut", "demo", "--format", "mermaid") + "\n```"


def benchmark_block(max_users: int) -> str:
    return "```\n$ python3 scripts/benchmark.py\n\n" + run("scripts/benchmark.py", "--max", str(max_users)) + "\n```"


def test_block() -> str:
    proc = subprocess.run(
        [PY_EXE, "-m", "pytest", "-q", "--no-header", "-p", "no:cacheprovider"],
        cwd=ROOT, capture_output=True, text=True,
        env={**__import__("os").environ, "CONTAINMENT_CUT_REQUIRE_DIFFERENTIAL": "1"},
    )
    if proc.returncode != 0:
        raise SystemExit("the suite is not green; refusing to write a README that says it is\n" + proc.stdout)
    tail = [l for l in proc.stdout.splitlines() if l.strip()][-1]
    return "$ CONTAINMENT_CUT_REQUIRE_DIFFERENTIAL=1 pytest -q\n" + tail


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mutation-from", help="file with the output of scripts/mutation_test.py")
    parser.add_argument("--bench-max", type=int, default=20000)
    args = parser.parse_args()

    if args.mutation_from:
        mutation = Path(args.mutation_from).read_text(encoding="utf-8").strip()
    else:
        mutation = run("scripts/mutation_test.py")
    mutation_lines = [l for l in mutation.splitlines() if l.strip()]
    summary = next((l for l in mutation_lines if "mutants killed" in l), None)
    if summary is None or "0 survived" not in summary or "0 errors" not in summary:
        raise SystemExit(f"mutation run is not clean; refusing to publish it as if it were:\n{summary}")
    mutation_block = "$ python3 scripts/mutation_test.py\n\n" + "\n".join(
        l for l in mutation_lines if l.startswith(("  killed", "  SURVIVED", "  ERROR")) or "mutants killed" in l
    )

    template = (ROOT / "README.template.md").read_text(encoding="utf-8")
    out = (
        template.replace("{{DEMOBLOCK}}", condensed_demo())
        .replace("{{MERMAID}}", mermaid_block())
        .replace("{{BENCH}}", benchmark_block(args.bench_max))
        .replace("{{TESTCOUNT}}", test_block())
        .replace("{{MUTATION}}", mutation_block)
    )
    leftovers = re.findall(r"\{\{[A-Z]+\}\}", out)
    if leftovers:
        raise SystemExit(f"unfilled placeholders: {leftovers}")
    (ROOT / "README.md").write_text(out, encoding="utf-8")
    print(f"README.md written ({len(out.splitlines())} lines)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
