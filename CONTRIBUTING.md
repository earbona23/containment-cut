# Contributing

## The bar

This is a tool that tells people what to switch off during an incident. The standard is
correspondingly unfriendly:

1. **A claim in the output must be backed by something computed.** If the tool prints
   "optimal", a certificate verified it. If it prints "still reachable", a BFS said so.
   No adjective without a measurement behind it.
2. **A new test must be able to fail.** Before opening a PR, break the thing it covers
   and watch it go red. `python3 scripts/mutation_test.py` does this mechanically for the
   core; new algorithm code should come with a mutant added to `MUTANTS`.
3. **No approximation without a bound.** If you add a heuristic, state what it guarantees
   and cite the result. If it guarantees nothing, label it a heuristic in the output as
   well as in the code.
4. **Comments explain *why*.** The what is already in the code.

## Getting set up

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest -q                                          # ~1.5s, 269 tests
CONTAINMENT_CUT_REQUIRE_DIFFERENTIAL=1 pytest -q   # what CI runs
python3 scripts/mutation_test.py                   # ~6 min
python3 scripts/benchmark.py --max 5000
```

The mutation run is slow for one specific reason: `maxflow/level-graph-accepts-saturated-arcs`
does not make the solver wrong, it makes it **hang**, so that mutant burns the harness's
300-second per-run limit before being counted as killed. Everything else takes about a
second.

The README is generated. After changing behaviour, output or numbers:

```bash
python3 scripts/build_readme.py            # runs the tool, the suite, the benchmark and mutation
```

Edit `README.template.md`, never `README.md`. The generator refuses to write a README
claiming a green suite or a clean mutation run that did not happen.

## What is welcome

* More graph relations and their real containment actions, with the Microsoft Learn URL.
* Collectors that emit the graph format (see `docs/graph-format.md`). Keep them out of
  this package's dependency tree.
* Better cost models. The defaults are opinions and are meant to be argued with.
* Counter-examples. An instance where the plan is wrong is the most valuable issue you
  can file — attach the graph JSON.

## What is not

* Anything offensive. This computes containment, not attack paths. Enumeration or
  exploitation tooling will be closed.
* Runtime dependencies in the core.
* Code that mutates a tenant in the open-source build.
