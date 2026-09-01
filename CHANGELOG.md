# Changelog

## 0.1.0

First release.

* Exact minimum-cost mixed node/edge containment cut via node splitting and Dinic
  max-flow, with a machine-checkable optimality certificate on every plan.
* NP-hard bundled-action case solved by constraint generation over greedy weighted set
  cover, with a proved `H(d)` approximation bound (Chvátal 1979) and a certified
  instance-specific lower bound.
* Default action catalogue: 11 action kinds rendering real Microsoft Graph, PowerShell
  and Azure CLI commands, with documentation links.
* Synthetic demo tenant with a non-obvious optimum, pinned in the tests against
  exhaustive search.
* Terminal, JSON, Markdown and Mermaid output. Dry run always; `execute` refuses.
* Offline Ed25519 license verification in pure Python; zero runtime dependencies.
