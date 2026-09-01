---
name: Counter-example
about: The plan is wrong, incomplete, or not minimal on a graph you have
title: "[counter-example] "
labels: bug
---

**Attach the graph JSON** (redacted is fine — rename the ids, keep the shape and the costs).

**What the tool printed**

```
containment-cut plan --graph ... --format json
```

**What you believe the right answer is, and why**

A cheaper cut, a route the plan leaves open, or an action the plan proposes that cannot
actually be executed.

**Did the certificate pass?**

If `optimality_proved` is `true` and the cut still leaves a route open, that is the most
serious class of bug this project can have and it will be treated as such.
