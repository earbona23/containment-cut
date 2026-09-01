"""Execution: deliberately absent from the free tool, and gated in the paid one.

This file contains no HTTP client, no credential handling and no Graph call. That is not
an omission, it is the design. A tool that can compute "disable this account" and also
*do* it is one bad argument away from being an outage generator, and one stolen token
away from being the attacker's favourite utility.

What the free tool does: print the plan, exactly. What a licensed build adds:

  1. an explicit ``--execute`` flag, which is not the default and never will be;
  2. an explicit acknowledgement flag naming the tenant being changed;
  3. per-step confirmation, showing the command and the rollback before each call;
  4. a stop on the first non-2xx response -- half a containment plan is a known state
     only if you know exactly where it stopped;
  5. an append-only journal of what was actually issued and what came back.

Until every one of those exists, the honest behaviour is to refuse, which is what happens
below. A refusal that says why is more useful than a partial execution that says "done".
"""

from __future__ import annotations

from dataclasses import dataclass

from .license import entitlement
from .plan import ContainmentPlan


class ExecutionRefused(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class Gate:
    allowed: bool
    reason: str


def check_gate(plan: ContainmentPlan, *, execute_flag: bool, acknowledged: str | None) -> Gate:
    """Every condition that must hold before a single call could be made."""
    if not execute_flag:
        return Gate(False, "dry-run is the default; execution requires --execute")
    if not acknowledged:
        return Gate(False, "--i-understand-this-changes <tenant> is required and must match the graph")
    if plan.status != "cut-found":
        return Gate(False, f"there is no plan to execute (status: {plan.status})")
    if plan.certificate is None or not plan.certificate.ok:
        return Gate(False, "the plan's certificate did not verify; refusing to act on an unverified plan")
    ent = entitlement()
    if not ent.pro or "gated-execute" not in ent.features:
        return Gate(False, f"execution is a Pro feature ({ent.reason or 'license does not include gated-execute'})")
    return Gate(False, "gated execution is not implemented in the open-source build")


def run(plan: ContainmentPlan, **kwargs) -> None:
    gate = check_gate(plan, **kwargs)
    raise ExecutionRefused(gate.reason)
