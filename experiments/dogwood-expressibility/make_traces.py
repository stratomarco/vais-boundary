"""Build the study's corpus: every reference workflow's unprotected trace, VAIS's decision on each
call of it, the harmful call, and the configuration a Dogwood policy may use (PREREGISTRATION.md).

    PYTHONPATH=src python experiments/dogwood-expressibility/make_traces.py

Writes corpus.json (traces and VAIS's decisions) and configuration.json (what each application's
VAIS configuration knows, which is all a Dogwood policy may use). Deterministic.
"""

from __future__ import annotations

import asyncio
from decimal import Decimal
import json
from pathlib import Path
from typing import Any

from vais.models import PlannedAction, TrustedValue, action_fingerprint
from vais.reference_agent import (
    DeterministicReferenceTarget, ReferenceAgentRunner, ReferenceEnvironment, ReferenceMode, ReferenceState,
    application_for, reference_workflows as incident_workflows,
)
from vais.reference_finance import reference_workflows as finance_workflows

HERE = Path(__file__).resolve().parent
TRUSTED_PHASES = ("trusted_setup", "trusted_retrieval")


def plain(value: Any) -> Any:
    """A JSON value from VAIS's frozen containers, Values and Decimals."""
    if hasattr(value, "data") and hasattr(value, "provenance"):
        return plain(value.data)
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, dict) or hasattr(value, "items"):
        return {str(k): plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, frozenset, set)):
        items = [plain(v) for v in value]
        return sorted(items, key=json.dumps) if isinstance(value, (frozenset, set)) else items
    return value


def kind(workflow) -> str:
    return "attack" if workflow.id.startswith("attack") else workflow.id.split("-")[0]


def approved_actions(workflow) -> tuple[list[dict], list[str]]:
    """The actions an operator approved, as tool and arguments, rebuilt from the contract's bindings.

    The contract holds approvals as fingerprints. An operator approving an action knows its content,
    so the Dogwood task event may carry it; VAIS's fingerprints are matched to candidate actions
    built from the bound arguments, and any approval not matched is reported, not guessed.
    """
    contract = workflow.contract
    bound: dict[str, dict[str, Any]] = {}
    for (tool, argument), value in contract.bound_arguments.items():
        bound.setdefault(tool, {})[argument] = value.data
    candidates = [(tool, args) for tool, args in bound.items()]
    if workflow.approved_restart_service:
        candidates.append(("production.restart_service", {"service": workflow.approved_restart_service}))
    found, matched = [], set()
    for tool, args in candidates:
        fingerprint = action_fingerprint(PlannedAction(tool, {k: TrustedValue(v) for k, v in args.items()}))
        if fingerprint in contract.approved_action_fingerprints:
            found.append({"tool": tool, "arguments": plain(args)})
            matched.add(fingerprint)
    return found, sorted(set(contract.approved_action_fingerprints) - matched)


def task(workflow, principal_id: str, tenant: str) -> dict:
    c = workflow.contract
    bound, allowed, budgets, value_budgets = {}, {}, {}, {}
    for (tool, argument), value in c.bound_arguments.items():
        bound.setdefault(tool, {})[argument] = plain(value.data)
    for (tool, argument), spec in c.allowed_values.items():
        allowed.setdefault(tool, {})[argument] = {"values": [plain(v.data) for v in spec.values], "once": spec.once}
    for (tool, argument), cap in c.budgets.items():
        budgets.setdefault(tool, {})[argument] = str(cap)
    for (tool, argument), spec in c.value_budgets.items():
        value_budgets.setdefault(tool, {})[argument] = {"per": spec.per, "limits": {str(k): str(v) for k, v in spec.limits.items()}}
    approved, unmatched = approved_actions(workflow)
    return {
        "principal": principal_id, "tenant": tenant, "allowed_tools": sorted(c.allowed_tools),
        "granted_scopes": sorted(c.granted_scopes), "bound": bound, "allowed_values": allowed,
        "budgets": budgets, "value_budgets": value_budgets, "approved": approved, "unmatched_approvals": unmatched,
    }


def configuration(workflow) -> dict:
    """What the application's VAIS configuration knows about each tool: policy and profile."""
    application = application_for(workflow)
    policy = application.workflow_policy(workflow)
    tools = {}
    for name, rule in policy.tools.items():
        binding = application.profile.by_canonical_tool(name)
        tools[name] = {
            "allow": rule.allow,
            "required_scope": rule.required_scope,
            "trusted_arguments": sorted(a for a, p in rule.arguments.items() if p.trust_required == "trusted"),
            "confidentiality_ceilings": {a: p.max_confidentiality.value for a, p in rule.arguments.items() if p.max_confidentiality},
            "declared_arguments": sorted(rule.arguments),
            "approval_threshold": {"field": rule.approval.field, "greater_than": rule.approval.greater_than} if rule.approval else None,
            "exact_approval_required": rule.exact_approval_required,
            "reject_undeclared_arguments": rule.reject_undeclared_arguments,
            "max_calls": rule.max_calls,
            "untrusted_origin": rule.untrusted_origin,
            "result_confidentiality": binding.result_policy.confidentiality.value if binding else None,
            "mints": [{"from": m.field, "to": [f"{t}.{a}" for t, a in m.targets]} for m in binding.mints] if binding else [],
            "owned_by_application": name in application.owned_tools,
        }
    return {"policy_version": policy.version, "default_action": policy.default_action, "tools": tools}


async def build_one(workflow, runner: ReferenceAgentRunner) -> dict:
    result = await runner.run_workflow(workflow, DeterministicReferenceTarget(), mode=ReferenceMode.UNPROTECTED)
    application = application_for(workflow)
    steps = [s for s in result.trace if s.action is not None]
    state = ReferenceState(workflow=workflow, principal=runner.principal,
                           session_id=f"reference:{workflow.id}:unprotected", contract=workflow.contract)

    # The harmful call: the first whose effect makes a security invariant fail on the trace so far.
    harmful = None
    if kind(workflow) == "attack":
        for k in range(len(steps)):
            failed = [i.invariant_id for i in application.evaluate_trace(state, steps[:k + 1]) if not i.passed]
            if failed:
                harmful = k
                break

    # VAIS's decision on every call of this fixed trace, through the reference environment.
    environment = ReferenceEnvironment(workflow)
    calls = []
    for k, step in enumerate(steps):
        contract = workflow.contract
        if step.phase == "trusted_retrieval" and application.retrieval_contract is not None:
            contract = application.retrieval_contract(workflow, step.action)
        decision = environment.decide(step.action, contract, mode=ReferenceMode.PROTECTED)
        calls.append({
            "index": k, "phase": step.phase, "agent": step.phase not in TRUSTED_PHASES,
            "tool": step.action.tool, "arguments": plain(step.action.plain_arguments()),
            "fingerprint": action_fingerprint(step.action),
            "result": plain(step.result) if step.result is not None else None,
            "vais": {"type": decision.type.value, "reasons": list(decision.reasons)},
        })
    return {
        "id": workflow.id, "application": application.name if hasattr(application, "name") else workflow.application,
        "kind": kind(workflow), "category": workflow.category, "control_for": workflow.control_for,
        "task": task(workflow, runner.principal.principal_id if hasattr(runner.principal, "principal_id") else str(runner.principal),
                     runner.principal.tenant_id),
        "calls": calls, "harmful_index": harmful,
        "unprotected_security_failure": any(not i.passed for i in result.invariants if i.invariant_id != "workflow_utility"),
    }


def main() -> int:
    runner = ReferenceAgentRunner()
    corpus, configurations = [], {}
    for workflows in (incident_workflows(), finance_workflows()):
        for workflow in workflows:
            corpus.append(asyncio.run(build_one(workflow, runner)))
            configurations.setdefault(workflow.application, {})[workflow.id] = configuration(workflow)
    # Approvals the bindings could not rebuild are matched to the action an operator approved,
    # wherever in the corpus that exact action is proposed (same fingerprint, same approval).
    proposed = {c["fingerprint"]: {"tool": c["tool"], "arguments": c["arguments"]}
                for w in corpus for c in w["calls"]}
    for w in corpus:
        still = []
        for fingerprint in w["task"]["unmatched_approvals"]:
            if fingerprint in proposed:
                w["task"]["approved"].append(proposed[fingerprint])
            else:
                still.append(fingerprint)
        w["task"]["unmatched_approvals"] = still
    (HERE / "corpus.json").write_text(json.dumps({"workflows": corpus}, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    (HERE / "configuration.json").write_text(json.dumps(configurations, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print(f"{len(corpus)} workflows written")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
