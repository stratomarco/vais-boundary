"""The expense example from the PHANTOM-B white paper, run through the reference monitor.

Shostack's paper (PHANTOM-B 1.0, 2026) illustrates prompt injection with an LLM doing expense
processing and a report that argues an out-of-policy expense should be approved; with no other
controls, the expense goes through. These tests pin what VAIS changes in that deployment and
what it does not, and back the worked example in docs/phantom-b.md.

The report is attacker-controlled, so its amount is untrusted data. The user's task names the
one report to review, so the report id is bound in the contract.
"""
from __future__ import annotations

from vais import (
    ApprovalPolicy,
    ArgumentPolicy,
    PlannedAction,
    Policy,
    ReferenceMonitor,
    SessionLedger,
    TaskContract,
    ToolPolicy,
    TrustedValue,
)
from vais.models import Provenance, TrustLevel, Value

POLICY = Policy(version=5, default_action="deny", tools={
    "approve_expense": ToolPolicy(
        allow=True,
        required_scope="expenses:approve",
        arguments={"report_id": ArgumentPolicy("trusted"), "amount": ArgumentPolicy()},
        approval=ApprovalPolicy("amount", 500),
        reject_undeclared_arguments=True,
        max_calls=1,
    ),
})

CONTRACT = TaskContract(
    allowed_tools={"approve_expense"},
    granted_scopes={"expenses:approve"},
    bound_arguments={("approve_expense", "report_id"): TrustedValue("EXP-1042", source="user_task")},
    principal_id="finance-agent", session_id="s1", tenant_id="acme", capability_id="review-EXP-1042",
)


def _from_report(data) -> Value:
    return Value(data, Provenance(source="expense_report", trust=TrustLevel.UNTRUSTED))


def _approve(report_id: Value, amount: float) -> PlannedAction:
    return PlannedAction("approve_expense", {"report_id": report_id, "amount": _from_report(amount)})


def _decide(action: PlannedAction, ledger: SessionLedger | None = None):
    return ReferenceMonitor(POLICY).evaluate(action, CONTRACT, ledger=ledger or SessionLedger(CONTRACT))


def test_the_ritz_above_the_threshold_needs_a_human():
    decision = _decide(_approve(TrustedValue("EXP-1042", source="user_task"), 2400))
    assert decision.type.value == "require_approval"
    assert decision.reasons == ("approval_required:approve_expense:amount",)


def test_the_ritz_below_the_threshold_is_the_models_call():
    """The gap, pinned so it stays visible (LIM-048).

    VAIS bounds the damage; it does not judge whether an expense is within company policy.
    Below the threshold, an injected approval of the assigned report is allowed.
    """
    assert _decide(_approve(TrustedValue("EXP-1042", source="user_task"), 450)).type.value == "allow"


def test_the_injection_cannot_move_the_approval_to_another_report():
    injected = _decide(_approve(_from_report("EXP-2077"), 450))
    assert injected.type.value == "deny"
    assert "untrusted_authority_argument:report_id" in injected.reasons

    relabelled = _decide(_approve(TrustedValue("EXP-2077", source="user_task"), 450))
    assert relabelled.reasons == ("bound_argument_changed:report_id",)


def test_one_task_approves_at_most_one_expense():
    ledger = SessionLedger(CONTRACT)
    first = _decide(_approve(TrustedValue("EXP-1042", source="user_task"), 100), ledger)
    second = _decide(_approve(TrustedValue("EXP-1042", source="user_task"), 100), ledger)
    assert (first.type.value, second.type.value) == ("allow", "deny")
