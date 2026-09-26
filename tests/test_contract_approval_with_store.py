"""A contract-held approval beside an approval store (FIND-062).

Before the fix, giving the monitor an ApprovalStore hid the contract's own approvals: the
store was checked and nothing else, so the gateway, which always has a store, ignored every
approval in its contract files. Now the store is tried first and the contract second, and
with a store the contract's approval counts only through a ledger, once.
"""
from __future__ import annotations

from vais.approvals import ApprovalStore
from vais.ledger import SessionLedger
from vais.models import PlannedAction, TaskContract, TrustedValue
from vais.monitor import ReferenceMonitor
from vais.policy import Policy, ToolPolicy

POLICY = Policy(version=3, default_action="deny", tools={
    "deploy": ToolPolicy(True, exact_approval_required=True),
})


def _action(target: str = "prod") -> PlannedAction:
    return PlannedAction("deploy", {"target": TrustedValue(target, source="user")})


def _contract() -> TaskContract:
    base = TaskContract(allowed_tools={"deploy"}, principal_id="alice", session_id="s-1", tenant_id="acme",
                        capability_id="root")
    return base.with_approved_action(_action())


def _decisions(monitor, contract, store, ledger, n=3, action=None):
    return [monitor.evaluate(action or _action(), contract, store, ledger).type.value for _ in range(n)]


def test_with_a_store_and_a_ledger_the_contract_approval_counts_once():
    contract = _contract()
    assert _decisions(ReferenceMonitor(POLICY), contract, ApprovalStore(), SessionLedger(contract)) == [
        "allow", "require_approval", "require_approval"]


def test_it_approves_only_the_exact_action():
    contract = _contract()
    decisions = _decisions(ReferenceMonitor(POLICY), contract, ApprovalStore(), SessionLedger(contract),
                           n=1, action=_action("staging"))
    assert decisions == ["require_approval"]


def test_a_store_without_a_ledger_never_makes_a_contract_approval_reusable():
    # Without a ledger nothing could make the contract's approval single-use, so it does not
    # count; this is the pre-fix behaviour, kept for callers with a store and no ledger.
    assert _decisions(ReferenceMonitor(POLICY), _contract(), ApprovalStore(), None) == ["require_approval"] * 3


def test_without_a_store_contract_approvals_behave_as_before():
    contract = _contract()
    monitor = ReferenceMonitor(POLICY)
    assert _decisions(monitor, contract, None, None) == ["allow"] * 3  # reusable, LIM-044
    assert _decisions(monitor, contract, None, SessionLedger(contract)) == ["allow", "require_approval", "require_approval"]


def test_the_store_is_tried_first_and_each_approval_is_spent_once():
    contract = _contract()
    store, ledger = ApprovalStore(), SessionLedger(contract)
    store.grant(_action(), contract)
    # The store's grant, then the contract's approval, then nothing.
    assert _decisions(ReferenceMonitor(POLICY), contract, store, ledger) == ["allow", "allow", "require_approval"]
    assert [entry.contract_approval for entry in ledger.entries] == [False, True]
