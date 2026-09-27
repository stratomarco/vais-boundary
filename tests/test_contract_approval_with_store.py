"""A contract-held approval beside an approval store (FIND-062, DEC-060).

Before the fix, giving the monitor an ApprovalStore hid the contract's own approvals: the
store was checked and nothing else, so the gateway, which always has a store, ignored every
approval in its contract files. Now the store's grants are tried first and the contract's
approval second, and with a store the contract approval's use is recorded in the store, so it
is single-use across a restart and across processes sharing the file. A first fix counted the
use only in the session ledger, which lives in one process's memory; a restarted gateway, or a
second worker, then allowed the same pre-approved action again.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest

from vais.approvals import ApprovalStore, ContractApprovalUse
from vais.ledger import SessionLedger
from vais.models import PlannedAction, TaskContract, TrustedValue, action_fingerprint
from vais.monitor import ReferenceMonitor
from vais.policy import Policy, ToolPolicy

SRC = Path(__file__).resolve().parents[1] / "src"
POLICY = Policy(version=3, default_action="deny", tools={
    "deploy": ToolPolicy(True, exact_approval_required=True),
})


def _action(target: str = "prod") -> PlannedAction:
    return PlannedAction("deploy", {"target": TrustedValue(target, source="user")})


def _contract(capability_id: str = "root") -> TaskContract:
    base = TaskContract(allowed_tools={"deploy"}, principal_id="alice", session_id="s-1", tenant_id="acme",
                        capability_id=capability_id)
    return base.with_approved_action(_action())


def _decisions(contract, store, ledger, n=3, action=None):
    monitor = ReferenceMonitor(POLICY)
    return [monitor.evaluate(action or _action(), contract, store, ledger).type.value for _ in range(n)]


ONCE = ["allow", "require_approval", "require_approval"]


# --- the rules ------------------------------------------------------------------------

def test_with_a_store_the_contract_approval_counts_once_with_or_without_a_ledger():
    assert _decisions(_contract(), ApprovalStore(), SessionLedger(_contract())) == ONCE
    assert _decisions(_contract(), ApprovalStore(), None) == ONCE


def test_it_approves_only_the_exact_action():
    assert _decisions(_contract(), ApprovalStore(), None, n=1, action=_action("staging")) == ["require_approval"]


def test_without_a_store_contract_approvals_behave_as_before():
    assert _decisions(_contract(), None, None) == ["allow"] * 3  # reusable, LIM-044
    assert _decisions(_contract(), None, SessionLedger(_contract())) == ONCE


def test_the_store_is_tried_first_and_each_approval_is_spent_once():
    contract = _contract()
    store, ledger = ApprovalStore(), SessionLedger(contract)
    store.grant(_action(), contract)
    # The store's grant, then the contract's approval, then nothing.
    assert _decisions(contract, store, ledger) == ["allow", "allow", "require_approval"]
    assert [entry.contract_approval for entry in ledger.entries] == [False, True]
    assert store.contract_approval_used(action_fingerprint(_action()), contract)


def test_a_use_the_ledger_already_saw_is_not_spent_again_in_the_store():
    contract, ledger = _contract(), SessionLedger(_contract())
    assert _decisions(contract, None, ledger, n=1) == ["allow"]
    store = ApprovalStore()
    assert _decisions(contract, store, ledger, n=1) == ["require_approval"]
    assert not store.contract_approval_used(action_fingerprint(_action()), contract)


def test_a_delegate_shares_its_parents_single_use():
    # Keyed by session, like the ledger (DEC-050): a delegate with another capability
    # cannot spend the parent's approval a second time.
    parent = _contract()
    child = parent.delegate(capability_id="deployer")
    store = ApprovalStore()
    assert _decisions(parent, store, None, n=1) == ["allow"]
    assert _decisions(child, store, None, n=1) == ["require_approval"]


def test_another_session_has_its_own_use():
    store = ApprovalStore()
    other = TaskContract(allowed_tools={"deploy"}, principal_id="alice", session_id="s-2", tenant_id="acme",
                         capability_id="root").with_approved_action(_action())
    assert _decisions(_contract(), store, None, n=1) == ["allow"]
    assert _decisions(other, store, None, n=1) == ["allow"]


# --- durability: what the in-memory ledger could not give ----------------------------------

def test_single_use_survives_a_restart(tmp_path):
    path = tmp_path / "approvals.json"
    assert _decisions(_contract(), ApprovalStore(path), SessionLedger(_contract()), n=1) == ["allow"]
    # A new process: fresh store instance and fresh ledger, same file.
    assert _decisions(_contract(), ApprovalStore(path), SessionLedger(_contract()), n=1) == ["require_approval"]


def test_two_store_instances_sharing_a_file_allow_it_once(tmp_path):
    path = tmp_path / "approvals.json"
    first, second = ApprovalStore(path), ApprovalStore(path)  # both loaded before either decides
    decisions = _decisions(_contract(), first, None, n=1) + _decisions(_contract(), second, None, n=1)
    assert decisions == ["allow", "require_approval"]


_WORKER = """
import sys, time
sys.path.insert(0, {src!r})
from vais.approvals import ApprovalStore
from vais.ledger import SessionLedger
from vais.models import PlannedAction, TaskContract, TrustedValue
from vais.monitor import ReferenceMonitor
from vais.policy import Policy, ToolPolicy
action = PlannedAction("deploy", {{"target": TrustedValue("prod", source="user")}})
contract = TaskContract(allowed_tools={{"deploy"}}, principal_id="alice", session_id="s-1", tenant_id="acme",
                        capability_id="root").with_approved_action(action)
monitor = ReferenceMonitor(Policy(version=3, default_action="deny", tools={{"deploy": ToolPolicy(True, exact_approval_required=True)}}))
store, ledger = ApprovalStore({path!r}), SessionLedger(contract)
while time.time() < {start!r}:
    time.sleep(0.001)
print(monitor.evaluate(action, contract, store, ledger).type.value)
"""


def test_processes_racing_on_one_file_allow_it_once(tmp_path):
    path = tmp_path / "approvals.json"
    script = _WORKER.format(src=str(SRC), path=str(path), start=time.time() + 3.0)
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    workers = [subprocess.Popen([sys.executable, "-c", script], stdout=subprocess.PIPE, text=True, env=env)
               for _ in range(6)]
    results = [worker.communicate(timeout=120)[0].strip() for worker in workers]
    assert sorted(results) == ["allow"] + ["require_approval"] * 5


# --- the file ---------------------------------------------------------------------------

def test_a_store_without_contract_approval_uses_is_written_as_before(tmp_path):
    path = tmp_path / "approvals.json"
    store = ApprovalStore(path)
    store.grant(_action(), _contract())
    records = json.loads(path.read_text(encoding="utf-8"))
    assert [sorted(r) for r in records] == [["capability_id", "consumed", "expires_at", "fingerprint",
                                             "principal_id", "session_id", "tenant_id"]]


def test_use_records_round_trip_and_duplicates_are_refused(tmp_path):
    path = tmp_path / "approvals.json"
    store = ApprovalStore(path)
    store.grant(_action(), _contract())
    assert store.use_contract_approval(action_fingerprint(_action()), _contract())
    records = json.loads(path.read_text(encoding="utf-8"))
    assert [r.get("kind") for r in records] == [None, "contract_approval_use"]
    assert ApprovalStore(path).contract_approval_used(action_fingerprint(_action()), _contract())

    path.write_text(json.dumps(records + [records[1]]), encoding="utf-8")
    with pytest.raises(ValueError):
        ApprovalStore(path)


def test_a_malformed_use_record_is_refused():
    with pytest.raises(ValueError):
        ContractApprovalUse("0" * 64, "alice", "", "acme")
    with pytest.raises(ValueError):
        ContractApprovalUse("0" * 64, "alice", "s-1", "acme", kind="grant")
