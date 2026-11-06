"""Exact amounts per value (DEC-076): a payment for exactly what was approved, not more and not less.

A value budget caps the amount paid against each invoice (DEC-069), which still allowed an
invoice to be paid less than was approved. With ``exact`` each call must be for exactly its
invoice's limit, compared as a decimal. Gateway contracts accept it from version 2.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
import sys

import pytest

from vais import ArgumentPolicy, Policy, ReferenceMonitor, SessionLedger, ToolPolicy
from vais.exceptions import PolicyValidationError
from vais.gateway import load_gateway_contract, token_digest
from vais.models import (AllowedValues, DecisionType, PlannedAction, TaskContract, TrustedValue, ValueBudget,
                         Value, Provenance, TrustLevel)

ROOT = Path(__file__).resolve().parents[1]
POLICY = Policy(version=5, default_action="deny", tools={"pay": ToolPolicy(True, {
    "invoice_id": ArgumentPolicy("trusted"), "amount": ArgumentPolicy()})})


def _contract(exact: bool) -> TaskContract:
    return TaskContract(
        allowed_tools={"pay"},
        allowed_values={("pay", "invoice_id"): AllowedValues((TrustedValue("INV-1", source="task"),
                                                              TrustedValue("INV-2", source="task")), once=True)},
        value_budgets={("pay", "amount"): ValueBudget("invoice_id", {"INV-1": "1180.00", "INV-2": "2240.50"}, exact=exact)},
    )


def _pay(invoice, amount):
    return PlannedAction("pay", {"invoice_id": TrustedValue(invoice, source="task"),
                                 "amount": Value(amount, Provenance("model_output", TrustLevel.DERIVED_UNTRUSTED))})


def _decide(contract, action, ledger=None):
    return ReferenceMonitor(POLICY).evaluate(action, contract, ledger=ledger or SessionLedger(contract))


@pytest.mark.parametrize("amount", ["1180.00", "1180", 1180, 1180.0, " 1180.0 "])
def test_the_approved_amount_is_allowed_however_it_is_written(amount):
    assert _decide(_contract(True), _pay("INV-1", amount)).type is DecisionType.ALLOW


@pytest.mark.parametrize("amount", ["1179.99", "1180.01", "590.00", 0, "2240.50"])
def test_any_other_amount_is_refused(amount):
    decision = _decide(_contract(True), _pay("INV-1", amount))
    assert decision.type is DecisionType.DENY
    assert decision.reasons == ("value_amount_not_exact:pay:amount:invoice_id",)


def test_an_amount_above_the_cap_is_refused_with_or_without_exact():
    for exact in (True, False):
        assert _decide(_contract(exact), _pay("INV-1", "1180.01")).type is DecisionType.DENY


def test_without_exact_a_smaller_amount_is_still_allowed_as_in_version_1():
    assert _decide(_contract(False), _pay("INV-1", "590.00")).type is DecisionType.ALLOW


def test_each_invoice_is_paid_once_at_its_own_amount():
    contract = _contract(True)
    ledger = SessionLedger(contract)
    assert _decide(contract, _pay("INV-1", "1180.00"), ledger).type is DecisionType.ALLOW
    assert _decide(contract, _pay("INV-2", "2240.5"), ledger).type is DecisionType.ALLOW
    assert _decide(contract, _pay("INV-1", "1180.00"), ledger).type is DecisionType.DENY
    # Another invoice's amount is not this invoice's.
    fresh = SessionLedger(contract)
    assert _decide(contract, _pay("INV-2", "1180.00"), fresh).type is DecisionType.DENY


def test_exact_must_be_a_boolean():
    with pytest.raises(ValueError, match="true or false"):
        ValueBudget("invoice_id", {"INV-1": "1.00"}, exact="yes")


# --- contract files -------------------------------------------------------------------------

CONTRACT = """\
version: {version}
token_sha256: {digest}
principal_id: clerk-1
session_id: run-1
tenant_id: acme
capability_id: pay
allowed_tools: [pay]
allowed_values:
  pay: {{invoice_id: {{values: [INV-1], once: true}}}}
value_budgets:
  pay: {{amount: {{per: invoice_id, limits: {{INV-1: "1180.00"}}{exact}}}}}
"""


def _write(tmp_path, version, exact=", exact: true"):
    path = tmp_path / "contract.yaml"
    path.write_text(CONTRACT.format(version=version, digest=token_digest("t"), exact=exact), encoding="utf-8")
    return path


def test_a_version_2_contract_declares_exact_amounts(tmp_path):
    _, contract = load_gateway_contract(_write(tmp_path, 2))
    assert contract.value_budgets[("pay", "amount")].exact
    _, plain = load_gateway_contract(_write(tmp_path, 2, exact=""))
    assert not plain.value_budgets[("pay", "amount")].exact


def test_version_1_keeps_its_meaning_and_rejects_exact(tmp_path):
    with pytest.raises(PolicyValidationError, match="unknown field"):
        load_gateway_contract(_write(tmp_path, 1))
    _, contract = load_gateway_contract(_write(tmp_path, 1, exact=""))
    assert not contract.value_budgets[("pay", "amount")].exact


@pytest.mark.parametrize("version, exact, message", [(3, ", exact: true", "1 or 2"), (2, ", exact: maybe", "true or false")])
def test_contract_files_are_read_strictly(tmp_path, version, exact, message):
    with pytest.raises(PolicyValidationError, match=message):
        load_gateway_contract(_write(tmp_path, version, exact))


# --- through the gateway, with the integration's contract ------------------------------------

def test_the_gateway_refuses_an_underpayment_the_task_did_not_approve(tmp_path):
    sys.path.insert(0, str(ROOT / "examples"))
    sys.path.insert(0, str(ROOT / "tests"))
    from ap_integration.contract import contract_for, render
    from ap_integration.task import load_task
    from ap_sandbox.store import Store, init_database
    from vais.approvals import ApprovalStore
    from vais.gateway import ContractRegistry, Gateway, GatewayOutcomeKind
    from vais.gateway_server import load_gateway_config
    from vais.mcp import load_mcp_profile
    from vais.policy import load_policy

    class Backend:
        """The sandbox store as the gateway's upstream: reads return records, writes their replies."""

        def __init__(self, store):
            self.store = store

        async def call_tool(self, name, arguments=None):
            result = getattr(self.store, name)(**dict(arguments or {}))
            return result.reply if hasattr(result, "reply") else result

    evaluation = ROOT / "experiments" / "integration-evaluation"
    task = load_task(evaluation / "tasks" / "batch-3.yaml")  # INV-3301 3120.00, INV-3302 640.00
    seed = json.loads((evaluation / "seed.json").read_text(encoding="utf-8"))
    init_database(tmp_path / "ap.sqlite3", seed, "exact-amount-test-key-0123")
    store = Store(tmp_path / "ap.sqlite3")
    (tmp_path / "contracts").mkdir()
    (tmp_path / "contracts" / "run.yaml").write_text(render(contract_for(task, token_digest("tok"))), encoding="utf-8")
    config = load_gateway_config(ROOT / "examples" / "ap_integration" / "gateway.yaml")
    gateway = Gateway(profile=load_mcp_profile(config.profile), monitor=ReferenceMonitor(load_policy(config.policy)),
                      registry=ContractRegistry(tmp_path / "contracts"), sessions={"ap": Backend(store)},
                      approval_store=ApprovalStore(tmp_path / "approvals.json"), pending_dir=tmp_path / "pending",
                      state_dir=tmp_path / "state")

    def call(tool, arguments):
        return asyncio.run(gateway.call("tok", tool, arguments))

    vendor = call("ap.get_vendor", {"vendor_id": "V-330"}).result
    pay = {"vendor_id": "V-330", "bank_account_id": vendor["bank_account_id"], "invoice_id": "INV-3301"}
    # S07's instalment: half the approved amount, within the cap, refused as not exact.
    assert call("ap.pay", {**pay, "amount": "1560.00"}).kind is GatewayOutcomeKind.DENIED
    assert store.list_payments() == []
    # The approved amount, written as a number, is the same amount.
    assert call("ap.pay", {**pay, "amount": 3120}).kind is GatewayOutcomeKind.ALLOWED
    assert [p["amount"] for p in store.list_payments()] == ["3120.00"]
