"""Amount caps per allowed value (DEC-069, P1b-10).

A session budget caps a total but not how it is split between the allowed values, so in the
finance gap rerun one invoice was overpaid while the total held (FIND-071). A value budget caps
the amount separately for each allowed value of another argument.
"""

from __future__ import annotations

import asyncio
from decimal import Decimal
import json

import pytest

from vais import ArgumentPolicy, Policy, ReferenceMonitor, ToolPolicy
from vais.approvals import ApprovalStore
from vais.exceptions import PolicyValidationError
from vais.gateway import ContractRegistry, Gateway, GatewayOutcomeKind, load_gateway_contract, token_digest
from vais.ledger import SessionLedger
from vais.mcp import MCPProfile, MCPToolBinding
from vais.models import (
    AllowedValues,
    ConfidentialityLevel,
    DecisionType,
    PlannedAction,
    Provenance,
    TaskContract,
    TrustLevel,
    TrustedValue,
    Value,
    ValueBudget,
)


def trusted(value):
    return TrustedValue(value, source="user")


def untrusted(value):
    return Value(value, Provenance(source="model_output", trust=TrustLevel.DERIVED_UNTRUSTED,
                                   confidentiality=ConfidentialityLevel.PUBLIC))


POLICY = Policy(version=6, default_action="deny", tools={
    "pay": ToolPolicy(True, {"invoice": ArgumentPolicy("trusted"), "amount": ArgumentPolicy()}),
})
LIMITS = {"INV-1": "1250.00", "INV-2": "3400.00"}


def contract(*, once=False, limits=None, budget=None, **extra):
    return TaskContract(
        allowed_tools={"pay"},
        allowed_values={("pay", "invoice"): AllowedValues((trusted("INV-1"), trusted("INV-2")), once=once)},
        budgets={} if budget is None else {("pay", "amount"): budget},
        value_budgets={("pay", "amount"): ValueBudget(per="invoice", limits=LIMITS if limits is None else limits)},
        **extra,
    )


def pay(invoice, amount):
    return PlannedAction("pay", {"invoice": trusted(invoice), "amount": untrusted(amount)})


def decide(actions, c=None, *, ledger=True):
    c = c or contract()
    monitor, session = ReferenceMonitor(POLICY), (SessionLedger(c) if ledger else None)
    return [monitor.evaluate(a, c, ledger=session) for a in actions]


# --- the contract --------------------------------------------------------------------------

@pytest.mark.parametrize("per, limits", [
    ("", LIMITS), ("invoice", {}), ("invoice", {"INV-1": -1}), ("invoice", {"INV-1": float("nan")}),
    ("invoice", {"INV-1": True}), ("invoice", {"INV-1": "lots"}), ("invoice", "1250"),
])
def test_a_malformed_value_budget_is_refused(per, limits):
    with pytest.raises(ValueError):
        ValueBudget(per=per, limits=limits)


@pytest.mark.parametrize("limits", [
    {"INV-1": "1250.00"},                                         # INV-2 left uncapped
    {"INV-1": "1250.00", "INV-2": "3400.00", "INV-3": "1.00"},    # a value that is not allowed
])
def test_every_allowed_value_gets_exactly_one_cap(limits):
    with pytest.raises(ValueError, match="exactly one limit"):
        contract(limits=limits)


def test_a_value_budget_needs_allowed_values_for_its_key():
    with pytest.raises(ValueError, match="allowed values"):
        TaskContract(allowed_tools={"pay"},
                     value_budgets={("pay", "amount"): ValueBudget(per="invoice", limits=LIMITS)})


def test_a_value_budget_cannot_be_per_its_own_argument():
    with pytest.raises(ValueError, match="own argument"):
        TaskContract(allowed_tools={"pay"},
                     allowed_values={("pay", "amount"): AllowedValues((trusted("1"),))},
                     value_budgets={("pay", "amount"): ValueBudget(per="amount", limits={"1": "1"})})


def test_the_value_budgets_are_immutable():
    c = contract()
    with pytest.raises(TypeError):
        c.value_budgets[("pay", "amount")] = None
    with pytest.raises(TypeError):
        c.value_budgets[("pay", "amount")].limits["INV-1"] = Decimal("1e9")


# --- the monitor ---------------------------------------------------------------------------

def test_each_invoice_may_be_paid_up_to_its_own_amount():
    assert [d.type for d in decide([pay("INV-1", 1250), pay("INV-2", 3400)])] == [DecisionType.ALLOW] * 2


@pytest.mark.parametrize("invoice, amount", [
    # the three overpayments within the total that the finance gap rerun observed (FIND-071)
    ("INV-1", 1450), ("INV-2", 4650), ("INV-2", 3900),
])
def test_an_invoice_overpaid_within_the_total_is_refused(invoice, amount):
    (d,) = decide([pay(invoice, amount)], contract(budget="4650.00"))
    assert d.reasons == ("value_budget_exceeded:pay:amount:invoice",)


def test_the_cap_holds_across_several_payments_to_one_invoice():
    first, second, third = decide([pay("INV-1", 1000), pay("INV-1", 250), pay("INV-1", "0.01")])
    assert (first.type, second.type) == (DecisionType.ALLOW, DecisionType.ALLOW)
    assert third.reasons == ("value_budget_exceeded:pay:amount:invoice",)


def test_one_invoice_spending_does_not_use_another_invoices_cap():
    decisions = decide([pay("INV-1", 1250), pay("INV-2", 3400)])
    assert all(d.type == DecisionType.ALLOW for d in decisions)


def test_a_refused_payment_spends_nothing():
    over, exact = decide([pay("INV-1", 1251), pay("INV-1", 1250)])
    assert over.type == DecisionType.DENY and exact.type == DecisionType.ALLOW


def test_without_a_ledger_the_cap_refuses_rather_than_lapses():
    (d,) = decide([pay("INV-1", 1)], ledger=False)
    assert d.reasons == ("budget_requires_ledger:pay:amount",)


@pytest.mark.parametrize("amount", [-100, True, "lots"])
def test_an_amount_that_cannot_count_is_refused(amount):
    (d,) = decide([pay("INV-1", amount)])
    assert d.reasons == ("invalid_budget_amount:amount",)


def test_a_value_outside_the_list_is_refused_before_the_cap():
    (d,) = decide([pay("INV-3", 1)])
    assert d.reasons == ("argument_not_allowed:invoice",)


def test_the_total_budget_still_applies_beside_the_caps():
    first, second = decide([pay("INV-2", 3400), pay("INV-1", 1250)], contract(budget="4000"))
    assert first.type == DecisionType.ALLOW and second.reasons == ("budget_exceeded:pay:amount",)


def test_a_cap_refusal_comes_before_an_approval_is_spent():
    policy = Policy(version=6, default_action="deny", tools={
        "pay": ToolPolicy(True, {"invoice": ArgumentPolicy("trusted"), "amount": ArgumentPolicy()},
                          exact_approval_required=True)})
    store, c = ApprovalStore(), contract()
    big = pay("INV-1", 2000)
    store.grant(big, c)
    assert ReferenceMonitor(policy).evaluate(big, c, store, SessionLedger(c)).reasons == (
        "value_budget_exceeded:pay:amount:invoice",)
    assert store.consume(big, c), "the human's approval was not spent on a refused action"


def test_a_delegate_inherits_the_caps_and_spends_the_same_ones():
    parent = contract(session_id="s1", capability_id="root")
    child = parent.delegate(capability_id="child")
    assert child.value_budgets == parent.value_budgets
    monitor, ledger = ReferenceMonitor(POLICY), SessionLedger(parent)
    assert monitor.evaluate(pay("INV-1", 1000), parent, ledger=ledger).type == DecisionType.ALLOW
    assert monitor.evaluate(pay("INV-1", 251), child, ledger=ledger).reasons == ("value_budget_exceeded:pay:amount:invoice",)


def test_the_caps_survive_a_restart(tmp_path):
    c, path = contract(), tmp_path / "ledger.json"

    def decide_now(action):
        return ReferenceMonitor(POLICY).evaluate(action, c, ledger=SessionLedger(c, path))

    assert decide_now(pay("INV-1", 1000)).type == DecisionType.ALLOW
    assert decide_now(pay("INV-1", 251)).reasons == ("value_budget_exceeded:pay:amount:invoice",)
    assert decide_now(pay("INV-1", 250)).type == DecisionType.ALLOW
    entries = json.loads(path.read_text(encoding="utf-8"))["entries"]
    assert entries[0]["values"] == [["invoice", '"INV-1"']] and entries[0]["amounts"] == [["amount", "1000"]]


# --- the gateway ---------------------------------------------------------------------------

CONTRACT_YAML = """\
version: 1
token_sha256: {digest}
principal_id: alice
session_id: s-1
tenant_id: acme
capability_id: root
allowed_tools: [ops.pay]
allowed_values:
  ops.pay:
    invoice: {{values: [INV-1, INV-2]}}
value_budgets:
  ops.pay:
    amount: {{per: invoice, limits: {{INV-1: 1250.00, INV-2: 3400.00}}}}
"""


def test_a_contract_file_declares_value_budgets(tmp_path):
    path = tmp_path / "c.yaml"
    path.write_text(CONTRACT_YAML.format(digest=token_digest("t")), encoding="utf-8")
    _, c = load_gateway_contract(path)
    budget = c.value_budgets[("ops.pay", "amount")]
    assert budget.per == "invoice" and budget.limit_for("INV-2") == Decimal("3400.0")


@pytest.mark.parametrize("change", [
    ("{per: invoice, limits: {INV-1: 1250.00, INV-2: 3400.00}}", "{per: invoice, limits: {INV-1: 1250.00}}"),
    ("{per: invoice, limits: {INV-1: 1250.00, INV-2: 3400.00}}", "{per: invoice, limits: {INV-1: -1, INV-2: 1}}"),
    ("{per: invoice, limits: {INV-1: 1250.00, INV-2: 3400.00}}", "{per: nothing, limits: {INV-1: 1, INV-2: 1}}"),
    ("{per: invoice, limits: {INV-1: 1250.00, INV-2: 3400.00}}", "{per: invoice}"),
    ("{per: invoice, limits: {INV-1: 1250.00, INV-2: 3400.00}}", "{per: invoice, limits: {INV-1: 1, INV-2: 1}, cap: 3}"),
])
def test_a_malformed_value_budget_in_a_contract_file_is_refused(tmp_path, change):
    path = tmp_path / "c.yaml"
    path.write_text(CONTRACT_YAML.format(digest=token_digest("t")).replace(*change), encoding="utf-8")
    with pytest.raises(PolicyValidationError):
        load_gateway_contract(path)


class Upstream:
    def __init__(self):
        self.calls = []

    async def call_tool(self, name, arguments=None):
        self.calls.append((name, dict(arguments or {})))
        return {"status": "paid"}


def test_the_gateway_enforces_the_caps_across_calls(tmp_path):
    (tmp_path / "contracts").mkdir()
    (tmp_path / "contracts" / "c.yaml").write_text(CONTRACT_YAML.format(digest=token_digest("t")), encoding="utf-8")
    upstream = Upstream()
    policy = Policy(version=6, default_action="deny", tools={
        "ops.pay": ToolPolicy(True, {"invoice": ArgumentPolicy("trusted"), "amount": ArgumentPolicy()})})
    gateway = Gateway(profile=MCPProfile((MCPToolBinding("ops", "pay", "ops.pay"),)), monitor=ReferenceMonitor(policy),
                      registry=ContractRegistry(tmp_path / "contracts"), sessions={"ops": upstream},
                      approval_store=ApprovalStore(), pending_dir=tmp_path / "pending")

    def call(invoice, amount):
        return asyncio.run(gateway.call("t", "ops.pay", {"invoice": invoice, "amount": amount})).kind

    assert call("INV-1", 1450) is GatewayOutcomeKind.DENIED   # over its own amount
    assert call("INV-1", 1000) is GatewayOutcomeKind.ALLOWED
    assert call("INV-1", 250) is GatewayOutcomeKind.ALLOWED
    assert call("INV-1", 1) is GatewayOutcomeKind.DENIED
    assert call("INV-2", 3400) is GatewayOutcomeKind.ALLOWED
    assert [args["amount"] for _, args in upstream.calls] == [1000, 250, 3400]
