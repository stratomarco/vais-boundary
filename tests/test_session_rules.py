"""Allowed values and session budgets (DEC-067, LIM-072).

A contract binds one value per argument; a task that legitimately uses several lists them as
allowed values, optionally single-use, and caps a numeric argument's session total with a
budget. Both are enforced with a SessionLedger and refuse without one.
"""

from __future__ import annotations

import asyncio
from decimal import Decimal
import json

import pytest

from vais import ArgumentPolicy, Policy, ReferenceMonitor, ToolPolicy
from vais.approvals import ApprovalStore
from vais.exceptions import PolicyValidationError
from vais.gateway import ContractRegistry, Gateway, GatewayOutcomeKind, label_agent_action, load_gateway_contract, token_digest
from vais.ledger import LedgerEntry, SessionLedger
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
    session_amount,
)
from vais.policy import ApprovalPolicy


def trusted(value):
    return TrustedValue(value, source="user")


def untrusted(value):
    return Value(value, Provenance(source="model_output", trust=TrustLevel.DERIVED_UNTRUSTED,
                                   confidentiality=ConfidentialityLevel.PUBLIC))


POLICY = Policy(version=6, default_action="deny", tools={
    "pay": ToolPolicy(True, {"invoice": ArgumentPolicy("trusted"), "amount": ArgumentPolicy()},
                      approval=ApprovalPolicy("amount", 5000.0)),
})


def contract(*, once=True, budget="4650.00", **extra):
    return TaskContract(
        allowed_tools={"pay"},
        allowed_values={("pay", "invoice"): AllowedValues((trusted("INV-1"), trusted("INV-2")), once=once)},
        budgets={} if budget is None else {("pay", "amount"): budget},
        **extra,
    )


def pay(invoice, amount, *, invoice_trusted=True):
    return PlannedAction("pay", {"invoice": trusted(invoice) if invoice_trusted else untrusted(invoice),
                                 "amount": untrusted(amount)})


# --- the contract --------------------------------------------------------------------------

@pytest.mark.parametrize("values, once", [((), False), ((untrusted("x"),), False),
                                          ((trusted("a"), trusted("a")), False), ((trusted("a"),), "yes")])
def test_malformed_allowed_values_are_refused(values, once):
    with pytest.raises(ValueError):
        AllowedValues(values, once=once)


@pytest.mark.parametrize("limit", [-1, "-0.01", float("nan"), float("inf"), True, "abc", [1]])
def test_a_budget_must_be_a_finite_non_negative_amount(limit):
    with pytest.raises(ValueError):
        contract(budget=limit)


def test_an_argument_cannot_be_both_bound_and_given_allowed_values():
    with pytest.raises(ValueError, match="both bound"):
        contract(bound_arguments={("pay", "invoice"): trusted("INV-1")})


@pytest.mark.parametrize("data, expected", [(1250, Decimal("1250")), (1250.5, Decimal("1250.5")), ("0.10", Decimal("0.10")),
                                            (True, None), (-1, None), (float("nan"), None), ("x", None), ([1], None)])
def test_amounts_are_read_exactly_and_never_negative(data, expected):
    assert session_amount(data) == expected


def test_the_new_fields_are_immutable():
    c = contract()
    with pytest.raises(TypeError):
        c.budgets[("pay", "amount")] = Decimal("1e9")
    with pytest.raises(TypeError):
        c.allowed_values |= {}


# --- the monitor ---------------------------------------------------------------------------

def decide(actions, c=None, *, ledger=True):
    c = c or contract()
    monitor = ReferenceMonitor(POLICY)
    session = SessionLedger(c) if ledger else None
    return [monitor.evaluate(a, c, ledger=session) for a in actions]


def test_the_two_invoices_within_the_total_are_allowed():
    assert [d.type for d in decide([pay("INV-1", 1250), pay("INV-2", 3400)])] == [DecisionType.ALLOW] * 2


def test_a_value_outside_the_list_is_refused():
    (d,) = decide([pay("INV-3", 10)])
    assert d.reasons == ("argument_not_allowed:invoice",)


def test_a_listed_value_must_carry_its_trusted_label():
    (d,) = decide([pay("INV-1", 10, invoice_trusted=False)])
    assert "allowed_argument_not_trusted:invoice" in d.reasons


def test_a_single_use_value_is_refused_the_second_time():
    d = decide([pay("INV-1", 100), pay("INV-1", 100)])
    assert d[1].reasons == ("allowed_value_already_used:invoice",)


def test_without_once_a_value_may_repeat_within_the_budget():
    d = decide([pay("INV-1", 100), pay("INV-1", 100)], contract(once=False))
    assert [x.type for x in d] == [DecisionType.ALLOW] * 2


def test_the_budget_allows_exactly_the_total_and_refuses_a_cent_more():
    assert decide([pay("INV-1", 1250), pay("INV-2", 3400)])[1].type == DecisionType.ALLOW
    d = decide([pay("INV-1", 1250), pay("INV-2", "3400.01")])
    assert d[1].reasons == ("budget_exceeded:pay:amount",)


@pytest.mark.parametrize("amount", [-100, True, "lots"])  # NaN cannot even be a Value
def test_an_amount_that_cannot_count_is_refused(amount):
    (d,) = decide([pay("INV-1", amount)])
    assert d.type == DecisionType.DENY


def test_a_refused_action_spends_nothing():
    d = decide([pay("INV-1", 5000), pay("INV-3", 100), pay("INV-2", 4000)], contract(budget="5000"))
    assert [x.type for x in d] == [DecisionType.ALLOW, DecisionType.DENY, DecisionType.DENY]
    assert d[2].reasons == ("budget_exceeded:pay:amount",)
    d = decide([pay("INV-3", 100), pay("INV-1", 5000)], contract(budget="5000"))
    assert d[1].type == DecisionType.ALLOW, "the refused INV-3 call spent no budget"


@pytest.mark.parametrize("c, reason", [(contract(budget=None), "single_use_requires_ledger:pay:invoice"),
                                       (contract(once=False), "budget_requires_ledger:pay:amount")])
def test_without_a_ledger_the_rules_refuse_rather_than_lapse(c, reason):
    (d,) = decide([pay("INV-1", 10)], c, ledger=False)
    assert d.reasons == (reason,)


def test_a_budget_refusal_comes_before_an_approval_is_spent():
    store, c = ApprovalStore(), contract(budget="5000")
    big = pay("INV-1", 6000)
    store.grant(big, c)
    monitor, ledger = ReferenceMonitor(POLICY), SessionLedger(c)
    assert monitor.evaluate(big, c, store, ledger).reasons == ("budget_exceeded:pay:amount",)
    assert store.consume(big, c), "the human's approval was not spent on a refused action"


def test_a_delegate_inherits_the_rules_and_spends_the_same_budget():
    parent = contract(session_id="s1", capability_id="root")
    child = parent.delegate(capability_id="child")
    assert child.allowed_values == parent.allowed_values and child.budgets == parent.budgets
    monitor, ledger = ReferenceMonitor(POLICY), SessionLedger(parent)
    assert monitor.evaluate(pay("INV-1", 4000), parent, ledger=ledger).type == DecisionType.ALLOW
    d = monitor.evaluate(pay("INV-2", 1000), child, ledger=ledger)
    assert d.reasons == ("budget_exceeded:pay:amount",)


# --- the session record --------------------------------------------------------------------

def test_spending_and_used_values_survive_a_restart(tmp_path):
    c, path = contract(), tmp_path / "ledger.json"
    assert decide_with(path, c, pay("INV-1", 1250)).type == DecisionType.ALLOW
    assert decide_with(path, c, pay("INV-1", 1)).reasons == ("allowed_value_already_used:invoice",)
    assert decide_with(path, c, pay("INV-2", 3401)).reasons == ("budget_exceeded:pay:amount",)
    assert decide_with(path, c, pay("INV-2", 3400)).type == DecisionType.ALLOW


def decide_with(path, c, action):
    return ReferenceMonitor(POLICY).evaluate(action, c, ledger=SessionLedger(c, path))


def test_a_ledger_without_the_rules_is_written_exactly_as_before(tmp_path):
    c = TaskContract(allowed_tools={"pay"})
    ledger = SessionLedger(c, tmp_path / "l.json")
    ledger.record(LedgerEntry("pay", "abc"))
    entry = json.loads((tmp_path / "l.json").read_text(encoding="utf-8"))["entries"][0]
    assert set(entry) == {"tool", "action_fingerprint", "contract_approval"}


@pytest.mark.parametrize("extra", [{"amounts": [["amount", "-5"]]}, {"amounts": [["amount", "x"]]},
                                   {"values": [["invoice"]]}, {"values": "INV-1"}, {"spent": 1}])
def test_a_malformed_ledger_entry_is_refused(tmp_path, extra):
    c = contract()
    path = tmp_path / "l.json"
    entry = {"tool": "pay", "action_fingerprint": None, "contract_approval": False, **extra}
    path.write_text(json.dumps({"version": 1, "identity": ["legacy"] * 3, "entries": [entry]}), encoding="utf-8")
    with pytest.raises(ValueError):
        SessionLedger(c, path)


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
    invoice: {{values: [INV-1, INV-2], once: true}}
budgets:
  ops.pay: {{amount: 4650.00}}
"""


def test_a_contract_file_declares_allowed_values_and_budgets(tmp_path):
    path = tmp_path / "c.yaml"
    path.write_text(CONTRACT_YAML.format(digest=token_digest("t")), encoding="utf-8")
    _, c = load_gateway_contract(path)
    allowed = c.allowed_values[("ops.pay", "invoice")]
    assert allowed.once and [v.data for v in allowed.values] == ["INV-1", "INV-2"]
    assert all(v.provenance.source == "contract" for v in allowed.values)
    assert c.budgets[("ops.pay", "amount")] == Decimal("4650.0")


@pytest.mark.parametrize("change", [
    ("{values: [INV-1, INV-2], once: true}", "{values: [], once: true}"),
    ("{values: [INV-1, INV-2], once: true}", "{values: [INV-1, INV-2], once: maybe}"),
    ("{values: [INV-1, INV-2], once: true}", "{values: [INV-1, INV-1]}"),
    ("{values: [INV-1, INV-2], once: true}", "{values: [INV-1], limit: 3}"),
    ("{amount: 4650.00}", "{amount: -1}"),
    ("{amount: 4650.00}", "{amount: lots}"),
])
def test_a_malformed_rule_in_a_contract_file_is_refused(tmp_path, change):
    path = tmp_path / "c.yaml"
    path.write_text(CONTRACT_YAML.format(digest=token_digest("t")).replace(*change), encoding="utf-8")
    with pytest.raises(PolicyValidationError):
        load_gateway_contract(path)


def test_the_gateway_labels_a_listed_value_with_its_trusted_label(tmp_path):
    path = tmp_path / "c.yaml"
    path.write_text(CONTRACT_YAML.format(digest=token_digest("t")), encoding="utf-8")
    _, c = load_gateway_contract(path)
    action = label_agent_action("ops.pay", {"invoice": "INV-2", "amount": 10}, c, ConfidentialityLevel.PUBLIC)
    assert action.arguments["invoice"].is_trusted and not action.arguments["amount"].is_trusted
    other = label_agent_action("ops.pay", {"invoice": "INV-9", "amount": 10}, c, ConfidentialityLevel.PUBLIC)
    assert not other.arguments["invoice"].is_trusted


class Upstream:
    def __init__(self):
        self.calls = []

    async def call_tool(self, name, arguments=None):
        self.calls.append((name, dict(arguments or {})))
        return {"status": "paid"}


def test_the_gateway_enforces_the_budget_across_calls(tmp_path):
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

    assert call("INV-1", 1250) is GatewayOutcomeKind.ALLOWED
    assert call("INV-1", 10) is GatewayOutcomeKind.DENIED  # single use
    assert call("INV-9", 10) is GatewayOutcomeKind.DENIED  # not listed
    assert call("INV-2", 3450) is GatewayOutcomeKind.DENIED  # over the total
    assert call("INV-2", 3400) is GatewayOutcomeKind.ALLOWED
    assert [args["invoice"] for _, args in upstream.calls] == ["INV-1", "INV-2"]
