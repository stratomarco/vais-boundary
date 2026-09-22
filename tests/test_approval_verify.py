"""VERIFY agrees with ENFORCE about approvals, and sees replay (FIND-050, FIND-051).

FIND-050. The monitor consumes ``ApprovalStore`` grants, but ``exact_action_approval``
looked only at the contract's approved fingerprints. A payment correctly approved
through the store was allowed by ENFORCE and then reported as unapproved by VERIFY,
so the recommended consume-once mechanism could not pass the default invariant set.

FIND-051. ``exact_action_approval`` asks whether each effect was approved, never how
often the same approval was used. On the contract path one approval paid twice and
both layers stayed silent. ``approval_single_use`` asks that second question.

Both were found in the rc12 review, not by a campaign: the benchmarks never ran the
store path under VERIFY, and no invariant looked across effects for approvals.
"""
from __future__ import annotations

import pytest

from vais import (
    PlannedAction,
    ProtectedExecutor,
    ReferenceMonitor,
    SandboxExecutor,
    TaskContract,
    TrustedValue,
    load_default_invariants,
    load_default_policy,
)
from vais.approvals import ApprovalStore
from vais.exceptions import PolicyValidationError
from vais.invariants import load_invariants
from vais.reward import DeclarativeVerifiableReward


def _contract(session_id: str = "s1") -> TaskContract:
    destination = TrustedValue("ACME-001", source="application")
    return TaskContract(
        allowed_tools={"make_payment"},
        bound_arguments={("make_payment", "destination"): destination},
        granted_scopes={"payments:send"},
        principal_id="p1",
        session_id=session_id,
        tenant_id="t1",
        capability_id="c1",
    )


def _payment(amount, contract=None) -> PlannedAction:
    contract = contract or _contract()
    return PlannedAction(
        "make_payment",
        {"destination": contract.bound_arguments[("make_payment", "destination")],
         "amount": TrustedValue(amount, source="application")},
    )


def _run(actions, contract, store=None):
    records = ProtectedExecutor(
        ReferenceMonitor(load_default_policy()), SandboxExecutor(), approval_store=store
    ).run(actions, contract)
    return records, [r.effect for r in records if r.effect is not None]


def _reasons(violations):
    return [(v.invariant_id, v.reason) for v in violations]


# --- FIND-050: the verifier sees store grants ---------------------------------------

def test_store_approved_payment_passes_verify_when_the_store_is_supplied():
    contract, action, store = _contract(), _payment(500), ApprovalStore()
    store.grant(action, contract)
    records, effects = _run([action], contract, store)

    assert records[0].decision.type.value == "allow"
    assert load_default_invariants().evaluate(effects, contract, store) == ()


def test_store_approved_payment_is_flagged_when_verify_is_not_given_the_store():
    # The pre-rc12 behaviour, still true when the caller omits the store. Kept as a
    # test so the reason a caller must pass it stays visible.
    contract, action, store = _contract(), _payment(500), ApprovalStore()
    store.grant(action, contract)
    _, effects = _run([action], contract, store)

    assert _reasons(load_default_invariants().evaluate(effects, contract)) == [
        ("payment_exact_action_approval", "effect_not_exactly_approved"),
    ]


def test_an_unconsumed_grant_is_not_evidence_of_approval():
    # DEC-041. The effect below never went through the store-backed decision, so its
    # grant was never consumed. A grant existing is not proof the effect was approved.
    contract, action, store = _contract(), _payment(500), ApprovalStore()
    store.grant(action, contract)
    effect = SandboxExecutor().execute(action)

    assert _reasons(load_default_invariants().evaluate([effect], contract, store)) == [
        ("payment_exact_action_approval", "effect_not_exactly_approved"),
    ]


def test_a_grant_consumed_by_another_session_does_not_approve_this_one():
    granted_for, action, store = _contract("s1"), _payment(500), ApprovalStore()
    store.grant(action, granted_for)
    _, effects = _run([action], granted_for, store)

    other = _contract("s2")
    assert _reasons(load_default_invariants().evaluate(effects, other, store)) == [
        ("payment_exact_action_approval", "effect_not_exactly_approved"),
    ]


def test_reward_forwards_the_store_to_the_engine():
    contract, action, store = _contract(), _payment(500), ApprovalStore()
    store.grant(action, contract)
    _, effects = _run([action], contract, store)
    rewarder = DeclarativeVerifiableReward(load_default_invariants())

    assert rewarder.evaluate(effects, contract, store) == (0.0, ())
    assert rewarder.evaluate(effects, contract)[0] == 1.0


# --- FIND-051: one approval, one effect -------------------------------------------

def test_one_contract_approval_replayed_across_two_payments_is_reported():
    contract = _contract().with_approved_action(_payment(500))
    records, effects = _run([_payment(500, contract), _payment(500, contract)], contract)

    # ENFORCE on the contract path still allows the replay (LIM-044); VERIFY now sees it.
    assert [r.decision.type.value for r in records] == ["allow", "allow"]
    violations = load_default_invariants().evaluate(effects, contract)
    assert _reasons(violations) == [("payment_approval_single_use", "approval_reused:payment_sent:2>1")]
    assert violations[0].effect_index == 1


def test_distinct_approved_payments_are_not_reuse():
    contract = _contract().with_approved_action(_payment(500)).with_approved_action(_payment(600))
    _, effects = _run([_payment(500, contract), _payment(600, contract)], contract)

    assert load_default_invariants().evaluate(effects, contract) == ()


def test_repeated_payments_below_the_threshold_are_not_reuse():
    contract = _contract()
    _, effects = _run([_payment(50, contract)] * 3, contract)

    assert load_default_invariants().evaluate(effects, contract) == ()


def test_each_reused_approval_is_reported_once_at_its_first_reuse():
    contract = _contract().with_approved_action(_payment(500)).with_approved_action(_payment(600))
    actions = [_payment(500, contract), _payment(600, contract), _payment(500, contract),
               _payment(600, contract), _payment(500, contract)]
    _, effects = _run(actions, contract)

    violations = load_default_invariants().evaluate(effects, contract)
    assert [(v.effect_index, v.reason) for v in violations] == [
        (2, "approval_reused:payment_sent:3>1"),
        (3, "approval_reused:payment_sent:2>1"),
    ]


def test_limitation_a_genuine_reapproval_is_still_flagged():
    # DEC-042. The store keeps one grant per identity, so after grant, consume, grant,
    # consume it cannot say the action was approved twice. VERIFY reports the second
    # payment for review rather than guess. If this starts failing, update DEC-042.
    contract, action, store = _contract(), _payment(500), ApprovalStore()
    store.grant(action, contract)
    _, first = _run([action], contract, store)
    store.grant(action, contract)
    _, second = _run([action], contract, store)

    assert _reasons(load_default_invariants().evaluate(first + second, contract, store)) == [
        ("payment_approval_single_use", "approval_reused:payment_sent:2>1"),
    ]


# --- loader ---------------------------------------------------------------------

def _write(tmp_path, body: str):
    path = tmp_path / "inv.yaml"
    path.write_text("version: 1\ninvariants:\n  - id: once\n    type: approval_single_use\n"
                    "    effect: payment_sent\n" + body, encoding="utf-8")
    return path


def test_loader_accepts_approval_single_use(tmp_path):
    engine = load_invariants(_write(tmp_path, "    field: amount\n    greater_than: 100\n"))
    (item,) = engine.invariants
    assert (item.type, item.field, item.greater_than) == ("approval_single_use", "amount", 100.0)


@pytest.mark.parametrize("body", [
    "    greater_than: 100\n",                    # no field
    "    field: amount\n",                        # no threshold
    "    field: amount\n    greater_than: true\n",
    "    field: amount\n    greater_than: .inf\n",
    "    field: amount\n    greater_than: [1]\n",
])
def test_loader_rejects_incomplete_approval_single_use(tmp_path, body):
    with pytest.raises(PolicyValidationError):
        load_invariants(_write(tmp_path, body))
