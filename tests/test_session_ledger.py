"""A stateful monitor: limits and single-use approvals enforced in flight (P1b-3).

Without a ledger the reference monitor decides one action at a time and remembers
nothing. A bound over several actions could only be detected afterwards, in VERIFY
(LIM-035, issue #4), and an approval held in the contract authorized its action every
time it was proposed (LIM-044). A ``SessionLedger`` gives the monitor that memory, and
the same ledger lets VERIFY check that every effect corresponds to an ALLOW.

The last test is the acceptance criterion for P1b-3: with a shared ledger, ENFORCE
and VERIFY agree on every generated trace, and without one they demonstrably do not.
"""
from __future__ import annotations

import asyncio
import random
import threading
import time

import pytest

from vais import (
    ArgumentPolicy,
    MCPEffectMapping,
    MCPProfile,
    MCPProtectedClient,
    PlannedAction,
    Policy,
    ProtectedExecutor,
    ReferenceMonitor,
    SandboxExecutor,
    SessionLedger,
    TaskContract,
    ToolPolicy,
    TrustedValue,
    action_fingerprint,
)
from vais.approvals import ApprovalStore
from vais.exceptions import PolicyValidationError
from vais.invariants import DeclarativeInvariantEngine, InvariantDefinition, load_invariants
from vais.mcp import MCPToolBinding
from vais.policy import ApprovalPolicy, load_policy


def _contract(session_id: str = "s1", approvals=()) -> TaskContract:
    return TaskContract(
        allowed_tools={"make_payment"},
        bound_arguments={("make_payment", "destination"): TrustedValue("ACME-001", source="application")},
        granted_scopes={"payments:send"},
        approved_action_fingerprints=frozenset(approvals),
        principal_id="p1", session_id=session_id, tenant_id="t1", capability_id="c1",
    )


def _payment(amount) -> PlannedAction:
    return PlannedAction("make_payment", {
        "destination": TrustedValue("ACME-001", source="application"),
        "amount": TrustedValue(amount, source="application"),
    })


def _policy(max_calls=None, exact=False, threshold=100.0) -> Policy:
    return Policy(version=5, default_action="deny", tools={"make_payment": ToolPolicy(
        allow=True,
        required_scope="payments:send",
        arguments={"destination": ArgumentPolicy(trust_required="trusted"), "amount": ArgumentPolicy()},
        approval=None if threshold is None else ApprovalPolicy("amount", threshold),
        exact_approval_required=exact,
        reject_undeclared_arguments=True,
        max_calls=max_calls,
    )})


def _decisions(monitor, actions, contract, store=None, ledger=None):
    return [monitor.evaluate(a, contract, store, ledger).type.value for a in actions]


# --- limits in flight -------------------------------------------------------------

def test_max_calls_is_enforced_in_flight_with_a_ledger():
    contract = _contract()
    ledger = SessionLedger(contract)
    monitor = ReferenceMonitor(_policy(max_calls=2))

    assert _decisions(monitor, [_payment(10)] * 4, contract, ledger=ledger) == ["allow", "allow", "deny", "deny"]
    assert monitor.evaluate(_payment(10), contract, None, ledger).reasons == ("call_limit_reached:make_payment:2",)
    assert len(ledger.entries) == 2


def test_denied_actions_do_not_count_towards_the_limit():
    contract = _contract()
    ledger = SessionLedger(contract)
    monitor = ReferenceMonitor(_policy(max_calls=1))
    hijacked = PlannedAction("make_payment", {"destination": TrustedValue("EVIL"), "amount": TrustedValue(10)})

    assert _decisions(monitor, [hijacked, hijacked, _payment(10)], contract, ledger=ledger) == ["deny", "deny", "allow"]


def test_a_declared_limit_without_a_ledger_fails_closed():
    decision = ReferenceMonitor(_policy(max_calls=5)).evaluate(_payment(10), _contract())
    assert decision.type.value == "deny"
    assert decision.reasons == ("call_limit_requires_ledger:make_payment",)


def test_reaching_the_limit_does_not_spend_an_approval():
    contract, store = _contract(), ApprovalStore()
    ledger = SessionLedger(contract)
    monitor = ReferenceMonitor(_policy(max_calls=1))
    store.grant(_payment(500), contract)
    assert monitor.evaluate(_payment(500), contract, store, ledger).type.value == "allow"

    store.grant(_payment(500), contract)  # a second, genuine approval
    assert monitor.evaluate(_payment(500), contract, store, ledger).reasons == ("call_limit_reached:make_payment:1",)
    assert store.was_consumed(action_fingerprint(_payment(500)), contract) is False


def test_concurrent_decisions_cannot_both_take_the_last_call():
    contract = _contract()
    ledger = SessionLedger(contract)
    monitor = ReferenceMonitor(_policy(max_calls=1))
    results, start = [], threading.Barrier(16)

    def worker():
        start.wait()
        results.append(monitor.evaluate(_payment(10), contract, None, ledger).type.value)

    threads = [threading.Thread(target=worker) for _ in range(16)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert results.count("allow") == 1
    assert len(ledger.entries) == 1


class _SlowLedger(SessionLedger):
    """Pauses between reading the count and returning it, to widen the race window.

    Without the pause the window between checking a limit and recording an ALLOW is
    too small to hit reliably, and a mutant that removes the monitor's lock survived
    the test above. With it, a monitor that checks and records in separate critical
    sections lets every thread read the old count.
    """

    def calls(self, tool):
        count = super().calls(tool)
        time.sleep(0.01)
        return count


def test_checking_a_limit_and_recording_the_allow_are_one_atomic_step():
    contract = _contract()
    ledger = _SlowLedger(contract)
    monitor = ReferenceMonitor(_policy(max_calls=1))
    results, start = [], threading.Barrier(8)

    def worker():
        start.wait()
        results.append(monitor.evaluate(_payment(10), contract, None, ledger).type.value)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert results.count("allow") == 1
    assert len(ledger.entries) == 1


# --- single-use contract approvals ---------------------------------------------------

def test_a_contract_held_approval_is_single_use_with_a_ledger():
    contract = _contract(approvals=[action_fingerprint(_payment(500))])
    ledger = SessionLedger(contract)
    monitor = ReferenceMonitor(_policy())

    assert _decisions(monitor, [_payment(500)] * 3, contract, ledger=ledger) == [
        "allow", "require_approval", "require_approval",
    ]
    assert [e.contract_approval for e in ledger.entries] == [True]


def test_limitation_a_contract_held_approval_is_still_reusable_without_a_ledger():
    # LIM-044 holds for callers that pass neither a store nor a ledger.
    contract = _contract(approvals=[action_fingerprint(_payment(500))])
    assert _decisions(ReferenceMonitor(_policy()), [_payment(500)] * 3, contract) == ["allow"] * 3


def test_a_ledger_from_another_session_is_refused():
    ledger = SessionLedger(_contract("s1"))
    decision = ReferenceMonitor(_policy(max_calls=5)).evaluate(_payment(10), _contract("s2"), None, ledger)
    assert decision.reasons == ("ledger_identity_mismatch",)
    assert ledger.entries == ()


# --- FIND-056 ------------------------------------------------------------------

def test_exact_and_threshold_approval_together_consume_one_grant_once():
    contract, store = _contract(), ApprovalStore()
    monitor = ReferenceMonitor(_policy(exact=True, threshold=100.0))
    store.grant(_payment(500), contract)

    assert _decisions(monitor, [_payment(500)] * 2, contract, store) == ["allow", "require_approval"]


def test_exact_approval_still_required_below_the_threshold():
    contract, store = _contract(), ApprovalStore()
    decision = ReferenceMonitor(_policy(exact=True, threshold=100.0)).evaluate(_payment(50), contract, store)
    assert decision.reasons == ("exact_approval_required:make_payment",)


# --- enforcement paths pass the ledger through -------------------------------------------

def test_protected_executor_enforces_the_limit():
    contract = _contract()
    executor = ProtectedExecutor(ReferenceMonitor(_policy(max_calls=1)), SandboxExecutor(), ledger=SessionLedger(contract))
    records = executor.run([_payment(10), _payment(20)], contract)
    assert [r.decision.type.value for r in records] == ["allow", "deny"]
    assert [r.effect is not None for r in records] == [True, False]


class _Session:
    def __init__(self):
        self.calls = 0

    async def call_tool(self, name, arguments=None):
        self.calls += 1
        return {"ok": True}


def test_mcp_client_enforces_the_limit():
    contract, session = _contract(), _Session()
    profile = MCPProfile((MCPToolBinding("pay", "make_payment", "make_payment",
                                         effect=MCPEffectMapping("payment_sent", {"destination": "destination", "amount": "amount"})),))
    client = MCPProtectedClient(server_id="pay", session=session, profile=profile,
                                monitor=ReferenceMonitor(_policy(max_calls=1)), ledger=SessionLedger(contract))
    decisions = [asyncio.run(client.execute(_payment(10), contract)).decision.type.value for _ in range(2)]
    assert decisions == ["allow", "deny"]
    assert session.calls == 1


# --- VERIFY reads the same ledger -------------------------------------------------------

MEDIATED = InvariantDefinition(id="mediated", description="d", type="monitor_mediated", effect="payment_sent")


def test_effects_that_went_through_the_monitor_are_mediated():
    contract = _contract()
    ledger = SessionLedger(contract)
    records = ProtectedExecutor(ReferenceMonitor(_policy(max_calls=5)), SandboxExecutor(), ledger=ledger).run(
        [_payment(10), _payment(10)], contract)
    effects = [r.effect for r in records]
    assert DeclarativeInvariantEngine([MEDIATED]).evaluate(effects, contract, ledger=ledger) == ()


def test_an_effect_that_bypassed_the_monitor_is_reported():
    contract = _contract()
    ledger = SessionLedger(contract)
    mediated = ProtectedExecutor(ReferenceMonitor(_policy(max_calls=5)), SandboxExecutor(), ledger=ledger).run(
        [_payment(10)], contract)[0].effect
    bypass = SandboxExecutor().execute(_payment(10))  # same action, never evaluated

    (violation,) = DeclarativeInvariantEngine([MEDIATED]).evaluate([mediated, bypass], contract, ledger=ledger)
    assert (violation.effect_index, violation.reason) == (1, "effect_not_in_ledger")


def test_mediation_fails_closed_without_the_ledger_or_with_the_wrong_one():
    effect = SandboxExecutor().execute(_payment(10))
    engine = DeclarativeInvariantEngine([MEDIATED])
    assert engine.evaluate([effect], _contract())[0].reason == "missing_session_ledger"
    assert engine.evaluate([effect], _contract(), ledger=SessionLedger(_contract("s2")))[0].reason == "ledger_identity_mismatch"
    assert engine.evaluate([], _contract()) == ()


# --- loader ------------------------------------------------------------------------

def test_policy_v5_loads_max_calls(tmp_path):
    path = tmp_path / "p.yaml"
    path.write_text("version: 5\ndefault_action: deny\ntools:\n  t:\n    allow: true\n    max_calls: 3\n", encoding="utf-8")
    assert load_policy(path).tools["t"].max_calls == 3


@pytest.mark.parametrize("version, value", [(4, "3"), (5, "-1"), (5, "true"), (5, "1.5"), (5, "[1]"), (5, "{}")])
def test_policy_rejects_bad_or_unsupported_max_calls(tmp_path, version, value):
    path = tmp_path / "p.yaml"
    path.write_text(f"version: {version}\ndefault_action: deny\ntools:\n  t:\n    allow: true\n    max_calls: {value}\n", encoding="utf-8")
    with pytest.raises(PolicyValidationError):
        load_policy(path)


def test_tool_policy_rejects_bad_max_calls_in_code():
    for bad in (-1, True, 1.5):
        with pytest.raises(ValueError):
            ToolPolicy(allow=True, max_calls=bad)


def test_invariant_loader_accepts_monitor_mediated(tmp_path):
    path = tmp_path / "i.yaml"
    path.write_text("version: 1\ninvariants:\n  - id: m\n    type: monitor_mediated\n    effect: payment_sent\n", encoding="utf-8")
    (item,) = load_invariants(path).invariants
    assert (item.type, item.effect) == ("monitor_mediated", "payment_sent")


# --- acceptance: ENFORCE and VERIFY agree ------------------------------------------------

LIMIT = 3
AGREEMENT_INVARIANTS = DeclarativeInvariantEngine([
    InvariantDefinition(id="volume", description="d", type="max_effect_count", effect="payment_sent", max_count=LIMIT),
    InvariantDefinition(id="once", description="d", type="approval_single_use", effect="payment_sent",
                        field="amount", greater_than=100.0),
    InvariantDefinition(id="approved", description="d", type="exact_action_approval", effect="payment_sent",
                        field="amount", greater_than=100.0),
    MEDIATED,
])


def _trace(rng: random.Random) -> list[PlannedAction]:
    return [_payment(rng.choice([10, 50, 500, 700])) for _ in range(rng.randint(1, 12))]


@pytest.mark.parametrize("seed", range(200))
def test_enforce_and_verify_agree_when_they_share_a_ledger(seed):
    rng = random.Random(seed)
    approvals = [action_fingerprint(_payment(500)), action_fingerprint(_payment(700))]
    contract = _contract(approvals=approvals)
    ledger = SessionLedger(contract)
    executor = ProtectedExecutor(ReferenceMonitor(_policy(max_calls=LIMIT)), SandboxExecutor(), ledger=ledger)

    effects = [r.effect for r in executor.run(_trace(rng), contract) if r.effect is not None]

    assert AGREEMENT_INVARIANTS.evaluate(effects, contract, ledger=ledger) == ()


def test_without_a_ledger_the_same_traces_do_disagree():
    # The agreement test above is only meaningful if it could fail. Without a ledger,
    # and with no declared limit for it to fail closed on, ENFORCE allows traces that
    # VERIFY then flags, on a clear majority of the same seeds.
    approvals = [action_fingerprint(_payment(500)), action_fingerprint(_payment(700))]
    disagreements = 0
    for seed in range(200):
        contract = _contract(approvals=approvals)
        ledger_for_verify = SessionLedger(contract)
        executor = ProtectedExecutor(ReferenceMonitor(_policy(max_calls=None)), SandboxExecutor())
        effects = [r.effect for r in executor.run(_trace(random.Random(seed)), contract) if r.effect is not None]
        engine = DeclarativeInvariantEngine([i for i in AGREEMENT_INVARIANTS.invariants if i.type != "monitor_mediated"])
        disagreements += bool(engine.evaluate(effects, contract, ledger=ledger_for_verify))
    assert disagreements > 100
