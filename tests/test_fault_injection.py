"""P1-5: fail-closed verification under fault injection.

The README claims the boundary fails closed. This module injects the adverse
conditions the roadmap named and records, cell by cell, what actually happens.
A fail-open under resource exhaustion is the usual way systems like this die in
production, so each cell asserts the outcome rather than describing it.

Three cells turned out not to be testable as written, and saying why is part of
the result rather than an omission:

* **Clock skew across the approval window.** There is no approval window. No
  clock, TTL, expiry or deadline appears anywhere in the enforcement path, so no
  decision can be moved by moving the clock. The corresponding property, that an
  approval never expires, is asserted below instead.
* **Evaluator timeout.** There is no timeout mechanism to test. A pathological
  invariant does not deny; it hangs its caller. Recorded as LIM-040.
* **Out of memory.** Not reproducible in a unit test without faking the
  condition into something that is no longer OOM. The nearest real case, an
  unbounded recursion during canonicalization, is already covered by FIND-041
  and `test_fingerprint_recursion`.
"""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest
import yaml

from vais import (
    ApprovalStore,
    DecisionType,
    Effect,
    PlannedAction,
    ReferenceMonitor,
    TaskContract,
    TrustedValue,
    AuditTrail,
    load_invariants,
    load_policy,
)
from vais.exceptions import PolicyValidationError
from vais.invariants import DeclarativeInvariantEngine


def write(tmp_path, name: str, text: str):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def action() -> PlannedAction:
    return PlannedAction("send_email", {"recipient": TrustedValue("a@b.test", "user")})


def contract() -> TaskContract:
    return TaskContract(allowed_tools={"send_email"})


# --- config faults ------------------------------------------------------------

def test_a_missing_policy_file_raises_rather_than_defaulting(tmp_path):
    """No Policy object is produced, so no monitor can be built from it."""
    with pytest.raises(FileNotFoundError):
        load_policy(tmp_path / "does-not-exist.yaml")


@pytest.mark.parametrize(
    "name, text",
    [
        ("truncated", "version: 4\ntools:\n  send_email:\n    allow:"),
        ("top_level_list", "- a\n- b"),
        ("top_level_scalar", "just a string"),
        ("unknown_field", "version: 4\nbogus: 1"),
        ("v4_allow_default", "version: 4\ndefault_action: allow"),
        ("null_tools", "version: 4\ntools: null"),
        ("unsupported_version", "version: 9"),
        ("boolean_version", "version: true"),
    ],
)
def test_a_corrupt_policy_is_rejected(tmp_path, name, text):
    with pytest.raises(PolicyValidationError):
        load_policy(write(tmp_path, f"{name}.yaml", text))


def test_malformed_yaml_raises_a_yaml_error_not_a_policy_error(tmp_path):
    """LIM-039, asserted rather than assumed.

    Both outcomes fail closed, but they fail closed as different exception types.
    An application that catches `PolicyValidationError` in order to degrade
    gracefully will not catch a policy file that is not valid YAML at all, and
    will see an unhandled `yaml.YAMLError` instead.
    """
    path = write(tmp_path, "bad.yaml", "tools: [unclosed\n")
    with pytest.raises(yaml.YAMLError):
        load_policy(path)
    assert not issubclass(yaml.YAMLError, PolicyValidationError)


@pytest.mark.parametrize("text", ["", "   \n\n", "# only a comment\n"])
def test_an_empty_policy_file_is_deny_all_not_allow_all(tmp_path, text):
    """The most important config cell: emptiness must not mean permissiveness."""
    policy = load_policy(write(tmp_path, "empty.yaml", text))
    assert policy.default_action == "deny"
    assert len(policy.tools) == 0

    decision = ReferenceMonitor(policy).evaluate(action(), contract())
    assert decision.type is DecisionType.DENY
    assert decision.reasons == ("tool_not_in_policy:send_email",)


# --- invariant faults ---------------------------------------------------------

def test_an_invariant_referencing_an_absent_effect_field_fails_closed(tmp_path):
    path = write(tmp_path, "inv.yaml", """
version: 1
invariants:
  - id: ceiling
    description: bounds body confidentiality
    type: confidentiality_ceiling
    effect: email_sent
    field: body
    max_confidentiality: public
""")
    engine = load_invariants(path)
    violations = engine.evaluate([Effect("email_sent", {"body": "x"})], contract())
    assert [v.reason for v in violations] == ["missing_effect_provenance:body"]


def test_an_invariant_on_an_effect_kind_never_produced_is_silently_inert(tmp_path):
    """LIM-041: a typo in `effect` disables the rule and reports nothing.

    Nothing validates that an invariant's effect kind is ever emitted by the
    application. `payment_send` against an application that emits `payment_sent`
    loads cleanly, evaluates cleanly, and never fires. The loader cannot detect
    this, because it has no inventory of the effect kinds an application
    produces.
    """
    path = write(tmp_path, "typo.yaml", """
version: 1
invariants:
  - id: typo_effect
    description: watches an effect kind that never occurs
    type: forbidden_effect
    effect: payment_send
""")
    engine = load_invariants(path)
    assert engine.evaluate([Effect("payment_sent", {"amount": 10})], contract()) == ()


def test_an_evaluator_that_raises_does_not_yield_an_empty_violation_set(monkeypatch, tmp_path):
    """A fault inside evaluation must not read as "nothing was violated"."""
    path = write(tmp_path, "inv.yaml", """
version: 1
invariants:
  - id: forbid
    description: forbids the effect outright
    type: forbidden_effect
    effect: email_sent
""")
    engine = load_invariants(path)

    def exploding(*args, **kwargs):
        raise RuntimeError("evaluator fault")

    monkeypatch.setattr(DeclarativeInvariantEngine, "_violation_reason", staticmethod(exploding))
    with pytest.raises(RuntimeError):
        engine.evaluate([Effect("email_sent", {"body": "x"})], contract())


# --- storage faults -----------------------------------------------------------

def test_a_failed_audit_write_leaves_the_in_memory_chain_intact(tmp_path):
    """The audit write is separate from recording, so a full disk loses the file
    and not the chain. The error surfaces rather than being swallowed."""
    trail = AuditTrail()
    for i in range(3):
        trail.record("authorization_decision", tool="t", decision="allow", details={"i": i})

    with patch("pathlib.Path.write_text", side_effect=OSError(28, "No space left on device")):
        with pytest.raises(OSError):
            trail.write_jsonl(tmp_path / "audit.jsonl")

    assert len(trail.events) == 3
    assert trail.verify() is True


def test_a_failed_approval_persist_keeps_memory_and_record_consistent(tmp_path):
    """FIND-046, the fault this module was written to find.

    `consume` used to mark the grant spent in memory and then persist. A failed
    write left memory saying spent and the record saying unspent. The call itself
    failed closed, because the error propagated instead of returning an
    authorization, but the next process to load the store read the grant as
    unspent and consumed it again, so consume-once did not survive a restart.
    """
    path = tmp_path / "approvals.json"
    store = ApprovalStore(path)
    store.grant(action(), contract())

    with patch("pathlib.Path.write_text", side_effect=OSError(28, "No space left on device")):
        with pytest.raises(OSError):
            store.consume(action(), contract())

    in_memory = next(iter(store._grants.values())).consumed
    on_record = json.loads(path.read_text(encoding="utf-8"))[0]["consumed"]
    assert in_memory == on_record is False

    restarted = ApprovalStore(path)
    assert restarted.consume(action(), contract()) is True
    assert restarted.consume(action(), contract()) is False


def test_a_failed_grant_persist_leaves_no_half_written_approval(tmp_path):
    path = tmp_path / "approvals.json"
    store = ApprovalStore(path)

    with patch("pathlib.Path.write_text", side_effect=OSError(28, "No space left on device")):
        with pytest.raises(OSError):
            store.grant(action(), contract())

    assert store._grants == {}
    assert not path.exists()


def test_the_normal_approval_path_is_unchanged(tmp_path):
    path = tmp_path / "approvals.json"
    store = ApprovalStore(path)
    store.grant(action(), contract())

    assert store.consume(action(), contract()) is True
    assert store.consume(action(), contract()) is False
    assert json.loads(path.read_text(encoding="utf-8"))[0]["consumed"] is True


# --- the cells that have no mechanism to test ---------------------------------

def test_no_decision_in_the_enforcement_path_reads_a_clock(tmp_path):
    """Why the clock-skew cell is not applicable, asserted from the source.

    Approvals are consume-once and identity-scoped, with no expiry. Skewing a
    clock cannot change a decision because no decision consults one. The cost of
    that design is the property below: a grant stays valid indefinitely until it
    is consumed.
    """
    from pathlib import Path as _Path

    import vais.approvals
    import vais.monitor

    for module in (vais.monitor, vais.approvals):
        source = _Path(module.__file__).read_text(encoding="utf-8")
        for token in ("time.", "datetime", "expires", "ttl", "deadline", "monotonic"):
            assert token not in source, f"{module.__name__} references {token!r}"

    store = ApprovalStore(tmp_path / "a.json")
    store.grant(action(), contract())
    assert store.consume(action(), contract()) is True
