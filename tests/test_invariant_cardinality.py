"""LIM-035: bounds over a *set* of effects, and the half of that problem VAIS does not solve.

Issue #2 observed that the central property is stated over "an unauthorized externally
observable effect", singular, and that composition therefore splits in two:

* the **flow** half - a sequence such as SECRET -> PUBLIC - which trace-level invariants
  already express;
* the **volume** half - N individually authorized effects whose *count* is the problem -
  which nothing in the enforcement path could express, because the policy schema is a
  closed allowlist and rejects any field it does not know.

``max_effect_count`` closes the expressibility gap in VERIFY. It does **not** close it in
ENFORCE: ``ReferenceMonitor.evaluate`` takes one ``PlannedAction`` and holds no state
across decisions, so the 5,001st call is observed after the fact rather than denied in
flight. The final test in this module asserts that limitation deliberately, so it stays
visible and so a future fix has a test to invert.
"""

from pathlib import Path

import pytest

from vais import (
    DecisionType,
    Effect,
    PlannedAction,
    PolicyValidationError,
    Provenance,
    ReferenceMonitor,
    TaskContract,
    TrustLevel,
    TrustedValue,
    Value,
    load_invariants,
    load_policy,
)

ROOT = Path(__file__).resolve().parents[1]

BOUND = """
version: 1
invariants:
  - id: record_read_volume
    description: a task may read at most five records
    type: max_effect_count
    effect: record_read
    max_count: 5
"""


def engine(tmp_path, text=BOUND):
    path = tmp_path / "bound.yaml"
    path.write_text(text, encoding="utf-8")
    return load_invariants(path)


def reads(count):
    return [Effect("record_read", {"index": str(i)}) for i in range(count)]


def test_count_at_the_bound_is_not_a_violation(tmp_path):
    assert engine(tmp_path).evaluate(reads(5), TaskContract(allowed_tools={"read"})) == ()


def test_count_above_the_bound_violates(tmp_path):
    violations = engine(tmp_path).evaluate(reads(6), TaskContract(allowed_tools={"read"}))
    assert len(violations) == 1
    assert violations[0].invariant_id == "record_read_volume"
    assert violations[0].reason == "effect_count_exceeds_limit:record_read:6>5"


def test_a_large_breach_reports_one_violation_not_one_per_excess_effect(tmp_path):
    violations = engine(tmp_path).evaluate(reads(5000), TaskContract(allowed_tools={"read"}))
    assert len(violations) == 1
    assert violations[0].reason == "effect_count_exceeds_limit:record_read:5000>5"


def test_violation_points_at_the_effect_that_crossed_the_bound(tmp_path):
    violations = engine(tmp_path).evaluate(reads(9), TaskContract(allowed_tools={"read"}))
    # Zero-based: the sixth read is the one the bound of five forbids.
    assert violations[0].effect_index == 5


def test_only_the_named_effect_kind_is_counted(tmp_path):
    effects = [Effect("other_effect", {}) for _ in range(3)] + reads(7)
    violations = engine(tmp_path).evaluate(effects, TaskContract(allowed_tools={"read"}))
    assert len(violations) == 1
    assert violations[0].reason == "effect_count_exceeds_limit:record_read:7>5"
    # Three unrelated effects precede the reads, so the crossing read sits at index 8.
    assert violations[0].effect_index == 8


def test_a_bound_of_zero_forbids_the_effect_entirely(tmp_path):
    text = BOUND.replace("max_count: 5", "max_count: 0")
    assert engine(tmp_path, text).evaluate(reads(0), TaskContract(allowed_tools={"read"})) == ()
    violations = engine(tmp_path, text).evaluate(reads(1), TaskContract(allowed_tools={"read"}))
    assert violations[0].reason == "effect_count_exceeds_limit:record_read:1>0"


@pytest.mark.parametrize(
    "value",
    [
        "max_count: true",  # bool is an int in Python; a boolean bound is a config error
        "max_count: 5.5",  # a float bound would make the comparison depend on rounding
        "max_count: '5'",
        "max_count: -1",
    ],
)
def test_loader_rejects_a_bound_that_is_not_a_non_negative_integer(tmp_path, value):
    with pytest.raises(PolicyValidationError):
        engine(tmp_path, BOUND.replace("max_count: 5", value))


def test_loader_rejects_the_type_without_a_bound(tmp_path):
    with pytest.raises(PolicyValidationError):
        engine(tmp_path, BOUND.replace("    max_count: 5\n", ""))


def test_default_invariants_still_load_and_the_new_type_is_supported(tmp_path):
    # The shipped set is unchanged; the point is that adding the type broke nothing.
    assert load_invariants(ROOT / "invariants" / "default.yaml") is not None
    assert engine(tmp_path) is not None


def test_enforcement_does_not_bound_volume_documented_limitation():
    """LIM-035, asserted rather than only written down.

    The monitor authorizes each action on its own merits. Six identical authorized
    actions produce six ALLOW decisions, because nothing accumulates between calls.
    Detection of the breach happens later, in VERIFY, via ``max_effect_count``.

    If a future release enforces a bound in flight, this test should fail and be
    rewritten - that failure is the signal, not a regression.
    """
    policy = load_policy(ROOT / "policies" / "default.yaml")
    monitor = ReferenceMonitor(policy)
    contract = TaskContract(
        allowed_tools={"send_email"},
        granted_scopes={"email:send"},
        bound_arguments={("send_email", "recipient"): TrustedValue("alice@example.com", "user")},
    )
    action = PlannedAction(
        "send_email",
        {
            "recipient": TrustedValue("alice@example.com", "user"),
            "body": Value("hello", Provenance("model", TrustLevel.DERIVED_UNTRUSTED)),
        },
    )
    decisions = [monitor.evaluate(action, contract).type for _ in range(6)]
    assert decisions == [DecisionType.ALLOW] * 6
