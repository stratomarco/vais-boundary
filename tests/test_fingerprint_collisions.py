"""The two collision families that survive rc9's NFC hardening.

rc8/rc9 closed the Unicode/name-collision and scalar-type families (see
docs/ATTACK-SURFACE.md S3). Two families remain, and neither is a canonicalization
bug in ``action_fingerprint`` itself:

1. **Reference-vs-referent (accepted risk).** The fingerprint binds argument
   *values*, never the *contents* of any resource an argument merely names. Two
   executions of the same action are indistinguishable to the fingerprint even
   if the referent changed between approval and execution. This is inherent to
   argument hashing and is recorded here as negative evidence + accepted risk;
   the mitigation is application-level (bind a content hash into the arguments,
   or treat reference-typed arguments as non-approvable).

2. **Inverse utility (no spurious collisions found).** Semantically identical
   actions must produce *identical* fingerprints, or approvals churn and utility
   retention (the moat) drops. These tests confirm robustness across key order,
   list/tuple, and Unicode form. The one deliberate exception is numeric type
   (``1`` vs ``1.0``): kept distinct on purpose because type-sensitivity is a
   security property (so ``True`` != ``1``); documented, not "fixed".
"""

import pytest

from vais import (
    PlannedAction,
    Provenance,
    TrustLevel,
    TrustedValue,
    Value,
)
from vais.models import action_fingerprint


def _action(tool: str, **kwargs) -> PlannedAction:
    return PlannedAction(
        tool,
        {name: TrustedValue(value, "user") for name, value in kwargs.items()},
    )


# --- Family 1: reference-vs-referent (accepted risk, negative evidence) --------

def test_fingerprint_is_blind_to_referent_contents():
    """Two actions naming the same resource share a fingerprint regardless of
    what that resource contains. The fingerprint cannot see the referent, so a
    referent mutation between approval and execution is undetectable at this
    layer. Documented accepted risk; mitigation is application-level.
    """
    approved = _action("read_file", path="/data/report.csv")
    at_execution = _action("read_file", path="/data/report.csv")  # contents may have changed
    assert action_fingerprint(approved) == action_fingerprint(at_execution)


def test_distinct_references_do_not_collide():
    """Sanity floor: different reference values must give different fingerprints,
    so the accepted risk is strictly about the *referent*, not the reference."""
    assert action_fingerprint(_action("read_file", path="/data/a.csv")) != action_fingerprint(
        _action("read_file", path="/data/b.csv")
    )


# --- Family 2: inverse utility bug (semantically identical -> identical hash) ---

def test_argument_key_order_does_not_change_fingerprint():
    a = PlannedAction("t", {"x": TrustedValue(1, "user"), "y": TrustedValue(2, "user")})
    b = PlannedAction("t", {"y": TrustedValue(2, "user"), "x": TrustedValue(1, "user")})
    assert action_fingerprint(a) == action_fingerprint(b)


def test_nested_dict_key_order_does_not_change_fingerprint():
    a = _action("t", cfg={"a": 1, "b": 2})
    b = _action("t", cfg={"b": 2, "a": 1})
    assert action_fingerprint(a) == action_fingerprint(b)


def test_list_and_tuple_arguments_are_equivalent():
    """deep_freeze normalizes both sequences to tuples, so a list and tuple with
    the same elements are the same action and must not force re-approval."""
    assert action_fingerprint(_action("t", items=[1, 2, 3])) == action_fingerprint(
        _action("t", items=(1, 2, 3))
    )


def test_unicode_equivalent_forms_do_not_change_fingerprint():
    """NFC-equivalent spellings of the same string are the same value."""
    composed = "café"          # café  (U+00E9)
    decomposed = "café"        # café  (e + combining acute)
    assert composed != decomposed    # distinct code points...
    assert action_fingerprint(_action("t", note=composed)) == action_fingerprint(
        _action("t", note=decomposed)   # ...but the same fingerprint after NFC
    )


def test_numeric_type_difference_is_intentional_and_documented():
    """`1` vs `1.0` DO differ. This is deliberate type-sensitivity (a security
    property), not a utility bug to fix. Recorded so the trade-off is explicit:
    applications should normalize numeric types before building an action."""
    assert action_fingerprint(_action("pay", amount=100)) != action_fingerprint(
        _action("pay", amount=100.0)
    )
    # bool is not int here either (True != 1), which is the reason the above holds.
    assert action_fingerprint(_action("pay", amount=1)) != action_fingerprint(
        PlannedAction("pay", {"amount": Value(True, Provenance("user", TrustLevel.TRUSTED))})
    )
