"""P1-6: the campaign's triage and gate, tested in the ordinary suite.

mapfuzz keeps a CI step whose only job is to assert that triage exits non-zero on
a known-real fixture, because a gate that never fires is worse than no gate: it
reports green forever and nobody looks. These tests are that step, run on every
commit rather than only on the nightly campaign.

The self-tests in `campaigns.targets` cover the other half, proving each target
can tell a clean rejection from a bug before a campaign result is believed.
"""

from __future__ import annotations

import pytest

from campaigns.targets import TARGETS, selftest
from campaigns.triage import (
    REAL,
    REVIEW,
    Signature,
    classify,
    dedup,
    gate,
    scrub,
    signature_from_exception,
)
from vais.models import deep_freeze


def test_scrub_removes_values_that_vary_between_inputs():
    assert scrub("at 0xDEADBEEF") == "at 0xADDR"
    assert scrub("unknown field(s): 12345") == "unknown field(s): N"
    assert scrub("unknown field(s): 'aaa'") == scrub("unknown field(s): 'bbb'")


def test_dedup_buckets_by_location_not_by_artifact_count():
    same = [(f"seed:{i}", Signature("py-typeerror", "policy.py:204")) for i in range(10_000)]
    other = [("seed:x", Signature("py-typeerror", "invariants.py:99"))]
    buckets = dedup(same + other)

    assert len(buckets) == 2
    assert buckets[0].count == 10_000
    assert len(buckets[0].sources) == 3, "sources are capped so a report stays readable"


def test_a_fault_in_vais_code_is_real_and_gates():
    signature = Signature("py-typeerror", "policy.py:204", in_vais=True)
    verdict, _ = classify(signature)
    assert verdict == REAL
    assert gate(dedup([("seed:1", signature)])) == 1


def test_a_fault_inside_a_dependency_is_reported_but_does_not_gate():
    """LIM-043: still a contract violation, still reported, not VAIS's to fix."""
    signature = Signature("py-recursionerror", "scanner.py:306", in_vais=False)
    verdict, reason = classify(signature)
    assert verdict == REVIEW
    assert "dependency" in reason
    assert gate(dedup([("seed:1", signature)])) == 0


def test_the_same_fault_class_gates_differently_by_location():
    """The location, not the exception type, decides whether CI fails."""
    inside = Signature("py-recursionerror", "models.py:160", in_vais=True)
    outside = Signature("py-recursionerror", "scanner.py:306", in_vais=False)
    assert classify(inside)[0] == REAL
    assert classify(outside)[0] == REVIEW


def test_an_empty_run_does_not_gate():
    assert gate([]) == 0


def test_signature_locates_a_fault_raised_inside_vais():
    """Without this the gate would never fire, since everything would look external."""
    with pytest.raises(ValueError) as caught:
        deep_freeze({"unsupported": {1, 2, 3}})
    signature = signature_from_exception(caught.value, target="value")
    assert signature.in_vais is True
    assert signature.location.startswith("models.py:")
    assert signature.fault_class == "py-valueerror"


@pytest.mark.parametrize("target", sorted(TARGETS))
def test_each_target_passes_its_own_selftest(target):
    """A campaign result is only meaningful if the harness can detect a fault."""
    assert selftest(target) == []
