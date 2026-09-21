"""P1-4: fork, truncate, splice and reorder against the audit chain.

`docs/ATTACK-SURFACE.md` S7 recorded these as a hypothesis and said explicitly:
"Truncation is the predicted weak spot; do not assert it until the test fails."
This module runs the tests and converts the hypothesis into recorded fact.

The outcome splits cleanly along one line, and it is not the line the intended
property in S7 draws. What decides detection is not *which* manipulation is
performed but whether the attacker recomputes the chain afterwards. The chain
carries no secret and no signature, so recomputation needs nothing the attacker
does not already have. `_rebuild_chain` below is the whole attack, in eleven
lines, using only public SHA-256.

None of the non-detection results is a defect. `docs/threat-model.md` lists
cryptographically tamper-evident audit storage as an explicit non-goal, and
`docs/RELATED-ARCHITECTURES.md` records signing as gap G-B1 against Proof of
Execution. What was missing was a demonstration of exactly where the line falls,
so that "tamper-evident" is never read as more than it is.
"""

from __future__ import annotations

import dataclasses
import hashlib
import threading

import pytest

from vais import AuditTrail
from vais.audit import AuditEvent
from vais.models import canonical_json, deep_freeze

ZERO = "0" * 64


def trail(n: int = 5) -> AuditTrail:
    t = AuditTrail()
    for i in range(n):
        t.record("authorization_decision", tool=f"tool{i}", decision="allow", details={"i": i})
    return t


def _rebuild_chain(
    events: list[AuditEvent],
    *,
    start: int = 1,
    break_link_at: int | None = None,
) -> list[AuditEvent]:
    """Recompute sequence, previous_hash and event_hash across a whole list.

    This is the capability an attacker with write access to the log already has.
    It requires no key, because the chain has none.

    `start` renumbers the sequence, and `break_link_at` severs the linkage at one
    index while leaving every stored hash self-consistent. Both exist so a test
    can trip exactly one of the verifier's three checks; without them every
    manipulation breaks two at once and the tests cannot tell which check is
    doing the work.
    """
    out: list[AuditEvent] = []
    previous = ZERO
    for offset, event in enumerate(events):
        body = dict(
            sequence=start + offset, event_type=event.event_type, tool=event.tool,
            decision=event.decision, reasons=event.reasons, details=event.details,
            previous_hash=ZERO if break_link_at == offset else previous,
        )
        digest = hashlib.sha256(canonical_json(body)).hexdigest()
        out.append(AuditEvent(**body, event_hash=digest))
        previous = digest
    return out


def _recomputes(event: AuditEvent) -> bool:
    body = dict(
        sequence=event.sequence, event_type=event.event_type, tool=event.tool,
        decision=event.decision, reasons=event.reasons, details=event.details,
        previous_hash=event.previous_hash,
    )
    return hashlib.sha256(canonical_json(body)).hexdigest() == event.event_hash


# --- what the chain does detect ----------------------------------------------

def test_an_untampered_chain_verifies():
    assert trail().verify() is True


def test_an_empty_chain_verifies():
    """Vacuously true, and worth pinning: no events is not an error state."""
    assert AuditTrail().verify() is True


@pytest.mark.parametrize(
    "field, value",
    [
        ("event_type", "something_else"),
        ("tool", "other_tool"),
        ("decision", "deny"),
        ("reasons", ("invented",)),
        ("details", deep_freeze({"i": 999})),
        ("previous_hash", ZERO),
        ("sequence", 99),
        ("event_hash", "f" * 64),
    ],
)
def test_editing_any_field_in_place_is_detected(field, value):
    t = trail()
    t._events[2] = dataclasses.replace(t._events[2], **{field: value})
    assert t.verify() is False, f"edit to {field} went undetected"


def test_dropping_events_from_the_front_is_detected():
    """The sequence check catches this: the survivor at position 1 still says 2."""
    t = trail()
    t._events = t._events[1:]
    assert t.verify() is False


def test_reordering_without_rebuilding_is_detected():
    t = trail()
    t._events[1], t._events[3] = t._events[3], t._events[1]
    assert t.verify() is False


def test_splicing_without_rebuilding_is_detected():
    t = trail()
    t._events.insert(2, t._events[0])
    assert t.verify() is False


def test_a_first_event_that_does_not_start_from_zero_is_detected():
    t = AuditTrail()
    t.record("authorization_decision", details={})
    t._events[0] = dataclasses.replace(t._events[0], previous_hash="f" * 64)
    assert t.verify() is False


def test_a_renumbered_chain_is_caught_by_the_sequence_check_alone():
    """Isolates one of the verifier's three checks.

    Every stored hash recomputes and the linkage is unbroken end to end. The only
    thing wrong is that the chain starts at 2. If the sequence check were removed
    this would pass, which is why it is asserted separately from the tests that
    break several checks at once.
    """
    t = trail()
    t._events = _rebuild_chain(t._events, start=2)
    events = t.events

    assert [e.sequence for e in events] == [2, 3, 4, 5, 6]
    assert events[0].previous_hash == ZERO
    assert all(events[i].previous_hash == events[i - 1].event_hash for i in range(1, len(events)))
    assert all(_recomputes(e) for e in events)

    assert t.verify() is False


def test_a_severed_link_is_caught_by_the_previous_hash_check_alone():
    """Isolates the second check.

    Sequences run 1..N and every stored hash recomputes against its own body. The
    only fault is that event 3 claims to follow nothing. If the previous_hash
    check were removed this would pass.
    """
    t = trail()
    t._events = _rebuild_chain(t._events, break_link_at=2)
    events = t.events

    assert [e.sequence for e in events] == [1, 2, 3, 4, 5]
    assert all(_recomputes(e) for e in events)
    severed = [i for i in range(1, len(events)) if events[i].previous_hash != events[i - 1].event_hash]
    assert severed == [2]

    assert t.verify() is False


def test_concurrent_records_produce_one_contiguous_verified_chain():
    """`record` holds an RLock; this asserts the chain that results is sound."""
    t = AuditTrail()

    def worker(k: int) -> None:
        for i in range(50):
            t.record("authorization_decision", tool=f"t{k}", decision="allow", details={"k": k, "i": i})

    threads = [threading.Thread(target=worker, args=(k,)) for k in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    events = t.events
    assert len(events) == 400
    assert [e.sequence for e in events] == list(range(1, 401))
    assert len({e.event_hash for e in events}) == 400
    assert t.verify() is True


# --- what the chain does not detect, and why ---------------------------------
#
# Each test below asserts a gap rather than a guarantee. If the chain is ever
# signed or externally anchored (gap G-B1), these are the tests that should
# start failing, and that failure is the point.

def test_truncating_the_tail_is_not_detected():
    """S7's predicted weak spot, now demonstrated. LIM-037.

    `verify()` has no notion of expected length and no signed head, so any prefix
    of a valid chain is itself a valid chain. This is the cheapest attack of all:
    it needs no recomputation, only the ability to delete from the end.
    """
    t = trail()
    t._events = t._events[:3]
    assert t.verify() is True
    assert len(t.events) == 3


def test_splicing_a_forged_allow_and_rebuilding_is_not_detected():
    """The result that matters most. LIM-037.

    An attacker who can write the log can insert an authorization decision that
    never happened and leave the chain fully verifiable, because rebuilding needs
    only public SHA-256.
    """
    t = trail()
    forged = AuditEvent(
        sequence=0, event_type="authorization_decision", tool="exfiltrate_database",
        decision="allow", reasons=(), details=deep_freeze({"note": "never happened"}),
        previous_hash=ZERO, event_hash="",
    )
    t._events = _rebuild_chain(t._events[:2] + [forged] + t._events[2:])

    assert t.verify() is True
    forged_now = [e for e in t.events if e.tool == "exfiltrate_database"]
    assert len(forged_now) == 1
    assert forged_now[0].decision == "allow"
    assert forged_now[0].sequence == 3


def test_deleting_an_event_and_rebuilding_is_not_detected():
    t = trail()
    t._events = _rebuild_chain([e for e in t._events if e.tool != "tool2"])
    assert t.verify() is True
    assert "tool2" not in {e.tool for e in t.events}


def test_reversing_the_chain_and_rebuilding_is_not_detected():
    t = trail()
    original_order = [e.tool for e in t.events]
    t._events = _rebuild_chain(list(reversed(t._events)))
    assert t.verify() is True
    assert [e.tool for e in t.events] == list(reversed(original_order))


def test_a_fork_is_invisible_from_either_branch():
    """Structural, not a bug: `verify()` sees one list and cannot know of another.

    Two branches share a prefix, so the shared events hash identically, and each
    branch verifies on its own. Detecting the fork needs a commitment published
    somewhere both branches can be compared against.
    """
    branch_a, branch_b = trail(3), trail(3)
    assert branch_a.events[2].event_hash == branch_b.events[2].event_hash

    branch_a.record("authorization_decision", tool="original", decision="allow", details={})
    branch_b.record("authorization_decision", tool="rewritten", decision="deny", details={})

    assert branch_a.verify() is True
    assert branch_b.verify() is True
    assert branch_a.events[3].event_hash != branch_b.events[3].event_hash


def test_the_verifier_reports_no_locus_for_a_break():
    """LIM-038: `verify()` returns a bare bool.

    For an audit trail whose stated purpose is investigation, knowing that the
    chain is broken without knowing where is a weak signal. An investigator
    cannot tell a single edited event from a wholly rewritten prefix.
    """
    t = trail()
    t._events[2] = dataclasses.replace(t._events[2], decision="deny")
    result = t.verify()
    assert result is False
    assert isinstance(result, bool)
