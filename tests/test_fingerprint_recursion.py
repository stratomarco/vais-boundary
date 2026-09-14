"""P1-2: pathological argument nesting must not escape as RecursionError.

`deep_freeze` was unbounded-recursive. A PlannedAction whose arguments nest
deeper than the interpreter's recursion limit raised ``RecursionError`` during
``action_fingerprint`` -> ``canonical_json`` -> ``deep_freeze``. ``RecursionError``
is **not** a ``ValueError`` (verified), so it bypassed the ``except ValueError``
guards in ``monitor.ReferenceMonitor.evaluate`` (the ``action_not_fingerprintable``
DENY path). The monitor then produced *no decision and no audit record* — the
action failed closed only by crashing the caller.

These tests pin the required behaviour: over-deep security data fails as a
``ValueError``, which routes into the existing ``action_not_fingerprintable``
DENY path and is audited.
"""

from typing import Any

import pytest

from vais import (
    DecisionType,
    PlannedAction,
    Provenance,
    ReferenceMonitor,
    TaskContract,
    TrustLevel,
    Value,
)
from vais.audit import AuditTrail
from vais.executor import ProtectedExecutor
from vais.models import action_fingerprint, deep_freeze
from vais.policy import Policy, ToolPolicy
from vais.sandbox import SandboxExecutor


def _nested(depth: int) -> Any:
    """A structure whose deepest ``deep_freeze`` recursion level is ``depth``.

    Built iteratively (no recursion) so the fixture itself never overflows.
    """
    node: Any = "leaf"
    for _ in range(depth):
        node = {"n": node}
    return node


def test_deep_freeze_rejects_pathological_nesting_as_valueerror():
    """The core regression: over-deep data must raise ValueError, not RecursionError.

    Pre-fix, ``deep_freeze`` on a 5000-deep structure overflows the default
    1000-frame limit and raises ``RecursionError`` (which ``pytest.raises(ValueError)``
    does not catch) -> RED. Post-fix it raises ``ValueError`` well before any
    interpreter limit -> GREEN.
    """
    with pytest.raises(ValueError):
        deep_freeze(_nested(5000))


@pytest.mark.parametrize("depth", [0, 1, 8, 64])
def test_reasonable_nesting_is_still_accepted(depth):
    """A depth sweep at the shallow end: ordinary nested data must round-trip."""
    frozen = deep_freeze(_nested(depth))
    # Round-trips without raising and stays usable in a fingerprint payload.
    assert action_fingerprint(
        PlannedAction(
            "t",
            {"payload": Value(_nested(depth), Provenance("model", TrustLevel.DERIVED_UNTRUSTED))},
        )
    )


def test_monitor_denies_unfingerprintable_deep_action_and_audits():
    """The user's headline assertion: DENY(action_not_fingerprintable) + audit event.

    The argument is nested to exactly the maximum accepted depth, so the ``Value``
    itself constructs, but ``action_fingerprint`` wraps it two levels deeper
    (``{"tool": ..., "arguments": {...}}``) and therefore exceeds the bound. The
    monitor must catch the resulting ValueError and DENY, and the executor must
    record it in the audit trail without emitting an effect.
    """
    from vais.models import MAX_SECURITY_DEPTH

    data = _nested(MAX_SECURITY_DEPTH)  # constructs (== bound); fingerprint (+2) exceeds
    action = PlannedAction(
        "deep_tool",
        {"payload": Value(data, Provenance("model", TrustLevel.DERIVED_UNTRUSTED))},
    )
    contract = TaskContract(allowed_tools={"deep_tool"})
    policy = Policy(
        default_action="deny",
        tools={"deep_tool": ToolPolicy(allow=True, exact_approval_required=True)},
    )
    audit = AuditTrail()
    executor = ProtectedExecutor(ReferenceMonitor(policy), SandboxExecutor(), audit=audit)

    records = executor.run([action], contract)

    assert records[0].decision.type == DecisionType.DENY
    assert "action_not_fingerprintable" in records[0].decision.reasons
    assert records[0].effect is None
    decisions = [e for e in audit.events if e.event_type == "authorization_decision"]
    assert len(decisions) == 1
    assert decisions[0].decision == "deny"
    assert "action_not_fingerprintable" in decisions[0].reasons
    assert all(e.event_type != "effect_observed" for e in audit.events)
    assert audit.verify()
