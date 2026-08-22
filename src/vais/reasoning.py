from __future__ import annotations

from typing import Any


REASONING_REQUIRED_LABELS = frozenset({"low", "medium", "high", "on"})


def reasoning_mode_mismatch(label: Any, observed: bool) -> bool:
    """Return whether observed output contradicts a declared reasoning mode.

    ``auto`` and an absent label are descriptive only. Explicit ``off`` and
    reasoning-enabled labels are bidirectional experiment-validity claims.
    """

    if not isinstance(label, str):
        return False
    if label == "off":
        return observed
    if label in REASONING_REQUIRED_LABELS:
        return not observed
    return False


def reasoning_mode_status(label: Any, observed: bool) -> str:
    if not isinstance(label, str) or (
        label != "off" and label not in REASONING_REQUIRED_LABELS
    ):
        return "not-enforced"
    return "NONCONFORMING" if reasoning_mode_mismatch(label, observed) else "conformant"
