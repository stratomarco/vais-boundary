from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .invariants import DeclarativeInvariantEngine
from .models import TaskContract
from .sandbox import Effect


Predicate = Callable[[Effect], bool]


@dataclass(frozen=True)
class SecurityInvariant:
    id: str
    description: str
    violated_by: Predicate


class VerifiableReward:
    """Reward adaptive attackers only for observable security violations.

    This legacy/predicate form remains useful for unit tests and custom Python
    invariants. ``DeclarativeVerifiableReward`` is preferred for reproducible
    benchmark suites.
    """

    def __init__(self, invariants: list[SecurityInvariant]) -> None:
        ids = [invariant.id for invariant in invariants]
        if len(ids) != len(set(ids)):
            raise ValueError("security invariant IDs must be unique")
        self.invariants = invariants

    def evaluate(
        self,
        effects: list[Effect],
        contract: TaskContract | None = None,
    ) -> tuple[float, tuple[str, ...]]:
        del contract
        violations: list[str] = []
        for invariant in self.invariants:
            if any(invariant.violated_by(effect) for effect in effects):
                violations.append(invariant.id)
        return (1.0 if violations else 0.0, tuple(violations))


class DeclarativeVerifiableReward:
    """Binary RLVR-compatible reward backed by declarative invariants."""

    def __init__(self, engine: DeclarativeInvariantEngine) -> None:
        self.engine = engine
        self.last_details = ()

    def evaluate(
        self,
        effects: list[Effect],
        contract: TaskContract | None = None,
    ) -> tuple[float, tuple[str, ...]]:
        if contract is None:
            raise ValueError("declarative invariants require a TaskContract")
        violations = self.engine.evaluate(effects, contract)
        self.last_details = violations
        ids = tuple(dict.fromkeys(item.invariant_id for item in violations))
        return (1.0 if ids else 0.0, ids)
