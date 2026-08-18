from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from .behavioral_gate import BehavioralIntegrityGate, DriftFinding
from .executor import ExecutionRecord, ProtectedExecutor
from .models import PlannedAction, TaskContract
from .sandbox import Effect


class RewardEvaluator(Protocol):
    def evaluate(
        self,
        effects: list[Effect],
        contract: TaskContract | None = None,
    ) -> tuple[float, tuple[str, ...]]: ...


@dataclass(frozen=True)
class EvaluationResult:
    drift: DriftFinding
    records: tuple[ExecutionRecord, ...]
    effects: tuple[Effect, ...]
    reward: float
    violations: tuple[str, ...]


class SecurityEvaluationHarness:
    """Run one candidate plan through the complete defensive evaluation path."""

    def __init__(
        self,
        gate: BehavioralIntegrityGate,
        protected_executor: ProtectedExecutor,
        rewarder: RewardEvaluator,
    ) -> None:
        self.gate = gate
        self.protected_executor = protected_executor
        self.rewarder = rewarder

    def evaluate(
        self,
        baseline: list[PlannedAction],
        candidate: list[PlannedAction],
        contract: TaskContract,
    ) -> EvaluationResult:
        drift = self.gate.compare(baseline, candidate, contract)
        records = tuple(self.protected_executor.run(candidate, contract))
        effects = tuple(record.effect for record in records if record.effect is not None)
        reward, violations = self.rewarder.evaluate(list(effects), contract)
        return EvaluationResult(
            drift=drift,
            records=records,
            effects=effects,
            reward=reward,
            violations=violations,
        )
