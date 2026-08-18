from __future__ import annotations

from dataclasses import dataclass

from .audit import AuditTrail
from .models import Decision, DecisionType, PlannedAction, TaskContract
from .monitor import ReferenceMonitor
from .sandbox import Effect, SandboxExecutor
from .approvals import ApprovalStore


@dataclass(frozen=True)
class ExecutionRecord:
    action: PlannedAction
    decision: Decision
    effect: Effect | None


class ProtectedExecutor:
    """Fail-closed execution boundary.

    Only ALLOW is forwarded. DENY and REQUIRE_APPROVAL produce no external
    effect. An optional audit trail records both authorization and execution.
    """

    def __init__(
        self,
        monitor: ReferenceMonitor,
        executor: SandboxExecutor,
        audit: AuditTrail | None = None,
        approval_store: ApprovalStore | None = None,
    ) -> None:
        self.monitor = monitor
        self.executor = executor
        self.audit = audit
        self.approval_store = approval_store

    def run(self, actions: list[PlannedAction], contract: TaskContract) -> list[ExecutionRecord]:
        records: list[ExecutionRecord] = []
        for action in actions:
            decision = self.monitor.evaluate(action, contract, self.approval_store)
            if self.audit:
                self.audit.record(
                    "authorization_decision",
                    tool=action.tool,
                    decision=decision.type.value,
                    reasons=decision.reasons,
                    details={"arguments": sorted(action.arguments)},
                )

            effect = self.executor.execute(action) if decision.type == DecisionType.ALLOW else None
            if self.audit and effect is not None:
                self.audit.record(
                    "effect_observed",
                    tool=action.tool,
                    details={"effect": effect.kind, "fields": sorted(effect.attributes)},
                )

            records.append(ExecutionRecord(action=action, decision=decision, effect=effect))
        return records
