from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass

from .models import PlannedAction, TaskContract, action_fingerprint, security_equal


@dataclass(frozen=True)
class DriftFinding:
    changed: bool
    score: int
    reasons: tuple[str, ...]
    security_escalation: bool = False
    security_contraction: bool = False
    escalation_reasons: tuple[str, ...] = ()
    contraction_reasons: tuple[str, ...] = ()

    @property
    def direction(self) -> str:
        if self.security_escalation and self.security_contraction:
            return "mixed"
        if self.security_escalation:
            return "escalation"
        if self.security_contraction:
            return "contraction"
        return "none"


class BehavioralIntegrityGate:
    """Detect security-relevant plan drift.

    The gate compares externally meaningful actions before and after exposure to
    untrusted content. It is diagnostic, not an authorization mechanism; the
    reference monitor remains the enforcement boundary.
    """

    def compare(
        self,
        baseline: list[PlannedAction],
        candidate: list[PlannedAction],
        contract: TaskContract,
    ) -> DriftFinding:
        score = 0
        reasons: list[str] = []

        base_counts = Counter(a.tool for a in baseline)
        cand_counts = Counter(a.tool for a in candidate)

        for tool, count in (cand_counts - base_counts).items():
            score += 2 * count
            if base_counts[tool] == 0:
                reasons.append(f"tool_added:{tool}")
            else:
                reasons.append(f"tool_count_increased:{tool}:{count}")
            if tool not in contract.allowed_tools:
                score += 5 * count
                reasons.append(f"unauthorized_tool_added:{tool}")

        for tool, count in (base_counts - cand_counts).items():
            score += count
            if cand_counts[tool] == 0:
                reasons.append(f"tool_removed:{tool}")
            else:
                reasons.append(f"tool_count_decreased:{tool}:{count}")

        # Compare corresponding actions of the same tool for integrity and
        # confidentiality drift, even when the tool name itself did not change.
        base_by_tool: dict[str, list[PlannedAction]] = defaultdict(list)
        cand_by_tool: dict[str, list[PlannedAction]] = defaultdict(list)
        for action in baseline:
            base_by_tool[action.tool].append(action)
        for action in candidate:
            cand_by_tool[action.tool].append(action)

        for tool in set(base_by_tool) & set(cand_by_tool):
            for base_action, cand_action in zip(base_by_tool[tool], cand_by_tool[tool]):
                for field in set(base_action.arguments) & set(cand_action.arguments):
                    before = base_action.arguments[field]
                    after = cand_action.arguments[field]
                    if before.is_trusted and not after.is_trusted:
                        score += 3
                        reasons.append(f"integrity_degraded:{tool}.{field}")
                    if after.confidentiality.rank > before.confidentiality.rank:
                        score += 4
                        reasons.append(
                            f"confidentiality_increased:{tool}.{field}:"
                            f"{before.confidentiality.value}>{after.confidentiality.value}"
                        )

        # Exact approvals bind to the complete action. Detect drift from a
        # previously approved baseline action even when the changed field is not
        # individually bound in the task contract (for example amount 150 ->
        # 999). This is diagnostic only; the reference monitor still enforces.
        approved_baseline_tools: set[str] = set()
        for action in baseline:
            try:
                if action_fingerprint(action) in contract.approved_action_fingerprints:
                    approved_baseline_tools.add(action.tool)
            except ValueError:
                continue
        for action in candidate:
            if action.tool not in approved_baseline_tools:
                continue
            try:
                approved = action_fingerprint(action) in contract.approved_action_fingerprints
            except ValueError:
                approved = False
            if not approved:
                score += 6
                reasons.append(f"approved_action_drift:{action.tool}")

        for (tool, field), trusted in contract.bound_arguments.items():
            matching = [a for a in candidate if a.tool == tool]
            if not matching:
                continue
            for action in matching:
                proposed = action.arguments.get(field)
                if proposed is None:
                    score += 5
                    reasons.append(f"bound_argument_missing:{tool}.{field}")
                    continue
                if not security_equal(proposed.data, trusted.data):
                    score += 5
                    reasons.append(f"bound_argument_drift:{tool}.{field}")
                if not proposed.is_trusted:
                    score += 3
                    reasons.append(f"authority_became_untrusted:{tool}.{field}")

        unique_reasons = tuple(dict.fromkeys(reasons))
        escalation_reasons = tuple(
            reason for reason in unique_reasons if _is_escalation_reason(reason)
        )
        contraction_reasons = tuple(
            reason for reason in unique_reasons if _is_contraction_reason(reason)
        )
        return DriftFinding(
            changed=bool(unique_reasons),
            score=score,
            reasons=unique_reasons,
            security_escalation=bool(escalation_reasons),
            security_contraction=bool(contraction_reasons),
            escalation_reasons=escalation_reasons,
            contraction_reasons=contraction_reasons,
        )


_ESCALATION_PREFIXES = (
    "tool_added:",
    "tool_count_increased:",
    "unauthorized_tool_added:",
    "integrity_degraded:",
    "confidentiality_increased:",
    "approved_action_drift:",
    "bound_argument_missing:",
    "bound_argument_drift:",
    "authority_became_untrusted:",
)

_CONTRACTION_PREFIXES = (
    "tool_removed:",
    "tool_count_decreased:",
)


def _is_escalation_reason(reason: str) -> bool:
    """Return whether a drift reason expands authority, effects, or exposure.

    This classification is diagnostic. It does not authorize an action and it
    does not replace the reference monitor or invariant engine.
    """

    return reason.startswith(_ESCALATION_PREFIXES)


def _is_contraction_reason(reason: str) -> bool:
    """Return whether a drift reason removes previously proposed behavior."""

    return reason.startswith(_CONTRACTION_PREFIXES)
