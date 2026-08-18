from __future__ import annotations

from .models import (
    Decision,
    DecisionType,
    PlannedAction,
    TaskContract,
    TrustLevel,
    action_fingerprint,
    security_equal,
)
from .policy import Policy
from .approvals import ApprovalStore
import math


class ReferenceMonitor:
    """Deterministic authorization point for consequential actions.

    Enforcement order is intentionally fail-closed:
    dynamic task authorization -> static tool policy -> capability scope ->
    argument integrity/confidentiality -> approval requirements.
    """

    def __init__(self, policy: Policy) -> None:
        self.policy = policy

    def evaluate(self, action: PlannedAction, contract: TaskContract,
                 approval_store: ApprovalStore | None = None) -> Decision:
        reasons: list[str] = []

        if action.tool not in contract.allowed_tools:
            return Decision(DecisionType.DENY, (f"tool_not_authorized:{action.tool}",))

        # Dynamic authorization always wins over permissive static policy.
        for (tool, field), trusted in contract.bound_arguments.items():
            if tool != action.tool:
                continue
            proposed = action.arguments.get(field)
            if proposed is None:
                reasons.append(f"missing_bound_argument:{field}")
                continue
            if not security_equal(proposed.data, trusted.data):
                reasons.append(f"bound_argument_changed:{field}")
            if not proposed.is_trusted:
                reasons.append(f"bound_argument_not_trusted:{field}")

        tool_policy = self.policy.tools.get(action.tool)
        if tool_policy is None:
            if reasons:
                return Decision(DecisionType.DENY, tuple(dict.fromkeys(reasons)))
            if self.policy.default_action == "allow":
                return Decision(DecisionType.ALLOW)
            return Decision(DecisionType.DENY, (f"tool_not_in_policy:{action.tool}",))

        if not tool_policy.allow:
            return Decision(DecisionType.DENY, (f"tool_denied_by_policy:{action.tool}",))

        if tool_policy.reject_undeclared_arguments:
            extras = sorted(set(action.arguments) - set(tool_policy.arguments))
            if extras:
                reasons.extend(f"undeclared_argument:{field}" for field in extras)

        if tool_policy.required_scope and tool_policy.required_scope not in contract.granted_scopes:
            reasons.append(f"missing_required_scope:{tool_policy.required_scope}")

        for field, arg_policy in tool_policy.arguments.items():
            value = action.arguments.get(field)

            if arg_policy.trust_required:
                if value is None:
                    reasons.append(f"missing_required_argument:{field}")
                    continue
                if arg_policy.trust_required == TrustLevel.TRUSTED.value and not value.is_trusted:
                    reasons.append(f"untrusted_authority_argument:{field}")

            if arg_policy.max_confidentiality is not None:
                if value is None:
                    # A confidentiality ceiling does not make an optional field mandatory.
                    continue
                if value.confidentiality.rank > arg_policy.max_confidentiality.rank:
                    reasons.append(
                        "confidentiality_exceeds_limit:"
                        f"{field}:{value.confidentiality.value}>"
                        f"{arg_policy.max_confidentiality.value}"
                    )

        if reasons:
            return Decision(DecisionType.DENY, tuple(dict.fromkeys(reasons)))

        if tool_policy.exact_approval_required:
            try:
                fingerprint = action_fingerprint(action)
            except ValueError:
                return Decision(DecisionType.DENY, ("action_not_fingerprintable",))
            approved = (approval_store.consume(action, contract) if approval_store is not None
                        else fingerprint in contract.approved_action_fingerprints)
            if not approved:
                return Decision(
                    DecisionType.REQUIRE_APPROVAL,
                    (f"exact_approval_required:{action.tool}",),
                )

        approval = tool_policy.approval
        if approval:
            value = action.arguments.get(approval.field)
            if value is None:
                return Decision(DecisionType.DENY, (f"missing_approval_field:{approval.field}",))
            try:
                numeric = float(value.data)
                if isinstance(value.data, bool) or not math.isfinite(numeric):
                    raise ValueError
                exceeds = numeric > approval.greater_than
            except (TypeError, ValueError):
                return Decision(DecisionType.DENY, (f"invalid_numeric_field:{approval.field}",))
            if exceeds:
                try:
                    fingerprint = action_fingerprint(action)
                except ValueError:
                    return Decision(DecisionType.DENY, ("action_not_fingerprintable",))
                approved = (approval_store.consume(action, contract) if approval_store is not None
                            else fingerprint in contract.approved_action_fingerprints)
                if not approved:
                    return Decision(
                        DecisionType.REQUIRE_APPROVAL,
                        (f"approval_required:{action.tool}:{approval.field}",),
                    )

        return Decision(DecisionType.ALLOW)
