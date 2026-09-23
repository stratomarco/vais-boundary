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
from .ledger import LedgerEntry, SessionLedger
from .revocation import RevocationList
from typing import Callable
import math
import time


class ReferenceMonitor:
    """Deterministic authorization point for consequential actions.

    Enforcement order is intentionally fail-closed:
    contract validity and revocation -> dynamic task authorization -> static tool
    policy -> capability scope -> argument integrity/confidentiality and action origin ->
    call limits -> approval requirements.

    Without a ``SessionLedger`` the monitor decides one action at a time and keeps
    no state, so limits over several actions are left to VERIFY (LIM-035) and an
    approval held in the contract can be used repeatedly (LIM-044). With one, it
    enforces ``max_calls`` in flight and makes contract-held approvals single-use,
    checking and recording under the ledger's lock.
    """

    def __init__(
        self,
        policy: Policy,
        *,
        clock: Callable[[], float] | None = None,
        revocations: RevocationList | None = None,
    ) -> None:
        self.policy = policy
        # Read only for contracts that carry a validity window, so decisions on contracts
        # without one stay deterministic and never depend on the time.
        self._clock = clock or time.time
        self.revocations = revocations

    def evaluate(self, action: PlannedAction, contract: TaskContract,
                 approval_store: ApprovalStore | None = None,
                 ledger: SessionLedger | None = None) -> Decision:
        if ledger is None:
            return self._evaluate(action, contract, approval_store, None)[0]
        if not ledger.matches(contract):
            # A ledger records one session's history. Reading another session's
            # would let one session spend another's limits or approvals.
            return Decision(DecisionType.DENY, ("ledger_identity_mismatch",))
        with ledger.lock:
            decision, contract_approval = self._evaluate(action, contract, approval_store, ledger)
            if decision.type == DecisionType.ALLOW:
                try:
                    fingerprint = action_fingerprint(action)
                except ValueError:
                    fingerprint = None
                ledger.record(LedgerEntry(action.tool, fingerprint, contract_approval))
            return decision

    def _evaluate(self, action: PlannedAction, contract: TaskContract,
                  approval_store: ApprovalStore | None,
                  ledger: SessionLedger | None) -> tuple[Decision, bool]:
        """Return the decision and whether a contract-held approval authorized it."""
        # Whether the authority still holds comes before what it authorizes (LIM-047).
        if contract.not_before is not None or contract.not_after is not None:
            now = self._clock()
            if contract.not_before is not None and now < contract.not_before:
                return Decision(DecisionType.DENY, ("contract_not_yet_valid",)), False
            if contract.not_after is not None and now >= contract.not_after:
                return Decision(DecisionType.DENY, ("contract_expired",)), False
        if self.revocations is not None and self.revocations.is_revoked(contract):
            return Decision(DecisionType.DENY, ("contract_revoked",)), False

        reasons: list[str] = []

        if action.tool not in contract.allowed_tools:
            return Decision(DecisionType.DENY, (f"tool_not_authorized:{action.tool}",)), False

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
                return Decision(DecisionType.DENY, tuple(dict.fromkeys(reasons))), False
            if self.policy.default_action == "allow":
                return Decision(DecisionType.ALLOW), False
            return Decision(DecisionType.DENY, (f"tool_not_in_policy:{action.tool}",)), False

        if not tool_policy.allow:
            return Decision(DecisionType.DENY, (f"tool_denied_by_policy:{action.tool}",)), False

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

        # The action's origin is judged with its arguments: from labels, never content.
        # A missing origin counts as untrusted, so opting in cannot be defeated by a
        # caller that does not supply one.
        origin_untrusted = action.origin is None or action.origin.trust != TrustLevel.TRUSTED
        if origin_untrusted and tool_policy.untrusted_origin == "deny":
            reasons.append(f"untrusted_origin:{action.tool}")

        if reasons:
            return Decision(DecisionType.DENY, tuple(dict.fromkeys(reasons))), False

        # Call limits come before approvals, so reaching a limit never spends a
        # human's approval on an action that is then denied anyway.
        if tool_policy.max_calls is not None:
            if ledger is None:
                # A declared limit that cannot be enforced must not be silently ignored.
                return Decision(DecisionType.DENY, (f"call_limit_requires_ledger:{action.tool}",)), False
            if ledger.calls(action.tool) >= tool_policy.max_calls:
                return Decision(
                    DecisionType.DENY,
                    (f"call_limit_reached:{action.tool}:{tool_policy.max_calls}",),
                ), False

        # Decide whether any approval is needed, then check for one once. Before
        # rc13 each approval rule checked separately, so a tool requiring both an
        # exact approval and a threshold approval consumed the store grant in the
        # first check and found it spent in the second: the action could never be
        # allowed, and the approval was burned (FIND-056).
        approval_reason: str | None = None
        if tool_policy.exact_approval_required:
            approval_reason = f"exact_approval_required:{action.tool}"

        approval = tool_policy.approval
        if approval:
            value = action.arguments.get(approval.field)
            if value is None:
                return Decision(DecisionType.DENY, (f"missing_approval_field:{approval.field}",)), False
            try:
                numeric = float(value.data)
                if isinstance(value.data, bool) or not math.isfinite(numeric):
                    raise ValueError
                exceeds = numeric > approval.greater_than
            except (TypeError, ValueError):
                return Decision(DecisionType.DENY, (f"invalid_numeric_field:{approval.field}",)), False
            if exceeds and approval_reason is None:
                approval_reason = f"approval_required:{action.tool}:{approval.field}"

        if origin_untrusted and tool_policy.untrusted_origin == "require_approval" and approval_reason is None:
            approval_reason = f"approval_required:{action.tool}:untrusted_origin"

        if approval_reason is None:
            return Decision(DecisionType.ALLOW), False

        try:
            fingerprint = action_fingerprint(action)
        except ValueError:
            return Decision(DecisionType.DENY, ("action_not_fingerprintable",)), False

        if approval_store is not None:
            if approval_store.consume(action, contract):
                return Decision(DecisionType.ALLOW), False
            return Decision(DecisionType.REQUIRE_APPROVAL, (approval_reason,)), False

        if fingerprint in contract.approved_action_fingerprints and (
            ledger is None or not ledger.contract_approval_used(fingerprint)
        ):
            return Decision(DecisionType.ALLOW), True
        return Decision(DecisionType.REQUIRE_APPROVAL, (approval_reason,)), False
