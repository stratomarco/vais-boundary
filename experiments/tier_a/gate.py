"""The VAIS adapter for BrokenPilot's ticket tool.

Authority is fixed from the user's own goal *before* any retrieved document or
memory entry is read (integration rule 1). The model may choose content, but the
ticket it acts on is authority (rule 4): a proposed ticket id is accepted as trusted
only if it equals the one the user named, following ``rebind_reference_value`` in
``vais.reference_agent``. Nothing here inspects what the injected text says.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from vais import (
    AuditTrail,
    Effect,
    PlannedAction,
    ProtectedExecutor,
    Provenance,
    ReferenceMonitor,
    TaskContract,
    TrustedValue,
    TrustLevel,
    Value,
    action_fingerprint,
    load_invariants,
    load_policy,
)
from vais.models import security_equal
from vais.reward import DeclarativeVerifiableReward
from vais.taint import derive_model_output

from .env import bp_data, bp_tools

HERE = Path(__file__).resolve().parent
TICKET_RE = re.compile(r"\bTCK-\d{4}\b", re.IGNORECASE)
NO_TICKET = "__no_ticket_authorized__"
TOOL = "update_ticket"


def build_contract(user: dict[str, Any], goal: str, episode_id: str) -> TaskContract:
    """Authority from trusted input only. No ticket named means no ticket authorized."""
    match = TICKET_RE.search(goal)
    bound = match.group(0).upper() if match else NO_TICKET
    return TaskContract(
        allowed_tools={TOOL},
        bound_arguments={(TOOL, "ticket_id"): TrustedValue(bound, source="user_goal")},
        granted_scopes={"ticket:write"},
        principal_id=user["id"],
        session_id=episode_id,
        tenant_id=user["tenant"],
        capability_id="brokenpilot.agent",
    )


def visible_values(goal: str, docs: list[dict[str, Any]], memories: list[dict[str, Any]]) -> list[Value]:
    """Everything the model saw, labeled by where it came from, never by what it says."""
    seen: list[Value] = [TrustedValue(goal, source="user_goal")]
    for doc in docs:
        seen.append(Value(doc.get("body", ""), Provenance(source=f"rag:{doc.get('id')}", trust=TrustLevel.UNTRUSTED)))
    for mem in memories:
        seen.append(Value(mem.get("content", ""), Provenance(source=f"memory:{mem.get('id')}", trust=TrustLevel.UNTRUSTED)))
    return seen


def rebind(contract: TaskContract, field: str, data: Any, visible: list[Value]) -> Value:
    bound = contract.bound_arguments.get((TOOL, field))
    if bound is not None and security_equal(data, bound.data):
        return bound
    return derive_model_output(data, *visible)


@dataclass
class GateOutcome:
    decision: str
    reasons: tuple[str, ...]
    effect: Effect | None
    adapter_error: str | None = None


class TicketExecutor:
    """Executes an ALLOWed action against BrokenPilot's real ticket tool."""

    def __init__(self, user: dict[str, Any], controls: Any) -> None:
        self.user = user
        self.controls = controls

    def execute(self, action: PlannedAction) -> Effect:
        args = action.plain_arguments()
        ticket = bp_data.get_ticket(args["ticket_id"])
        if ticket is None:
            return Effect("ticket_update_failed", {"ticket_id": args["ticket_id"], "reason": "unknown_ticket"},
                          tool=TOOL, action_fingerprint=action_fingerprint(action))
        result = bp_tools.update_ticket_tool(
            user=self.user, ticket=ticket, status=args["status"], note=args.get("note", ""),
            approval_token=None, controls=self.controls,
        )
        updated = result["ticket"]
        return Effect(
            "ticket_updated",
            {"ticket_id": updated["id"], "status": updated["status"], "ticket_tenant": updated["tenant"],
             "actor_tenant": self.user["tenant"]},
            provenance={k: v.provenance for k, v in action.arguments.items()},
            tool=TOOL,
            action_fingerprint=action_fingerprint(action),
        )


class VaisGate:
    def __init__(self, policy_path: Path = HERE / "policy.yaml", invariants_path: Path = HERE / "invariants.yaml") -> None:
        self.policy = load_policy(policy_path)
        self.engine = load_invariants(invariants_path)
        self.reward = DeclarativeVerifiableReward(self.engine)

    def run(self, proposal: dict[str, Any], contract: TaskContract, visible: list[Value],
            user: dict[str, Any], controls: Any, audit: AuditTrail) -> GateOutcome:
        # Adapter contract (ATTACK-SURFACE S3): a ValueError while building Values is a
        # denial, and it is audited, never dropped.
        try:
            ticket_id = str(proposal.get("ticket_id", "")).strip().upper()
            action = PlannedAction(TOOL, {
                "ticket_id": rebind(contract, "ticket_id", ticket_id, visible),
                "status": derive_model_output(str(proposal.get("status", "")).strip().lower(), *visible),
                "note": derive_model_output(str(proposal.get("note", ""))[:500], *visible),
            })
        except ValueError as exc:
            audit.record("authorization_decision", tool=TOOL, decision="deny",
                         reasons=("adapter_rejected_value",), details={"error": type(exc).__name__})
            return GateOutcome("deny", ("adapter_rejected_value",), None, adapter_error=str(exc)[:200])
        executor = ProtectedExecutor(ReferenceMonitor(self.policy), TicketExecutor(user, controls), audit=audit)
        record = executor.run([action], contract)[0]
        return GateOutcome(record.decision.type.value, tuple(record.decision.reasons), record.effect)

    def verify(self, effect: Effect | None, contract: TaskContract) -> tuple[str, ...]:
        """Independent post-execution verification. Runs in every arm, enforcing or not."""
        if effect is None or effect.kind != "ticket_updated":
            return ()
        _, violated = self.reward.evaluate([effect], contract)
        return tuple(violated)
