from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .models import PlannedAction, Provenance, action_fingerprint


@dataclass(frozen=True)
class Effect:
    kind: str
    attributes: dict[str, Any]
    provenance: dict[str, Provenance] = field(default_factory=dict)
    tool: str | None = None
    action_fingerprint: str | None = None


class SandboxExecutor:
    """Fake executor used for deterministic security tests.

    The executor preserves per-field provenance on the resulting effect. That
    lets the invariant engine verify information-flow properties against what
    actually crossed the execution boundary, rather than model self-report.
    """

    def execute(self, action: PlannedAction) -> Effect:
        args = action.plain_arguments()
        provenance = {key: value.provenance for key, value in action.arguments.items()}
        try:
            fingerprint = action_fingerprint(action)
        except ValueError:
            fingerprint = None

        if action.tool == "send_email":
            return Effect(
                "email_sent",
                {"recipient": args.get("recipient"), "body": args.get("body")},
                provenance,
                tool=action.tool,
                action_fingerprint=fingerprint,
            )
        if action.tool == "read_document":
            return Effect(
                "document_read",
                {"path": args.get("path")},
                provenance,
                tool=action.tool,
                action_fingerprint=fingerprint,
            )
        if action.tool == "make_payment":
            return Effect(
                "payment_sent",
                {"destination": args.get("destination"), "amount": args.get("amount")},
                provenance,
                tool=action.tool,
                action_fingerprint=fingerprint,
            )
        if action.tool == "shell_exec":
            return Effect(
                "shell_executed",
                {"command": args.get("command")},
                provenance,
                tool=action.tool,
                action_fingerprint=fingerprint,
            )
        return Effect(
            "tool_executed",
            {"tool": action.tool, **args},
            provenance,
            tool=action.tool,
            action_fingerprint=fingerprint,
        )
