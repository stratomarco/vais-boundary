from __future__ import annotations

from dataclasses import dataclass, field
from collections.abc import Mapping
from typing import Any
import unicodedata

from .models import FrozenDict, PlannedAction, Provenance, action_fingerprint, deep_freeze


@dataclass(frozen=True)
class Effect:
    kind: str
    attributes: Mapping[str, Any]
    provenance: Mapping[str, Provenance] = field(default_factory=dict)
    tool: str | None = None
    action_fingerprint: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.kind, str) or not self.kind.strip():
            raise ValueError("effect kind must be a non-empty string")
        attributes = deep_freeze(self.attributes)
        if not isinstance(attributes, FrozenDict):
            raise ValueError("effect attributes must be a mapping")
        provenance: dict[str, Provenance] = {}
        for key, value in self.provenance.items():
            if not isinstance(key, str) or not key.strip():
                raise ValueError("effect provenance keys must be non-empty strings")
            normalized = unicodedata.normalize("NFC", key)
            if normalized in provenance:
                raise ValueError("Unicode normalization produced duplicate effect provenance")
            if not isinstance(value, Provenance):
                raise ValueError("effect provenance values must be Provenance")
            provenance[normalized] = value
        if self.tool is not None and (not isinstance(self.tool, str) or not self.tool.strip()):
            raise ValueError("effect tool must be a non-empty string or None")
        if self.action_fingerprint is not None and (
            not isinstance(self.action_fingerprint, str) or not self.action_fingerprint.strip()
        ):
            raise ValueError("effect action_fingerprint must be a non-empty string or None")
        object.__setattr__(self, "kind", unicodedata.normalize("NFC", self.kind))
        object.__setattr__(self, "attributes", attributes)
        object.__setattr__(self, "provenance", FrozenDict(provenance))
        if self.tool is not None:
            object.__setattr__(self, "tool", unicodedata.normalize("NFC", self.tool))


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
