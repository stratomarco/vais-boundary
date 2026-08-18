from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
import hashlib
import threading

from .models import canonical_json, deep_freeze


@dataclass(frozen=True)
class AuditEvent:
    sequence: int
    event_type: str
    tool: str | None = None
    decision: str | None = None
    reasons: tuple[str, ...] = ()
    details: Any = field(default_factory=dict)
    previous_hash: str = "0" * 64
    event_hash: str = ""


class AuditTrail:
    """In-memory deterministic audit trail with JSONL export.

    Sequence numbers are used instead of timestamps so security regression tests
    remain reproducible. Production adapters can add wall-clock metadata outside
    this core representation.
    """

    def __init__(self) -> None:
        self._events: list[AuditEvent] = []
        self._lock = threading.RLock()

    @property
    def events(self) -> tuple[AuditEvent, ...]:
        return tuple(self._events)

    def record(
        self,
        event_type: str,
        *,
        tool: str | None = None,
        decision: str | None = None,
        reasons: tuple[str, ...] = (),
        details: dict[str, Any] | None = None,
    ) -> AuditEvent:
        _reject_secret_fields(details or {})
        with self._lock:
            previous = self._events[-1].event_hash if self._events else "0" * 64
            body = dict(sequence=len(self._events) + 1, event_type=event_type, tool=tool,
                        decision=decision, reasons=tuple(reasons),
                        details=deep_freeze(details or {}), previous_hash=previous)
            digest = hashlib.sha256(canonical_json(body)).hexdigest()
            event = AuditEvent(**body, event_hash=digest)
            self._events.append(event)
            return event

    def verify(self) -> bool:
        previous = "0" * 64
        for expected, event in enumerate(self._events, 1):
            body = dict(sequence=event.sequence, event_type=event.event_type, tool=event.tool,
                        decision=event.decision, reasons=event.reasons, details=event.details,
                        previous_hash=event.previous_hash)
            if event.sequence != expected or event.previous_hash != previous:
                return False
            if hashlib.sha256(canonical_json(body)).hexdigest() != event.event_hash:
                return False
            previous = event.event_hash
        return True

    def to_jsonl(self) -> str:
        return "\n".join(canonical_json({
            "sequence": event.sequence, "event_type": event.event_type,
            "tool": event.tool, "decision": event.decision, "reasons": event.reasons,
            "details": event.details, "previous_hash": event.previous_hash,
            "event_hash": event.event_hash,
        }).decode("utf-8") for event in self._events)

    def write_jsonl(self, path: str | Path) -> None:
        Path(path).write_text(self.to_jsonl() + ("\n" if self._events else ""), encoding="utf-8")


def _reject_secret_fields(value: Any) -> None:
    """Fail closed on common secret-bearing field names; callers should log metadata only."""
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = str(key).casefold().replace("-", "_")
            if any(marker in normalized for marker in ("secret", "password", "token", "api_key")):
                raise ValueError(f"audit detail field is secret-bearing: {key}")
            _reject_secret_fields(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _reject_secret_fields(item)
