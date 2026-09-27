from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
import hashlib
import json
import threading

from .models import PlannedAction, TaskContract, action_fingerprint, canonical_json, deep_freeze


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
        return self.verify_report().ok

    def verify_report(self) -> "AuditVerification":
        """Check every event and report every break, not only whether there is one (LIM-038)."""
        return _verify(list(self._events))

    @classmethod
    def from_jsonl(cls, text: str) -> "AuditTrail":
        """A trail read back from ``to_jsonl`` output, for verification.

        Events are taken as written, hashes included; nothing is recomputed. A line that is
        not an event cannot be represented, so use ``verify_jsonl`` to check a file.
        """
        trail = cls()
        for line in text.splitlines():
            if line.strip():
                event = _event_from_json(line)
                if event is None:
                    raise ValueError("not an audit event line")
                trail._events.append(event)
        return trail

    def to_jsonl(self) -> str:
        return "\n".join(canonical_json({
            "sequence": event.sequence, "event_type": event.event_type,
            "tool": event.tool, "decision": event.decision, "reasons": event.reasons,
            "details": event.details, "previous_hash": event.previous_hash,
            "event_hash": event.event_hash,
        }).decode("utf-8") for event in self._events)

    def write_jsonl(self, path: str | Path) -> None:
        Path(path).write_text(self.to_jsonl() + ("\n" if self._events else ""), encoding="utf-8")


@dataclass(frozen=True)
class AuditBreak:
    """One failed check. ``position`` is the event's 1-based place in the trail.

    ``check`` is one of:

    - ``malformed``: the line is not an audit event, so neither it nor its link can be checked;
    - ``sequence``: the event's sequence number is not its position (removed or reordered events);
    - ``link``: its ``previous_hash`` is not the preceding event's hash, so the trail was spliced
      here, or everything on one side of this point was rewritten with recomputed hashes;
    - ``content``: its own hash does not match its content, so it was edited in place. If the
      next event still links to the stored hash, only this record changed.
    """

    position: int
    check: str


@dataclass(frozen=True)
class AuditVerification:
    events: int
    breaks: tuple[AuditBreak, ...] = ()

    @property
    def ok(self) -> bool:
        return not self.breaks

    @property
    def first_break(self) -> AuditBreak | None:
        return self.breaks[0] if self.breaks else None

    def describe(self) -> str:
        if self.ok:
            return f"intact: {self.events} events, every link and hash checks"
        lines = [f"broken: {len(self.breaks)} failed check(s) in {self.events} events"]
        for item in self.breaks:
            lines.append(f"  event {item.position}: {item.check}")
        return "\n".join(lines)


def verify_jsonl(text: str) -> AuditVerification:
    """Verify an audit file's text, reporting malformed lines as breaks rather than raising."""
    lines = [line for line in text.splitlines() if line.strip()]
    return _verify([_event_from_json(line) for line in lines])


def _verify(events: list[AuditEvent | None]) -> AuditVerification:
    breaks: list[AuditBreak] = []
    previous: str | None = "0" * 64  # None: the preceding event could not be read
    for position, event in enumerate(events, 1):
        if event is None:
            breaks.append(AuditBreak(position, "malformed"))
            previous = None
            continue
        if event.sequence != position:
            breaks.append(AuditBreak(position, "sequence"))
        if previous is not None and event.previous_hash != previous:
            breaks.append(AuditBreak(position, "link"))
        body = dict(sequence=event.sequence, event_type=event.event_type, tool=event.tool,
                    decision=event.decision, reasons=event.reasons, details=event.details,
                    previous_hash=event.previous_hash)
        try:
            recomputed = hashlib.sha256(canonical_json(body)).hexdigest()
        except ValueError:
            recomputed = None
        if recomputed != event.event_hash:
            breaks.append(AuditBreak(position, "content"))
        # The next event is checked against the hash this one stores, so an edit that left
        # the stored hash alone shows as one content break, not a broken chain from here on.
        previous = event.event_hash
    return AuditVerification(len(events), tuple(breaks))


_EVENT_FIELDS = {"sequence", "event_type", "tool", "decision", "reasons", "details", "previous_hash", "event_hash"}


def _event_from_json(line: str) -> AuditEvent | None:
    try:
        raw = json.loads(line)
    except ValueError:
        return None
    if not isinstance(raw, dict) or set(raw) != _EVENT_FIELDS:
        return None
    if (isinstance(raw["sequence"], bool) or not isinstance(raw["sequence"], int)
            or not isinstance(raw["event_type"], str) or not isinstance(raw["reasons"], list)
            or not all(isinstance(r, str) for r in raw["reasons"])
            or not isinstance(raw["previous_hash"], str) or not isinstance(raw["event_hash"], str)):
        return None
    try:
        details = deep_freeze(raw["details"])
    except ValueError:
        return None
    return AuditEvent(raw["sequence"], raw["event_type"], raw["tool"], raw["decision"], tuple(raw["reasons"]),
                      details, raw["previous_hash"], raw["event_hash"])


def action_audit_details(action: PlannedAction, contract: TaskContract) -> dict[str, Any]:
    """Details that identify which action was decided, and for whom, without its values.

    Before rc12 an authorization event carried only the argument names, so the chain
    could show that *a* payment was allowed but not which one or for which session.
    The fingerprint is a SHA-256 of the canonical action and carries no argument value,
    so it adds identity without adding secrets. An action that cannot be fingerprinted
    records ``None``; the monitor denies those, and the audit must still record the
    denial rather than raise.
    """
    try:
        fingerprint = action_fingerprint(action)
    except ValueError:
        fingerprint = None
    return {
        "arguments": sorted(action.arguments),
        "action_fingerprint": fingerprint,
        "principal_id": contract.principal_id,
        "session_id": contract.session_id,
        "tenant_id": contract.tenant_id,
        "capability_id": contract.capability_id,
    }


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
