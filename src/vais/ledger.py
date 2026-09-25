from __future__ import annotations

from dataclasses import dataclass
import threading

from .models import TaskContract


@dataclass(frozen=True)
class LedgerEntry:
    """One action the reference monitor allowed.

    ``contract_approval`` is true when the action was authorized by an approval held
    in the task contract rather than one consumed from an ``ApprovalStore``. Those are
    the approvals the ledger itself has to make single-use.
    """

    tool: str
    action_fingerprint: str | None
    contract_approval: bool = False


class SessionLedger:
    """What one session's reference monitor has already allowed.

    The monitor alone decides one action at a time and remembers nothing, so a bound
    over several actions could only be checked after the fact (LIM-035) and an
    approval carried in the contract could be used again and again (LIM-044). Passing
    a ledger gives the monitor that memory. It checks and records under one lock, so
    two concurrent decisions cannot both pass a limit that only one of them fits.

    The same ledger can be handed to the invariant engine, so VERIFY reads the record
    ENFORCE wrote rather than a separate account of it. A ledger belongs to one
    session, identified by principal, session and tenant, and the monitor denies any
    action evaluated against a contract from a different session. The capability id is
    deliberately left out: a delegate made with ``TaskContract.delegate`` shares its
    parent's session, so its calls count against the same limits and it cannot reset
    them by delegating.

    It lives in memory, in one process. Like the approval store (LIM-045), it does not
    coordinate between processes (LIM-055).
    """

    def __init__(self, contract: TaskContract) -> None:
        self.identity = _identity(contract)
        self.lock = threading.RLock()
        self._entries: list[LedgerEntry] = []

    def matches(self, contract: TaskContract) -> bool:
        return _identity(contract) == self.identity

    @property
    def entries(self) -> tuple[LedgerEntry, ...]:
        with self.lock:
            return tuple(self._entries)

    def calls(self, tool: str) -> int:
        with self.lock:
            return sum(entry.tool == tool for entry in self._entries)

    def contract_approval_used(self, fingerprint: str) -> bool:
        with self.lock:
            return any(
                entry.contract_approval and entry.action_fingerprint == fingerprint
                for entry in self._entries
            )

    def record(self, entry: LedgerEntry) -> None:
        """Append an allowed action. Called by the reference monitor, under its lock."""
        with self.lock:
            self._entries.append(entry)


def _identity(contract: TaskContract) -> tuple[str, str, str]:
    return (contract.principal_id, contract.session_id, contract.tenant_id)
