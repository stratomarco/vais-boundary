from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from pathlib import Path

from .durable import SharedStateLock, write_json_atomic
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

    Without a ``path`` it lives in one process's memory, and a restart or a second worker
    starts from nothing (LIM-055). With a ``path`` the record is a file: the monitor's
    lock also takes an operating-system lock on it and reloads it, so the check and the
    record are one critical section for every process on this machine sharing the file,
    and the record survives a restart. A write that fails is rolled back in memory and
    raised, so the decision it would have recorded is never returned.
    """

    def __init__(self, contract: TaskContract, path: str | Path | None = None, *,
                 lock_timeout: float = 30.0) -> None:
        self.identity = _identity(contract)
        self.path = Path(path) if path is not None else None
        self._entries: list[LedgerEntry] = []
        self.lock = SharedStateLock(self.path, self._reload, lock_timeout)
        if self.path is not None:
            with self.lock:  # loads the file, and checks that it belongs to this session
                pass

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
            if self.path is not None:
                try:
                    write_json_atomic(self.path, {
                        "version": 1,
                        "identity": list(self.identity),
                        "entries": [asdict(e) for e in self._entries],
                    })
                except BaseException:
                    self._entries.pop()
                    raise

    def _reload(self) -> None:
        if self.path is None or not self.path.exists():
            return
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict) or raw.get("version") != 1:
            raise ValueError(f"{self.path}: not a version 1 session ledger")
        if tuple(raw.get("identity") or ()) != self.identity:
            # Reading another session's record would let one session spend another's limits.
            raise ValueError(f"{self.path}: the ledger belongs to a different session")
        entries = raw.get("entries")
        if not isinstance(entries, list):
            raise ValueError(f"{self.path}: entries must be a list")
        loaded = []
        for item in entries:
            if (not isinstance(item, dict) or set(item) != {"tool", "action_fingerprint", "contract_approval"}
                    or not isinstance(item["tool"], str) or not isinstance(item["contract_approval"], bool)
                    or not (item["action_fingerprint"] is None or isinstance(item["action_fingerprint"], str))):
                raise ValueError(f"{self.path}: malformed ledger entry")
            loaded.append(LedgerEntry(**item))
        self._entries = loaded


def _identity(contract: TaskContract) -> tuple[str, str, str]:
    return (contract.principal_id, contract.session_id, contract.tenant_id)
