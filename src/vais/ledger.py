from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
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

    ``values`` holds, for arguments whose allowed values are single-use, the canonical
    text of the value used; ``amounts`` holds, for budgeted arguments, the amount spent.
    Both are (argument, text) pairs and empty unless the contract declares those rules
    (DEC-067), so a ledger without them is written exactly as before.
    """

    tool: str
    action_fingerprint: str | None
    contract_approval: bool = False
    values: tuple[tuple[str, str], ...] = ()
    amounts: tuple[tuple[str, str], ...] = ()


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

    def used_values(self, tool: str, field: str) -> frozenset[str]:
        with self.lock:
            return frozenset(text for entry in self._entries if entry.tool == tool
                             for name, text in entry.values if name == field)

    def total(self, tool: str, field: str) -> Decimal:
        with self.lock:
            return sum((Decimal(text) for entry in self._entries if entry.tool == tool
                        for name, text in entry.amounts if name == field), Decimal(0))

    def total_for(self, tool: str, field: str, per: str, key: str) -> Decimal:
        """The sum of ``field`` over allowed ``tool`` actions whose ``per`` argument had
        canonical value ``key`` (DEC-069)."""
        with self.lock:
            return sum((Decimal(text) for entry in self._entries
                        if entry.tool == tool and (per, key) in entry.values
                        for name, text in entry.amounts if name == field), Decimal(0))

    def record(self, entry: LedgerEntry) -> None:
        """Append an allowed action. Called by the reference monitor, under its lock."""
        with self.lock:
            self._entries.append(entry)
            if self.path is not None:
                try:
                    write_json_atomic(self.path, {
                        "version": 1,
                        "identity": list(self.identity),
                        "entries": [_entry_dict(e) for e in self._entries],
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
            if (not isinstance(item, dict) or not _BASE_KEYS <= set(item) <= _BASE_KEYS | {"values", "amounts"}
                    or not isinstance(item["tool"], str) or not isinstance(item["contract_approval"], bool)
                    or not (item["action_fingerprint"] is None or isinstance(item["action_fingerprint"], str))):
                raise ValueError(f"{self.path}: malformed ledger entry")
            values = _pairs(item.get("values", []), self.path)
            amounts = _pairs(item.get("amounts", []), self.path)
            for _, text in amounts:
                try:
                    amount = Decimal(text)
                except InvalidOperation:
                    raise ValueError(f"{self.path}: malformed ledger amount") from None
                if not amount.is_finite() or amount < 0:
                    raise ValueError(f"{self.path}: malformed ledger amount")
            loaded.append(LedgerEntry(item["tool"], item["action_fingerprint"], item["contract_approval"], values, amounts))
        self._entries = loaded


_BASE_KEYS = {"tool", "action_fingerprint", "contract_approval"}


def _entry_dict(entry: LedgerEntry) -> dict:
    data = {"tool": entry.tool, "action_fingerprint": entry.action_fingerprint,
            "contract_approval": entry.contract_approval}
    if entry.values:
        data["values"] = [list(pair) for pair in entry.values]
    if entry.amounts:
        data["amounts"] = [list(pair) for pair in entry.amounts]
    return data


def _pairs(raw, path) -> tuple[tuple[str, str], ...]:
    if not isinstance(raw, list) or any(
        not isinstance(pair, list) or len(pair) != 2 or not all(isinstance(part, str) for part in pair)
        for pair in raw
    ):
        raise ValueError(f"{path}: malformed ledger entry")
    return tuple((pair[0], pair[1]) for pair in raw)


def _identity(contract: TaskContract) -> tuple[str, str, str]:
    return (contract.principal_id, contract.session_id, contract.tenant_id)
