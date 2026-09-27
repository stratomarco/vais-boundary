from __future__ import annotations

import json
from pathlib import Path

from .durable import SharedStateLock, write_json_atomic
from .models import TaskContract


class RevocationList:
    """Sessions and capabilities whose authority has been withdrawn.

    A task contract has no way to learn that the authority it captured no longer holds
    (LIM-047). Give one of these to the ``ReferenceMonitor`` and every decision checks it
    first. Revoking a session withdraws every capability in it, including delegates made
    with ``TaskContract.delegate``, which keep their parent's session. Revoking a
    capability withdraws only that one.

    Without a ``path`` it lives in one process's memory, and a restart forgets every
    revocation (LIM-056). With a ``path`` it is a file that every check reloads under an
    operating-system lock, so a revocation made by one process, an operator's command for
    instance, holds for every process on this machine sharing the file, and survives a
    restart. A revocation that cannot be written raises and is not applied in memory.
    """

    def __init__(self, path: str | Path | None = None, *, lock_timeout: float = 30.0) -> None:
        self.path = Path(path) if path is not None else None
        self._sessions: set[tuple[str, str, str]] = set()
        self._capabilities: set[tuple[str, str, str, str]] = set()
        self._lock = SharedStateLock(self.path, self._reload, lock_timeout)
        if self.path is not None:
            with self._lock:  # loads the file, and rejects a malformed one now
                pass

    def revoke_session(self, contract: TaskContract) -> None:
        with self._lock:
            key = _session(contract)
            if key not in self._sessions:
                self._sessions.add(key)
                self._persist(lambda: self._sessions.discard(key))

    def revoke_capability(self, contract: TaskContract) -> None:
        with self._lock:
            key = (*_session(contract), contract.capability_id)
            if key not in self._capabilities:
                self._capabilities.add(key)
                self._persist(lambda: self._capabilities.discard(key))

    def is_revoked(self, contract: TaskContract) -> bool:
        with self._lock:
            return (
                _session(contract) in self._sessions
                or (*_session(contract), contract.capability_id) in self._capabilities
            )

    def _persist(self, undo) -> None:
        if self.path is None:
            return
        try:
            write_json_atomic(self.path, {
                "version": 1,
                "sessions": sorted(list(key) for key in self._sessions),
                "capabilities": sorted(list(key) for key in self._capabilities),
            })
        except BaseException:
            undo()
            raise

    def _reload(self) -> None:
        if self.path is None or not self.path.exists():
            return
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict) or raw.get("version") != 1:
            raise ValueError(f"{self.path}: not a version 1 revocation list")
        sessions, capabilities = raw.get("sessions"), raw.get("capabilities")
        if not isinstance(sessions, list) or not isinstance(capabilities, list):
            raise ValueError(f"{self.path}: sessions and capabilities must be lists")
        for items, size in ((sessions, 3), (capabilities, 4)):
            for item in items:
                if not isinstance(item, list) or len(item) != size or not all(isinstance(v, str) for v in item):
                    raise ValueError(f"{self.path}: malformed revocation entry")
        self._sessions = {tuple(item) for item in sessions}
        self._capabilities = {tuple(item) for item in capabilities}


def _session(contract: TaskContract) -> tuple[str, str, str]:
    return (contract.principal_id, contract.session_id, contract.tenant_id)
